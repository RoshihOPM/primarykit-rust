# Transactional audit outbox (PostgreSQL)

The optional `audit` module now includes an **opt-in** outbox and a separate
worker. Generated Axum applications own the code, migrations, integration and
credentials. The generator enables neither routes nor background processes.

## Write path

1. Begin an SQLx transaction for a business mutation.
2. Construct `audit::AuditContext` from a verified principal and trusted
   server/request context, never an unsigned user-supplied actor/tenant ID.
3. Call `audit::record_and_enqueue(&mut tx, context, action, resource_type,
   resource_id, "analytics")` within that transaction. The destination is a
   configured identifier, **not a URL**.
4. Commit only after the business writes and audit/outbox inserts succeed.
   Rollback removes both the event and its notification automatically.

The returned stable `audit_event_id` identifies the notification. Existing
`record()` and `record_with_context()` calls do not enqueue events; migrate
application call sites explicitly.

This is a PostgreSQL transactional outbox, **not** a distributed atomic
transaction between PostgreSQL and RabbitMQ/Kafka/HTTP.

## Delivery path

Supervise `audit::outbox::run_worker(pool, handler, shutdown)` as a separate
process or long-lived Tokio task. The `AuditDeliveryHandler` callback must
resolve destination keys using an explicit allowlist; do not allow arbitrary
URLs (SSRF). Implement TLS, credentials, external request timeouts and retry
classification. Return success only after the external system has durably
acknowledged the event (for RabbitMQ, a publisher confirmation).

Failed delivery returns `DeliveryFailure::Retry` or `Permanent`. The worker
uses `FOR UPDATE SKIP LOCKED`, a 90-second lease, and monotonic fencing
generations. Delivery callbacks are capped at 25 seconds. Attempts use bounded
exponential backoff and terminate after eight failures; a crashed final
attempt is also marked dead after lease expiry. Shutdown finishes the active
delivery and interrupts idle sleep.

**At-least-once semantics:** crashes, lost acknowledgements or timed-out
callbacks can produce duplicates. Consumers must deduplicate by
`(destination, audit_event_id)` transactionally with their business changes.
Lease fencing protects outbox bookkeeping, **not** external side effects.

On PostgreSQL failure, the worker returns an error for its supervisor to
restart/alert; it never deliberately acknowledges an undelivered event.

## Operations and security

- Monitor `audit::outbox::stats(pool)` through authenticated operations only:
  pending, due, dead and oldest pending age. Alert on dead rows, backlog and
  excessive age.
- Dead rows remain available for investigation. Requeue only after checking
  downstream idempotency and correcting the root cause.
- Restrict access to the append-only audit history and mutable operational
  outbox. Plan retention/archiving and high-volume table growth.
- Store no secrets or personal profiles in audit identifiers. The outbox stores
  only the event ID, configured destination and delivery metadata; the worker
  reads the full event context from PostgreSQL.
- Protect broker and webhook destinations with explicit allowlists, TLS and
  least-privilege credentials.

`20261105000001_audit_delivery_outbox.sql` is an **additive** migration. Never
rewrite already applied SQLx migrations. Previously generated projects are
independent and are not automatically upgraded by newer generator releases.

### Гарантии

Аудит и outbox записываются в **одной транзакции PostgreSQL**. При откате
операции обе записи откатываются. Доставка выполняется по принципу
**at-least-once**, поэтому потребитель обязан обеспечить идемпотентность по
`(destination, audit_event_id)`. Отправка в брокер или HTTP не становится
атомарной частью транзакции БД.
