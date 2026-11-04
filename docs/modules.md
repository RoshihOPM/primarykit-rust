# PrimaryKit Rust portable modules

Modules are copied into the target project under src/modules and registered
as public library exports. Generated projects are independent from PrimaryKit.

## Commands

    cargo run -p primarykit -- modules
    cargo run -p primarykit -- add api_errors --project ./inventory_api
    cargo run -p primarykit -- add pagination --project ./inventory_api
    cargo run -p primarykit -- add audit --project ./db_api

Dependencies are resolved automatically. Installing pagination also installs
api_errors. audit is only valid with the PostgreSQL template.

## Module inventory

| Module | Template | Dependencies | Functionality |
|---|---|---|---|
| api_errors | basic / postgres | none | Typed safe JSON HTTP error responses |
| pagination | basic / postgres | api_errors | Validated page/per_page and SQL offsets |
| audit | postgres | none | Transactional audit writer with append-only PostgreSQL triggers |
| auth | postgres | none | Argon2id passwords, opaque revocable/rotating sessions |
| permissions | postgres | auth | Tenant-scoped deny-by-default RBAC |
| api_keys | postgres | permissions | One-time opaque tenant keys with live RBAC |
| auth_http | postgres | auth | Identity API with encrypted transactional outbox |
| auth_smtp | postgres | auth_http | TLS-only SMTP delivery callback |
| owned_records | postgres | permissions | Tenant and owner-aware SQL access |
| webhooks | postgres | none | Signed inbound webhook receipts and durable outbound delivery |
| tasks | basic / postgres | none | Durable RabbitMQ worker with retries, DLQ and shutdown |

In a generated application's Rust code, import items through the library
crate's public modules, for example:

    use inventory_api::modules::pagination::Pagination;
    use inventory_api::modules::api_errors::ApiError;

The installer does not inject HTTP routes or run arbitrary module scripts.
Applications wire exported functions into their own business logic.

For the audit module, business changes and audit writes must share an SQLx
transaction. Run both versioned SQLx migrations before using audit, and commit
only when both writes succeed. The resource-history index supports lookups;
the second migration rejects UPDATE, DELETE and TRUNCATE with SQLSTATE 42501.

This is **append-only protection, not tamper-proof storage**: PostgreSQL table
owners and superusers can disable/drop triggers, and a compromised privileged
connection can modify history. Use separate migration and application database
roles, prohibit application DDL, audit privileged changes externally, and define
a retention/partitioning policy before the table grows without bound. Existing
deployments must apply the additive migration; never rewrite an applied SQLx
migration checksum.

The additive `20261104000011_audit_actor_context.sql` migration adds `actor_kind`
(`user`, `service`, `system`, or `legacy`), optional `tenant_id`, and
`request_id` for correlation. Use `audit::record_with_context` with a trusted
`AuditContext` in the **same SQLx transaction** as the domain write. IDs must
come from validated sessions, service authentication and server-side request
context, not unsigned request headers. A user/service actor requires a
non-empty bounded actor ID; old `record` calls and existing rows remain
`legacy` for compatibility. Tenant and request IDs are limited to 128
characters by database constraints. Do not put passwords, session tokens,
authorization headers or other secrets in audit identifiers. Restrict
audit-table SELECT grants and define data retention. The generator does not
automatically patch previously copied projects: apply this new migration and
port the writer explicitly to existing deployments.

## Safety policy

- Only catalog modules may be installed; no remote template code is fetched.
- Reject incompatible templates, unknown modules, edited registration blocks,
  modified provenance schemas, and pre-existing destination files.
- Preserve user code outside the managed module-registration markers.
- Resolve dependencies before changing any files; avoid partial installs
  for standard errors.
- No arbitrary replacement of application files or migrations.
- Installation is not fully crash-atomic; if a process is interrupted during
  a write, inspect and reconcile the project before retrying.
- Generator provenance is local metadata, not a cryptographic attestation.

For production systems, security review and integration testing are required
before deploying generated modules.


## Authentication and authorization (initial modules)

    cargo run -p primarykit -- add permissions --project ./db_api

Installs both \`auth\` and \`permissions\`, their migrations and module-local
dependencies in the generated project's managed Cargo dependency block.
Old projects without this block must be migrated deliberately: the installer
refuses to edit an unmarked Cargo manifest.

The \`auth\` module supplies Argon2id password hashing/verification and 256-bit
random, opaque sessions (only SHA-256 token digests are stored). Sessions are
revocable, expire in PostgreSQL and can be rotated in a single transaction.
Password verification must run via \`tokio::task::spawn_blocking\`, with throttling
and consistent error handling on login attempts. Raw tokens are secrets: never
include them in logs, URLs or analytics.

The \`permissions\` module checks a user's ACTIVE status and explicit role
assignments in a specific tenant. A missing role or permission denies access,
and database errors must never be converted into allow decisions. The caller
must derive the tenant scope from trusted resource data and additionally
constrain business queries by tenant and object identifiers.

These are **code modules**, not a complete identity product. This release
does not supply login/register HTTP endpoints, recovery, MFA, tenant provisioning,
distributed rate limiting, cleanup workers or a full account-management UI.
Review the business flow and threat model before exposing authentication publicly.

For RBAC, `has_permission` accepts an `AuthenticatedUser` obtained from
`auth::authenticate_session`, not an arbitrary user ID. The principal's
identity field cannot be initialized from outside the auth module. After
authentication, business queries still need to enforce actual tenant and
resource ownership. Sessions must be revalidated for each incoming request.


## Optional HTTP identity flows

Install the portable Axum module in a PostgreSQL project:

    primarykit add auth_http --project ./db_api

It depends on \`auth\` and exposes an **opt-in** router. You must construct an
\`auth_http::IdentityState\` with a PostgreSQL pool and a \`TokenDelivery\`
callback, then merge \`auth_http::routes(state)\` into the app router.
No routes are exposed automatically by the generator.

Routes: POST /auth/register, /auth/verify-email, /auth/login,
/auth/logout, /auth/me, /auth/password-reset/request,
/auth/password-reset/confirm. Only verification activates a new user.
Password reset revokes all active sessions. Tokens for verification and
password reset are 256-bit opaque secrets, hashed in PostgreSQL and single-use.
No token is included in a public verification/reset-request response.
The host application's token delivery callback must construct a trusted HTTPS
URL and send email; the module does not bundle SMTP credentials or a mail worker.

The database-backed identity limiter allows five attempts per 15-minute
window per normalized email and operation. **It is not an edge/IP limiter.**
In production use TLS and additional per-IP/network limits at an ingress
or reverse proxy. Do not trust spoofable X-Forwarded-For headers without
explicit proxy trust configuration. Password hashing/verification is moved
to Tokio's blocking thread pool. Keep its concurrency bounded by operational
policy to avoid CPU and memory exhaustion.

Identity emails are committed to an encrypted PostgreSQL transactional outbox
at the same time as the one-time token. Delivery happens **after commit**, not
inside HTTP requests. The generated project's IdentityState requires an
\`outbox_keys: Arc<OutboxKeyring>\` loaded from a deployment secret manager. Use
independently generated random 32-byte keys (never hard-code test keys in
production); share them with all HTTP replicas and delivery workers. Keys
are not stored in PostgreSQL. All messages are tagged with a key ID and previous keys can decrypt outstanding
backlog. Existing pre-versioned messages are tagged `legacy` during migration.
Read `docs/identity-key-rotation.md` before changing the active key.

Run \`auth_http::identity_outbox::run_worker(pool, key, deliver, shutdown)\` as
a separate long-lived Tokio task/process. The callback is still provided
by the host application and must send the mail with a trusted HTTPS reset/
verify URL and bounded network timeouts. The queue uses row leases with
\`FOR UPDATE SKIP LOCKED\`, bounded exponential retries and dead-letter
states. **Delivery is at least once:** if a worker crashes after the provider
accepted an email but before acknowledgement, the email can be delivered
again. The provider integration should support idempotency where available.
After successful delivery the encrypted token payload is erased from its
outbox row; the one-time token hash remains until retention cleanup.

The worker also invokes \`cleanup_once\` to remove stale counters, expired
tokens, and old sessions in bounded batches. Monitor dead rows, lag, retry
counts, missing email deliveries, and key validity.

This module remains **not fully production-ready**: configure TLS, network
edge/IP rate limiting, email retry policies, operational alerts and a threat
model before exposing it publicly.

## Example object-level authorization

Install \`owned_records\` in a PostgreSQL service. It also installs
\`auth\` and \`permissions\`.

    primarykit add owned_records --project ./db_api

The module supplies an example \`owned_records\` table and typed Rust
functions \`get(pool, validated_principal, id)\` and
\`update(pool, validated_principal, id, body)\`.

It deliberately derives the tenant from the **stored resource**, not an
untrusted tenant header. Both actions enforce user activation, explicit
tenant RBAC grants and resource ownership in the **same SQL statement**.
Missing resources, wrong owners and denied grants all return absence or
false to avoid exposing cross-tenant existence. Integration tests exercise
legitimate access, intruders in the same tenant, missing write permission
and deactivated users.

This is a reference implementation: real applications must embed equivalent
predicates into their own domain queries and decide whether a role grants
access beyond the owner. Do not treat a separate \`has_permission\` call
followed by an unguarded resource update as safe.


### Memory and password-reset concurrency

Argon2 password operations are bounded to four concurrent blocking workers
per server process. Workers retain semaphore permits until hashing completes,
even when HTTP requests are cancelled. Deploy independent network-edge
throttling and measure queue latency before exposing login publicly.

After verifying a password, session creation rechecks the exact verified
password hash under a PostgreSQL row lock. A concurrent password reset either
revokes the newly committed session or changes the password first, preventing
issuance of a session using superseded credentials.

## Production SMTP adapter

Install `auth_smtp` into an Axum/PostgreSQL project to add an optional
TLS-only SMTP provider callback compatible with the transactional identity
outbox:

    primarykit add auth_smtp --project ./db_api

Configure `SMTP_RELAY_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
`SMTP_FROM`, `IDENTITY_PUBLIC_ORIGIN` (HTTPS origin without a path), and
`IDENTITY_OUTBOX_KEY_HEX` (active 32-byte key encoded as
64 hexadecimal characters; never commit this secret). The adapter requires
SMTP TLS via certificate-verified SMTPS on port 465. No plaintext or
opportunistic SMTP downgrade is permitted.

Call `auth_smtp::SmtpConfig::from_env()?.delivery()?` to construct the
`TokenDelivery` callback. Call `auth_smtp::outbox_keys_from_env()?` to
load the encryption key. Pass both to `auth_http::IdentityState` for
HTTP routes and to `auth_http::identity_outbox::run_worker` in a **separate
long-running worker process**. Do not run the worker as part of each request.

The email contains a verification or reset link with the token in the URL
**fragment**, not the HTTP query string. Your frontend must read that fragment,
POST the token to `/auth/verify-email` or
`/auth/password-reset/confirm`, then immediately clear it from browser
history. Do not log the full URL or leak it to third-party scripts.

Run one to a few worker replicas initially; the PostgreSQL leases avoid
simultaneous claims. Delivery is at-least-once: if the SMTP server accepts a
message and the worker crashes before acknowledgement, it might be delivered
again. Test how your provider handles this and keep the mail content
idempotent.

`identity_outbox::stats(pool)` reports queued, due, dead-letter counts and
oldest pending age. Monitor them in an authenticated operations service;
alert on increasing dead letters or delivery age beyond expected latency.
`identity_outbox::cleanup_once` scrubs expired/used pending secrets and
purges old metadata in bounded batches. Rotate using
`IDENTITY_OUTBOX_KEY_ID` and `IDENTITY_OUTBOX_PREVIOUS_KEYS` and retain
previous keys until no encrypted pending rows use them. Read
`docs/identity-key-rotation.md` for safe rollout and rollback.

See `docs/identity-operations.md` for a worker integration example and
Nginx ingress rules. SMTP provider credentials must be provisioned separately;
this adapter never registers with or configures an external provider.


## Portable webhooks

Install in a generated PostgreSQL application:

    primarykit add webhooks --project ./db_api

Incoming webhook handlers must obtain a **per-source secret of at least 32
bytes** from a secret manager and derive source identity from trusted route
configuration, not an arbitrary unsigned request header. Use
webhooks::verify(secret, source, event_id, signature, exact_body, now_unix)
before JSON parsing or any business mutation. The signature header uses
t=unix_seconds,v1=HMAC-SHA256 and authenticates the timestamp, source ID,
event ID and the exact request bytes. Reject timestamps outside +/- 5 minutes
and enforce a 256 KiB body-size limit at the reverse proxy as well as in code.

On successful verification, open a SQLx transaction and call
webhooks::reserve_inbound(&mut tx, &verified). Only for Inserted should the
handler perform its domain writes; commit the receipt and all business writes
in the **same transaction**. A duplicate receipt means already processed.
An event ID reused for different bytes is a Conflict, not a duplicate.
If the transaction rolls back, replay protection rolls back with it.
Retention of inbox receipts defaults to 30 days; increase it if any provider
retries longer. Duplicate external deliveries are expected.

For outgoing events, call webhooks::outbox::enqueue(tx, configured_destination,
event_id, raw_body) within the originating domain transaction. This stores
the payload and stable event ID, **not the destination URL or signing key**.
Run webhooks::outbox::run_worker as an independent supervised process with
DeliverySecrets loaded from a secret manager and a WebhookDelivery callback.

The delivery callback receives the configured destination identifier,
event ID, signed timestamp header and original body. It must resolve the
destination ID to a **fixed HTTPS allowlist** with DNS/private-address
protection, avoid redirects, use bounded timeouts and treat only successful
2xx responses as accepted. Never allow arbitrary user-supplied destination
URLs. The worker uses PostgreSQL SKIP LOCKED, attempt fencing and bounded
backoff, scrubs payloads after success or terminal failure, and exposes
operational counters through outbox::stats. Delivery is **at least once**,
not exactly once: the receiver must deduplicate event IDs.

A missing destination key pauses delivery without consuming retry budget.
Alert on dead-letter growth, oldest pending age, wrong credentials,
connection failures and queue lag. The queue stores **unencrypted payload
bytes** until completion; restrict PostgreSQL read access and avoid putting
unnecessary secrets or personal information in messages.

A full HTTP transport, production secret provisioning, broker setup and
per-provider authentication policies are intentionally application-owned.
The module never exposes HTTP routes automatically.

## API keys (tenant-scoped)

The optional `api_keys` module depends on `permissions` and `auth`:

    primarykit add api_keys --project ./db_api

An authenticated user may issue a 256-bit opaque API key for a tenant only
when current RBAC grants `api_keys.create` AND each requested scope.
The returned bearer token is disclosed once; PostgreSQL stores only its
SHA-256 digest. Scopes must be distinct, cannot contain wildcards, and must
match explicit tenant permissions. Key expiry is capped at 90 days.

`authenticate(pool, token)` resolves a typed, non-forgeable principal.
`allows(pool, &principal, permission)` rechecks the saved scopes, live RBAC,
expiry, revocation and user activation on every use. Revoking a role therefore
removes key access immediately. Simply checking the token once and trusting
a requested permission is unsafe.

The owner may revoke a key while active. Other users need `api_keys.revoke`
in the same tenant. Do not include API tokens in URLs, logs or analytics;
use an Authorization header behind TLS, and implement client-level limits.

This is a portable backend module, not a complete HTTP key-management API.
Applications must build their own audit trail, authorization middleware and
administration UX; do not grant tenant-wide access based solely on key format.

## RabbitMQ tasks (opt-in)

Install `tasks` in an independent basic or PostgreSQL Axum project:

    primarykit add tasks --project ./app_api

The host constructs `tasks::TaskConfig::new("orders")`, creates a RabbitMQ
connection with `tasks::connect(url, false)`, then creates separate AMQP
channels for publishing and consuming. Run `tasks::declare(&channel, &config)`
on each channel before using `tasks::enqueue` or `tasks::run_worker`.
Only `amqps://` connections are accepted by default. The `true` option
permits **only loopback** plaintext `amqp://` for local integration tests.

The module declares durable `orders`, `orders.retry` and `orders.dead`
queues. Messages use delivery mode 2 and **mandatory publisher confirms**:
unroutable or unconfirmed publications are errors, not successes. A worker
acknowledges only after handler success or broker-confirmed retry enqueue.
Transient failures and timeouts get up to five attempts by default, via a
30-second TTL retry queue. Malformed messages, permanent failures and exhausted
retries are rejected into a dead-letter queue. A failed retry publication
requeues the original delivery and fails the worker so its supervisor can
restart it rather than spinning indefinitely.

Each message has a stable UUID across retries. Processing is **at least once**:
ack loss, reconnects or confirmed retry republishing can duplicate side
effects. The application MUST apply an idempotency key in the same PostgreSQL
transaction as its business writes, or implement equivalent transactional
deduplication in its own storage. A publisher call is **not** atomic with
PostgreSQL commits; use a transactional outbox when both need to succeed.
Do not assume that a RabbitMQ publish after a database write cannot be lost.

`run_worker` processes one task at a time per AMQP channel with bounded
payloads (128 KiB), configurable handler timeout and graceful shutdown after
the active task. Scale with additional worker channels/processes. Supervise
workers, alert on DLQ depth and stale queues, ensure termination grace exceeds
the configured handler timeout, and use dedicated broker permissions/vhosts.
Message bodies are plaintext within RabbitMQ; apply TLS, least privilege and
data minimization. Retry queue topology (TTL/DLX) cannot be silently modified
after declaration: plan migration when changing it.

A generated project does not automatically run a consumer or configure a
RabbitMQ account. Deployment must provide broker credentials, TLS validation,
queue monitoring and worker lifecycle management. Integration tests run
against `AMQP_URL` when set; CI provisions an ephemeral RabbitMQ instance.
