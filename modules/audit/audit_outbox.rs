//! Durable PostgreSQL outbox for committed audit events.
//!
//! Delivery is at least once. The host must use a trusted destination registry,
//! idempotently consume the stable audit_event_id, and supervise this worker.
//! No HTTP URLs or broker credentials are stored in the outbox.

use sqlx::PgPool;
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{sync::watch, time::timeout};

const MAX_ATTEMPTS: i32 = 8;
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(25);
const IDLE_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum AuditOutboxError {
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("audit delivery lease was lost; delivery outcome is uncertain")]
    LeaseLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryFailure {
    Retry,
    Permanent,
}

/// The destination is a trusted configuration key, never a user-controlled URL.
/// A consumer must deduplicate using (destination, audit_event_id).
#[derive(Debug, Clone)]
pub struct AuditDelivery {
    pub destination: String,
    pub audit_event_id: i64,
    pub actor_id: Option<String>,
    pub actor_kind: String,
    pub tenant_id: Option<String>,
    pub request_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
}

pub type AuditDeliveryFuture = Pin<Box<dyn Future<Output = Result<(), DeliveryFailure>> + Send>>;
pub type AuditDeliveryHandler = Arc<dyn Fn(AuditDelivery) -> AuditDeliveryFuture + Send + Sync>;

#[derive(Debug, sqlx::FromRow)]
struct ClaimedDelivery {
    id: i64,
    lease_generation: i64,
    attempts: i32,
    destination: String,
    audit_event_id: i64,
    actor_id: Option<String>,
    actor_kind: String,
    tenant_id: Option<String>,
    request_id: Option<String>,
    action: String,
    resource_type: String,
    resource_id: String,
}

/// Reserve exactly one due row without a long-lived transaction or connection.
/// Each expired lease is reissued with a new fencing generation.
async fn claim_one(
    pool: &PgPool,
    destination_filter: Option<&str>,
) -> Result<Option<ClaimedDelivery>, sqlx::Error> {
    sqlx::query_as::<_, ClaimedDelivery>(
        r#"
        WITH candidate AS (
            SELECT o.id
            FROM audit_delivery_outbox o
            WHERE o.delivered_at IS NULL AND o.dead_at IS NULL
              AND o.attempts < 8
              AND o.available_at <= clock_timestamp()
              AND (o.leased_until IS NULL OR o.leased_until < clock_timestamp())
              AND ($1::TEXT IS NULL OR o.destination = $1)
            ORDER BY o.available_at, o.id
            LIMIT 1
            FOR UPDATE OF o SKIP LOCKED
        ), leased AS (
            UPDATE audit_delivery_outbox o
            SET attempts = o.attempts + 1,
                lease_generation = o.lease_generation + 1,
                leased_until = clock_timestamp() + INTERVAL '90 seconds'
            FROM candidate c
            WHERE o.id = c.id
            RETURNING o.id, o.lease_generation, o.attempts,
                      o.destination, o.audit_event_id
        )
        SELECT l.id, l.lease_generation, l.attempts, l.destination,
               l.audit_event_id, e.actor_id, e.actor_kind, e.tenant_id,
               e.request_id, e.action, e.resource_type, e.resource_id
        FROM leased l
        JOIN audit_events e ON e.id = l.audit_event_id
        "#,
    )
    .bind(destination_filter)
    .fetch_optional(pool)
    .await
}

/// If the eighth attempt crashed after external delivery but before a DB
/// acknowledgement, its lease expires and it must be marked dead for review.
/// This bounded sweep prevents an eighth-attempt orphan from remaining pending.
async fn dead_letter_exhausted(
    pool: &PgPool,
    destination_filter: Option<&str>,
) -> Result<u64, sqlx::Error> {
    let updated = sqlx::query(
        r#"
        WITH expired AS (
            SELECT id FROM audit_delivery_outbox
            WHERE delivered_at IS NULL AND dead_at IS NULL
              AND attempts >= 8
              AND (leased_until IS NULL OR leased_until < clock_timestamp())
              AND ($1::TEXT IS NULL OR destination = $1)
            ORDER BY id LIMIT 100 FOR UPDATE SKIP LOCKED
        )
        UPDATE audit_delivery_outbox o
        SET dead_at = clock_timestamp(), leased_until = NULL
        FROM expired e WHERE o.id = e.id
        "#,
    )
    .bind(destination_filter)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated)
}

async fn complete_claim(pool: &PgPool, id: i64, generation: i64) -> Result<(), AuditOutboxError> {
    let updated = sqlx::query(
        r#"
        UPDATE audit_delivery_outbox
        SET delivered_at = clock_timestamp(), leased_until = NULL
        WHERE id = $1 AND lease_generation = $2
          AND leased_until > clock_timestamp()
          AND delivered_at IS NULL AND dead_at IS NULL
        "#,
    )
    .bind(id)
    .bind(generation)
    .execute(pool)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(AuditOutboxError::LeaseLost);
    }
    Ok(())
}

async fn fail_claim(
    pool: &PgPool,
    id: i64,
    generation: i64,
    terminal: bool,
) -> Result<(), AuditOutboxError> {
    let updated = sqlx::query(
        r#"
        UPDATE audit_delivery_outbox
        SET leased_until = NULL,
            dead_at = CASE WHEN $3 OR attempts >= 8
                      THEN clock_timestamp() ELSE NULL END,
            available_at = clock_timestamp()
                 + (LEAST(900, 5 * (1 << LEAST(attempts, 7)))
                    * INTERVAL '1 second')
        WHERE id = $1 AND lease_generation = $2
          AND leased_until > clock_timestamp()
          AND delivered_at IS NULL AND dead_at IS NULL
        "#,
    )
    .bind(id)
    .bind(generation)
    .bind(terminal)
    .execute(pool)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(AuditOutboxError::LeaseLost);
    }
    Ok(())
}

async fn send_filtered(
    pool: &PgPool,
    deliver: &AuditDeliveryHandler,
    destination_filter: Option<&str>,
) -> Result<bool, AuditOutboxError> {
    dead_letter_exhausted(pool, destination_filter).await?;
    let Some(claimed) = claim_one(pool, destination_filter).await? else {
        return Ok(false);
    };
    let event = AuditDelivery {
        destination: claimed.destination,
        audit_event_id: claimed.audit_event_id,
        actor_id: claimed.actor_id,
        actor_kind: claimed.actor_kind,
        tenant_id: claimed.tenant_id,
        request_id: claimed.request_id,
        action: claimed.action,
        resource_type: claimed.resource_type,
        resource_id: claimed.resource_id,
    };
    let result = timeout(DELIVERY_TIMEOUT, (deliver)(event)).await;
    match result {
        Ok(Ok(())) => complete_claim(pool, claimed.id, claimed.lease_generation).await?,
        Ok(Err(DeliveryFailure::Permanent)) => {
            fail_claim(pool, claimed.id, claimed.lease_generation, true).await?
        }
        Ok(Err(DeliveryFailure::Retry)) | Err(_) => {
            fail_claim(
                pool,
                claimed.id,
                claimed.lease_generation,
                claimed.attempts >= MAX_ATTEMPTS,
            )
            .await?
        }
    }
    Ok(true)
}

/// Process a single due audit notification. False means no eligible work.
/// A timed-out callback may have completed side effects: expect duplicates.
pub async fn send_next(
    pool: &PgPool,
    deliver: &AuditDeliveryHandler,
) -> Result<bool, AuditOutboxError> {
    send_filtered(pool, deliver, None).await
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AuditOutboxStats {
    pub pending: i64,
    pub due: i64,
    pub dead: i64,
    pub oldest_pending_seconds: f64,
}

/// Expose to authenticated operations/metrics only, never a public API.
pub async fn stats(pool: &PgPool) -> Result<AuditOutboxStats, sqlx::Error> {
    let (pending, due, dead, oldest_pending_seconds): (i64, i64, i64, f64) = sqlx::query_as(
        r#"
            SELECT COUNT(*) FILTER
                       (WHERE delivered_at IS NULL AND dead_at IS NULL)::BIGINT,
                   COUNT(*) FILTER
                       (WHERE delivered_at IS NULL AND dead_at IS NULL
                          AND available_at <= clock_timestamp())::BIGINT,
                   COUNT(*) FILTER (WHERE dead_at IS NOT NULL)::BIGINT,
                   GREATEST(0, COALESCE(EXTRACT(EPOCH FROM (
                       clock_timestamp() - MIN(created_at) FILTER
                       (WHERE delivered_at IS NULL AND dead_at IS NULL)
                   )), 0))::FLOAT8
            FROM audit_delivery_outbox
            "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(AuditOutboxStats {
        pending,
        due,
        dead,
        oldest_pending_seconds,
    })
}

async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(delay) => false,
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow_and_update(),
    }
}

/// Run in a supervised process. Stop claiming when cancelled, but finish
/// the current bounded delivery. Database errors terminate the worker so
/// supervision/alerting can act rather than silently dropping audit events.
pub async fn run_worker(
    pool: PgPool,
    delivery: AuditDeliveryHandler,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AuditOutboxError> {
    loop {
        if *shutdown.borrow() {
            break;
        }
        if !send_next(&pool, &delivery).await? && wait_or_shutdown(&mut shutdown, IDLE_DELAY).await
        {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "audit_outbox_tests.rs"]
mod tests;
