//! Transactional outgoing webhooks with bounded retries and signed payloads.
//! The host maps destination IDs to allowlisted HTTPS endpoints and supplies
//! timeouts, redirect policy and secret keys. No URL is stored in the outbox.

use super::{body_hash, sign, valid_id, DedupResult, WebhookError, MAX_BODY_SIZE};
use sqlx::{PgPool, Postgres, Transaction};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, time::timeout};

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_ATTEMPTS: i32 = 8;
type Claimed = (i64, String, String, Vec<u8>, i32);

/// Insert within the same transaction as the business event. An identical
/// destination/event ID is idempotent; a changed payload is rejected.
pub async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    destination: &str,
    event_id: &str,
    body: &[u8],
) -> Result<DedupResult, WebhookError> {
    if !valid_id(destination) || !valid_id(event_id) || body.len() > MAX_BODY_SIZE {
        return Err(WebhookError::InvalidInput);
    }
    let hash = body_hash(body);
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO webhook_outbox(destination, event_id, body_hash, payload) \
         VALUES($1, $2, $3, $4) \
         ON CONFLICT(destination, event_id) DO NOTHING RETURNING id",
    )
    .bind(destination)
    .bind(event_id)
    .bind(&hash)
    .bind(body)
    .fetch_optional(&mut **tx)
    .await?;
    if id.is_some() {
        return Ok(DedupResult::Inserted);
    }
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT body_hash FROM webhook_outbox WHERE destination=$1 AND event_id=$2",
    )
    .bind(destination)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await?;
    if previous.as_deref() == Some(hash.as_str()) {
        Ok(DedupResult::Duplicate)
    } else {
        Err(WebhookError::Conflict)
    }
}

/// Callback arguments: configured destination ID, event ID, signature header,
/// original raw payload bytes. The callback sends to a trusted HTTPS endpoint.
pub type DeliveryFuture = Pin<Box<dyn Future<Output = Result<(), ()>> + Send>>;
pub type WebhookDelivery =
    Arc<dyn Fn(String, String, String, Vec<u8>) -> DeliveryFuture + Send + Sync>;
/// Secrets are injected at runtime and must not be stored in PostgreSQL.
pub type DeliverySecrets = BTreeMap<String, Vec<u8>>;

async fn send_filtered(
    pool: &PgPool,
    secrets: &DeliverySecrets,
    delivery: &WebhookDelivery,
    filter: Option<&str>,
) -> Result<bool, WebhookError> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WebhookError::Clock)?
        .as_secs();
    let timestamp = i64::try_from(time).map_err(|_| WebhookError::Clock)?;
    let candidate: Option<Claimed> = sqlx::query_as(
        "WITH candidate AS ( \
          SELECT id FROM webhook_outbox WHERE delivered_at IS NULL \
          AND dead_at IS NULL AND attempts < 8 \
          AND available_at <= clock_timestamp() \
          AND (lease_until IS NULL OR lease_until <= clock_timestamp()) \
          AND ($1::TEXT IS NULL OR destination = $1) \
          ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED \
         ) \
         UPDATE webhook_outbox w SET attempts = w.attempts + 1, \
            lease_until = clock_timestamp() + INTERVAL '90 seconds' \
         FROM candidate c WHERE w.id = c.id \
         RETURNING w.id, w.destination, w.event_id, w.payload, w.attempts",
    )
    .bind(filter)
    .fetch_optional(pool)
    .await?;
    let Some((id, destination, event_id, payload, attempt)) = candidate else {
        return Ok(false);
    };

    let signed = secrets
        .get(&destination)
        .ok_or(WebhookError::MissingDestination)
        .and_then(|key| sign(key, &destination, &event_id, timestamp, &payload));
    let signature = match signed {
        Ok(signature) => signature,
        Err(error) => {
            // Missing/wrong configuration is NOT an outbound HTTP failure:
            // preserve payload and retry budget so an operator can repair it.
            sqlx::query(
                "UPDATE webhook_outbox SET attempts = attempts - 1, \
                 lease_until = NULL, \
                 available_at = clock_timestamp() + INTERVAL '30 seconds' \
                 WHERE id = $1 AND attempts = $2 AND delivered_at IS NULL",
            )
            .bind(id)
            .bind(attempt)
            .execute(pool)
            .await?;
            tracing::error!(
                outbox_id = id,
                "webhook destination configuration missing or invalid"
            );
            return Err(error);
        }
    };
    let delivered = timeout(
        DELIVERY_TIMEOUT,
        (delivery)(destination, event_id, signature, payload),
    )
    .await
    .map(|result| result.is_ok())
    .unwrap_or(false);

    if delivered {
        sqlx::query(
            "UPDATE webhook_outbox SET delivered_at = clock_timestamp(), \
             payload = '\\x'::BYTEA, lease_until = NULL \
             WHERE id = $1 AND attempts = $2 AND delivered_at IS NULL",
        )
        .bind(id)
        .bind(attempt)
        .execute(pool)
        .await?;
    } else {
        let terminal = attempt >= MAX_ATTEMPTS;
        sqlx::query(
            "UPDATE webhook_outbox SET lease_until = NULL, \
             available_at = clock_timestamp() + \
                (LEAST(1800, 30 * (1 << LEAST(attempts - 1, 6))) * INTERVAL '1 second'), \
             dead_at = CASE WHEN $3 THEN clock_timestamp() ELSE dead_at END, \
             payload = CASE WHEN $3 THEN '\\x'::BYTEA ELSE payload END \
             WHERE id = $1 AND attempts = $2 AND delivered_at IS NULL",
        )
        .bind(id)
        .bind(attempt)
        .bind(terminal)
        .execute(pool)
        .await?;
        tracing::warn!(
            outbox_id = id,
            attempt,
            "outgoing webhook scheduled for retry"
        );
    }
    Ok(true)
}

pub async fn send_next(
    pool: &PgPool,
    secrets: &DeliverySecrets,
    delivery: &WebhookDelivery,
) -> Result<bool, WebhookError> {
    send_filtered(pool, secrets, delivery, None).await
}

#[cfg(test)]
pub(super) async fn send_next_to(
    pool: &PgPool,
    secrets: &DeliverySecrets,
    delivery: &WebhookDelivery,
    destination: &str,
) -> Result<bool, WebhookError> {
    send_filtered(pool, secrets, delivery, Some(destination)).await
}

#[derive(Debug, Clone, Copy)]
pub struct WebhookStats {
    pub pending: i64,
    pub due: i64,
    pub dead: i64,
    pub oldest_pending_seconds: f64,
}

pub async fn stats(pool: &PgPool) -> Result<WebhookStats, sqlx::Error> {
    let (pending, due, dead, oldest_pending_seconds): (i64, i64, i64, f64) =
        sqlx::query_as(
            "SELECT \
              COUNT(*) FILTER(WHERE delivered_at IS NULL AND dead_at IS NULL)::BIGINT, \
              COUNT(*) FILTER(WHERE delivered_at IS NULL AND dead_at IS NULL \
                 AND available_at <= clock_timestamp())::BIGINT, \
              COUNT(*) FILTER(WHERE dead_at IS NOT NULL)::BIGINT, \
              GREATEST(0, COALESCE(EXTRACT(EPOCH FROM (clock_timestamp() - \
                 MIN(available_at) FILTER(WHERE delivered_at IS NULL AND dead_at IS NULL))), 0))::FLOAT8 \
             FROM webhook_outbox",
        )
        .fetch_one(pool)
        .await?;
    Ok(WebhookStats {
        pending,
        due,
        dead,
        oldest_pending_seconds,
    })
}

/// Bounded retention. Retain inbox keys beyond a sender's retry horizon.
pub async fn cleanup_once(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let inbox = sqlx::query(
        "DELETE FROM webhook_inbox WHERE id IN ( \
          SELECT id FROM webhook_inbox WHERE \
          received_at < clock_timestamp() - INTERVAL '30 days' \
          ORDER BY id LIMIT 200)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    let outbox = sqlx::query(
        "DELETE FROM webhook_outbox WHERE id IN ( \
          SELECT id FROM webhook_outbox WHERE \
          delivered_at < clock_timestamp() - INTERVAL '30 days' \
          OR dead_at < clock_timestamp() - INTERVAL '30 days' \
          ORDER BY id LIMIT 200)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(inbox + outbox)
}

/// Run as a separate supervised process. Delivery is at least once.
pub async fn run_worker(
    pool: PgPool,
    secrets: Arc<DeliverySecrets>,
    delivery: WebhookDelivery,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut next_cleanup = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if *shutdown.borrow() {
            break;
        }
        match send_next(&pool, &secrets, &delivery).await {
            Ok(true) => {}
            Ok(false) => tokio::time::sleep(Duration::from_secs(2)).await,
            Err(error) => {
                tracing::error!(%error, "webhook outbox delivery failed");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        if tokio::time::Instant::now() >= next_cleanup {
            if let Err(error) = cleanup_once(&pool).await {
                tracing::error!(%error, "webhook cleanup failed");
            }
            next_cleanup = tokio::time::Instant::now() + Duration::from_secs(120);
        }
        if shutdown.has_changed().is_err() || *shutdown.borrow_and_update() {
            break;
        }
    }
}
