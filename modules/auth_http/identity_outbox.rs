//! Durable, at-least-once email delivery for auth_http.
//!
//! Queue entries and one-time tokens are committed in the same PostgreSQL
//! transaction. Raw secrets are encrypted with a deployment-managed AEAD key,
//! never persisted as plaintext. Multiple workers can poll concurrently.
//! Providers must tolerate duplicate deliveries after an acknowledgement race.

use super::TokenDelivery;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{sync::watch, time::timeout};

const MAX_DELIVERY_ATTEMPTS: i32 = 8;
const SEND_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug, Error)]
pub enum OutboxError {
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("encrypted identity secret could not be processed")]
    Crypto,
}

fn hash_token(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

/// Queues a verification/reset token and a recoverable encrypted email
/// payload in the caller's transaction. The HTTP caller MUST commit only
/// after this function returns successfully.
pub async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    user_id: i64,
    purpose: &'static str,
    ttl_minutes: i64,
    key: &[u8; 32],
) -> Result<(), OutboxError> {
    if !matches!(purpose, "verify" | "reset") || !(1..=1440).contains(&ttl_minutes) {
        return Err(OutboxError::Crypto);
    }
    let mut secret = [0_u8; 32];
    let mut nonce = [0_u8; 12];
    OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|_| OutboxError::Crypto)?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| OutboxError::Crypto)?;
    let token = hex::encode(secret);
    let digest = hash_token(&token);
    let sealed = cipher(key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: token.as_bytes(),
                aad: digest.as_bytes(),
            },
        )
        .map_err(|_| OutboxError::Crypto)?;

    sqlx::query(
        "INSERT INTO auth_http_one_time_tokens (token_hash, user_id, purpose, expires_at) \
         VALUES ($1, $2, $3, clock_timestamp() + ($4::BIGINT * INTERVAL '1 minute'))",
    )
    .bind(&digest)
    .bind(user_id)
    .bind(purpose)
    .bind(ttl_minutes)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO auth_http_outbox (token_hash, user_id, purpose, nonce, ciphertext) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(digest)
    .bind(user_id)
    .bind(purpose)
    .bind(nonce.as_slice())
    .bind(sealed)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

type Claimed = (i64, String, String, String, Vec<u8>, Vec<u8>, i32);

async fn send_filtered(
    pool: &PgPool,
    key: &[u8; 32],
    deliver: &TokenDelivery,
    email_filter: Option<&str>,
) -> Result<bool, OutboxError> {
    // The lease prevents concurrent deliveries. attempt number fences delayed
    // acknowledgements from workers whose lease has expired.
    let item: Option<Claimed> = sqlx::query_as(
        "WITH candidate AS ( \
           SELECT o.id FROM auth_http_outbox o \
           JOIN auth_http_one_time_tokens t ON t.token_hash = o.token_hash \
           JOIN auth_users u ON u.id = t.user_id \
           WHERE o.delivered_at IS NULL AND o.dead_at IS NULL \
             AND o.available_at <= clock_timestamp() \
             AND (o.locked_until IS NULL OR o.locked_until < clock_timestamp()) \
             AND o.attempts < 8 \
             AND t.used_at IS NULL AND t.expires_at > clock_timestamp() \
             AND (t.purpose = 'verify' OR u.is_active) \
             AND ($1::TEXT IS NULL OR lower(u.email) = $1) \
           ORDER BY o.id LIMIT 1 FOR UPDATE OF o SKIP LOCKED \
         ) \
         UPDATE auth_http_outbox o \
         SET locked_until = clock_timestamp() + INTERVAL '90 seconds', \
             attempts = o.attempts + 1 \
         FROM candidate c, auth_users u \
         WHERE o.id = c.id AND u.id = o.user_id \
         RETURNING o.id, o.token_hash, o.purpose, u.email, \
                   o.nonce, o.ciphertext, o.attempts",
    )
    .bind(email_filter)
    .fetch_optional(pool)
    .await?;
    let Some((id, digest, purpose, email, nonce, ciphertext, attempt)) = item else {
        return Ok(false);
    };

    let token = if nonce.len() == 12 {
        cipher(key)
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: digest.as_bytes(),
                },
            )
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    } else {
        None
    };
    let delivery_result = if let Some(token) = token {
        let kind: &'static str = if purpose == "verify" {
            "verify"
        } else {
            "reset"
        };
        timeout(SEND_TIMEOUT, (deliver)(kind, email, token))
            .await
            .map(|result| result.is_ok())
            .unwrap_or(false)
    } else {
        tracing::error!(outbox_id = id, "unable to decrypt identity email");
        false
    };

    if delivery_result {
        sqlx::query(
            "UPDATE auth_http_outbox SET delivered_at = clock_timestamp(), \
               ciphertext = '\\x'::BYTEA, locked_until = NULL \
             WHERE id = $1 AND attempts = $2 AND delivered_at IS NULL",
        )
        .bind(id)
        .bind(attempt)
        .execute(pool)
        .await?;
    } else {
        // Bounded exponential backoff, max eight tries. A corrupt payload is
        // terminal rather than retrying the same secret indefinitely.
        let terminal = attempt >= MAX_DELIVERY_ATTEMPTS || nonce.len() != 12;
        sqlx::query(
            "UPDATE auth_http_outbox SET locked_until = NULL, \
             available_at = clock_timestamp() + \
               (LEAST(1800, 30 * (1 << LEAST(attempts - 1, 6))) * INTERVAL '1 second'), \
             dead_at = CASE WHEN $3 THEN clock_timestamp() ELSE dead_at END, \
             ciphertext = CASE WHEN $3 THEN '\\x'::BYTEA ELSE ciphertext END \
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
            "identity email scheduled for retry"
        );
    }
    Ok(true)
}

/// Send a single due message. Repeated invocations safely run across replicas.
/// Returns false when no eligible work was claimed.
pub async fn send_next(
    pool: &PgPool,
    key: &[u8; 32],
    deliver: &TokenDelivery,
) -> Result<bool, OutboxError> {
    send_filtered(pool, key, deliver, None).await
}

#[cfg(test)]
pub(super) async fn send_next_for_email(
    pool: &PgPool,
    key: &[u8; 32],
    deliver: &TokenDelivery,
    email: &str,
) -> Result<bool, OutboxError> {
    send_filtered(pool, key, deliver, Some(email)).await
}

/// Aggregate operational counters. Read these from a secured monitoring
/// endpoint or metric exporter; they must not be exposed anonymously.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OutboxStats {
    pub pending: i64,
    pub due: i64,
    pub dead: i64,
    pub oldest_pending_seconds: f64,
}

pub async fn stats(pool: &PgPool) -> Result<OutboxStats, sqlx::Error> {
    let (pending, due, dead, oldest_pending_seconds): (i64, i64, i64, f64) =
        sqlx::query_as(
            "SELECT \
               COUNT(*) FILTER(WHERE delivered_at IS NULL AND dead_at IS NULL)::BIGINT, \
               COUNT(*) FILTER(WHERE delivered_at IS NULL AND dead_at IS NULL \
                                 AND available_at <= clock_timestamp())::BIGINT, \
               COUNT(*) FILTER(WHERE dead_at IS NOT NULL)::BIGINT, \
               GREATEST(0, COALESCE(EXTRACT(EPOCH FROM (clock_timestamp() - \
                 MIN(available_at) FILTER(WHERE delivered_at IS NULL AND dead_at IS NULL))), 0))::FLOAT8 \
             FROM auth_http_outbox",
        )
        .fetch_one(pool)
        .await?;
    Ok(OutboxStats {
        pending,
        due,
        dead,
        oldest_pending_seconds,
    })
}

/// Bounded cleanup for stale tokens, rate-limit buckets, expired sessions,
/// and delivered/dead outbox rows. Call periodically; one pass has a cap.
pub async fn cleanup_once(pool: &PgPool) -> Result<u64, sqlx::Error> {
    // Scrub obsolete encrypted secrets promptly rather than retaining them
    // for the seven-day metadata retention window. Skip active worker leases.
    let scrubbed = sqlx::query(
        "WITH obsolete AS ( \
           SELECT o.id FROM auth_http_outbox o \
           JOIN auth_http_one_time_tokens t ON t.token_hash = o.token_hash \
           WHERE o.delivered_at IS NULL AND o.dead_at IS NULL \
             AND (t.used_at IS NOT NULL OR t.expires_at <= clock_timestamp()) \
             AND (o.locked_until IS NULL OR o.locked_until < clock_timestamp()) \
           ORDER BY o.id LIMIT 200 FOR UPDATE OF o SKIP LOCKED \
         ) \
         UPDATE auth_http_outbox o SET dead_at = clock_timestamp(), \
           locked_until = NULL, ciphertext = '\\x'::BYTEA \
         FROM obsolete WHERE o.id = obsolete.id",
    )
    .execute(pool)
    .await?
    .rows_affected();

    let outbox = sqlx::query(
        "DELETE FROM auth_http_outbox WHERE id IN ( \
         SELECT id FROM auth_http_outbox \
         WHERE delivered_at < clock_timestamp() - INTERVAL '7 days' \
            OR dead_at < clock_timestamp() - INTERVAL '7 days' \
         ORDER BY id LIMIT 200)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    let tokens = sqlx::query(
        "DELETE FROM auth_http_one_time_tokens WHERE token_hash IN ( \
         SELECT token_hash FROM auth_http_one_time_tokens \
         WHERE expires_at < clock_timestamp() - INTERVAL '7 days' \
         ORDER BY expires_at LIMIT 200)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    let limits = sqlx::query(
        "DELETE FROM auth_http_attempts WHERE key_hash IN ( \
         SELECT key_hash FROM auth_http_attempts \
         WHERE window_start < clock_timestamp() - INTERVAL '1 day' \
         ORDER BY window_start LIMIT 200)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    let sessions = sqlx::query(
        "DELETE FROM auth_sessions WHERE token_hash IN ( \
         SELECT token_hash FROM auth_sessions \
         WHERE expires_at < clock_timestamp() - INTERVAL '7 days' \
            OR revoked_at < clock_timestamp() - INTERVAL '7 days' \
         ORDER BY expires_at LIMIT 200)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(scrubbed + outbox + tokens + limits + sessions)
}

/// Run as a dedicated worker process/task. An email provider may deliver
/// successfully just before the worker crashes: duplicates are possible.
/// The callback must implement its own bounded network timeouts.
pub async fn run_worker(
    pool: PgPool,
    key: Arc<[u8; 32]>,
    deliver: TokenDelivery,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut next_cleanup = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if *shutdown.borrow() {
            break;
        }
        match send_next(&pool, &key, &deliver).await {
            Ok(true) => {}
            Ok(false) => tokio::time::sleep(Duration::from_secs(2)).await,
            Err(error) => {
                tracing::error!(%error, "identity outbox poll failed");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        if tokio::time::Instant::now() >= next_cleanup {
            if let Err(error) = cleanup_once(&pool).await {
                tracing::error!(%error, "identity maintenance failed");
            }
            next_cleanup = tokio::time::Instant::now() + Duration::from_secs(120);
        }
        if shutdown.has_changed().is_err() || *shutdown.borrow_and_update() {
            break;
        }
    }
}
