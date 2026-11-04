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
use std::{collections::BTreeMap, sync::Arc, time::Duration};
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
    #[error("outbox worker is missing a required encryption key")]
    MissingKey,
}

const LEGACY_KEY_ID: &str = "legacy";

/// Immutable keyring used by HTTP issuers and mail workers. The active key
/// encrypts new messages; previous keys remain read-only for queued messages.
/// Key material is intentionally excluded from Debug and Serialize.
pub struct OutboxKeyring {
    active_id: String,
    keys: BTreeMap<String, [u8; 32]>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyringError {
    #[error("outbox key identifier must be 1..32 ASCII letters, digits, _ or -")]
    InvalidId,
    #[error("duplicate outbox encryption key identifier")]
    DuplicateId,
}

fn valid_key_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl OutboxKeyring {
    pub fn new(
        active_id: impl Into<String>,
        active_key: [u8; 32],
        previous: impl IntoIterator<Item = (String, [u8; 32])>,
    ) -> Result<Self, KeyringError> {
        let active_id = active_id.into();
        if !valid_key_id(&active_id) {
            return Err(KeyringError::InvalidId);
        }
        let mut keys = BTreeMap::new();
        keys.insert(active_id.clone(), active_key);
        for (id, key) in previous {
            if !valid_key_id(&id) {
                return Err(KeyringError::InvalidId);
            }
            if keys.insert(id, key).is_some() {
                return Err(KeyringError::DuplicateId);
            }
        }
        Ok(Self { active_id, keys })
    }

    pub fn active_id(&self) -> &str {
        &self.active_id
    }

    fn active_key(&self) -> &[u8; 32] {
        // Invariant established by new(); active_id is always in keys.
        &self.keys[&self.active_id]
    }

    fn decrypt_key(&self, id: &str) -> Option<&[u8; 32]> {
        self.keys.get(id)
    }

    fn ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }
}

fn aad(key_id: &str, token_hash: &str) -> Vec<u8> {
    format!("primarykit:outbox:v2:{key_id}:{token_hash}").into_bytes()
}

/// Reject workers that are missing any key for a *currently encrypted*
/// queued message. This is an operational preflight for key rotation.
async fn ensure_key_coverage_filtered(
    pool: &PgPool,
    keys: &OutboxKeyring,
    email_filter: Option<&str>,
) -> Result<(), OutboxError> {
    let missing: Option<String> = sqlx::query_scalar(
        "SELECT o.encryption_key_id FROM auth_http_outbox o \
         JOIN auth_users u ON u.id = o.user_id \
         WHERE o.delivered_at IS NULL AND o.dead_at IS NULL \
           AND octet_length(o.ciphertext) > 0 \
           AND NOT (o.encryption_key_id = ANY($1::TEXT[])) \
           AND ($2::TEXT IS NULL OR lower(u.email) = $2) \
         LIMIT 1",
    )
    .bind(keys.ids())
    .bind(email_filter)
    .fetch_optional(pool)
    .await?;
    if let Some(id) = missing {
        tracing::error!(key_id = %id, "outbox worker lacks a required decryption key");
        return Err(OutboxError::MissingKey);
    }
    Ok(())
}

pub async fn ensure_key_coverage(pool: &PgPool, keys: &OutboxKeyring) -> Result<(), OutboxError> {
    ensure_key_coverage_filtered(pool, keys, None).await
}

/// Count all encrypted, undelivered rows using a key before retiring it.
/// Zero means no pending ciphertext requires this key.
pub async fn encrypted_pending_for_key(pool: &PgPool, key_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM auth_http_outbox \
         WHERE encryption_key_id = $1 AND delivered_at IS NULL \
           AND dead_at IS NULL AND octet_length(ciphertext) > 0",
    )
    .bind(key_id)
    .fetch_one(pool)
    .await
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
    keys: &OutboxKeyring,
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
    let key_id = keys.active_id();
    let authenticated_data = aad(key_id, &digest);
    let sealed = cipher(keys.active_key())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: token.as_bytes(),
                aad: &authenticated_data,
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
        "INSERT INTO auth_http_outbox          (token_hash, user_id, purpose, nonce, ciphertext, encryption_key_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(digest)
    .bind(user_id)
    .bind(purpose)
    .bind(nonce.as_slice())
    .bind(sealed)
    .bind(key_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn decrypt_token(
    keys: &OutboxKeyring,
    key_id: &str,
    digest: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Option<String> {
    // Key ID is authenticated for v2 ciphertext. The legacy fallback only
    // applies to rows migrated from the pre-versioned format.
    if nonce.len() == 12 {
        let result = keys.decrypt_key(&key_id).and_then(|key| {
            let authenticated_data = aad(&key_id, &digest);
            cipher(key)
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &authenticated_data,
                    },
                )
                .or_else(|_| {
                    if key_id == LEGACY_KEY_ID {
                        cipher(key).decrypt(
                            Nonce::from_slice(&nonce),
                            Payload {
                                msg: &ciphertext,
                                aad: digest.as_bytes(),
                            },
                        )
                    } else {
                        Err(chacha20poly1305::aead::Error)
                    }
                })
                .ok()
        });
        result.and_then(|bytes| String::from_utf8(bytes).ok())
    } else {
        None
    }
}

type Claimed = (i64, String, String, String, Vec<u8>, Vec<u8>, i32, String);

async fn send_filtered(
    pool: &PgPool,
    keys: &OutboxKeyring,
    deliver: &TokenDelivery,
    email_filter: Option<&str>,
) -> Result<bool, OutboxError> {
    // Fail closed before claiming work. An unavailable old key must never
    // consume retry attempts or mark queued messages as permanently dead.
    ensure_key_coverage_filtered(pool, keys, email_filter).await?;
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
             AND o.encryption_key_id = ANY($2::TEXT[]) \
           ORDER BY o.id LIMIT 1 FOR UPDATE OF o SKIP LOCKED \
         ) \
         UPDATE auth_http_outbox o \
         SET locked_until = clock_timestamp() + INTERVAL '90 seconds', \
             attempts = o.attempts + 1 \
         FROM candidate c, auth_users u \
         WHERE o.id = c.id AND u.id = o.user_id \
         RETURNING o.id, o.token_hash, o.purpose, u.email, \
                   o.nonce, o.ciphertext, o.attempts, o.encryption_key_id",
    )
    .bind(email_filter)
    .bind(keys.ids())
    .fetch_optional(pool)
    .await?;
    let Some((id, digest, purpose, email, nonce, ciphertext, attempt, key_id)) = item else {
        return Ok(false);
    };

    let token = decrypt_token(keys, &key_id, &digest, &nonce, &ciphertext);
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
    keys: &OutboxKeyring,
    deliver: &TokenDelivery,
) -> Result<bool, OutboxError> {
    send_filtered(pool, keys, deliver, None).await
}

#[cfg(test)]
pub(super) async fn send_next_for_email(
    pool: &PgPool,
    keys: &OutboxKeyring,
    deliver: &TokenDelivery,
    email: &str,
) -> Result<bool, OutboxError> {
    send_filtered(pool, keys, deliver, Some(email)).await
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
    keys: Arc<OutboxKeyring>,
    deliver: TokenDelivery,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut next_cleanup = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if *shutdown.borrow() {
            break;
        }
        match send_next(&pool, &keys, &deliver).await {
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

#[cfg(test)]
mod keyring_tests {
    use super::*;

    #[test]
    fn decrypts_pre_versioned_legacy_payloads_without_weakening_new_aad() {
        let key = [42_u8; 32];
        let keys =
            OutboxKeyring::new("v2", [43_u8; 32], [("legacy".to_owned(), key)]).expect("keyring");
        let plaintext = "a".repeat(64);
        let digest = hash_token(&plaintext);
        let nonce = [11_u8; 12];

        // Old deployments authenticated only the SHA-256 token digest.
        let old = cipher(&key)
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: digest.as_bytes(),
                },
            )
            .expect("legacy encryption");
        assert_eq!(
            decrypt_token(&keys, "legacy", &digest, &nonce, &old),
            Some(plaintext.clone())
        );
        assert_eq!(decrypt_token(&keys, "v2", &digest, &nonce, &old), None);

        // New ciphertext authenticates the key ID as well as the digest.
        let new_aad = aad("v2", &digest);
        let current = cipher(keys.active_key())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &new_aad,
                },
            )
            .expect("new encryption");
        assert_eq!(
            decrypt_token(&keys, "v2", &digest, &nonce, &current),
            Some(plaintext)
        );
        assert_eq!(
            decrypt_token(&keys, "legacy", &digest, &nonce, &current),
            None
        );
    }

    #[test]
    fn rejects_invalid_and_duplicate_ids() {
        assert!(OutboxKeyring::new("v2", [1; 32], [("v2".to_owned(), [2; 32])]).is_err());
        assert!(OutboxKeyring::new("bad id", [1; 32], []).is_err());
        assert!(OutboxKeyring::new("", [1; 32], []).is_err());
    }
}
