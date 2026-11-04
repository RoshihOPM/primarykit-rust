//! Portable HMAC webhook verification and transactional replay protection.
//! Verify exact raw bytes; reserve a receipt inside the same PostgreSQL
//! transaction as business changes, so a rollback also releases the receipt.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use thiserror::Error;

#[path = "webhook_outbox.rs"]
pub mod outbox;

type HmacSha256 = Hmac<Sha256>;
pub const MAX_BODY_SIZE: usize = 256 * 1024;
const MAX_SKEW_SECONDS: u64 = 300;

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("invalid webhook configuration or request")]
    InvalidInput,
    #[error("invalid webhook signature")]
    InvalidSignature,
    #[error("webhook timestamp outside replay window")]
    Expired,
    #[error("event ID reused with another payload")]
    Conflict,
    #[error("signing secret not configured for destination")]
    MissingDestination,
    #[error("system clock unavailable")]
    Clock,
    #[error("webhook database failure")]
    Database(#[from] sqlx::Error),
}

pub fn valid_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')
        })
}

fn validate(secret: &[u8], source: &str, event_id: &str, body: &[u8]) -> Result<(), WebhookError> {
    if !(32..=4096).contains(&secret.len())
        || !valid_id(source)
        || !valid_id(event_id)
        || body.len() > MAX_BODY_SIZE
    {
        return Err(WebhookError::InvalidInput);
    }
    Ok(())
}

pub fn body_hash(body: &[u8]) -> String {
    format!("{:x}", Sha256::digest(body))
}

fn mac_for(
    secret: &[u8],
    source: &str,
    event_id: &str,
    timestamp: i64,
    body: &[u8],
) -> Result<HmacSha256, WebhookError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| WebhookError::InvalidInput)?;
    mac.update(b"primarykit:webhook:v1\n");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(source.as_bytes());
    mac.update(b"\n");
    mac.update(event_id.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    Ok(mac)
}

/// The header signs timestamp, source, event ID and exact raw body bytes.
pub fn sign(
    secret: &[u8],
    source: &str,
    event_id: &str,
    timestamp: i64,
    body: &[u8],
) -> Result<String, WebhookError> {
    validate(secret, source, event_id, body)?;
    if timestamp < 0 {
        return Err(WebhookError::InvalidInput);
    }
    let signature = mac_for(secret, source, event_id, timestamp, body)?
        .finalize()
        .into_bytes();
    Ok(format!("t={timestamp},v1={}", hex::encode(signature)))
}

/// Cannot be instantiated outside this module without verifying the signature.
#[derive(Debug, Clone)]
pub struct VerifiedEvent {
    source: String,
    event_id: String,
    fingerprint: String,
}

impl VerifiedEvent {
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
}

/// Server-supplied now must come from a trusted clock.
pub fn verify(
    secret: &[u8],
    source: &str,
    event_id: &str,
    signature: &str,
    body: &[u8],
    now: i64,
) -> Result<VerifiedEvent, WebhookError> {
    validate(secret, source, event_id, body)?;
    let (time, digest) = signature
        .strip_prefix("t=")
        .and_then(|value| value.split_once(",v1="))
        .ok_or(WebhookError::InvalidSignature)?;
    if time.is_empty() || time.len() > 20 || digest.len() != 64 {
        return Err(WebhookError::InvalidSignature);
    }
    let timestamp: i64 = time.parse().map_err(|_| WebhookError::InvalidSignature)?;
    if now < 0 || timestamp < 0 {
        return Err(WebhookError::InvalidSignature);
    }
    if now.abs_diff(timestamp) > MAX_SKEW_SECONDS {
        return Err(WebhookError::Expired);
    }
    let digest = hex::decode(digest).map_err(|_| WebhookError::InvalidSignature)?;
    mac_for(secret, source, event_id, timestamp, body)?
        .verify_slice(&digest)
        .map_err(|_| WebhookError::InvalidSignature)?;
    Ok(VerifiedEvent {
        source: source.to_owned(),
        event_id: event_id.to_owned(),
        fingerprint: body_hash(body),
    })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DedupResult {
    Inserted,
    Duplicate,
}

/// Receipt and business changes must commit in one caller-owned transaction.
/// PostgreSQL uniqueness serializes concurrent inserts for the same event.
pub async fn reserve_inbound(
    tx: &mut Transaction<'_, Postgres>,
    event: &VerifiedEvent,
) -> Result<DedupResult, WebhookError> {
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO webhook_inbox (source, event_id, body_hash) \
         VALUES ($1, $2, $3) ON CONFLICT (source, event_id) DO NOTHING RETURNING id",
    )
    .bind(&event.source)
    .bind(&event.event_id)
    .bind(&event.fingerprint)
    .fetch_optional(&mut **tx)
    .await?;
    if id.is_some() {
        return Ok(DedupResult::Inserted);
    }
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT body_hash FROM webhook_inbox WHERE source = $1 AND event_id = $2",
    )
    .bind(&event.source)
    .bind(&event.event_id)
    .fetch_optional(&mut **tx)
    .await?;
    if previous.as_deref() == Some(event.fingerprint.as_str()) {
        Ok(DedupResult::Duplicate)
    } else {
        Err(WebhookError::Conflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"replay-test-secret-with-enough-entropy-0123456";

    #[test]
    fn signatures_bind_metadata_body_and_timestamp() {
        let body = br#"{"paid":true}"#;
        let tag = sign(SECRET, "billing", "event-123", 1_800_000_000, body)
            .expect("sign event");
        let verified = verify(SECRET, "billing", "event-123", &tag, body, 1_800_000_050)
            .expect("verify event");
        assert_eq!(verified.source(), "billing");
        assert_eq!(verified.event_id(), "event-123");
        assert!(matches!(
            verify(SECRET, "billing", "event-123", &tag, body, 1_800_000_500),
            Err(WebhookError::Expired)
        ));
        assert!(verify(SECRET, "billing", "event-123", &tag, br#"{"paid":false}"#, 1_800_000_050).is_err());
        assert!(verify(SECRET, "other", "event-123", &tag, body, 1_800_000_050).is_err());
        assert!(verify(SECRET, "billing", "other", &tag, body, 1_800_000_050).is_err());
        assert!(verify(SECRET, "billing", "event-123", &format!("{tag},v1=00"), body, 1_800_000_050).is_err());
        assert!(sign(b"short", "billing", "event", 1, body).is_err());
        assert!(sign(SECRET, "billing", "../bad", 1, body).is_err());
        assert!(sign(SECRET, "billing", "event", 1, &vec![0; MAX_BODY_SIZE + 1]).is_err());
    }
}
