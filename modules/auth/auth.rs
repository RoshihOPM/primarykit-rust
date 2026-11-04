//! Password hashing and revocable opaque sessions.
//!
//! Hashing uses Argon2id and is CPU/memory intensive: call it from
//! tokio::task::spawn_blocking in async request handlers.
//! This module intentionally does not expose login or registration routes:
//! applications must implement rate limiting, user enumeration protection
//! and account lifecycle policy independently.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;

const SESSION_BYTES: usize = 32;
const MAX_SESSION_SECONDS: i64 = 60 * 60 * 24 * 30;
const MIN_PASSWORD_BYTES: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("password must contain between 12 and 1024 bytes")]
    InvalidPassword,
    #[error("session lifetime must be between 1 and 2592000 seconds")]
    InvalidTtl,
    #[error("cryptographic randomness unavailable")]
    Randomness,
    #[error("password hashing failed")]
    Hashing,
    #[error("user does not exist or is disabled")]
    InactiveUser,
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AuthenticatedUser {
    user_id: i64,
}

impl AuthenticatedUser {
    /// Validated identity returned only by authenticate_session.
    pub const fn user_id(self) -> i64 {
        self.user_id
    }
}

/// CPU- and memory-intensive. Do not execute directly on Tokio executor threads.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    if !(MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&password.len()) {
        return Err(AuthError::InvalidPassword);
    }
    let mut random = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| AuthError::Randomness)?;
    let salt = SaltString::encode_b64(&random).map_err(|_| AuthError::Hashing)?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|encoded| encoded.to_string())
        .map_err(|_| AuthError::Hashing)
}

/// CPU- and memory-intensive. Run in spawn_blocking; rate limit login attempts.
pub fn verify_password(password: &str, encoded: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn issue_token() -> Result<String, AuthError> {
    let mut token_bytes = [0_u8; SESSION_BYTES];
    OsRng
        .try_fill_bytes(&mut token_bytes)
        .map_err(|_| AuthError::Randomness)?;
    Ok(hex::encode(token_bytes))
}

fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

fn valid_token(token: &str) -> bool {
    token.len() == SESSION_BYTES * 2 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_ttl(ttl_seconds: i64) -> Result<(), AuthError> {
    if !(1..=MAX_SESSION_SECONDS).contains(&ttl_seconds) {
        return Err(AuthError::InvalidTtl);
    }
    Ok(())
}

/// Return the raw token exactly once. Store only its SHA-256 digest in PostgreSQL.
/// Token entropy is 256 bits; keep the returned token out of logs and URLs.
pub async fn create_session(
    pool: &PgPool,
    user_id: i64,
    ttl_seconds: i64,
) -> Result<String, AuthError> {
    validate_ttl(ttl_seconds)?;
    let token = issue_token()?;
    let digest = token_hash(&token);
    let inserted: Option<(String,)> = sqlx::query_as(
        "INSERT INTO auth_sessions (token_hash, user_id, expires_at) \
         SELECT $1, id, clock_timestamp() + ($3::BIGINT * INTERVAL '1 second') \
         FROM auth_users WHERE id = $2 AND is_active \
         RETURNING token_hash",
    )
    .bind(&digest)
    .bind(user_id)
    .bind(ttl_seconds)
    .fetch_optional(pool)
    .await?;
    if inserted.is_none() {
        return Err(AuthError::InactiveUser);
    }
    Ok(token)
}

/// Issue a session only if the password hash verified by the caller is still current.
/// Holding a share lock through the insert prevents password-reset races:
/// an UPDATE to the user's password waits until session insertion commits,
/// and then reset revokes the inserted session.
pub async fn create_session_if_password_unchanged(
    pool: &PgPool,
    user_id: i64,
    verified_password_hash: &str,
    ttl_seconds: i64,
) -> Result<Option<String>, AuthError> {
    validate_ttl(ttl_seconds)?;
    let mut tx = pool.begin().await?;
    let authorized: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM auth_users \
         WHERE id = $1 AND password_hash = $2 AND is_active FOR SHARE",
    )
    .bind(user_id)
    .bind(verified_password_hash)
    .fetch_optional(&mut *tx)
    .await?;
    if authorized.is_none() {
        return Ok(None);
    }
    let token = issue_token()?;
    sqlx::query(
        "INSERT INTO auth_sessions(token_hash, user_id, expires_at) \
         VALUES($1, $2, clock_timestamp() + ($3::BIGINT * INTERVAL '1 second'))",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .bind(ttl_seconds)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(token))
}

/// Authentication is performed against PostgreSQL on every call; no stale session cache.
pub async fn authenticate_session(
    pool: &PgPool,
    token: &str,
) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    if !valid_token(token) {
        return Ok(None);
    }
    let user_id: Option<(i64,)> = sqlx::query_as(
        "SELECT s.user_id FROM auth_sessions s \
         JOIN auth_users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL \
         AND s.expires_at > clock_timestamp() AND u.is_active",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await?;
    Ok(user_id.map(|(user_id,)| AuthenticatedUser { user_id }))
}

/// Revocation is idempotent; a database failure is an error, never success.
pub async fn revoke_session(pool: &PgPool, token: &str) -> Result<bool, sqlx::Error> {
    if !valid_token(token) {
        return Ok(false);
    }
    let result = sqlx::query(
        "UPDATE auth_sessions SET revoked_at = clock_timestamp() \
         WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(token_hash(token))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Rotate atomically: at most one concurrent rotation succeeds for the same token.
/// A missing/expired/revoked token returns None and does not issue another session.
pub async fn rotate_session(
    pool: &PgPool,
    old_token: &str,
    ttl_seconds: i64,
) -> Result<Option<String>, AuthError> {
    validate_ttl(ttl_seconds)?;
    if !valid_token(old_token) {
        return Ok(None);
    }
    let mut tx = pool.begin().await?;
    let old_hash = token_hash(old_token);
    let user: Option<(i64,)> = sqlx::query_as(
        "SELECT s.user_id FROM auth_sessions s \
         JOIN auth_users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL \
         AND s.expires_at > clock_timestamp() AND u.is_active FOR UPDATE OF s",
    )
    .bind(&old_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((user_id,)) = user else {
        return Ok(None);
    };

    let new_token = issue_token()?;
    sqlx::query("UPDATE auth_sessions SET revoked_at = clock_timestamp() WHERE token_hash = $1")
        .bind(&old_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO auth_sessions (token_hash, user_id, expires_at) \
         VALUES ($1, $2, clock_timestamp() + ($3::BIGINT * INTERVAL '1 second'))",
    )
    .bind(token_hash(&new_token))
    .bind(user_id)
    .bind(ttl_seconds)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(new_token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_email() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        format!("auth-{nanos}-{}@example.invalid", std::process::id())
    }

    async fn test_pool() -> Option<PgPool> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("test database accessible");
        sqlx::migrate!().run(&pool).await.expect("apply migrations");
        Some(pool)
    }

    async fn test_user(pool: &PgPool) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO auth_users (email, password_hash) \
             VALUES ($1, $2) RETURNING id",
        )
        .bind(unique_email())
        .bind("test-only-placeholder-hash")
        .fetch_one(pool)
        .await
        .expect("create user")
    }

    #[test]
    fn argon2id_hashes_and_validates_passwords() {
        let encoded = hash_password("strong-test-password").expect("hash");
        assert!(encoded.starts_with("$argon2id$"));
        assert!(verify_password("strong-test-password", &encoded));
        assert!(!verify_password("different-password", &encoded));
        assert!(!verify_password("strong-test-password", "invalid"));
        assert_ne!(
            encoded,
            hash_password("strong-test-password").expect("different salt")
        );
    }

    #[test]
    fn rejects_unsafe_password_and_token_sizes() {
        assert!(hash_password("short").is_err());
        assert!(hash_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
        assert!(!valid_token("not-a-token"));
        assert!(validate_ttl(0).is_err());
        assert!(validate_ttl(MAX_SESSION_SECONDS + 1).is_err());
    }

    #[tokio::test]
    async fn session_lifecycle_revocation_and_inactive_users() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let user_id = test_user(&pool).await;
        let token = create_session(&pool, user_id, 60).await.expect("session");
        assert_eq!(token.len(), 64);
        assert_eq!(
            authenticate_session(&pool, &token)
                .await
                .expect("authenticate"),
            Some(AuthenticatedUser { user_id })
        );
        let stored: String =
            sqlx::query_scalar("SELECT token_hash FROM auth_sessions WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("stored digest");
        assert_ne!(stored, token);
        assert!(revoke_session(&pool, &token).await.expect("revoke"));
        assert!(!revoke_session(&pool, &token).await.expect("idempotent"));
        assert_eq!(
            authenticate_session(&pool, &token)
                .await
                .expect("after revoke"),
            None
        );

        let active_token = create_session(&pool, user_id, 60).await.expect("session");
        sqlx::query("UPDATE auth_users SET is_active = false WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("disable");
        assert_eq!(
            authenticate_session(&pool, &active_token)
                .await
                .expect("disabled user"),
            None
        );
        assert!(matches!(
            create_session(&pool, user_id, 60).await,
            Err(AuthError::InactiveUser)
        ));
    }

    #[tokio::test]
    async fn stale_password_hash_cannot_issue_a_session() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let user_id = test_user(&pool).await;
        let old_hash = "test-only-placeholder-hash";
        let token = create_session_if_password_unchanged(&pool, user_id, old_hash, 60)
            .await
            .expect("insert")
            .expect("current password");
        assert!(authenticate_session(&pool, &token)
            .await
            .expect("authenticate")
            .is_some());

        sqlx::query("UPDATE auth_users SET password_hash = 'changed-hash' WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("reset password");
        assert!(create_session_if_password_unchanged(&pool, user_id, old_hash, 60)
            .await
            .expect("stale login")
            .is_none());
    }

    #[tokio::test]
    async fn concurrent_rotations_serialize_and_only_one_succeeds() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let user_id = test_user(&pool).await;
        let token = create_session(&pool, user_id, 60).await.expect("session");
        let (first, second) = tokio::join!(
            rotate_session(&pool, &token, 120),
            rotate_session(&pool, &token, 120)
        );
        let outcomes = [first.expect("first"), second.expect("second")];
        assert_eq!(outcomes.iter().filter(|result| result.is_some()).count(), 1);
        assert_eq!(
            authenticate_session(&pool, &token)
                .await
                .expect("old token"),
            None
        );
    }

    #[tokio::test]
    async fn rotation_is_atomic_and_expired_tokens_are_denied() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let user_id = test_user(&pool).await;
        let old = create_session(&pool, user_id, 60).await.expect("session");
        let next = rotate_session(&pool, &old, 120)
            .await
            .expect("rotation")
            .expect("valid session");
        assert!(rotate_session(&pool, &old, 120)
            .await
            .expect("old revoked")
            .is_none());
        assert_eq!(authenticate_session(&pool, &old).await.expect("old"), None);
        assert!(authenticate_session(&pool, &next)
            .await
            .expect("new")
            .is_some());

        sqlx::query("UPDATE auth_sessions SET created_at = clock_timestamp() - INTERVAL '2 seconds', expires_at = clock_timestamp() - INTERVAL '1 second' WHERE token_hash = $1")
            .bind(token_hash(&next))
            .execute(&pool)
            .await
            .expect("expire session");
        assert_eq!(
            authenticate_session(&pool, &next).await.expect("expired"),
            None
        );
        assert!(rotate_session(&pool, &next, 60)
            .await
            .expect("cannot rotate expired token")
            .is_none());
    }
}
