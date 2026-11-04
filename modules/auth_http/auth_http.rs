//! Opt-in HTTP identity routes. Registering the routes requires an application
//! email delivery callback. No SMTP credentials or reset tokens are logged.
//! Deploy only behind TLS and a network-edge rate limit in addition to the
//! database-backed per-identity limiter.

use super::auth;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
};
use tokio::{sync::Semaphore, task};

const SESSION_TTL: i64 = 60 * 60 * 24;
const RESET_TTL_MINUTES: i64 = 15;
const VERIFY_TTL_MINUTES: i64 = 60 * 24;
const ATTEMPT_LIMIT: i32 = 5;
const MAX_PASSWORD_LENGTH: usize = 1024;

/// The host application must configure durable delivery/retries and build
/// trusted, HTTPS-only verification/reset links. Tokens are never placed in
/// HTTP responses by this module.
pub type DeliveryFuture = Pin<Box<dyn Future<Output = Result<(), ()>> + Send>>;
pub type TokenDelivery = Arc<dyn Fn(&'static str, String, String) -> DeliveryFuture + Send + Sync>;

#[derive(Clone)]
pub struct IdentityState {
    pub pool: PgPool,
    pub deliver: TokenDelivery,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    email: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailRequest {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetRequest {
    token: String,
    new_password: String,
}

#[derive(Serialize)]
struct SessionResponse {
    token: String,
    token_type: &'static str,
    expires_in: i64,
}

#[derive(Serialize)]
struct UserResponse {
    id: i64,
}

type HttpResult<T> = Result<T, StatusCode>;

/// Applications mount this router explicitly, e.g. app.merge(auth_http::routes(state)).
pub fn routes(state: IdentityState) -> Router {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/verify-email", post(verify_email))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", post(me))
        .route("/auth/password-reset/request", post(request_reset))
        .route("/auth/password-reset/confirm", post(confirm_reset))
        .layer(DefaultBodyLimit::max(4 * 1024))
        .with_state(state)
}

fn normalized_email(email: &str) -> Option<String> {
    let email = email.trim();
    if !(3..=320).contains(&email.len())
        || !email.is_ascii()
        || email
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || email.matches('@').count() != 1
    {
        return None;
    }
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.len() < 3 || !domain.contains('.') {
        return None;
    }
    Some(email.to_ascii_lowercase())
}

fn valid_password(password: &str) -> bool {
    (12..=MAX_PASSWORD_LENGTH).contains(&password.len())
}

fn sha256(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn opaque_token() -> Result<String, StatusCode> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(hex::encode(bytes))
}

fn token_syntax(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Distributed fixed-window per-identity limiter; keys are SHA-256 digests,
/// not clear-text emails. Edge/IP limiting is still mandatory in production.
async fn allow_attempt(pool: &PgPool, purpose: &str, email: &str) -> HttpResult<bool> {
    let key = sha256(&format!("{purpose}:{email}"));
    let attempts: i32 = sqlx::query_scalar(
        "INSERT INTO auth_http_attempts (key_hash, window_start, attempts) \
         VALUES ($1, clock_timestamp(), 1) \
         ON CONFLICT (key_hash) DO UPDATE SET \
         attempts = CASE WHEN auth_http_attempts.window_start < \
          clock_timestamp() - INTERVAL '15 minutes' THEN 1 \
          ELSE LEAST(auth_http_attempts.attempts + 1, 1000000) END, \
         window_start = CASE WHEN auth_http_attempts.window_start < \
          clock_timestamp() - INTERVAL '15 minutes' THEN clock_timestamp() \
          ELSE auth_http_attempts.window_start END \
         RETURNING attempts",
    )
    .bind(key)
    .fetch_one(pool)
    .await
    .map_err(internal)?;
    Ok(attempts <= ATTEMPT_LIMIT)
}

fn internal(error: sqlx::Error) -> StatusCode {
    tracing::error!(error = %error, "identity persistence failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn argon2_slots() -> Arc<Semaphore> {
    // A cancelled request must not release its slot while a blocking hash
    // is still running. The blocking closure owns the permit.
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(SLOTS.get_or_init(|| Arc::new(Semaphore::new(4))))
}

async fn secure_hash(password: String) -> HttpResult<String> {
    let permit = argon2_slots()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    task::spawn_blocking(move || {
        let _permit = permit;
        auth::hash_password(&password)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::BAD_REQUEST)
}

async fn password_matches(password: String, hash: Option<String>) -> HttpResult<bool> {
    let permit = argon2_slots()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    task::spawn_blocking(move || {
        let _permit = permit;
        match hash {
            Some(hash) => auth::verify_password(&password, &hash),
            None => {
                // An unknown identity still pays the Argon2 cost, reducing
                // account-enumeration timing differences.
                if let Ok(dummy) = auth::hash_password("dummy-account-password") {
                    let _ = auth::verify_password(&password, &dummy);
                }
                false
            }
        }
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn enqueue_token(
    state: &IdentityState,
    user_id: i64,
    email: String,
    purpose: &'static str,
    ttl_minutes: i64,
) -> HttpResult<()> {
    let token = opaque_token()?;
    sqlx::query(
        "INSERT INTO auth_http_one_time_tokens (token_hash, user_id, purpose, expires_at) \
         VALUES ($1, $2, $3, clock_timestamp() + ($4::BIGINT * INTERVAL '1 minute'))",
    )
    .bind(sha256(&token))
    .bind(user_id)
    .bind(purpose)
    .bind(ttl_minutes)
    .execute(&state.pool)
    .await
    .map_err(internal)?;

    // A delivery failure does not reveal whether the email exists. The
    // application must supply reliable delivery, retry and monitoring.
    if (state.deliver)(purpose, email, token).await.is_err() {
        tracing::error!(purpose, "identity token delivery failed");
    }
    Ok(())
}

/// Registration creates an INACTIVE identity. An email-verification token
/// must be delivered and redeemed before the first successful login.
async fn register(
    State(state): State<IdentityState>,
    Json(input): Json<Credentials>,
) -> HttpResult<StatusCode> {
    let email = normalized_email(&input.email).ok_or(StatusCode::BAD_REQUEST)?;
    if !valid_password(&input.password) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !allow_attempt(&state.pool, "register", &email).await? {
        return Ok(StatusCode::ACCEPTED);
    }
    let password_hash = secure_hash(input.password).await?;
    let new_id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO auth_users (email, password_hash, is_active) \
         VALUES ($1, $2, FALSE) ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(&email)
    .bind(password_hash)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;
    // Re-send verification for existing pending identities, not active users.
    let candidate_id = match new_id {
        Some(id) => Some(id),
        None => sqlx::query_scalar::<_, i64>(
            "SELECT id FROM auth_users WHERE lower(email) = $1 AND NOT is_active",
        )
        .bind(&email)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?,
    };
    if let Some(id) = candidate_id {
        enqueue_token(&state, id, email, "verify", VERIFY_TTL_MINUTES).await?;
    }
    Ok(StatusCode::ACCEPTED)
}

async fn verify_email(
    State(state): State<IdentityState>,
    Json(input): Json<TokenRequest>,
) -> HttpResult<StatusCode> {
    if !token_syntax(&input.token) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut tx = state.pool.begin().await.map_err(internal)?;
    let id: Option<i64> = sqlx::query_scalar(
        "SELECT user_id FROM auth_http_one_time_tokens \
         WHERE token_hash = $1 AND purpose = 'verify' AND used_at IS NULL \
         AND expires_at > clock_timestamp() FOR UPDATE",
    )
    .bind(sha256(&input.token))
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let Some(id) = id else {
        return Err(StatusCode::BAD_REQUEST);
    };
    sqlx::query("UPDATE auth_users SET is_active = TRUE WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    sqlx::query(
        "UPDATE auth_http_one_time_tokens SET used_at = clock_timestamp() WHERE token_hash = $1",
    )
    .bind(sha256(&input.token))
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn login(
    State(state): State<IdentityState>,
    Json(input): Json<Credentials>,
) -> HttpResult<(HeaderMap, Json<SessionResponse>)> {
    let email = normalized_email(&input.email).ok_or(StatusCode::UNAUTHORIZED)?;
    if !valid_password(&input.password) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !allow_attempt(&state.pool, "login", &email).await? {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let user: Option<(i64, String, bool)> = sqlx::query_as(
        "SELECT id, password_hash, is_active FROM auth_users WHERE lower(email) = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;
    let verified = password_matches(input.password, user.as_ref().map(|u| u.1.clone())).await?;
    let Some((user_id, saved_hash, true)) = user else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    if !verified {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token =
        auth::create_session_if_password_unchanged(&state.pool, user_id, &saved_hash, SESSION_TTL)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "session persistence failed");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .ok_or(StatusCode::UNAUTHORIZED)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        "no-store"
            .parse()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    Ok((
        headers,
        Json(SessionResponse {
            token,
            token_type: "Bearer",
            expires_in: SESSION_TTL,
        }),
    ))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

async fn logout(State(state): State<IdentityState>, headers: HeaderMap) -> HttpResult<StatusCode> {
    if let Some(token) = bearer(&headers) {
        auth::revoke_session(&state.pool, token)
            .await
            .map_err(internal)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn me(
    State(state): State<IdentityState>,
    headers: HeaderMap,
) -> HttpResult<Json<UserResponse>> {
    let token = bearer(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let principal = auth::authenticate_session(&state.pool, token)
        .await
        .map_err(internal)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(UserResponse {
        id: principal.user_id(),
    }))
}

async fn request_reset(
    State(state): State<IdentityState>,
    Json(input): Json<EmailRequest>,
) -> HttpResult<StatusCode> {
    let Some(email) = normalized_email(&input.email) else {
        return Ok(StatusCode::ACCEPTED);
    };
    if !allow_attempt(&state.pool, "reset", &email).await? {
        return Ok(StatusCode::ACCEPTED);
    }
    let user_id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM auth_users WHERE lower(email) = $1 AND is_active")
            .bind(&email)
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?;
    if let Some(id) = user_id {
        enqueue_token(&state, id, email, "reset", RESET_TTL_MINUTES).await?;
    }
    Ok(StatusCode::ACCEPTED)
}

async fn confirm_reset(
    State(state): State<IdentityState>,
    Json(input): Json<ResetRequest>,
) -> HttpResult<StatusCode> {
    if !token_syntax(&input.token) || !valid_password(&input.new_password) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let new_hash = secure_hash(input.new_password).await?;
    let mut tx = state.pool.begin().await.map_err(internal)?;
    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT t.user_id FROM auth_http_one_time_tokens t \
         JOIN auth_users u ON u.id = t.user_id \
         WHERE t.token_hash = $1 AND t.purpose = 'reset' AND t.used_at IS NULL \
         AND t.expires_at > clock_timestamp() AND u.is_active FOR UPDATE OF t",
    )
    .bind(sha256(&input.token))
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let Some(id) = user_id else {
        return Err(StatusCode::BAD_REQUEST);
    };
    sqlx::query("UPDATE auth_users SET password_hash = $1 WHERE id = $2")
        .bind(new_hash)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    sqlx::query(
        "UPDATE auth_sessions SET revoked_at = clock_timestamp() \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query(
        "UPDATE auth_http_one_time_tokens SET used_at = clock_timestamp() \
         WHERE user_id = $1 AND purpose = 'reset' AND used_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Mutex;
    use tower::ServiceExt;

    fn test_email() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        format!("identity-{}-{nanos}@example.invalid", std::process::id())
    }

    async fn setup() -> Option<(IdentityState, Arc<Mutex<Vec<(String, String, String)>>>)> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("db");
        sqlx::migrate!().run(&pool).await.expect("migrations");
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&deliveries);
        let deliver: TokenDelivery = Arc::new(move |purpose, email, token| {
            recorded
                .lock()
                .expect("lock")
                .push((purpose.to_owned(), email, token));
            Box::pin(async { Ok(()) })
        });
        Some((IdentityState { pool, deliver }, deliveries))
    }

    async fn post(state: &IdentityState, uri: &str, payload: String) -> StatusCode {
        routes(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(payload))
                    .expect("request"),
            )
            .await
            .expect("response")
            .status()
    }

    #[tokio::test]
    async fn register_verify_and_reset_are_single_use() {
        let Some((state, deliveries)) = setup().await else {
            return;
        };
        let email = test_email();
        let register_body =
            format!(r#"{{"email":"{email}","password":"sample-secure-passphrase"}}"#);
        assert_eq!(
            post(&state, "/auth/register", register_body).await,
            StatusCode::ACCEPTED
        );

        let verify_token = deliveries.lock().expect("deliveries")[0].2.clone();
        assert_eq!(
            post(
                &state,
                "/auth/verify-email",
                format!(r#"{{"token":"{verify_token}"}}"#)
            )
            .await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            post(
                &state,
                "/auth/verify-email",
                format!(r#"{{"token":"{verify_token}"}}"#)
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post(
                &state,
                "/auth/password-reset/request",
                format!(r#"{{"email":"{email}"}}"#)
            )
            .await,
            StatusCode::ACCEPTED
        );
        let reset_token = deliveries.lock().expect("deliveries")[1].2.clone();
        assert_eq!(
            post(
                &state,
                "/auth/password-reset/confirm",
                format!(r#"{{"token":"{reset_token}","new_password":"new-secure-password-123"}}"#)
            )
            .await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            post(
                &state,
                "/auth/password-reset/confirm",
                format!(r#"{{"token":"{reset_token}","new_password":"new-secure-password-123"}}"#)
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn failed_logins_are_limited_across_requests() {
        let Some((state, _)) = setup().await else {
            return;
        };
        let email = test_email();
        let body = format!(r#"{{"email":"{email}","password":"incorrect-password"}}"#);
        for _ in 0..ATTEMPT_LIMIT {
            assert_eq!(
                post(&state, "/auth/login", body.clone()).await,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            post(&state, "/auth/login", body).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn reset_request_does_not_reveal_unknown_accounts() {
        let Some((state, deliveries)) = setup().await else {
            return;
        };
        let email = test_email();
        assert_eq!(
            post(
                &state,
                "/auth/password-reset/request",
                format!(r#"{{"email":"{email}"}}"#)
            )
            .await,
            StatusCode::ACCEPTED
        );
        assert!(deliveries.lock().expect("deliveries").is_empty());
    }
}
