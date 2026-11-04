//! Tenant-scoped opaque API keys. Secret disclosed once and never stored.
//! Issuance requires api_keys.create plus every requested tenant RBAC grant.
//! Each use rechecks the key and live permissions, including after revocation.

use super::auth::AuthenticatedUser;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::BTreeSet;
use thiserror::Error;

const PREFIX: &str = "pk_";
const MAX_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;

#[derive(Debug, Error)]
pub enum ApiKeyError {
    #[error("invalid tenant, label or scopes")]
    InvalidInput,
    #[error("API key lifetime must be between 1 second and 90 days")]
    InvalidTtl,
    #[error("API key issuance is forbidden")]
    Forbidden,
    #[error("secure randomness unavailable")]
    Randomness,
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
}

/// Not Debug or Serialize: caller must disclose this token only once.
pub struct IssuedApiKey {
    pub id: i64,
    pub token: String,
}

#[derive(Clone)]
pub struct ApiKeyPrincipal {
    id: i64,
    user_id: i64,
    tenant_id: String,
    scopes: Vec<String>,
}

impl ApiKeyPrincipal {
    pub const fn id(&self) -> i64 {
        self.id
    }
    pub const fn user_id(&self) -> i64 {
        self.user_id
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
}

fn valid_tenant(value: &str) -> bool {
    (1..=200).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn valid_scope(value: &str) -> bool {
    (1..=100).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn scopes_checked(values: &[String]) -> Result<Vec<String>, ApiKeyError> {
    let scopes: BTreeSet<String> = values.iter().cloned().collect();
    if !(1..=32).contains(&values.len())
        || scopes.len() != values.len()
        || scopes.iter().any(|s| !valid_scope(s))
    {
        return Err(ApiKeyError::InvalidInput);
    }
    Ok(scopes.into_iter().collect())
}

fn token_hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn token_valid(value: &str) -> bool {
    value.starts_with(PREFIX)
        && value.len() == PREFIX.len() + 64
        && value[PREFIX.len()..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Persist only the SHA-256 digest of a CSPRNG-issued 256-bit bearer token.
/// Issue requires live tenant RBAC in the same INSERT statement.
pub async fn issue(
    pool: &PgPool,
    actor: AuthenticatedUser,
    tenant: &str,
    label: &str,
    requested_scopes: &[String],
    ttl_seconds: i64,
) -> Result<IssuedApiKey, ApiKeyError> {
    if !valid_tenant(tenant)
        || label.trim().is_empty()
        || label.len() > 120
        || label.chars().any(char::is_control)
    {
        return Err(ApiKeyError::InvalidInput);
    }
    let scopes = scopes_checked(requested_scopes)?;
    if !(1..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(ApiKeyError::InvalidTtl);
    }
    let mut random = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| ApiKeyError::Randomness)?;
    let token = format!("{PREFIX}{}", hex::encode(random));

    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO api_keys (user_id, tenant_id, label, token_hash, scopes, expires_at) \
         SELECT u.id, $2, $3, $4, $5::TEXT[], \
                clock_timestamp() + ($6::BIGINT * INTERVAL '1 second') \
         FROM auth_users u WHERE u.id = $1 AND u.is_active \
           AND EXISTS (SELECT 1 FROM rbac_user_roles ur \
             JOIN rbac_roles r ON r.id = ur.role_id \
             JOIN rbac_role_permissions p ON p.role_id = r.id \
             WHERE ur.user_id = u.id AND r.tenant_id = $2 \
               AND p.permission = 'api_keys.create') \
           AND NOT EXISTS (SELECT 1 FROM UNNEST($5::TEXT[]) scope(permission) \
             WHERE NOT EXISTS (SELECT 1 FROM rbac_user_roles ur \
               JOIN rbac_roles r ON r.id = ur.role_id \
               JOIN rbac_role_permissions p ON p.role_id = r.id \
               WHERE ur.user_id = u.id AND r.tenant_id = $2 \
                 AND p.permission = scope.permission)) \
         RETURNING id",
    )
    .bind(actor.user_id())
    .bind(tenant)
    .bind(label)
    .bind(token_hash(&token))
    .bind(&scopes)
    .bind(ttl_seconds)
    .fetch_optional(pool)
    .await?;
    let Some(id) = id else {
        return Err(ApiKeyError::Forbidden);
    };
    Ok(IssuedApiKey { id, token })
}

pub async fn authenticate(
    pool: &PgPool,
    token: &str,
) -> Result<Option<ApiKeyPrincipal>, sqlx::Error> {
    if !token_valid(token) {
        return Ok(None);
    }
    let record: Option<(i64, i64, String, Vec<String>)> = sqlx::query_as(
        "SELECT k.id, k.user_id, k.tenant_id, k.scopes \
         FROM api_keys k JOIN auth_users u ON u.id = k.user_id \
         WHERE k.token_hash = $1 AND k.revoked_at IS NULL \
           AND k.expires_at > clock_timestamp() AND u.is_active",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await?;
    Ok(record.map(|(id, user_id, tenant_id, scopes)| ApiKeyPrincipal {
        id,
        user_id,
        tenant_id,
        scopes,
    }))
}

/// Deny unless BOTH the saved key scope and current tenant RBAC allow the
/// action. Also checks expiry, revocation and user activation on each use.
pub async fn allows(
    pool: &PgPool,
    key: &ApiKeyPrincipal,
    permission: &str,
) -> Result<bool, sqlx::Error> {
    if !valid_scope(permission) || !key.scopes.iter().any(|s| s == permission) {
        return Ok(false);
    }
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM api_keys k \
         JOIN auth_users u ON u.id = k.user_id AND u.is_active \
         WHERE k.id = $1 AND k.user_id = $2 AND k.tenant_id = $3 \
           AND k.revoked_at IS NULL AND k.expires_at > clock_timestamp() \
           AND $4 = ANY(k.scopes) \
           AND EXISTS (SELECT 1 FROM rbac_user_roles ur \
             JOIN rbac_roles r ON r.id = ur.role_id \
             JOIN rbac_role_permissions p ON p.role_id = r.id \
             WHERE ur.user_id = k.user_id AND r.tenant_id = k.tenant_id \
               AND p.permission = $4))",
    )
    .bind(key.id)
    .bind(key.user_id)
    .bind(&key.tenant_id)
    .bind(permission)
    .fetch_one(pool)
    .await
}

/// Owners may always revoke their own keys while active; other users need
/// api_keys.revoke in the same tenant. Repeated revocation returns false.
pub async fn revoke(
    pool: &PgPool,
    actor: AuthenticatedUser,
    key_id: i64,
) -> Result<bool, sqlx::Error> {
    if key_id <= 0 {
        return Ok(false);
    }
    let changed = sqlx::query(
        "UPDATE api_keys k SET revoked_at = clock_timestamp() \
         WHERE k.id = $1 AND k.revoked_at IS NULL \
           AND EXISTS (SELECT 1 FROM auth_users u WHERE u.id = $2 \
             AND u.is_active AND (u.id = k.user_id \
               OR EXISTS (SELECT 1 FROM rbac_user_roles ur \
                 JOIN rbac_roles r ON r.id = ur.role_id \
                 JOIN rbac_role_permissions p ON p.role_id = r.id \
                 WHERE ur.user_id = u.id AND r.tenant_id = k.tenant_id \
                   AND p.permission = 'api_keys.revoke')))",
    )
    .bind(key_id)
    .bind(actor.user_id())
    .execute(pool)
    .await?;
    Ok(changed.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::auth::{authenticate_session, create_session};
    use sqlx::postgres::PgPoolOptions;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_invalid_tenants_scopes_and_raw_tokens() {
        assert!(valid_scope("orders.read"));
        assert!(!valid_scope("orders read"));
        assert!(!valid_tenant("space tenant"));
        assert!(!token_valid("pk_wrong"));
        assert!(token_valid(&format!("pk_{}", "a".repeat(64))));
        assert!(scopes_checked(&["orders.read".into(), "orders.read".into()]).is_err());
    }

    #[tokio::test]
    async fn issue_check_live_rbac_revoke_and_expire() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("test database");
        sqlx::migrate!().run(&pool).await.expect("migrations");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let user: i64 = sqlx::query_scalar(
            "INSERT INTO auth_users(email,password_hash) VALUES ($1,'test') RETURNING id",
        )
        .bind(format!("key-{nanos}-{}@example.invalid", std::process::id()))
        .fetch_one(&pool)
        .await
        .expect("user");
        let tenant = format!("tenant-{nanos}");
        let role: i64 = sqlx::query_scalar(
            "INSERT INTO rbac_roles(tenant_id,name) VALUES ($1,'key-user') RETURNING id",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("role");
        sqlx::query("INSERT INTO rbac_user_roles(user_id,role_id) VALUES ($1,$2)")
            .bind(user)
            .bind(role)
            .execute(&pool)
            .await
            .expect("grant role");
        let session = create_session(&pool, user, 60).await.expect("session");
        let actor = authenticate_session(&pool, &session)
            .await
            .expect("session lookup")
            .expect("actor");
        let scopes = vec!["orders.read".to_owned()];

        assert!(matches!(
            issue(&pool, actor, &tenant, "automation", &scopes, 3600).await,
            Err(ApiKeyError::Forbidden)
        ));
        for permission in ["api_keys.create", "orders.read"] {
            sqlx::query("INSERT INTO rbac_role_permissions(role_id,permission) VALUES ($1,$2)")
                .bind(role)
                .bind(permission)
                .execute(&pool)
                .await
                .expect("permission");
        }
        assert!(matches!(
            issue(&pool, actor, "other-tenant", "automation", &scopes, 3600).await,
            Err(ApiKeyError::Forbidden)
        ));
        assert!(matches!(
            issue(&pool, actor, &tenant, "automation", &["orders.write".into()], 3600).await,
            Err(ApiKeyError::Forbidden)
        ));

        let issued = issue(&pool, actor, &tenant, "automation", &scopes, 3600)
            .await
            .expect("issued token");
        assert_eq!(issued.token.len(), 67);
        let digest: String = sqlx::query_scalar("SELECT token_hash FROM api_keys WHERE id=$1")
            .bind(issued.id)
            .fetch_one(&pool)
            .await
            .expect("digest");
        assert_ne!(digest, issued.token);
        let principal = authenticate(&pool, &issued.token)
            .await
            .expect("token lookup")
            .expect("authenticated key");
        assert_eq!(principal.tenant_id(), tenant);
        assert!(allows(&pool, &principal, "orders.read").await.expect("scope"));
        assert!(!allows(&pool, &principal, "orders.write").await.expect("scope"));

        sqlx::query("DELETE FROM rbac_role_permissions WHERE role_id=$1 AND permission='orders.read'")
            .bind(role)
            .execute(&pool)
            .await
            .expect("role revoked");
        assert!(!allows(&pool, &principal, "orders.read")
            .await
            .expect("live role denied"));
        assert!(revoke(&pool, actor, issued.id).await.expect("revoke"));
        assert!(!revoke(&pool, actor, issued.id).await.expect("idempotent"));
        assert!(authenticate(&pool, &issued.token)
            .await
            .expect("revoked")
            .is_none());
        assert!(!allows(&pool, &principal, "orders.read")
            .await
            .expect("revoked key denied"));

        sqlx::query("INSERT INTO rbac_role_permissions(role_id,permission) VALUES ($1,'orders.read')")
            .bind(role)
            .execute(&pool)
            .await
            .expect("restore role");
        let expiring = issue(&pool, actor, &tenant, "short", &scopes, 1)
            .await
            .expect("short-lived key");
        sqlx::query("UPDATE api_keys SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1")
            .bind(expiring.id)
            .execute(&pool)
            .await
            .expect("expire");
        assert!(authenticate(&pool, &expiring.token)
            .await
            .expect("expired")
            .is_none());
    }
}
