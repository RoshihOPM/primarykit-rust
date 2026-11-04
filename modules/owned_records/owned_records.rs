//! Reference implementation for object-level authorization.
//! The resource's tenant is read from trusted stored data; owner and RBAC
//! checks are part of the same SQL statement, not separate HTTP checks.

use super::auth::AuthenticatedUser;
use serde::Serialize;
use sqlx::{FromRow, PgPool};

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct OwnedRecord {
    pub id: i64,
    pub tenant_id: String,
    pub owner_user_id: i64,
    pub body: String,
}

/// A missing object, an inactive user, another owner or missing RBAC grant
/// all return None to avoid leaking cross-tenant object existence.
pub async fn get(
    pool: &PgPool,
    principal: AuthenticatedUser,
    id: i64,
) -> Result<Option<OwnedRecord>, sqlx::Error> {
    sqlx::query_as::<_, OwnedRecord>(
        "SELECT r.id, r.tenant_id, r.owner_user_id, r.body FROM owned_records r \
         JOIN auth_users u ON u.id = $2 AND u.is_active \
         WHERE r.id = $1 AND r.owner_user_id = $2 AND EXISTS ( \
           SELECT 1 FROM rbac_user_roles ur \
           JOIN rbac_roles role ON role.id = ur.role_id \
           JOIN rbac_role_permissions p ON p.role_id = role.id \
           WHERE ur.user_id = $2 AND role.tenant_id = r.tenant_id \
           AND p.permission = 'records.read' \
         )",
    )
    .bind(id)
    .bind(principal.user_id())
    .fetch_optional(pool)
    .await
}

/// Atomic update with authorization in the UPDATE predicate. Never perform
/// a SELECT permission check followed by an unguarded UPDATE.
pub async fn update(
    pool: &PgPool,
    principal: AuthenticatedUser,
    id: i64,
    body: &str,
) -> Result<bool, sqlx::Error> {
    let updated: Option<i64> = sqlx::query_scalar(
        "UPDATE owned_records r SET body = $3 \
         WHERE r.id = $1 AND r.owner_user_id = $2 \
         AND EXISTS (SELECT 1 FROM auth_users u WHERE u.id = $2 AND u.is_active) \
         AND EXISTS ( \
           SELECT 1 FROM rbac_user_roles ur \
           JOIN rbac_roles role ON role.id = ur.role_id \
           JOIN rbac_role_permissions p ON p.role_id = role.id \
           WHERE ur.user_id = $2 AND role.tenant_id = r.tenant_id \
           AND p.permission = 'records.write' \
         ) RETURNING r.id",
    )
    .bind(id)
    .bind(principal.user_id())
    .bind(body)
    .fetch_optional(pool)
    .await?;
    Ok(updated.is_some())
}

#[cfg(test)]
mod tests {
    use super::super::auth::{authenticate_session, create_session};
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn owner_and_permission_are_enforced_together() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("database available");
        sqlx::migrate!().run(&pool).await.expect("migrations");
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let owner: i64 = sqlx::query_scalar(
            "INSERT INTO auth_users(email, password_hash) VALUES ($1, 'test') RETURNING id",
        )
        .bind(format!(
            "owner-{}-{suffix}@example.invalid",
            std::process::id()
        ))
        .fetch_one(&pool)
        .await
        .expect("owner");
        let intruder: i64 = sqlx::query_scalar(
            "INSERT INTO auth_users(email, password_hash) VALUES ($1, 'test') RETURNING id",
        )
        .bind(format!(
            "intruder-{}-{suffix}@example.invalid",
            std::process::id()
        ))
        .fetch_one(&pool)
        .await
        .expect("intruder");
        let owner_session = create_session(&pool, owner, 120).await.expect("session");
        let intruder_session = create_session(&pool, intruder, 120).await.expect("session");
        let owner_principal = authenticate_session(&pool, &owner_session)
            .await
            .expect("auth")
            .expect("owner principal");
        let intruder_principal = authenticate_session(&pool, &intruder_session)
            .await
            .expect("auth")
            .expect("intruder principal");

        let tenant = format!("objects-{suffix}");
        let role: i64 = sqlx::query_scalar(
            "INSERT INTO rbac_roles(tenant_id,name) VALUES ($1,'reader') RETURNING id",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("role");
        sqlx::query(
            "INSERT INTO rbac_role_permissions(role_id,permission) VALUES ($1,'records.read')",
        )
        .bind(role)
        .execute(&pool)
        .await
        .expect("role permission");
        for user in [owner, intruder] {
            sqlx::query("INSERT INTO rbac_user_roles(user_id,role_id) VALUES ($1,$2)")
                .bind(user)
                .bind(role)
                .execute(&pool)
                .await
                .expect("assignment");
        }
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO owned_records(tenant_id,owner_user_id,body) VALUES ($1,$2,'private') RETURNING id",
        )
        .bind(&tenant)
        .bind(owner)
        .fetch_one(&pool)
        .await
        .expect("record");

        assert_eq!(
            get(&pool, owner_principal, id)
                .await
                .expect("owner read")
                .expect("found")
                .body,
            "private"
        );
        assert!(get(&pool, intruder_principal, id)
            .await
            .expect("intruder read")
            .is_none());
        assert!(!update(&pool, owner_principal, id, "new")
            .await
            .expect("write denied"));

        sqlx::query(
            "INSERT INTO rbac_role_permissions(role_id,permission) VALUES ($1,'records.write')",
        )
        .bind(role)
        .execute(&pool)
        .await
        .expect("write grant");
        assert!(!update(&pool, intruder_principal, id, "tampered")
            .await
            .expect("intruder write denied"));
        assert!(update(&pool, owner_principal, id, "changed")
            .await
            .expect("owner write"));
        assert_eq!(
            get(&pool, owner_principal, id)
                .await
                .expect("read")
                .expect("record")
                .body,
            "changed"
        );

        sqlx::query("UPDATE auth_users SET is_active = FALSE WHERE id = $1")
            .bind(owner)
            .execute(&pool)
            .await
            .expect("deactivate owner");
        assert!(get(&pool, owner_principal, id)
            .await
            .expect("disabled")
            .is_none());
        assert!(!update(&pool, owner_principal, id, "blocked")
            .await
            .expect("disabled"));
    }
}
