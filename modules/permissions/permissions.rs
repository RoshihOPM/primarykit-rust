//! Explicit tenant-scoped RBAC. Missing assignments deny access by default.
//!
//! IMPORTANT: pass a tenant ID retrieved from trusted resource data, not
//! from an unvalidated client-supplied tenant selector. A permission check
//! alone does NOT enforce object-level ownership: filter business SQL by
//! tenant and resource ID in the same operation.

use super::auth::AuthenticatedUser;
use sqlx::PgPool;

/// Database failures propagate and MUST NOT be treated as permission grants.
pub async fn has_permission(
    pool: &PgPool,
    principal: AuthenticatedUser,
    tenant_id: &str,
    permission: &str,
) -> Result<bool, sqlx::Error> {
    if tenant_id.is_empty() || permission.is_empty() {
        return Ok(false);
    }
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
         SELECT 1 FROM auth_users u \
         JOIN rbac_user_roles ur ON ur.user_id = u.id \
         JOIN rbac_roles r ON r.id = ur.role_id \
         JOIN rbac_role_permissions rp ON rp.role_id = r.id \
         WHERE u.id = $1 AND u.is_active \
         AND r.tenant_id = $2 AND rp.permission = $3 \
         )",
    )
    .bind(principal.user_id())
    .bind(tenant_id)
    .bind(permission)
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::super::auth::{authenticate_session, create_session};
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn deny_by_default_and_tenant_isolation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect to test database");
        sqlx::migrate!().run(&pool).await.expect("migrations");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let user_id: i64 = sqlx::query_scalar(
            "INSERT INTO auth_users(email, password_hash) VALUES ($1, $2) RETURNING id",
        )
        .bind(format!(
            "rbac-{nanos}-{}@example.invalid",
            std::process::id()
        ))
        .bind("test-only-placeholder-hash")
        .fetch_one(&pool)
        .await
        .expect("user");
        let token = create_session(&pool, user_id, 60)
            .await
            .expect("create session");
        let principal = authenticate_session(&pool, &token)
            .await
            .expect("authenticate")
            .expect("active session");
        let tenant_a = format!("tenant-a-{nanos}");
        let tenant_b = format!("tenant-b-{nanos}");
        assert!(!has_permission(&pool, principal, &tenant_a, "orders.read")
            .await
            .expect("default deny"));
        assert!(!has_permission(&pool, principal, "", "orders.read")
            .await
            .expect("invalid principal"));

        let role_id: i64 = sqlx::query_scalar(
            "INSERT INTO rbac_roles(tenant_id, name) VALUES ($1, $2) RETURNING id",
        )
        .bind(&tenant_a)
        .bind("viewer")
        .fetch_one(&pool)
        .await
        .expect("role");
        sqlx::query("INSERT INTO rbac_role_permissions(role_id, permission) VALUES ($1, $2)")
            .bind(role_id)
            .bind("orders.read")
            .execute(&pool)
            .await
            .expect("permission");
        sqlx::query("INSERT INTO rbac_user_roles(user_id, role_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(role_id)
            .execute(&pool)
            .await
            .expect("assignment");

        assert!(has_permission(&pool, principal, &tenant_a, "orders.read")
            .await
            .expect("granted"));
        assert!(!has_permission(&pool, principal, &tenant_a, "orders.write")
            .await
            .expect("wrong action"));
        assert!(!has_permission(&pool, principal, &tenant_b, "orders.read")
            .await
            .expect("wrong tenant"));

        sqlx::query("UPDATE auth_users SET is_active = false WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("deactivate");
        assert!(!has_permission(&pool, principal, &tenant_a, "orders.read")
            .await
            .expect("inactive user"));
    }
}
