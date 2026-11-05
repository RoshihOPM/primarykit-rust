//! Transactional audit event writer for PostgreSQL.
//! Call record() using the same SQLx transaction as the business operation.

use sqlx::{Postgres, Transaction};

#[path = "audit_outbox.rs"]
pub mod outbox;

/// Context must be derived from a verified principal and trusted request metadata.
/// Do not copy actor or tenant identifiers directly from unsigned client input.
#[derive(Debug, Clone, Copy)]
pub enum AuditActorKind {
    User,
    Service,
    System,
}

impl AuditActorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Service => "service",
            Self::System => "system",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AuditContext<'a> {
    pub actor_kind: AuditActorKind,
    pub actor_id: Option<&'a str>,
    pub tenant_id: Option<&'a str>,
    pub request_id: Option<&'a str>,
}

/// Record a contextual event atomically with the caller's business transaction.
/// PostgreSQL constraints reject missing user/service IDs and oversized context.
pub async fn record_with_context(
    tx: &mut Transaction<'_, Postgres>,
    context: AuditContext<'_>,
    action: &str,
    resource_type: &str,
    resource_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events \
         (actor_id, actor_kind, tenant_id, request_id, action, resource_type, resource_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(context.actor_id)
    .bind(context.actor_kind.as_str())
    .bind(context.tenant_id)
    .bind(context.request_id)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Write the authoritative append-only audit event and enqueue its notification
/// in one SQL statement and in the caller's domain transaction. Commit the
/// transaction only after all business mutations succeed. The destination is
/// a configured identifier, not a user-supplied URL. This is opt-in: legacy
/// record() and record_with_context() calls do not publish notifications.
pub async fn record_and_enqueue(
    tx: &mut Transaction<'_, Postgres>,
    context: AuditContext<'_>,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    destination: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        WITH event AS (
            INSERT INTO audit_events
                (actor_id, actor_kind, tenant_id, request_id,
                 action, resource_type, resource_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
        )
        INSERT INTO audit_delivery_outbox (audit_event_id, destination)
        SELECT id, $8 FROM event
        RETURNING audit_event_id
        "#,
    )
    .bind(context.actor_id)
    .bind(context.actor_kind.as_str())
    .bind(context.tenant_id)
    .bind(context.request_id)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(destination)
    .fetch_one(&mut **tx)
    .await
}

pub async fn record(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (actor_id, action, resource_type, resource_id) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(actor_id)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn record_is_atomic_with_caller_transaction() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("test database connection");
        sqlx::migrate!().run(&pool).await.expect("migrations");
        let mut tx = pool.begin().await.expect("transaction");
        record(&mut tx, Some("test-user"), "read", "test_resource", "one")
            .await
            .expect("record audit event");

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::BIGINT FROM audit_events WHERE resource_type = 'test_resource'",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("read in transaction");
        assert!(count >= 1);

        tx.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn contextual_events_are_atomic_and_preserve_trusted_identity() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("test database connection");
        sqlx::migrate!().run(&pool).await.expect("migrations");

        let mut tx = pool.begin().await.expect("transaction");
        record_with_context(
            &mut tx,
            AuditContext {
                actor_kind: AuditActorKind::User,
                actor_id: Some("verified-user"),
                tenant_id: Some("tenant-1"),
                request_id: Some("request-42"),
            },
            "updated",
            "actor_context_regression",
            "within_tx",
        )
        .await
        .expect("record contextual event");

        let row: (i64, String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT id, actor_kind, actor_id, tenant_id, request_id \
                 FROM audit_events WHERE resource_type = 'actor_context_regression' \
                 AND resource_id = 'within_tx' ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("read uncommitted event");
        assert_eq!(row.1, "user");
        assert_eq!(row.2.as_deref(), Some("verified-user"));
        assert_eq!(row.3.as_deref(), Some("tenant-1"));
        assert_eq!(row.4.as_deref(), Some("request-42"));
        tx.rollback().await.expect("rollback");

        let persisted: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_events WHERE id = $1)")
                .bind(row.0)
                .fetch_one(&pool)
                .await
                .expect("read after rollback");
        assert!(!persisted);
    }

    #[tokio::test]
    async fn user_context_without_actor_is_rejected() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("test database connection");
        sqlx::migrate!().run(&pool).await.expect("migrations");
        let mut tx = pool.begin().await.expect("transaction");
        let error = record_with_context(
            &mut tx,
            AuditContext {
                actor_kind: AuditActorKind::User,
                actor_id: None,
                tenant_id: None,
                request_id: None,
            },
            "attempt",
            "actor_context_regression",
            "missing_actor",
        )
        .await
        .expect_err("user actor id required");
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("23514")
        );
        tx.rollback().await.expect("rollback");
    }

    /// Previously applied audit migrations remain immutable; the new migration
    /// must prevent UPDATE, DELETE and TRUNCATE on generated PostgreSQL apps.
    #[tokio::test]
    async fn audit_history_rejects_mutation() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("test database connection");
        sqlx::migrate!().run(&pool).await.expect("migrations");
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO audit_events(action, resource_type, resource_id)              VALUES ('created', 'append_only_regression', 'event') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .expect("insert audit event");

        let assert_rejected = |error: sqlx::Error| {
            let code = error
                .as_database_error()
                .and_then(|db_error| db_error.code());
            assert_eq!(code.as_deref(), Some("42501"));
        };
        for sql in [
            "UPDATE audit_events SET action = 'tampered' WHERE id = $1",
            "DELETE FROM audit_events WHERE id = $1",
        ] {
            let error = sqlx::query(sql)
                .bind(id)
                .execute(&pool)
                .await
                .expect_err("audit mutation must be rejected");
            assert_rejected(error);
        }

        // TRUNCATE would erase other tests' history if the trigger were absent:
        // always execute it within a transaction that is rolled back.
        let mut tx = pool.begin().await.expect("transaction");
        let error = sqlx::query("TRUNCATE TABLE audit_events")
            .execute(&mut *tx)
            .await
            .expect_err("audit truncation must be rejected");
        assert_rejected(error);
        tx.rollback().await.expect("rollback");
    }
}
