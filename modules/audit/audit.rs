//! Transactional audit event writer for PostgreSQL.
//! Call record() using the same SQLx transaction as the business operation.

use sqlx::{Postgres, Transaction};

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
