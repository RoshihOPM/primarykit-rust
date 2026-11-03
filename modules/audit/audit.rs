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
}
