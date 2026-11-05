//! Database-backed audit outbox regressions. CI runs these in generated Axum apps.
use super::*;
use crate::modules::audit::{record_and_enqueue, AuditActorKind, AuditContext};
use sqlx::postgres::PgPoolOptions;
use std::time::{SystemTime, UNIX_EPOCH};

async fn test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("test database");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    Some(pool)
}

fn unique_destination() -> String {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("audit_test_{}_{suffix}", std::process::id())
}

async fn insert_test_event(pool: &PgPool, destination: &str) -> i64 {
    let mut tx = pool.begin().await.expect("begin");
    let id = record_and_enqueue(
        &mut tx,
        AuditContext {
            actor_kind: AuditActorKind::System,
            actor_id: None,
            tenant_id: Some("tenant-test"),
            request_id: None,
        },
        "created",
        "outbox_regression",
        "item",
        destination,
    )
    .await
    .expect("record and queue");
    tx.commit().await.expect("commit");
    id
}

#[tokio::test]
async fn records_event_and_outbox_atomically_on_commit_or_rollback() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let destination = unique_destination();
    let mut tx = pool.begin().await.expect("begin");
    let id = record_and_enqueue(
        &mut tx,
        AuditContext {
            actor_kind: AuditActorKind::User,
            actor_id: Some("signed-in-user"),
            tenant_id: Some("trusted-tenant"),
            request_id: Some("server-request"),
        },
        "changed",
        "audit_outbox_atomic",
        "rollback",
        &destination,
    )
    .await
    .expect("record and queue");

    let seen: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM audit_delivery_outbox WHERE audit_event_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .expect("uncommitted row");
    assert_eq!(seen, 1);
    tx.rollback().await.expect("rollback");

    let (event_exists, outbox_exists): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM audit_events WHERE id = $1), \
         EXISTS(SELECT 1 FROM audit_delivery_outbox WHERE audit_event_id = $1)",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .expect("post rollback check");
    assert!(!event_exists);
    assert!(!outbox_exists);

    let committed = insert_test_event(&pool, &unique_destination()).await;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM audit_delivery_outbox WHERE audit_event_id = $1",
    )
    .bind(committed)
    .fetch_one(&pool)
    .await
    .expect("committed row");
    assert_eq!(count, 1);
}

#[tokio::test]
async fn invalid_destination_rejects_entire_event_write() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin");
    let error = record_and_enqueue(
        &mut tx,
        AuditContext {
            actor_kind: AuditActorKind::System,
            actor_id: None,
            tenant_id: None,
            request_id: None,
        },
        "changed",
        "outbox_regression",
        "invalid-destination",
        "http://untrusted.example",
    )
    .await
    .expect_err("destination name must be constrained");
    assert_eq!(
        error.as_database_error().and_then(|db| db.code()).as_deref(),
        Some("23514")
    );
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn expired_lease_is_fenced_before_acknowledgement() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let destination = unique_destination();
    let id = insert_test_event(&pool, &destination).await;
    let first = claim_one(&pool, Some(&destination))
        .await
        .expect("claim")
        .expect("first claim");
    assert_eq!(first.audit_event_id, id);
    assert_eq!(first.attempts, 1);
    assert!(claim_one(&pool, Some(&destination))
        .await
        .expect("second claim")
        .is_none());

    sqlx::query(
        "UPDATE audit_delivery_outbox SET leased_until = clock_timestamp() \
         - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(first.id)
    .execute(&pool)
    .await
    .expect("expire lease");
    let second = claim_one(&pool, Some(&destination))
        .await
        .expect("claim after expiry")
        .expect("second claim");
    assert_eq!(second.attempts, 2);
    assert_eq!(second.lease_generation, first.lease_generation + 1);
    assert!(matches!(
        complete_claim(&pool, first.id, first.lease_generation).await,
        Err(AuditOutboxError::LeaseLost)
    ));
    complete_claim(&pool, second.id, second.lease_generation)
        .await
        .expect("new lease may acknowledge");
    let done: bool = sqlx::query_scalar(
        "SELECT delivered_at IS NOT NULL FROM audit_delivery_outbox WHERE id = $1",
    )
    .bind(first.id)
    .fetch_one(&pool)
    .await
    .expect("delivery state");
    assert!(done);
}

#[tokio::test]
async fn retry_eventually_dead_letters_after_eight_failed_attempts() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let destination = unique_destination();
    insert_test_event(&pool, &destination).await;

    for attempt in 1..=MAX_ATTEMPTS {
        let claim = claim_one(&pool, Some(&destination))
            .await
            .expect("claim")
            .expect("eligible retry");
        assert_eq!(claim.attempts, attempt);
        fail_claim(&pool, claim.id, claim.lease_generation, false)
            .await
            .expect("retry or dead letter");
        if attempt < MAX_ATTEMPTS {
            sqlx::query(
                "UPDATE audit_delivery_outbox SET available_at = clock_timestamp() \
                 - INTERVAL '1 second' WHERE id = $1",
            )
            .bind(claim.id)
            .execute(&pool)
            .await
            .expect("advance retry clock");
        }
    }
    let (attempts, dead): (i32, bool) = sqlx::query_as(
        "SELECT attempts, dead_at IS NOT NULL FROM audit_delivery_outbox \
         WHERE destination = $1",
    )
    .bind(&destination)
    .fetch_one(&pool)
    .await
    .expect("dead-letter state");
    assert_eq!(attempts, MAX_ATTEMPTS);
    assert!(dead);
    assert!(claim_one(&pool, Some(&destination))
        .await
        .expect("claim after terminal state")
        .is_none());
}

#[tokio::test]
async fn crashed_final_attempt_is_reaped_after_lease_expiry() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let destination = unique_destination();
    insert_test_event(&pool, &destination).await;

    sqlx::query(
        "UPDATE audit_delivery_outbox \
         SET attempts = 7 WHERE destination = $1",
    )
    .bind(&destination)
    .execute(&pool)
    .await
    .expect("simulate preceding attempts");
    let final_claim = claim_one(&pool, Some(&destination))
        .await
        .expect("claim")
        .expect("final attempt");
    assert_eq!(final_claim.attempts, MAX_ATTEMPTS);
    sqlx::query(
        "UPDATE audit_delivery_outbox SET leased_until = clock_timestamp() \
         - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(final_claim.id)
    .execute(&pool)
    .await
    .expect("simulate crash after attempt");
    assert_eq!(
        dead_letter_exhausted(&pool, Some(&destination))
            .await
            .expect("reaper"),
        1
    );
    let dead: bool = sqlx::query_scalar(
        "SELECT dead_at IS NOT NULL FROM audit_delivery_outbox WHERE id = $1",
    )
    .bind(final_claim.id)
    .fetch_one(&pool)
    .await
    .expect("dead state");
    assert!(dead);
}

#[tokio::test]
async fn confirmed_callback_receives_stable_event_id_and_metadata() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let destination = unique_destination();
    let event_id = insert_test_event(&pool, &destination).await;
    let expected_destination = destination.clone();
    let handler: AuditDeliveryHandler = Arc::new(move |item| {
        assert_eq!(item.audit_event_id, event_id);
        assert_eq!(item.destination, expected_destination);
        assert_eq!(item.actor_kind, "system");
        assert_eq!(item.tenant_id.as_deref(), Some("tenant-test"));
        Box::pin(async { Ok(()) })
    });
    assert!(send_filtered(&pool, &handler, Some(&destination))
        .await
        .expect("delivery"));
    assert!(!send_filtered(&pool, &handler, Some(&destination))
        .await
        .expect("no second delivery"));
}

#[tokio::test]
async fn shutdown_interrupts_idle_wait() {
    let (sender, mut receiver) = watch::channel(false);
    let waiting = tokio::spawn(async move {
        wait_or_shutdown(&mut receiver, Duration::from_secs(30)).await
    });
    tokio::task::yield_now().await;
    sender.send(true).expect("receiver is alive");
    assert!(timeout(Duration::from_secs(2), waiting)
        .await
        .expect("shutdown must be prompt")
        .expect("join task"));
}
