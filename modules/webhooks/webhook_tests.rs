//! PostgreSQL integration tests for dedupe, rollback and retry semantics.
use super::{outbox, reserve_inbound, sign, verify, DedupResult, WebhookError};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const KEY: &[u8] = b"test-provider-hmac-secret-for-webhooks-1234567890";

fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(&url)
        .await
        .expect("test database available");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    Some(pool)
}

#[tokio::test]
async fn inbound_receipt_rolls_back_and_rejects_conflicting_payloads() {
    let Some(pool) = pool().await else {
        return;
    };
    let source = unique("provider");
    let id = unique("inbound");
    let tag = sign(KEY, &source, &id, 1_800_000_000, b"original").expect("sign");
    let event = verify(KEY, &source, &id, &tag, b"original", 1_800_000_005)
        .expect("verify");
    let mut tx = pool.begin().await.expect("begin");
    assert_eq!(
        reserve_inbound(&mut tx, &event).await.expect("reserve"),
        DedupResult::Inserted
    );
    tx.rollback().await.expect("rollback");

    let mut tx = pool.begin().await.expect("begin");
    assert_eq!(
        reserve_inbound(&mut tx, &event).await.expect("reserve again"),
        DedupResult::Inserted
    );
    tx.commit().await.expect("commit");

    let mut tx = pool.begin().await.expect("begin");
    assert_eq!(
        reserve_inbound(&mut tx, &event).await.expect("duplicate"),
        DedupResult::Duplicate
    );
    let changed_tag = sign(KEY, &source, &id, 1_800_000_000, b"changed").expect("sign");
    let changed = verify(KEY, &source, &id, &changed_tag, b"changed", 1_800_000_005)
        .expect("verified change");
    assert!(matches!(
        reserve_inbound(&mut tx, &changed).await,
        Err(WebhookError::Conflict)
    ));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn concurrent_inbound_events_are_processed_once() {
    let Some(pool) = pool().await else {
        return;
    };
    let source = unique("source");
    let id = unique("concurrent");
    let tag = sign(KEY, &source, &id, 1_800_000_000, b"body").expect("sign");
    let verified = verify(KEY, &source, &id, &tag, b"body", 1_800_000_010)
        .expect("verify");
    let process = || async {
        let mut tx = pool.begin().await.expect("begin");
        let result = reserve_inbound(&mut tx, &verified)
            .await
            .expect("reserve");
        tx.commit().await.expect("commit");
        result
    };
    let (first, second) = tokio::join!(process(), process());
    assert_eq!(
        u8::from(first == DedupResult::Inserted) + u8::from(second == DedupResult::Inserted),
        1
    );
}

#[tokio::test]
async fn outgoing_failures_retry_then_scrub_payload() {
    let Some(pool) = pool().await else {
        return;
    };
    let destination = unique("destination");
    let event_id = unique("outgoing");
    let mut tx = pool.begin().await.expect("begin");
    assert_eq!(
        outbox::enqueue(&mut tx, &destination, &event_id, b"private data")
            .await
            .expect("enqueue"),
        DedupResult::Inserted
    );
    assert_eq!(
        outbox::enqueue(&mut tx, &destination, &event_id, b"private data")
            .await
            .expect("duplicate"),
        DedupResult::Duplicate
    );
    assert!(matches!(
        outbox::enqueue(&mut tx, &destination, &event_id, b"different").await,
        Err(WebhookError::Conflict)
    ));
    tx.commit().await.expect("commit");

    let mut keys = BTreeMap::new();
    keys.insert(destination.clone(), KEY.to_vec());
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&attempts);
    let delivery: outbox::WebhookDelivery = Arc::new(move |_dest, _id, header, body| {
        let counter = Arc::clone(&counter);
        Box::pin(async move {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_secs() as i64;
            let _verified = verify(KEY, &_dest, &_id, &header, &body, now)
                .expect("valid outgoing signature");
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(())
            } else {
                Ok(())
            }
        })
    });
    assert!(
        outbox::send_next_to(&pool, &keys, &delivery, &destination)
            .await
            .expect("first attempt")
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    sqlx::query(
        "UPDATE webhook_outbox SET available_at=clock_timestamp() - INTERVAL '1 second' \
         WHERE destination=$1 AND event_id=$2",
    )
    .bind(&destination)
    .bind(&event_id)
    .execute(&pool)
    .await
    .expect("make retry due");
    assert!(
        outbox::send_next_to(&pool, &keys, &delivery, &destination)
            .await
            .expect("second attempt")
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(
        !outbox::send_next_to(&pool, &keys, &delivery, &destination)
            .await
            .expect("already sent")
    );
    let (sent, size): (bool, i32) = sqlx::query_as(
        "SELECT delivered_at IS NOT NULL, octet_length(payload) FROM webhook_outbox \
         WHERE destination=$1 AND event_id=$2",
    )
    .bind(&destination)
    .bind(&event_id)
    .fetch_one(&pool)
    .await
    .expect("state");
    assert!(sent);
    assert_eq!(size, 0);
}

#[tokio::test]
async fn unknown_destination_preserves_attempts_and_secret_is_not_stored() {
    let Some(pool) = pool().await else {
        return;
    };
    let dest = unique("unconfigured");
    let mut tx = pool.begin().await.expect("begin");
    outbox::enqueue(&mut tx, &dest, &unique("event"), b"payload")
        .await
        .expect("enqueue");
    tx.commit().await.expect("commit");
    let delivery: outbox::WebhookDelivery =
        Arc::new(|_, _, _, _| Box::pin(async { Ok(()) }));
    assert!(matches!(
        outbox::send_next_to(&pool, &BTreeMap::new(), &delivery, &dest).await,
        Err(WebhookError::MissingDestination)
    ));
    let attempts: i32 =
        sqlx::query_scalar("SELECT attempts FROM webhook_outbox WHERE destination=$1")
            .bind(&dest)
            .fetch_one(&pool)
            .await
            .expect("attempts");
    assert_eq!(attempts, 0);
}
