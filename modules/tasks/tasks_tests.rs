//! Broker-independent validation and RabbitMQ integration regression tests.
use super::*;
use lapin::options::{BasicAckOptions, BasicGetOptions};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

async fn broker_setup() -> Option<(Connection, Channel, Channel, TaskConfig)> {
    let url = std::env::var("AMQP_URL").ok()?;
    let connection = connect(&url, true).await.expect("test broker connection");
    let producer = connection.create_channel().await.expect("producer");
    let consumer = connection.create_channel().await.expect("consumer");
    let mut config = TaskConfig::new(format!("pk_test_{}", Uuid::new_v4().simple()));
    config.retry_delay_ms = 100;
    config.handler_timeout = Duration::from_secs(3);
    declare(&producer, &config).await.expect("publisher topology");
    declare(&consumer, &config).await.expect("consumer topology");
    Some((connection, producer, consumer, config))
}

#[test]
fn validates_queue_and_message_limits() {
    let mut config = TaskConfig::new("orders");
    assert!(config.validate().is_ok());
    config.queue = "../escape".to_owned();
    assert!(config.validate().is_err());
    config.queue = "orders".to_owned();
    config.max_attempts = 0;
    assert!(config.validate().is_err());
    assert!(TaskMessage::new("orders.create", json!({"id": 1})).is_ok());
    assert!(TaskMessage::new("../../bad", json!(null)).is_err());
    let message = TaskMessage::new("task", json!({"body": "x".repeat(MAX_MESSAGE_BYTES)}))
        .expect("name accepted");
    assert!(matches!(message.encode(), Err(TaskError::InvalidTask)));
}

#[tokio::test]
async fn disallows_unencrypted_remote_broker() {
    assert!(matches!(
        connect("amqp://remote.internal:5672/%2f", true).await,
        Err(TaskError::InsecureTransport)
    ));
    assert!(matches!(
        connect("amqp://127.0.0.1:5672/%2f", false).await,
        Err(TaskError::InsecureTransport)
    ));
}

#[tokio::test]
async fn transient_failure_retries_with_stable_task_id_and_graceful_shutdown() {
    let Some((_connection, producer, consumer, config)) = broker_setup().await else {
        return;
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let seen = Arc::new(AtomicUsize::new(0));
    let seen_in_handler = Arc::clone(&seen);
    let expected_id = Arc::new(tokio::sync::Mutex::new(None::<String>));
    let expected_in_handler = Arc::clone(&expected_id);
    let handler: TaskHandler = Arc::new(move |message| {
        let count = Arc::clone(&seen_in_handler);
        let id_holder = Arc::clone(&expected_in_handler);
        let signal = shutdown_tx.clone();
        Box::pin(async move {
            let call = count.fetch_add(1, Ordering::SeqCst);
            let mut guard = id_holder.lock().await;
            if call == 0 {
                *guard = Some(message.id.clone());
                assert_eq!(message.attempt, 0);
                Err(TaskFailure::Retry)
            } else {
                assert_eq!(guard.as_deref(), Some(message.id.as_str()));
                assert_eq!(message.attempt, 1);
                let _ = signal.send(true);
                Ok(())
            }
        })
    });
    let worker_config = config.clone();
    let running = tokio::spawn(async move {
        run_worker(&consumer, &worker_config, &handler, shutdown_rx).await
    });

    let published_id = enqueue(&producer, &config, "email.send", json!({"recipient": "test"}))
        .await
        .expect("publish confirmed");
    timeout(Duration::from_secs(15), running)
        .await
        .expect("worker completes after retry")
        .expect("join worker")
        .expect("worker succeeded");
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    assert_eq!(expected_id.lock().await.as_deref(), Some(published_id.as_str()));
}

#[tokio::test]
async fn permanent_failure_is_dead_lettered_without_retry() {
    let Some((_connection, producer, consumer, config)) = broker_setup().await else {
        return;
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handler: TaskHandler = Arc::new(move |_message| {
        let signal = shutdown_tx.clone();
        Box::pin(async move {
            let _ = signal.send(true);
            Err(TaskFailure::Permanent)
        })
    });
    let worker_config = config.clone();
    let running = tokio::spawn(async move {
        run_worker(&consumer, &worker_config, &handler, shutdown_rx).await
    });
    let id = enqueue(&producer, &config, "unrecoverable", json!({}))
        .await
        .expect("published");
    timeout(Duration::from_secs(10), running)
        .await
        .expect("worker completes")
        .expect("join worker")
        .expect("worker succeeded");

    let dead = producer
        .basic_get(config.dead_queue().into(), BasicGetOptions::default())
        .await
        .expect("dead queue readable")
        .expect("permanent task dead-lettered");
    let received: TaskMessage = serde_json::from_slice(&dead.data).expect("decode task");
    assert_eq!(received.id, id);
    dead.ack(BasicAckOptions::default())
        .await
        .expect("ack dead letter");
}

#[tokio::test]
async fn mandatory_publish_rejects_unroutable_queue() {
    let Some((_connection, producer, _consumer, config)) = broker_setup().await else {
        return;
    };
    let task = TaskMessage::new("unroutable", json!({})).expect("task");
    let queue = format!("{}_not_declared", config.queue);
    let err = publish_confirmed(&producer, &queue, &task.id, &task.encode().expect("encode"))
        .await
        .expect_err("mandatory publish should be returned");
    assert!(matches!(err, TaskError::NotConfirmed));
}
