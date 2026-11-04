//! Opt-in RabbitMQ tasks for independent Axum services.
//! At-least-once delivery: handlers MUST make side effects idempotent by task ID.
//! One bounded task per consumer channel; scale via additional worker processes.
use futures_lite::stream::StreamExt;
use lapin::{
    message::Delivery,
    options::{
        BasicAckOptions, BasicCancelOptions, BasicConsumeOptions, BasicNackOptions,
        BasicPublishOptions, BasicQosOptions, BasicRejectOptions, ConfirmSelectOptions,
        QueueDeclareOptions,
    },
    types::{AMQPValue, FieldTable},
    BasicProperties, Channel, Confirmation, Connection, ConnectionProperties,
};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{sync::watch, time::timeout};
use uuid::Uuid;

pub const MAX_MESSAGE_BYTES: usize = 128 * 1024;
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);
const CONSUMER_TAG: &str = "primarykit-task-worker";

#[derive(Debug, Error)]
pub enum TaskError {
    #[error("invalid RabbitMQ connection or task configuration")]
    InvalidConfiguration,
    #[error("insecure AMQP connection is not permitted")]
    InsecureTransport,
    #[error("task name, ID or serialized payload is invalid")]
    InvalidTask,
    #[error("broker did not confirm routed, persistent publication")]
    NotConfirmed,
    #[error("broker operation timed out")]
    Timeout,
    #[error("RabbitMQ consumer ended unexpectedly")]
    ConsumerStopped,
    #[error("RabbitMQ operation failed")]
    Broker(#[from] lapin::Error),
    #[error("task JSON encoding failed")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct TaskConfig {
    pub queue: String,
    pub retry_delay_ms: u32,
    pub max_attempts: u16,
    pub handler_timeout: Duration,
}

impl TaskConfig {
    pub fn new(queue: impl Into<String>) -> Self {
        Self {
            queue: queue.into(),
            retry_delay_ms: 30_000,
            max_attempts: 5,
            handler_timeout: Duration::from_secs(120),
        }
    }

    pub fn validate(&self) -> Result<(), TaskError> {
        if !valid_identifier(&self.queue)
            || self.queue.len() > 120
            || !(100..=600_000).contains(&self.retry_delay_ms)
            || !(1..=20).contains(&self.max_attempts)
            || self.handler_timeout.is_zero()
            || self.handler_timeout > Duration::from_secs(3600)
        {
            return Err(TaskError::InvalidConfiguration);
        }
        Ok(())
    }

    fn retry_queue(&self) -> String {
        format!("{}.retry", self.queue)
    }

    fn dead_queue(&self) -> String {
        format!("{}.dead", self.queue)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// The task ID stays constant across broker redeliveries and retries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskMessage {
    pub id: String,
    pub name: String,
    pub attempt: u16,
    pub payload: serde_json::Value,
}

impl TaskMessage {
    pub fn new(name: &str, payload: serde_json::Value) -> Result<Self, TaskError> {
        if !valid_identifier(name) {
            return Err(TaskError::InvalidTask);
        }
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_owned(),
            attempt: 0,
            payload,
        })
    }

    fn validate(&self, max_attempts: u16) -> bool {
        Uuid::parse_str(&self.id).is_ok()
            && valid_identifier(&self.name)
            && self.attempt < max_attempts
    }

    fn encode(&self) -> Result<Vec<u8>, TaskError> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(TaskError::InvalidTask);
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskFailure {
    Retry,
    Permanent,
}

pub type TaskFuture = Pin<Box<dyn Future<Output = Result<(), TaskFailure>> + Send>>;
pub type TaskHandler = Arc<dyn Fn(TaskMessage) -> TaskFuture + Send + Sync>;

/// A plaintext broker is permitted only for an explicitly opted-in local test.
pub async fn connect(uri: &str, allow_insecure_loopback: bool) -> Result<Connection, TaskError> {
    if !uri.starts_with("amqps://") {
        let authority = uri
            .strip_prefix("amqp://")
            .and_then(|address| address.split('/').next())
            .ok_or(TaskError::InsecureTransport)?;
        let host_port = authority.rsplit('@').next().unwrap_or("");
        let host = host_port.split(':').next().unwrap_or("");
        if !(allow_insecure_loopback && matches!(host, "127.0.0.1" | "localhost")) {
            return Err(TaskError::InsecureTransport);
        }
    }
    Connection::connect(uri, ConnectionProperties::default().enable_auto_recover())
        .await
        .map_err(TaskError::from)
}

/// Creates a durable queue, TTL retry queue and dead-letter queue.
/// Changing the TTL or DLX on an existing queue requires an operator migration.
pub async fn declare(channel: &Channel, config: &TaskConfig) -> Result<(), TaskError> {
    config.validate()?;
    let mut main_args = FieldTable::default();
    main_args.insert(
        "x-dead-letter-exchange".into(),
        AMQPValue::LongString("".into()),
    );
    main_args.insert(
        "x-dead-letter-routing-key".into(),
        AMQPValue::LongString(config.dead_queue().into()),
    );
    channel
        .queue_declare(
            config.queue.clone().into(),
            QueueDeclareOptions::durable(),
            main_args,
        )
        .await?;

    let mut retry_args = FieldTable::default();
    retry_args.insert(
        "x-message-ttl".into(),
        AMQPValue::LongUInt(config.retry_delay_ms),
    );
    retry_args.insert(
        "x-dead-letter-exchange".into(),
        AMQPValue::LongString("".into()),
    );
    retry_args.insert(
        "x-dead-letter-routing-key".into(),
        AMQPValue::LongString(config.queue.clone().into()),
    );
    channel
        .queue_declare(
            config.retry_queue().into(),
            QueueDeclareOptions::durable(),
            retry_args,
        )
        .await?;
    channel
        .queue_declare(
            config.dead_queue().into(),
            QueueDeclareOptions::durable(),
            FieldTable::default(),
        )
        .await?;
    channel.confirm_select(ConfirmSelectOptions::default()).await?;
    Ok(())
}

async fn publish_confirmed(
    channel: &Channel,
    queue: &str,
    id: &str,
    bytes: &[u8],
) -> Result<(), TaskError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(TaskError::InvalidTask);
    }
    let properties = BasicProperties::default()
        .with_delivery_mode(2)
        .with_content_type("application/json".into())
        .with_message_id(id.into());
    let confirmation = timeout(
        PUBLISH_TIMEOUT,
        channel.basic_publish(
            "".into(),
            queue.into(),
            BasicPublishOptions {
                mandatory: true,
                ..BasicPublishOptions::default()
            },
            bytes,
            properties,
        ),
    )
    .await
    .map_err(|_| TaskError::Timeout)??;
    match timeout(PUBLISH_TIMEOUT, confirmation)
        .await
        .map_err(|_| TaskError::Timeout)??
    {
        Confirmation::Ack(None) => Ok(()),
        _ => Err(TaskError::NotConfirmed),
    }
}

/// The caller must declare topology and enable confirms on the publisher channel.
pub async fn enqueue(
    channel: &Channel,
    config: &TaskConfig,
    name: &str,
    payload: serde_json::Value,
) -> Result<String, TaskError> {
    config.validate()?;
    let message = TaskMessage::new(name, payload)?;
    let bytes = message.encode()?;
    publish_confirmed(channel, &config.queue, &message.id, &bytes).await?;
    Ok(message.id)
}

async fn acknowledge(delivery: &Delivery) -> Result<(), TaskError> {
    if !delivery.ack(BasicAckOptions::default()).await? {
        return Err(TaskError::NotConfirmed);
    }
    Ok(())
}

async fn reject_to_dead_letter(delivery: &Delivery) -> Result<(), TaskError> {
    if !delivery
        .reject(BasicRejectOptions { requeue: false })
        .await?
    {
        return Err(TaskError::NotConfirmed);
    }
    Ok(())
}

async fn process(
    channel: &Channel,
    config: &TaskConfig,
    handler: &TaskHandler,
    delivery: &Delivery,
) -> Result<(), TaskError> {
    if delivery.data.len() > MAX_MESSAGE_BYTES {
        return reject_to_dead_letter(delivery).await;
    }
    let Ok(mut message) = serde_json::from_slice::<TaskMessage>(&delivery.data) else {
        return reject_to_dead_letter(delivery).await;
    };
    if !message.validate(config.max_attempts) {
        return reject_to_dead_letter(delivery).await;
    }
    let result = timeout(config.handler_timeout, (handler)(message.clone())).await;
    match result {
        Ok(Ok(())) => acknowledge(delivery).await,
        Ok(Err(TaskFailure::Permanent)) => reject_to_dead_letter(delivery).await,
        Ok(Err(TaskFailure::Retry)) | Err(_) => {
            if message.attempt + 1 >= config.max_attempts {
                return reject_to_dead_letter(delivery).await;
            }
            message.attempt += 1;
            let payload = message.encode()?;
            if let Err(error) =
                publish_confirmed(channel, &config.retry_queue(), &message.id, &payload).await
            {
                // Never acknowledge an original before broker-confirmed retry.
                // On an uncertain publish, duplicates are possible by design.
                delivery
                    .nack(BasicNackOptions {
                        requeue: true,
                        ..BasicNackOptions::default()
                    })
                    .await?;
                return Err(error);
            }
            acknowledge(delivery).await
        }
    }
}

/// Processes one task per channel; use more channels/processes for concurrency.
/// On shutdown, finish the in-flight task and cancel the consumer cleanly.
/// Supervisors should enforce a termination grace longer than handler_timeout.
pub async fn run_worker(
    channel: &Channel,
    config: &TaskConfig,
    handler: &TaskHandler,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), TaskError> {
    config.validate()?;
    channel.confirm_select(ConfirmSelectOptions::default()).await?;
    channel.basic_qos(1, BasicQosOptions::default()).await?;
    let mut consumer = channel
        .basic_consume(
            config.queue.clone().into(),
            CONSUMER_TAG.into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await?;
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow_and_update() {
                    break;
                }
            }
            delivery = consumer.next() => {
                let delivery = match delivery {
                    Some(Ok(item)) => item,
                    Some(Err(error)) => return Err(TaskError::Broker(error)),
                    None => return Err(TaskError::ConsumerStopped),
                };
                process(channel, config, handler, &delivery).await?;
            }
        }
    }
    channel
        .basic_cancel(CONSUMER_TAG.into(), BasicCancelOptions::default())
        .await?;
    Ok(())
}

#[cfg(test)]
#[path = "tasks_tests.rs"]
mod tests;
