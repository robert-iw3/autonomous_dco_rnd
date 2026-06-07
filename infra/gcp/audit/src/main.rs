mod cache;
mod config;
mod transformer;
mod transmitter;

use crate::cache::TemporalCache;
use crate::config::Config;
use crate::transformer::{Transformer, UnifiedFlowRecord};
use crate::transmitter::Transmitter;

use std::sync::Arc;
use std::time::Instant;
use tokio::time::{sleep, Duration};
use tracing_subscriber::EnvFilter;

use google_cloud_pubsub::client::{Client, ClientConfig};
use google_cloud_pubsub::subscription::SubscribeConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    let cache = Arc::new(TemporalCache::new());
    let transformer = Transformer::new((*cache).clone(), config.sensor_id.clone());
    let transmitter = Transmitter::new(config.clone());

    // Background eviction of idle conversation state.
    let cache_clone = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(600)).await;
            cache_clone.remove_stale(3600);
        }
    });

    // Pub/Sub client (ADC / GKE Workload Identity).
    let client_config = ClientConfig::default().with_auth().await?;
    let client = Client::new(client_config).await?;
    let subscription = client.subscription(&config.subscription_id);

    tracing::info!("Nexus GCP Audit Log connector online.");

    // ack ONLY after the gateway confirms. On transmit failure we nack and
    // Pub/Sub redelivers (the queue is the source of truth → spool_replay=false).
    let mut stream = subscription.subscribe(Some(SubscribeConfig::default())).await?;

    let mut batch: Vec<UnifiedFlowRecord> = Vec::new();
    let mut pending: Vec<google_cloud_pubsub::subscriber::ReceivedMessage> = Vec::new();
    let mut batch_start = Instant::now();

    use futures::StreamExt;
    while let Some(message) = stream.next().await {
        // A Logging sink delivers one Cloud Audit Log LogEntry per message.
        if let Some(rec) = transformer.transform_message(&message.message.data) {
            batch.push(rec);
        } else {
            tracing::debug!(
                "Audit entry produced no record ({} bytes)",
                message.message.data.len()
            );
        }
        pending.push(message);

        if batch.len() >= config.batch_size
            || batch_start.elapsed() > Duration::from_secs(config.batch_timeout_secs)
        {
            flush_batch(&transmitter, &mut batch, &mut pending).await;
            batch_start = Instant::now();
        }
    }

    // Stream ended: flush remainder so nothing is silently dropped.
    flush_batch(&transmitter, &mut batch, &mut pending).await;
    Ok(())
}

/// Transmit the current batch. On success ack every pending message; on failure
/// nack them so Pub/Sub redelivers. Messages that produced no record are still
/// acked on success (empty batch => transmit_ok = true) to avoid poison loops.
async fn flush_batch(
    transmitter: &Transmitter,
    batch: &mut Vec<UnifiedFlowRecord>,
    pending: &mut Vec<google_cloud_pubsub::subscriber::ReceivedMessage>,
) {
    if pending.is_empty() {
        return;
    }
    let transmit_ok = if batch.is_empty() {
        true
    } else {
        let records = std::mem::take(batch);
        transmitter.spool_and_transmit(records).await
    };

    for msg in pending.drain(..) {
        if transmit_ok {
            if let Err(e) = msg.ack().await {
                tracing::warn!("Pub/Sub ack failed: {}", e);
            }
        } else if let Err(e) = msg.nack().await {
            tracing::warn!("Pub/Sub nack failed: {}", e);
        }
    }
}