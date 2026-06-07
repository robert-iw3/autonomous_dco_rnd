mod cache;
mod config;
mod transformer;
mod transmitter;

use crate::cache::TemporalCache;
use crate::config::Config;
use crate::transformer::{Transformer, UnifiedFlowRecord};
use crate::transmitter::Transmitter;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
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
    let transformer = Transformer::new((*cache).clone());
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

    tracing::info!("Nexus GCP VPC Flow connector online.");

    // Accumulate transformed records and the messages that produced them, so
    // we ack ONLY after the gateway confirms receipt. On transmit failure we
    // nack (or let the ack deadline lapse) and Pub/Sub redelivers.
    let mut stream = subscription.subscribe(Some(SubscribeConfig::default())).await?;

    let mut batch: Vec<UnifiedFlowRecord> = Vec::new();
    let mut pending_acks: Vec<google_cloud_pubsub::subscriber::ReceivedMessage> = Vec::new();
    let mut batch_start = Instant::now();
    let empty_meta: HashMap<String, String> = HashMap::new();

    use futures::StreamExt;
    while let Some(message) = stream.next().await {
        let data = &message.message.data;

        // A Logging sink delivers one LogEntry per Pub/Sub message.
        if let Ok(entry) = serde_json::from_slice::<serde_json::Value>(data) {
            if let Some(rec) = transformer.transform_entry(&entry, &empty_meta) {
                batch.push(rec);
            }
        } else {
            tracing::warn!("Undecodable Pub/Sub payload ({} bytes); acking to avoid poison loop", data.len());
        }
        pending_acks.push(message);

        let flush = batch.len() >= config.batch_size
            || batch_start.elapsed() > Duration::from_secs(config.batch_timeout_secs);

        if flush {
            flush_batch(&transmitter, &mut batch, &mut pending_acks).await;
            batch_start = Instant::now();
        }
    }

    // Stream ended: flush remainder so nothing is silently dropped.
    flush_batch(&transmitter, &mut batch, &mut pending_acks).await;
    Ok(())
}

/// Transmit the current batch. On success, ack every pending message; on
/// failure, nack them so Pub/Sub redelivers (queue is the source of truth).
async fn flush_batch(
    transmitter: &Transmitter,
    batch: &mut Vec<UnifiedFlowRecord>,
    pending: &mut Vec<google_cloud_pubsub::subscriber::ReceivedMessage>,
) {
    if pending.is_empty() {
        return;
    }

    // Even if `batch` is empty (all payloads undecodable), we still want to ack
    // the messages we consumed so they don't loop forever.
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