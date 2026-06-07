mod cache;
mod config;
mod transformer;
mod transmitter;

use crate::cache::FindingCache;
use crate::config::Config;
use crate::transformer::{Transformer, UnifiedFlowRecord};
use crate::transmitter::Transmitter;

use std::collections::HashSet;
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
    let cache = Arc::new(FindingCache::new());
    let transformer = Transformer::new(config.sensor_id.clone());
    let transmitter = Transmitter::new(config.clone());

    // SCC re-notifies on finding state changes; dedup TTL of 24h bounds the
    // cache while tolerating the typical re-emit cadence.
    let cache_clone = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(3600)).await;
            cache_clone.remove_stale(86400);
        }
    });

    let client_config = ClientConfig::default().with_auth().await?;
    let client = Client::new(client_config).await?;
    let subscription = client.subscription(&config.subscription_id);

    tracing::info!("Nexus GCP SCC connector online.");

    let mut stream = subscription.subscribe(Some(SubscribeConfig::default())).await?;

    let mut batch: Vec<UnifiedFlowRecord> = Vec::new();
    let mut batch_ids: Vec<String> = Vec::new();
    let mut seen_in_batch: HashSet<String> = HashSet::new();
    let mut pending: Vec<google_cloud_pubsub::subscriber::ReceivedMessage> = Vec::new();
    let mut batch_start = Instant::now();

    use futures::StreamExt;
    while let Some(message) = stream.next().await {
        // Decode once. Undecodable payloads are acked immediately (poison guard).
        let entry = match serde_json::from_slice::<serde_json::Value>(&message.message.data) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    "Undecodable SCC payload ({} bytes); acking.",
                    message.message.data.len()
                );
                let _ = message.ack().await;
                continue;
            }
        };

        // Dedup key: finding.name + eventTime -- a genuine update carries a new
        // eventTime and is NOT suppressed.
        let id = scc_dedup_key(&entry);
        let already = id
            .as_ref()
            .map(|k| cache.contains(k) || seen_in_batch.contains(k))
            .unwrap_or(false);

        if !already {
            if let Some(rec) = transformer.transform_message(&message.message.data) {
                batch.push(rec);
                if let Some(k) = id {
                    seen_in_batch.insert(k.clone());
                    batch_ids.push(k);
                }
            }
        }
        pending.push(message);

        if batch.len() >= config.batch_size
            || batch_start.elapsed() > Duration::from_secs(config.batch_timeout_secs)
        {
            flush_batch(
                &transmitter, &cache, &mut batch, &mut batch_ids,
                &mut seen_in_batch, &mut pending,
            )
            .await;
            batch_start = Instant::now();
        }
    }

    flush_batch(
        &transmitter, &cache, &mut batch, &mut batch_ids,
        &mut seen_in_batch, &mut pending,
    )
    .await;
    Ok(())
}

fn scc_dedup_key(entry: &serde_json::Value) -> Option<String> {
    let finding = entry.get("finding")?;
    let name = finding.get("name").and_then(|v| v.as_str())?;
    let when = finding
        .get("eventTime")
        .or_else(|| finding.get("createTime"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Some(format!("{}|{}", name, when))
}

#[allow(clippy::too_many_arguments)]
async fn flush_batch(
    transmitter: &Transmitter,
    cache: &FindingCache,
    batch: &mut Vec<UnifiedFlowRecord>,
    batch_ids: &mut Vec<String>,
    seen_in_batch: &mut HashSet<String>,
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

    if transmit_ok {
        // Commit dedup ids ONLY after the gateway accepted the batch.
        for id in batch_ids.drain(..) {
            cache.commit(&id);
        }
        seen_in_batch.clear();
        for msg in pending.drain(..) {
            if let Err(e) = msg.ack().await {
                tracing::warn!("Pub/Sub ack failed: {}", e);
            }
        }
    } else {
        // Do NOT commit; nack so Pub/Sub redelivers and we reprocess cleanly.
        batch_ids.clear();
        seen_in_batch.clear();
        for msg in pending.drain(..) {
            if let Err(e) = msg.nack().await {
                tracing::warn!("Pub/Sub nack failed: {}", e);
            }
        }
    }
}