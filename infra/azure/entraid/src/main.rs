// =====================================================================
// NOTE   : Event Hub checkpointing is still NOT implemented -- on restart the
//          consumer re-reads from the default position. A BlobCheckpointStore
//          advanced only after a confirmed transmit is the next step; it
//          depends on the pinned azure_messaging_eventhubs API and is left as
//          a TODO rather than guessed at here.
// =====================================================================
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    let cache = Arc::new(TemporalCache::new());
    let transmitter = Arc::new(Transmitter::new(config.clone())); // shared

    let cache_clone = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(600)).await;
            cache_clone.remove_stale(3600);
        }
    });

    tracing::info!("Nexus Azure Entra ID connector online.");

    use azure_messaging_eventhubs::consumer::ConsumerClient;
    let consumer = ConsumerClient::new(
        config.eventhub_connection_str.clone(),
        config.eventhub_name.clone(),
        config.consumer_group.clone(),
        Default::default(),
    )?;

    let partition_ids = consumer.get_partition_ids().await?;
    let mut handles = Vec::new();

    for partition_id in partition_ids {
        let consumer = consumer.clone();
        let config = config.clone();
        let cache = Arc::clone(&cache);
        let transmitter = Arc::clone(&transmitter);

        handles.push(tokio::spawn(async move {
            let transformer = Transformer::new((*cache).clone());
            let window = Duration::from_secs(config.batch_timeout_secs);

            loop {
                match consumer.read_events_from_partition(&partition_id, Default::default()).await {
                    Ok(mut stream) => {
                        use futures::StreamExt;
                        let mut batch: Vec<UnifiedFlowRecord> = Vec::new();
                        let mut batch_start = Instant::now();

                        loop {
                            let remaining = window
                                .saturating_sub(batch_start.elapsed())
                                .max(Duration::from_millis(50));

                            match tokio::time::timeout(remaining, stream.next()).await {
                                Ok(Some(Ok(event_data))) => {
                                    let body = event_data.body().unwrap_or_default();
                                    let body_str = String::from_utf8_lossy(&body);
                                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_str) {
                                        let events = parsed
                                            .get("records")
                                            .and_then(|r| r.as_array())
                                            .cloned()
                                            .unwrap_or_else(|| vec![parsed.clone()]);
                                        for event in &events {
                                            if let Some(rec) = transformer.transform_event(event) {
                                                batch.push(rec);
                                            }
                                        }
                                    }
                                    if batch.len() >= config.batch_size {
                                        flush(&transmitter, &mut batch, &partition_id).await;
                                        batch_start = Instant::now();
                                    }
                                }
                                Ok(Some(Err(e))) => {
                                    tracing::warn!("Partition {} event error: {}", partition_id, e);
                                }
                                Ok(None) => {
                                    // Stream ended: flush remainder, then reconnect.
                                    flush(&transmitter, &mut batch, &partition_id).await;
                                    break;
                                }
                                Err(_) => {
                                    // Idle window elapsed: flush whatever we have.
                                    flush(&transmitter, &mut batch, &partition_id).await;
                                    batch_start = Instant::now();
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Partition {} read error: {}. Retrying.", partition_id, e);
                        sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }));
    }

    futures::future::join_all(handles).await;
    Ok(())
}

async fn flush(transmitter: &Transmitter, batch: &mut Vec<UnifiedFlowRecord>, partition_id: &str) {
    if batch.is_empty() {
        return;
    }
    let records = std::mem::take(batch);
    if !transmitter.spool_and_transmit(records).await {
        tracing::error!("Batch transmit failed on partition {}", partition_id);
    }
}