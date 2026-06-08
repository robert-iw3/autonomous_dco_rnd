mod config;
mod cache;
mod checkpoint;
mod eventhubs_credential;
mod transformer;
mod transmitter;

use crate::config::Config;
use crate::cache::TemporalCache;
use crate::checkpoint::PartitionCheckpoint;
use crate::transformer::Transformer;
use crate::transmitter::Transmitter;

use std::collections::HashMap;
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
    let transmitter = Transmitter::new(config.clone());
    let checkpoint = Arc::new(PartitionCheckpoint::new(&config.spool_dir));

    let cache_clone = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(600)).await;
            cache_clone.remove_stale(3600);
        }
    });

    tracing::info!("Nexus Azure Activity Log connector online.");

    use azure_messaging_eventhubs::ConsumerClient;

    let eventhubs_credential = crate::eventhubs_credential::EventHubsCredentialChain::new()?;
    let consumer = Arc::new(
        ConsumerClient::builder()
            .with_consumer_group(config.consumer_group.clone())
            .open(&config.eventhub_namespace, config.eventhub_name.clone(), eventhubs_credential)
            .await?,
    );

    let partition_ids = consumer.get_eventhub_properties().await?.partition_ids;
    let mut handles = Vec::new();

    for partition_id in partition_ids {
        let consumer = Arc::clone(&consumer);
        let config = config.clone();
        let cache = Arc::clone(&cache);
        let transmitter = Transmitter::new(config.clone());
        let checkpoint = Arc::clone(&checkpoint);

        handles.push(tokio::spawn(async move {
            let transformer = Transformer::new((*cache).clone());
            let metadata = HashMap::new(); // Activity logs contain context inline

            // Resume just past the last confirmed-transmitted offset, if one
            // was persisted by a prior run -- otherwise fall back to the
            // Event Hub's default (latest) position.
            let receiver_options = checkpoint.load(&partition_id).map(|offset| {
                use azure_messaging_eventhubs::{OpenReceiverOptions, StartLocation, StartPosition};
                OpenReceiverOptions {
                    start_position: Some(StartPosition {
                        location: StartLocation::Offset(offset),
                        inclusive: false,
                    }),
                    ..Default::default()
                }
            });

            loop {
                match consumer.open_receiver_on_partition(partition_id.clone(), receiver_options.clone()).await {
                    Ok(receiver) => {
                        let mut batch = Vec::new();
                        let mut batch_start = Instant::now();
                        let mut pending_offset: Option<String> = None;

                        use futures::StreamExt;
                        let mut stream = receiver.stream_events();
                        while let Some(event_result) = stream.next().await {
                            if let Ok(event_data) = event_result {
                                pending_offset = event_data.offset().clone().or(pending_offset);
                                let body = event_data.event_data().body().unwrap_or_default();
                                let body_str = String::from_utf8_lossy(&body);

                                // Activity log events arrive as the records array or individual events
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_str) {
                                    let events = if let Some(records) = parsed.get("records").and_then(|r| r.as_array()) {
                                        records.clone()
                                    } else {
                                        vec![parsed]
                                    };

                                    for event in &events {
                                        if let Some(rec) = transformer.transform_event(event, &metadata) {
                                            batch.push(rec);
                                        }
                                    }
                                }
                            }

                            // Flush batch on size or time threshold
                            if batch.len() >= config.batch_size
                                || batch_start.elapsed() > Duration::from_secs(config.batch_timeout_secs)
                            {
                                if !batch.is_empty() {
                                    let records = std::mem::take(&mut batch);
                                    if transmitter.spool_and_transmit(records).await {
                                        if let Some(offset) = pending_offset.take() {
                                            checkpoint.save(&partition_id, &offset);
                                        }
                                    } else {
                                        tracing::error!("Batch transmit failed on partition {}", partition_id);
                                    }
                                }
                                batch_start = Instant::now();
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Partition {} receiver open error: {}. Retrying.", partition_id, e);
                        sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }));
    }

    futures::future::join_all(handles).await;
    Ok(())
}
