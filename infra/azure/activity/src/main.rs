mod config;
mod cache;
mod transformer;
mod transmitter;

use crate::config::Config;
use crate::cache::TemporalCache;
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

    let cache_clone = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(600)).await;
            cache_clone.remove_stale(3600);
        }
    });

    tracing::info!("Nexus Azure Activity Log connector online.");

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
        let transmitter = Transmitter::new(config.clone());

        handles.push(tokio::spawn(async move {
            let transformer = Transformer::new((*cache).clone());
            let metadata = HashMap::new(); // Activity logs contain context inline

            loop {
                match consumer.read_events_from_partition(&partition_id, Default::default()).await {
                    Ok(mut stream) => {
                        let mut batch = Vec::new();
                        let mut batch_start = Instant::now();

                        use futures::StreamExt;
                        while let Some(event_result) = stream.next().await {
                            if let Ok(event_data) = event_result {
                                let body = event_data.body().unwrap_or_default();
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
                                    if !transmitter.spool_and_transmit(records).await {
                                        tracing::error!("Batch transmit failed on partition {}", partition_id);
                                    }
                                }
                                batch_start = Instant::now();
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
