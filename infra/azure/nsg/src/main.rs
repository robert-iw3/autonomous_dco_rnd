mod cache;
mod config;
mod transformer;
mod transmitter;

use crate::cache::{MetadataCache, TemporalCache};
use crate::config::Config;
use crate::transformer::Transformer;
use crate::transmitter::Transmitter;

use azure_identity::DefaultAzureCredential;
use azure_storage_blobs::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    let temporal_cache = Arc::new(TemporalCache::new());
    let metadata_cache = Arc::new(MetadataCache::new());
    // ONE transmitter shared across all partitions (single sequence + spool).
    let transmitter = Arc::new(Transmitter::new(config.clone()));

    let credential = Arc::new(DefaultAzureCredential::new()?);
    let blob_client = BlobServiceClient::new(&config.storage_account_url, credential.clone());

    let tc = Arc::clone(&temporal_cache);
    let mc = Arc::clone(&metadata_cache);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(600)).await;
            tc.remove_stale(3600);
            mc.remove_stale(3600);
        }
    });

    tracing::info!("Nexus Azure NSG Flow connector online.");

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
        let blob_client = blob_client.clone();
        let transformer = Transformer::new((*temporal_cache).clone());
        let transmitter = Arc::clone(&transmitter);
        let metadata_cache = Arc::clone(&metadata_cache);

        handles.push(tokio::spawn(async move {
            loop {
                match consumer.read_events_from_partition(&partition_id, Default::default()).await {
                    Ok(mut stream) => {
                        use futures::StreamExt;
                        while let Some(event_result) = stream.next().await {
                            if let Ok(event_data) = event_result {
                                let body = event_data.body().unwrap_or_default();
                                let body_str = String::from_utf8_lossy(&body);

                                if let Some(blob_path) = extract_blob_path(&body_str) {
                                    tracing::info!("Processing blob: {}", blob_path);
                                    match fetch_and_parse_blob(
                                        &blob_client, &config.storage_container, &blob_path,
                                    )
                                    .await
                                    {
                                        Ok(blob_json) => {
                                            let metadata =
                                                fetch_nsg_metadata(&blob_path, &metadata_cache).await;
                                            let records =
                                                transformer.transform_blob(&blob_json, &metadata);
                                            if !records.is_empty()
                                                && !transmitter.spool_and_transmit(records).await
                                            {
                                                tracing::error!("Transmit failed for {}", blob_path);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!("Blob fetch failed for {}: {}", blob_path, e)
                                        }
                                    }
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

fn extract_blob_path(event_grid_json: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(event_grid_json).ok()?;
    let subject = parsed.get("subject")?.as_str()?;
    let marker = "/blobs/";
    let idx = subject.find(marker)?;
    Some(subject[idx + marker.len()..].to_string())
}

async fn fetch_and_parse_blob(
    client: &BlobServiceClient,
    container: &str,
    blob_path: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let container_client = client.container_client(container);
    let blob_client = container_client.blob_client(blob_path);
    let response = blob_client.get_content().await?;
    let parsed = serde_json::from_slice(&response)?;
    Ok(parsed)
}

/// Extract subscription / resource-group / NSG from the NSG flow-log path.
/// Real paths split on '/' into segments like:
///   ["resourceId=", "SUBSCRIPTIONS", "{sub}", "RESOURCEGROUPS", "{rg}",
///    "PROVIDERS", "MICROSOFT.NETWORK", "NETWORKSECURITYGROUPS", "{nsg}", ...]
async fn fetch_nsg_metadata(blob_path: &str, cache: &MetadataCache) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    let segs: Vec<&str> = blob_path.split('/').collect();

    let find_after = |label: &str| -> Option<String> {
        segs.iter()
            .position(|s| s.eq_ignore_ascii_case(label))
            .and_then(|i| segs.get(i + 1))
            .map(|s| s.to_string())
    };

    if let Some(sub) = find_after("SUBSCRIPTIONS") {
        metadata.insert("subscription_id".to_string(), sub);
    }
    if let Some(rg) = find_after("RESOURCEGROUPS") {
        metadata.insert("resource_group".to_string(), rg);
    }
    if let Some(nsg) = find_after("NETWORKSECURITYGROUPS") {
        metadata.insert("nsg_name".to_string(), nsg);
    }

    // Hydrate environment/region from the cache if a prior lookup populated it.
    // (Table Storage hydration via config.table_storage_url is still a TODO.)
    if let Some(sub) = metadata.get("subscription_id").cloned() {
        if let Some(cached) = cache.get(&sub) {
            for (k, v) in cached {
                metadata.entry(k).or_insert(v);
            }
        }
    }
    metadata.entry("environment".to_string()).or_insert_with(|| "unknown".to_string());
    metadata.entry("region".to_string()).or_insert_with(|| "unknown".to_string());
    metadata
}