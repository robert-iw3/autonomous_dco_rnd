mod cache;
mod config;
mod transformer;
mod transmitter;

use crate::cache::FindingCache;
use crate::config::Config;
use crate::transformer::Transformer;
use crate::transmitter::Transmitter;

use async_compression::tokio::bufread::GzipDecoder;
use aws_config::BehaviorVersion;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::time::{sleep, Duration};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    let cache = Arc::new(FindingCache::new());
    let transformer = Transformer::new();
    let transmitter = Transmitter::new(config.clone());

    let aws_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let sqs_client = aws_sdk_sqs::Client::new(&aws_config);
    let s3_client = aws_sdk_s3::Client::new(&aws_config);

    // GuardDuty findings can stay active for weeks; dedup on (id, updatedAt)
    // means a re-export of the SAME state is suppressed while an update passes.
    // A 7-day TTL bounds the cache without prematurely re-ingesting stale state.
    let cache_clone = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(3600)).await;
            cache_clone.remove_stale(7 * 86400);
        }
    });

    tracing::info!("Nexus AWS GuardDuty connector online.");

    loop {
        let out = match sqs_client
            .receive_message()
            .queue_url(&config.sqs_queue_url)
            .max_number_of_messages(10)
            .wait_time_seconds(20)
            .send()
            .await
        {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("SQS poll failed: {}. Retrying.", e);
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let messages = out.messages();

        for msg in messages {
            let Some(body) = msg.body() else { continue };
            let Some((bucket, key)) = parse_s3_notification(body) else { continue };

            let s3_object = match s3_client.get_object().bucket(&bucket).key(&key).send().await {
                Ok(o) => o,
                Err(e) => {
                    tracing::error!("S3 download failed for {}/{}: {}", bucket, key, e);
                    continue; // leave message in queue
                }
            };

            // Stream gzip -> string.
            let buf_reader = tokio::io::BufReader::new(s3_object.body.into_async_read());
            let mut decoder = GzipDecoder::new(buf_reader);
            let mut text = String::new();
            if let Err(e) = decoder.read_to_string(&mut text).await {
                tracing::error!("Gzip decompression failed for {}/{}: {}", bucket, key, e);
                continue;
            }

            // GuardDuty S3 export is JSON Lines: one finding per line.
            let mut normalized = Vec::new();
            let mut batch_ids: Vec<String> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            let mut total = 0u64;
            let mut parse_errors = 0u64;

            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                total += 1;

                let finding = match serde_json::from_str::<serde_json::Value>(line) {
                    Ok(v) => v,
                    Err(e) => {
                        parse_errors += 1;
                        tracing::warn!("Finding parse error in {}/{}: {}", bucket, key, e);
                        continue;
                    }
                };

                let id = finding_dedup_key(&finding);
                if let Some(ref k) = id {
                    // Skip only findings COMMITTED in a prior batch, or already
                    // present in THIS batch.
                    if cache.contains(k) || seen.contains(k) {
                        continue;
                    }
                }

                // GuardDuty findings carry accountId/region inline (unlike VPC
                // Flow / CloudTrail, which need a DynamoDB lookup to resolve
                // `environment` from an external identity table) -- there is
                // no metadata-cache plumbing in this connector, so
                // transform_finding() always sees an empty map and falls back
                // to environment="unknown" (transformer.rs's documented default).
                let empty_metadata: HashMap<String, String> = HashMap::new();
                if let Some(rec) = transformer.transform_finding(&finding, &empty_metadata) {
                    normalized.push(rec);
                    if let Some(k) = id {
                        seen.insert(k.clone());
                        batch_ids.push(k);
                    }
                }
            }

            if !normalized.is_empty() {
                if transmitter.spool_and_transmit(normalized).await {
                    // Commit dedup ids ONLY after the gateway accepted the batch.
                    for k in &batch_ids {
                        cache.commit(k);
                    }
                    delete_message(&sqs_client, &config.sqs_queue_url, msg).await;
                }
                // On failure: commit nothing, leave the message in the queue.
                // Redelivery sees contains()==false and reprocesses + resends.
            } else if total > 0 && parse_errors == total {
                // Whole object was unparseable: leave it for the SQS DLQ rather
                // than acking poison.
                tracing::error!(
                    "All {} findings failed to parse in {}/{}; leaving for DLQ.",
                    total, bucket, key
                );
            } else {
                // Empty, or everything was an already-committed duplicate: safe
                // to ack (nothing new to send).
                delete_message(&sqs_client, &config.sqs_queue_url, msg).await;
            }
        }
    }
}

async fn delete_message(client: &aws_sdk_sqs::Client, queue_url: &str, msg: &aws_sdk_sqs::types::Message) {
    if let Some(handle) = msg.receipt_handle() {
        let _ = client
            .delete_message()
            .queue_url(queue_url)
            .receipt_handle(handle)
            .send()
            .await;
    }
}

fn parse_s3_notification(body: &str) -> Option<(String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    let record = parsed.get("Records")?.get(0)?;
    let bucket = record.get("s3")?.get("bucket")?.get("name")?.as_str()?.to_string();
    let key = record.get("s3")?.get("object")?.get("key")?.as_str()?.to_string();
    Some((bucket, key))
}

/// Dedup on finding id + last-update time so an UPDATED finding re-ingests
/// while an identical re-export is suppressed.
fn finding_dedup_key(finding: &serde_json::Value) -> Option<String> {
    let id = finding.get("id").and_then(|v| v.as_str())?;
    let updated = finding
        .get("updatedAt")
        .or_else(|| finding.get("UpdatedAt"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Some(format!("{}|{}", id, updated))
}