mod cache;
mod config;
mod transformer;
mod transmitter;

use crate::cache::{MetadataCache, TemporalCache};
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
    let temporal_cache = Arc::new(TemporalCache::new());
    let metadata_cache = Arc::new(MetadataCache::new());
    let transformer = Transformer::new((*temporal_cache).clone());
    let transmitter = Transmitter::new(config.clone());

    let aws_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let sqs_client = aws_sdk_sqs::Client::new(&aws_config);
    let s3_client = aws_sdk_s3::Client::new(&aws_config);
    let ddb_client = aws_sdk_dynamodb::Client::new(&aws_config);

    let tc = Arc::clone(&temporal_cache);
    let mc = Arc::clone(&metadata_cache);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(600)).await;
            tc.remove_stale(3600);
            mc.remove_stale(3600);
        }
    });

    tracing::info!("Nexus AWS CloudTrail connector online.");

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

        let Some(messages) = out.messages() else { continue };

        for msg in messages {
            let Some(body) = msg.body() else { continue };
            let Some((bucket, key)) = parse_s3_notification(body) else { continue };

            let s3_object = match s3_client.get_object().bucket(&bucket).key(&key).send().await {
                Ok(o) => o,
                Err(e) => {
                    tracing::error!("S3 download failed for {}/{}: {}", bucket, key, e);
                    continue; // leave in queue
                }
            };

            let buf_reader = tokio::io::BufReader::new(s3_object.body.into_async_read());
            let mut decoder = GzipDecoder::new(buf_reader);
            let mut json_str = String::new();
            if let Err(e) = decoder.read_to_string(&mut json_str).await {
                tracing::error!("Gzip decompression failed: {}", e);
                continue;
            }

            let parsed = match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("JSON parse failed for {}/{}: {}", bucket, key, e);
                    continue;
                }
            };

            let Some(records) = parsed.get("Records").and_then(|r| r.as_array()) else {
                // Parsed but no Records array: nothing to do, ack to avoid a loop.
                delete_message(&sqs_client, &config.sqs_queue_url, msg).await;
                continue;
            };

            // Collect unique ARNs for batch metadata lookup.
            let arns: HashSet<String> = records.iter().filter_map(extract_arn).collect();

            let mut batch_meta: HashMap<String, HashMap<String, String>> = HashMap::new();
            let mut uncached: Vec<String> = Vec::new();
            for arn in &arns {
                if let Some(cached) = metadata_cache.get(arn) {
                    batch_meta.insert(arn.clone(), cached);
                } else {
                    uncached.push(arn.clone());
                }
            }
            for chunk in uncached.chunks(100) {
                let fetched = batch_fetch_metadata(&ddb_client, chunk).await;
                for (arn, meta) in fetched {
                    metadata_cache.insert(arn.clone(), meta.clone());
                    batch_meta.insert(arn, meta);
                }
            }

            let mut normalized = Vec::new();
            for record in records {
                let arn = extract_arn(record).unwrap_or_default();
                let meta = batch_meta.get(&arn).cloned().unwrap_or_default();
                if let Some(rec) = transformer.transform_record(record, &meta) {
                    normalized.push(rec);
                }
            }

            if !normalized.is_empty() {
                if transmitter.spool_and_transmit(normalized).await {
                    delete_message(&sqs_client, &config.sqs_queue_url, msg).await;
                }
                // On failure: leave in queue → SQS redelivers.
            } else {
                // Parsed fine but nothing mappable (e.g. events without
                // sourceIPAddress/eventName). Ack to avoid infinite redelivery.
                tracing::warn!(
                    "{} records in {}/{} produced no mappable rows; acking.",
                    records.len(), bucket, key
                );
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

fn extract_arn(record: &serde_json::Value) -> Option<String> {
    record.get("userIdentity")?.get("arn")?.as_str().map(|s| s.to_string())
}

/// Batch-fetch identity metadata from DynamoDB, handling builder errors and
/// UnprocessedKeys (throttled keys) with a bounded retry.
async fn batch_fetch_metadata(
    client: &aws_sdk_dynamodb::Client,
    arns: &[String],
) -> HashMap<String, HashMap<String, String>> {
    use aws_sdk_dynamodb::types::{AttributeValue, KeysAndAttributes};

    let mut results = HashMap::new();
    if arns.is_empty() {
        return results;
    }
    const TABLE: &str = "nexus_cloud_identity_metadata";

    let keys: Vec<HashMap<String, AttributeValue>> = arns
        .iter()
        .map(|arn| HashMap::from([("iam_arn".to_string(), AttributeValue::S(arn.clone()))]))
        .collect();

    let kaa = match KeysAndAttributes::builder().set_keys(Some(keys)).build() {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("KeysAndAttributes build failed: {}", e);
            return results;
        }
    };

    let mut request: Option<HashMap<String, KeysAndAttributes>> =
        Some(HashMap::from([(TABLE.to_string(), kaa)]));
    let mut attempts = 0u32;

    while let Some(req) = request.take() {
        attempts += 1;
        match client.batch_get_item().set_request_items(Some(req)).send().await {
            Ok(res) => {
                if let Some(items_by_table) = res.responses.as_ref() {
                    if let Some(items) = items_by_table.get(TABLE) {
                        for item in items {
                            let arn = item
                                .get("iam_arn")
                                .and_then(|v| v.as_s().ok())
                                .cloned()
                                .unwrap_or_default();
                            if arn.is_empty() {
                                continue;
                            }
                            let mut meta = HashMap::new();
                            for field in ["environment", "owner_team", "privilege_level"] {
                                if let Some(val) = item.get(field).and_then(|v| v.as_s().ok()) {
                                    meta.insert(field.to_string(), val.clone());
                                }
                            }
                            results.insert(arn, meta);
                        }
                    }
                }
                // Retry whatever DynamoDB throttled, up to a bound.
                if attempts < 5 {
                    if let Some(unproc) = res.unprocessed_keys.clone() {
                        if !unproc.is_empty() {
                            sleep(Duration::from_millis(100 * attempts as u64)).await;
                            request = Some(unproc);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("DynamoDB BatchGetItem failed: {}", e);
                break;
            }
        }
    }

    results
}