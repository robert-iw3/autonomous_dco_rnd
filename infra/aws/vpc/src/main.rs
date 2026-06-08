mod cache;
mod config;
mod transformer;
mod transmitter;

use crate::cache::{MetadataCache, TemporalCache};
use crate::config::Config;
use crate::transformer::Transformer;
use crate::transmitter::Transmitter;

use arrow::array::{Array, ArrayRef};
use aws_config::BehaviorVersion;
use futures::StreamExt;
use parquet::arrow::ParquetRecordBatchStreamBuilder;
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

    tracing::info!("Nexus AWS VPC Flow connector online.");

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

            // Download the Parquet object into memory.
            let s3_object = match s3_client.get_object().bucket(&bucket).key(&key).send().await {
                Ok(o) => o,
                Err(e) => {
                    tracing::error!("S3 download failed for {}/{}: {}", bucket, key, e);
                    continue;
                }
            };
            let data = match s3_object.body.collect().await {
                Ok(agg) => agg.into_bytes(),
                Err(e) => {
                    tracing::error!("S3 body read failed for {}/{}: {}", bucket, key, e);
                    continue;
                }
            };

            // Stream the Parquet row groups.
            let builder = match ParquetRecordBatchStreamBuilder::new(std::io::Cursor::new(data)).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("Parquet open failed for {}/{}: {}", bucket, key, e);
                    continue;
                }
            };
            let mut stream = match builder.build() {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Parquet stream build failed: {}", e);
                    continue;
                }
            };

            let mut normalized = Vec::new();
            // Per-file cache of vpc-id -> metadata so we hit DynamoDB once per VPC.
            let mut meta_by_vpc: HashMap<String, HashMap<String, String>> = HashMap::new();
            let empty: HashMap<String, String> = HashMap::new();

            while let Some(batch_result) = stream.next().await {
                let batch = match batch_result {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("Parquet batch read error: {}", e);
                        continue;
                    }
                };

                let rows = extract_rows_from_batch(&batch);
                for row in &rows {
                    let vpc = row.get("vpc-id").cloned().unwrap_or_default();
                    if !vpc.is_empty() && vpc != "-" && !meta_by_vpc.contains_key(&vpc) {
                        if let Some(cached) = metadata_cache.get(&vpc) {
                            meta_by_vpc.insert(vpc.clone(), cached);
                        } else {
                            let m = fetch_metadata(&ddb_client, &vpc).await;
                            metadata_cache.insert(vpc.clone(), m.clone());
                            meta_by_vpc.insert(vpc.clone(), m);
                        }
                    }
                    let meta = meta_by_vpc.get(&vpc).unwrap_or(&empty);
                    if let Some(rec) = transformer.transform_row(row, meta) {
                        normalized.push(rec);
                    }
                }
            }

            if normalized.is_empty() {
                // Parsed fine but nothing mappable (e.g. all NODATA rows): ack to
                // avoid an infinite redelivery loop.
                tracing::info!("No mappable rows in {}/{}; acking.", bucket, key);
                ack(&sqs_client, &config.sqs_queue_url, msg).await;
            } else if transmitter.spool_and_transmit(normalized).await {
                ack(&sqs_client, &config.sqs_queue_url, msg).await;
            }
            // On transmit failure: leave the message in the queue → SQS redelivers.
        }
    }
}

async fn ack(client: &aws_sdk_sqs::Client, queue_url: &str, msg: &aws_sdk_sqs::types::Message) {
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

/// Convert an Arrow RecordBatch to row maps, normalizing column names so the
/// transformer's hyphenated lookups match AWS's underscore Parquet columns.
fn extract_rows_from_batch(batch: &arrow::record_batch::RecordBatch) -> Vec<HashMap<String, String>> {
    use arrow::array::{Int64Array, StringArray};

    let schema = batch.schema();
    let num_rows = batch.num_rows();
    let mut rows = vec![HashMap::new(); num_rows];

    for (col_idx, field) in schema.fields().iter().enumerate() {
        // interface_id -> interface-id, "log status" -> log-status, etc.
        let name = field.name().replace(|c: char| c == '_' || c == ' ', "-");
        let column: &ArrayRef = batch.column(col_idx);

        if let Some(arr) = column.as_any().downcast_ref::<StringArray>() {
            for (r, row) in rows.iter_mut().enumerate() {
                if arr.is_valid(r) {
                    row.insert(name.clone(), arr.value(r).to_string());
                }
            }
        } else if let Some(arr) = column.as_any().downcast_ref::<Int64Array>() {
            for (r, row) in rows.iter_mut().enumerate() {
                if arr.is_valid(r) {
                    row.insert(name.clone(), arr.value(r).to_string());
                }
            }
        }
    }
    rows
}

/// Fetch identity/environment metadata for a VPC id from DynamoDB.
async fn fetch_metadata(
    client: &aws_sdk_dynamodb::Client,
    vpc_id: &str,
) -> HashMap<String, String> {
    use aws_sdk_dynamodb::types::AttributeValue;

    let mut meta = HashMap::new();
    match client
        .get_item()
        .table_name("nexus_cloud_identity_metadata")
        .key("vpc_id", AttributeValue::S(vpc_id.to_string()))
        .send()
        .await
    {
        Ok(res) => {
            if let Some(item) = res.item {
                for field in ["environment", "region", "owner_team"] {
                    if let Some(val) = item.get(field).and_then(|v| v.as_s().ok()) {
                        meta.insert(field.to_string(), val.clone());
                    }
                }
            }
        }
        Err(e) => tracing::warn!("DynamoDB GetItem failed for {}: {}", vpc_id, e),
    }
    meta
}