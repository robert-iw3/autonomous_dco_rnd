use crate::config::Config;
use crate::transformer::UnifiedFlowRecord;
use arrow::array::*;
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use hmac::{Hmac, Mac};
use parquet::arrow::ArrowWriter;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

type HmacSha256 = Hmac<Sha256>;

struct SequenceCounter {
    current: u64,
    path: PathBuf,
}

impl SequenceCounter {
    fn load(spool_dir: &Path) -> Self {
        let path = spool_dir.join(".transmit_sequence");
        let current = fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        Self { current, path }
    }

    fn next(&mut self) -> u64 {
        self.current += 1;
        let tmp = self.path.with_extension("tmp");
        if let Ok(mut f) = File::create(&tmp) {
            let _ = write!(f, "{}", self.current);
            let _ = fs::rename(&tmp, &self.path);
        }
        self.current
    }
}

pub struct Transmitter {
    config: Config,
    client: reqwest::Client,
    sequence: std::sync::Mutex<SequenceCounter>,
}

impl Transmitter {
    pub fn new(config: Config) -> Self {
        fs::create_dir_all(&config.spool_dir).ok();
        let sequence = SequenceCounter::load(&config.spool_dir);
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            sequence: std::sync::Mutex::new(sequence),
            config,
        }
    }

    fn compute_hmac(&self, payload: &[u8], sequence: u64, sensor_id: &str, timestamp: u64) -> String {
        let mut msg = Vec::with_capacity(payload.len() + 8 + sensor_id.len() + 8);
        msg.extend_from_slice(payload);
        msg.extend_from_slice(&sequence.to_be_bytes());
        msg.extend_from_slice(sensor_id.as_bytes());
        msg.extend_from_slice(&timestamp.to_be_bytes());

        let mut mac = HmacSha256::new_from_slice(self.config.integrity_secret.as_bytes())
            .expect("HMAC key init");
        mac.update(&msg);
        hex::encode(mac.finalize().into_bytes())
    }

    fn to_parquet(records: &[UnifiedFlowRecord]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("timestamp", DataType::Float64, false),
            Field::new("process_name", DataType::Utf8, false),
            Field::new("dst_ip", DataType::Utf8, false),
            Field::new("dst_port", DataType::Int32, false),
            Field::new("interval", DataType::Float64, false),
            Field::new("cv", DataType::Float64, false),
            Field::new("outbound_ratio", DataType::Float64, false),
            Field::new("entropy", DataType::Float64, false),
            Field::new("packet_size_mean", DataType::Float64, false),
            Field::new("packet_size_std", DataType::Float64, false),
            Field::new("packet_size_min", DataType::Int32, false),
            Field::new("packet_size_max", DataType::Int32, false),
            Field::new("packet_count", DataType::Int64, false),
            Field::new("mitre_tactic", DataType::Utf8, false),
            Field::new("cmd_entropy", DataType::Float64, false),
            Field::new("suppressed", DataType::Int32, false),
            Field::new("score", DataType::Int32, false),
            Field::new("cmd_snippet", DataType::Utf8, false),
            Field::new("process_tree", DataType::Utf8, false),
            Field::new("masquerade_detected", DataType::Int32, false),
            Field::new("reasons", DataType::Utf8, false),
            Field::new("mitre_technique", DataType::Utf8, false),
            Field::new("mitre_name", DataType::Utf8, false),
            Field::new("description", DataType::Utf8, false),
            Field::new("ml_result", DataType::Utf8, true),
            Field::new("process_hash", DataType::Utf8, false),
            Field::new("dns_query", DataType::Utf8, false),
            Field::new("event_type", DataType::Utf8, false),
            Field::new("dns_flags", DataType::Int32, false),
            Field::new("ja3_hash", DataType::Utf8, false),
            Field::new("sensor_id", DataType::Utf8, false),
        ]));

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Float64Array::from(records.iter().map(|r| r.timestamp).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.process_name.as_str()).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.dst_ip.as_str()).collect::<Vec<_>>())),
                Arc::new(Int32Array::from(records.iter().map(|r| r.dst_port).collect::<Vec<_>>())),
                Arc::new(Float64Array::from(records.iter().map(|r| r.interval).collect::<Vec<_>>())),
                Arc::new(Float64Array::from(records.iter().map(|r| r.cv).collect::<Vec<_>>())),
                Arc::new(Float64Array::from(records.iter().map(|r| r.outbound_ratio).collect::<Vec<_>>())),
                Arc::new(Float64Array::from(records.iter().map(|r| r.entropy).collect::<Vec<_>>())),
                Arc::new(Float64Array::from(records.iter().map(|r| r.packet_size_mean).collect::<Vec<_>>())),
                Arc::new(Float64Array::from(records.iter().map(|r| r.packet_size_std).collect::<Vec<_>>())),
                Arc::new(Int32Array::from(records.iter().map(|r| r.packet_size_min).collect::<Vec<_>>())),
                Arc::new(Int32Array::from(records.iter().map(|r| r.packet_size_max).collect::<Vec<_>>())),
                Arc::new(Int64Array::from(records.iter().map(|r| r.packet_count).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.mitre_tactic.as_str()).collect::<Vec<_>>())),
                Arc::new(Float64Array::from(records.iter().map(|r| r.cmd_entropy).collect::<Vec<_>>())),
                Arc::new(Int32Array::from(records.iter().map(|r| r.suppressed).collect::<Vec<_>>())),
                Arc::new(Int32Array::from(records.iter().map(|r| r.score).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.cmd_snippet.as_str()).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.process_tree.as_str()).collect::<Vec<_>>())),
                Arc::new(Int32Array::from(records.iter().map(|r| r.masquerade_detected).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.reasons.as_str()).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.mitre_technique.as_str()).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.mitre_name.as_str()).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.description.as_str()).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.ml_result.as_deref()).collect::<Vec<Option<&str>>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.process_hash.as_str()).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.dns_query.as_str()).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.event_type.as_str()).collect::<Vec<_>>())),
                Arc::new(Int32Array::from(records.iter().map(|r| r.dns_flags).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.ja3_hash.as_str()).collect::<Vec<_>>())),
                Arc::new(StringArray::from(records.iter().map(|r| r.sensor_id.as_str()).collect::<Vec<_>>())),
            ],
        )?;

        let mut buf = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut buf, schema, None)?;
        writer.write(&batch)?;
        writer.close()?;
        Ok(buf)
    }

    fn enforce_spool_bounds(&self) {
        let mut entries: Vec<(PathBuf, u64, SystemTime)> = match fs::read_dir(&self.config.spool_dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let p = e.path();
                    let name = p.file_name()?.to_string_lossy().to_string();
                    if name.starts_with("batch_") && name.ends_with(".parquet") {
                        let m = e.metadata().ok()?;
                        Some((p, m.len(), m.modified().ok()?))
                    } else {
                        None
                    }
                })
                .collect(),
            Err(_) => return,
        };

        entries.sort_by_key(|(_, _, mtime)| *mtime);

        let mut total_bytes: u64 = entries.iter().map(|(_, len, _)| *len).sum();
        let mut count = entries.len();

        for (path, len, _) in &entries {
            let over_files = count > self.config.max_spool_files;
            let over_bytes = total_bytes > self.config.max_spool_bytes;
            if !over_files && !over_bytes {
                break;
            }
            if fs::remove_file(path).is_ok() {
                total_bytes = total_bytes.saturating_sub(*len);
                count -= 1;
                tracing::warn!("Spool over budget; evicted oldest batch {:?} ({} bytes)", path, len);
            }
        }
    }

    pub async fn replay_spool(&self) {
        if !self.config.spool_replay {
            return;
        }
        let mut files: Vec<PathBuf> = match fs::read_dir(&self.config.spool_dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .map(|n| {
                            let n = n.to_string_lossy();
                            n.starts_with("batch_") && n.ends_with(".parquet")
                        })
                        .unwrap_or(false)
                })
                .collect(),
            Err(_) => return,
        };
        files.sort();

        for path in files {
            let Ok(bytes) = fs::read(&path) else { continue };
            tracing::info!("Replaying spooled batch {:?} ({} bytes)", path, bytes.len());
            if self.transmit_bytes(&bytes, Some(&path)).await {
                let _ = fs::remove_file(&path);
            } else {
                // Gateway still unhealthy; stop and let normal flow retry later.
                break;
            }
        }
    }

    pub async fn spool_and_transmit(&self, records: Vec<UnifiedFlowRecord>) -> bool {
        let parquet_bytes = match Self::to_parquet(&records) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("Parquet serialization failed: {}", e);
                return false;
            }
        };

        self.enforce_spool_bounds();

        // Spool to disk as crash-recovery guard (replayed only if spool_replay).
        let seq_for_name = { self.sequence.lock().unwrap().current + 1 };
        let file_path = self
            .config
            .spool_dir
            .join(format!("batch_{}.parquet", seq_for_name));
        if let Ok(mut f) = File::create(&file_path) {
            let _ = f.write_all(&parquet_bytes);
        }

        let ok = self.transmit_bytes(&parquet_bytes, Some(&file_path)).await;
        if ok {
            tracing::info!(
                "Transmitted batch ({} records, {} bytes parquet)",
                records.len(),
                parquet_bytes.len()
            );
        }
        ok
    }

    async fn transmit_bytes(&self, parquet_bytes: &[u8], spool_path: Option<&Path>) -> bool {
        let sequence = self.sequence.lock().unwrap().next();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let sensor_id = &self.config.sensor_id;
        let hmac_hex = self.compute_hmac(parquet_bytes, sequence, sensor_id, timestamp);

        let mut backoff = 1u64;
        let start = Instant::now();
        let deadline = Duration::from_secs(280);

        loop {
            if start.elapsed() > deadline {
                tracing::error!("Transmission deadline exceeded (seq={}). Retaining spool.", sequence);
                return false;
            }

            let result = self
                .client
                .post(&self.config.gateway_url)
                .header("Content-Type", "application/vnd.apache.parquet")
                .header("X-Batch-Sequence", sequence.to_string())
                .header("X-Batch-Timestamp", timestamp.to_string())
                .header("X-Sensor-Id", sensor_id.as_str())
                .header("X-Sensor-Type", self.config.sensor_type.as_str())
                .header("X-Batch-HMAC", &hmac_hex)
                .body(parquet_bytes.to_vec())
                .send()
                .await;

            match result {
                Ok(res) if res.status().is_success() => {
                    if let Some(p) = spool_path {
                        let _ = fs::remove_file(p);
                    }
                    return true;
                }
                Ok(res) if res.status().as_u16() == 403 => {
                    tracing::error!("[INTEGRITY] Gateway 403 for seq={}. Sensor may be banned.", sequence);
                    return false;
                }
                Ok(res) => {
                    tracing::warn!("Gateway rejected: HTTP {}. Retrying in {}s.", res.status(), backoff);
                }
                Err(e) => {
                    tracing::warn!("Gateway connection failed: {}. Retrying in {}s.", e, backoff);
                }
            }

            sleep(Duration::from_secs(backoff)).await;
            backoff = std::cmp::min(backoff * 2, self.config.max_backoff_sec);
        }
    }
}