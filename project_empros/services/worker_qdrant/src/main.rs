use async_trait::async_trait;
use bytes::Bytes;
use lib_siem_core::{start_durable_worker, SiemAdapter, WorkerConfig};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use qdrant_client::Qdrant;
use qdrant_client::qdrant::{
    NamedVectors, PointStruct, UpsertPointsBuilder, Vector, Vectors,
    point_id::PointIdOptions,
    vectors::VectorsOptions as VectorsEnum,
};
use serde::Deserialize;
use std::{collections::HashMap, fs, time::Duration};
use tracing::{error, info, warn, Level};
use arrow::array::AsArray;
use arrow::datatypes::DataType;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Deserialize, Clone)]
struct SchemaMapping {
    identifier_column: String,
    vector_name: String,
    primary_key_column: String,
    timestamp_column: String,
    sensor_id_column: String,
    vector_columns: Vec<String>,
    context_columns: Vec<String>,
}

#[derive(Deserialize, Clone)]
struct SchemaMappings {
    linux_c2: SchemaMapping,
    windows_c2: SchemaMapping,
    linux_sentinel: SchemaMapping,
    macos_sensor: SchemaMapping,
    sysmon_sensor: SchemaMapping,
    windows_deepsensor: SchemaMapping,
    trellix_ens: SchemaMapping,
    cloud_flow: SchemaMapping,
    network_tap: SchemaMapping,
    suricata_eve: SchemaMapping,
    // Cloud sub-types: gcp_audit, gcp_scc, gcp_vpc_flow, vmware_syslog all share
    // the cloud_flow vector space and route through the cloud_flow mapping.
    // They are defined in nexus.toml for TOML deserialization completeness but
    // duck-typed into the cloud_flow bucket based on the packet_count column heuristic.
    gcp_audit: SchemaMapping,
    gcp_scc: SchemaMapping,
    gcp_vpc_flow: SchemaMapping,
    vmware_syslog: SchemaMapping,
}

#[derive(Deserialize)]
struct Config {
    global: Global,
    qdrant: QdrantConf,
    schema_mappings: SchemaMappings,
}

#[derive(Deserialize)]
struct Global {
    nats_url: String,
    telemetry_stream: String,
    telemetry_subject: String,
    dlq_subject_prefix: String,
}

#[derive(Deserialize)]
struct QdrantConf {
    grpc_url: String,
    collection_name: String,
    batch_size: usize,
}

// -- Type-aware column-to-string helper ---------------------------------------
// Sensors emit timestamps as i64/f64 and event IDs as i32/i64; the worker
// uses these for payload metadata (not vector math), so we convert to String
// rather than panic on a StringArray downcast.
fn col_as_string(arr: &dyn arrow::array::Array, row: usize) -> String {
    if !arr.is_valid(row) {
        return String::new();
    }
    match arr.data_type() {
        DataType::Utf8     => arr.as_string::<i32>().value(row).to_string(),
        DataType::LargeUtf8 => arr.as_string::<i64>().value(row).to_string(),
        DataType::Int32    => arr.as_primitive::<arrow::datatypes::Int32Type>().value(row).to_string(),
        DataType::Int64    => arr.as_primitive::<arrow::datatypes::Int64Type>().value(row).to_string(),
        DataType::UInt32   => arr.as_primitive::<arrow::datatypes::UInt32Type>().value(row).to_string(),
        DataType::UInt64   => arr.as_primitive::<arrow::datatypes::UInt64Type>().value(row).to_string(),
        DataType::Float32  => arr.as_primitive::<arrow::datatypes::Float32Type>().value(row).to_string(),
        DataType::Float64  => arr.as_primitive::<arrow::datatypes::Float64Type>().value(row).to_string(),
        _                  => String::new(),
    }
}

struct QdrantAdapter {
    client: Qdrant,
    nats: async_nats::Client,
    collection: String,
    batch_size: usize,
    mappings: SchemaMappings,
}

#[async_trait]
impl SiemAdapter for QdrantAdapter {
    fn initialize(config_path: &str, nats_client: Option<async_nats::Client>) -> Self {
        let nats = nats_client.expect("CRITICAL: Qdrant worker requires a NATS client for tripwires");

        let config_raw = fs::read_to_string(config_path)
            .unwrap_or_else(|_| panic!("CRITICAL: Configuration file not found at {}", config_path));

        let conf: Config = toml::from_str(&config_raw)
            .expect("CRITICAL: Malformed TOML configuration");

        let client = Qdrant::from_url(&conf.qdrant.grpc_url)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .keep_alive_while_idle()
            .build()
            .unwrap_or_else(|e| panic!("CRITICAL: Failed to construct Qdrant client: {}", e));

        info!(
            "Qdrant Client initialized targeting {} | Collection: {}",
            conf.qdrant.grpc_url, conf.qdrant.collection_name
        );

        QdrantAdapter {
            client,
            nats,
            collection: conf.qdrant.collection_name,
            batch_size: conf.qdrant.batch_size,
            mappings: conf.schema_mappings,
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    async fn transmit_batch(
        &self,
        raw_payloads: &[Bytes],
        _nats_headers: &[Option<async_nats::HeaderMap>],
    ) -> Result<(), String> {
        if raw_payloads.is_empty() { return Ok(()); }
        let mut points = Vec::with_capacity(raw_payloads.len() * 100);

        for payload_bytes in raw_payloads {
            let payload_bytes = payload_bytes.clone();
            // -- 1. NATIVE IN-MEMORY PARQUET DECOMPRESSION --
            let builder = match ParquetRecordBatchReaderBuilder::try_new(payload_bytes) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Dropped corrupted Parquet buffer: {}", e);
                    continue;
                }
            };

            let schema = builder.schema().clone();
            let mut col_indices = std::collections::HashMap::with_capacity(schema.fields().len());
            for (i, field) in schema.fields().iter().enumerate() {
                col_indices.insert(field.name().to_string(), i);
            }

            // -- 2. DUCK-TYPING ROUTING --
            // Order is most-specific → least-specific. sysmon_sensor must precede
            // windows_c2 because sysmon records carry both "sysmon_event_id" AND
            // "Image"; checking windows_c2 ("Image") first would misclassify them.
            let has_col = |name: &str| col_indices.contains_key(name);

            let (active_mapping, active_source_type) = if has_col("session_id") && has_col("tls_ja3") && has_col("byte_ratio") {
                (&self.mappings.network_tap, "network_tap")
            } else if has_col("event_type") && has_col("sensor_id") && has_col("packet_count") && !has_col("comm") {
                // All cloud/VMware sub-types share the cloud_flow schema:
                //   gcp_audit, gcp_scc, gcp_vpc_flow, vmware_syslog, cloud_flow generic.
                // Their structs are deserialized from nexus.toml but all route here.
                (&self.mappings.cloud_flow, "cloud_flow")
            } else if has_col(&self.mappings.suricata_eve.identifier_column) && has_col("signature_id") {
                // community_id + signature_id is unique to Suricata EVE JSON -- IDS alerts
                // route to net_expert and store in c2_math space like C2 flows.
                (&self.mappings.suricata_eve, "suricata_eve")
            } else if has_col("outbound_ratio") && has_col("comm") {
                (&self.mappings.linux_c2, "linux_c2")
            } else if has_col(&self.mappings.trellix_ens.identifier_column) {
                // detection_name is unique to Trellix ENS endpoint telemetry.
                (&self.mappings.trellix_ens, "trellix_ens")
            } else if has_col(&self.mappings.sysmon_sensor.identifier_column) {
                // sysmon_event_id is unique to Sysmon -- checked before windows_c2
                // because sysmon records also carry "Image" (windows_c2 identifier).
                (&self.mappings.sysmon_sensor, "sysmon_sensor")
            } else if has_col(&self.mappings.windows_c2.identifier_column) {
                (&self.mappings.windows_c2, "windows_c2")
            } else if has_col(&self.mappings.linux_sentinel.identifier_column) {
                (&self.mappings.linux_sentinel, "linux_sentinel")
            } else if has_col(&self.mappings.macos_sensor.identifier_column) {
                // plist_path is unique to macOS persistence telemetry.
                (&self.mappings.macos_sensor, "macos_sensor")
            } else if has_col(&self.mappings.windows_deepsensor.identifier_column) {
                (&self.mappings.windows_deepsensor, "windows_deepsensor")
            } else {
                continue;
            };

            let active_vector_name = active_mapping.vector_name.clone();
            let pk_idx = *col_indices.get(&active_mapping.primary_key_column).unwrap_or(&0);
            let ts_idx = *col_indices.get(&active_mapping.timestamp_column).unwrap_or(&0);
            let sensor_idx = *col_indices.get(&active_mapping.sensor_id_column).unwrap_or(&0);

            let mut reader = match builder.build() {
                Ok(r) => r,
                Err(e) => { warn!("Failed to build Arrow reader: {}", e); continue; }
            };

            // -- 3. COLUMNAR BATCH ITERATION --
            while let Some(batch_result) = reader.next() {
                let batch = match batch_result {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                let num_rows = batch.num_rows();
                if num_rows == 0 { continue; }

                let pk_col    = batch.column(pk_idx);
                let ts_col    = batch.column(ts_idx);
                let sensor_col = batch.column(sensor_idx);

                let mut math_col_indices = Vec::with_capacity(active_mapping.vector_columns.len());
                for col in &active_mapping.vector_columns {
                    math_col_indices.push(col_indices.get(col).copied());
                }

                for row_idx in 0..num_rows {
                    let raw_id = col_as_string(pk_col.as_ref(), row_idx);
                    let extracted_id = if raw_id.is_empty() {
                        uuid::Uuid::new_v4().to_string()
                    } else {
                        raw_id
                    };
                    let extracted_timestamp = col_as_string(ts_col.as_ref(), row_idx);
                    let extracted_sensor    = col_as_string(sensor_col.as_ref(), row_idx);

                    // -- 4. DYNAMIC MATH EXTRACTION --
                    let mut raw_math: Vec<f32> = Vec::with_capacity(active_mapping.vector_columns.len());
                    for col in &active_mapping.vector_columns {
                        if let Some(&idx) = col_indices.get(col) {
                            let column = batch.column(idx);

                            let val = if column.is_valid(row_idx) {
                                match column.data_type() {
                                    DataType::Float32 => column.as_primitive::<arrow::datatypes::Float32Type>().value(row_idx),
                                    DataType::Float64 => column.as_primitive::<arrow::datatypes::Float64Type>().value(row_idx) as f32,
                                    DataType::Int32 => column.as_primitive::<arrow::datatypes::Int32Type>().value(row_idx) as f32,
                                    DataType::Int64 => column.as_primitive::<arrow::datatypes::Int64Type>().value(row_idx) as f32,
                                    _ => 0.0,
                                }
                            } else {
                                0.0
                            };
                            raw_math.push(val);
                        } else {
                            raw_math.push(0.0);
                        }
                    }

                    // -- 5. LAYER 1: IN-FLIGHT NORMALIZATION --
                    let normalized_math = if active_vector_name == "c2_math" && raw_math.len() == 8 {
                        vec![
                            raw_math[0].clamp(0.0, 1.0),
                            (raw_math[1] / 1500.0).clamp(0.0, 1.0),
                            (raw_math[2] / 500.0).clamp(0.0, 1.0),
                            1.0 / (1.0 + (raw_math[3] + 1.0).log10()),
                            (raw_math[4] / 2.0).clamp(0.0, 1.0),
                            (raw_math[5] / 8.0).clamp(0.0, 1.0),
                            (raw_math[6] / 8.0).clamp(0.0, 1.0),
                            raw_math[7].clamp(0.0, 1.0),
                        ]
                    } else if active_vector_name == "sentinel_math" && raw_math.len() == 5 {
                        vec![
                            (raw_math[0] / 8.0).clamp(0.0, 1.0),
                            (raw_math[1] / 1000.0).clamp(0.0, 1.0),
                            raw_math[2].clamp(0.0, 1.0),
                            (raw_math[3] / 10.0).clamp(0.0, 1.0),
                            raw_math[4].clamp(0.0, 1.0),
                        ]
                    } else if active_source_type == "sysmon_sensor" && raw_math.len() == 6 {
                        // sysmon_sensor windows_math (6D) -- all inputs pre-normalised [0,1] in schema.py:
                        //   [0] command_entropy    -- already in [0,1]
                        //   [1] parent_child_score -- already in [0,1]
                        //   [2] integrity_score    -- already in [0,1]
                        //   [3] anomaly_score      -- already in [0,1]
                        //   [4] grant_access_score -- GrantedAccess/0x1FFFFF (EventID 10)
                        //   [5] driver_trust_score -- signature validity inverted (EventID 6/7)
                        vec![
                            raw_math[0].clamp(0.0, 1.0),
                            raw_math[1].clamp(0.0, 1.0),
                            raw_math[2].clamp(0.0, 1.0),
                            raw_math[3].clamp(0.0, 1.0),
                            raw_math[4].clamp(0.0, 1.0),
                            raw_math[5].clamp(0.0, 1.0),
                        ]
                    } else if active_source_type == "macos_sensor" && raw_math.len() == 6 {
                        // macos_sensor windows_math (6D) -- same field layout as sysmon_sensor:
                        //   [0] command_entropy  [1] parent_child_score  [2] integrity_score
                        //   [3] anomaly_score    [4] grant_access_score  [5] driver_trust_score
                        vec![
                            raw_math[0].clamp(0.0, 1.0),
                            raw_math[1].clamp(0.0, 1.0),
                            raw_math[2].clamp(0.0, 1.0),
                            raw_math[3].clamp(0.0, 1.0),
                            raw_math[4].clamp(0.0, 1.0),
                            raw_math[5].clamp(0.0, 1.0),
                        ]
                    } else if active_source_type == "macos_sensor" && raw_math.len() == 4 {
                        // Legacy 4D placeholder -- pad grant_access_score and driver_trust_score
                        // to 0.0 until the macOS sensor emits the full 6D windows_math vector.
                        vec![
                            raw_math[0].clamp(0.0, 1.0),
                            raw_math[1].clamp(0.0, 1.0),
                            raw_math[2].clamp(0.0, 1.0),
                            raw_math[3].clamp(0.0, 1.0),
                            0.0, // grant_access_score -- not yet emitted by macOS sensor
                            0.0, // driver_trust_score -- not yet emitted by macOS sensor
                        ]
                    } else if active_vector_name == "deepsensor_math" && raw_math.len() == 4 {
                        // windows_deepsensor EdrRow deepsensor_math (4D):
                        //   [0] score          -- raw 0–10, scale /100
                        //   [1] avg_entropy    -- raw 0–8, scale /8
                        //   [2] max_velocity   -- raw 0–5000, scale /5000
                        //   [3] event_count    -- raw 0–100, scale /100
                        vec![
                            (raw_math[0] / 100.0).clamp(0.0, 1.0),
                            (raw_math[1] / 8.0).clamp(0.0, 1.0),
                            (raw_math[2] / 5000.0).clamp(0.0, 1.0),
                            (raw_math[3] / 100.0).clamp(0.0, 1.0),
                        ]
                    } else if active_vector_name == "trellix_math" && raw_math.len() == 6 {
                        // trellix_ens 6D -- all pre-normalised [0,1] by TrellixUEBAEngine:
                        //   [0] severity_score  -- ThreatSeverity 1-5 → [0.2, 1.0]
                        //   [1] threat_score    -- malicious=1.0 suspicious=0.7 pua=0.4 clean=0.0
                        //   [2] action_score    -- blocked=1.0 quarantined=0.75 cleaned=0.5 detected=0.25
                        //   [3] anomaly_score   -- IsolationForest UEBA
                        //   [4] entropy_score   -- Shannon entropy of FilePath+ProcessName
                        //   [5] frequency_score -- inverse ThreatName+ThreatType novelty
                        vec![
                            raw_math[0].clamp(0.0, 1.0),
                            raw_math[1].clamp(0.0, 1.0),
                            raw_math[2].clamp(0.0, 1.0),
                            raw_math[3].clamp(0.0, 1.0),
                            raw_math[4].clamp(0.0, 1.0),
                            raw_math[5].clamp(0.0, 1.0),
                        ]
                    } else if active_vector_name == "cloud_flow" && raw_math.len() == 5 {
                        vec![
                            1.0 / (1.0 + (raw_math[0] + 1.0).log10()),
                            raw_math[1].clamp(0.0, 1.0),
                            raw_math[2].clamp(0.0, 1.0),
                            (raw_math[3] / 1500.0).clamp(0.0, 1.0),
                            (raw_math[4] / 100.0).clamp(0.0, 1.0),
                        ]
                    } else if active_vector_name == "network_tap" && raw_math.len() == 8 {
                        vec![
                            raw_math[0].clamp(0.0, 1.0),
                            1.0 / (1.0 + (raw_math[1] + 1.0).log10()),
                            1.0 / (1.0 + (raw_math[2] + 1.0).log10()),
                            raw_math[3].clamp(0.0, 1.0),
                            raw_math[4].clamp(0.0, 1.0),
                            (raw_math[5] / 8.0).clamp(0.0, 1.0),
                            (raw_math[6] / 300000.0).clamp(0.0, 1.0),
                            (raw_math[7] / 10000.0).clamp(0.0, 1.0),
                        ]
                    } else {
                        continue;
                    };

                    // -- 6. PAYLOAD CONSTRUCTION ----------
                    // Each context column is now a top-level payload key with its native
                    // type, replacing the former json_context_map string blob. This enables
                    // O(log N) filtered queries via Qdrant's KEYWORD/FLOAT indexes.

                    let mut payload_map: qdrant_client::Payload = qdrant_client::Payload::new();

                    payload_map.insert("endpoint_id", extracted_id.clone());
                    payload_map.insert("timestamp", extracted_timestamp.clone());
                    payload_map.insert("source_type", active_source_type.to_string());
                    payload_map.insert("vector_name", active_vector_name.clone());
                    payload_map.insert("nexus_sensor_id", extracted_sensor.clone());

                    if let Ok(epoch) = extracted_timestamp.parse::<f64>() {
                        payload_map.insert("timestamp_epoch", epoch);
                    }

                    let mut anomaly_score_val: Option<f64> = None;

                    for col_name in &active_mapping.context_columns {
                        if let Some(&idx) = col_indices.get(col_name) {
                            let column = batch.column(idx);
                            if column.is_valid(row_idx) {
                                match column.data_type() {
                                    DataType::Utf8 => {
                                        let val = column.as_string::<i32>().value(row_idx);
                                        payload_map.insert(col_name.as_str(), val.to_string());
                                    },
                                    DataType::LargeUtf8 => {
                                        let val = column.as_string::<i64>().value(row_idx);
                                        payload_map.insert(col_name.as_str(), val.to_string());
                                    },
                                    DataType::Int32 => {
                                        let val = column.as_primitive::<arrow::datatypes::Int32Type>().value(row_idx);
                                        payload_map.insert(col_name.as_str(), val as i64);
                                    },
                                    DataType::Int64 => {
                                        let val = column.as_primitive::<arrow::datatypes::Int64Type>().value(row_idx);
                                        payload_map.insert(col_name.as_str(), val);
                                    },
                                    DataType::Float64 => {
                                        let val = column.as_primitive::<arrow::datatypes::Float64Type>().value(row_idx);
                                        payload_map.insert(col_name.as_str(), val);
                                        if col_name == "anomaly_score" {
                                            anomaly_score_val = Some(val);
                                        }
                                    },
                                    DataType::Float32 => {
                                        let val = column.as_primitive::<arrow::datatypes::Float32Type>().value(row_idx) as f64;
                                        payload_map.insert(col_name.as_str(), val);
                                        if col_name == "anomaly_score" {
                                            anomaly_score_val = Some(val);
                                        }
                                    },
                                    _ => {}
                                }
                            }
                        }
                    }

                    if let Some(score) = anomaly_score_val {
                        payload_map.insert("anomaly_score", score);
                    }

                    let deterministic_seed = format!("{}-{}", extracted_id, extracted_timestamp);
                    let point_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, deterministic_seed.as_bytes());

                    let mut named_vectors = HashMap::new();
                    named_vectors.insert(
                        active_vector_name.clone(),
                        Vector {
                            data: normalized_math,
                            ..Default::default()
                        },
                    );

                    points.push(PointStruct::new(
                        point_id.to_string(),
                        Vectors {
                            vectors_options: Some(VectorsEnum::Vectors(
                                NamedVectors {
                                    vectors: named_vectors,
                                },
                            )),
                        },
                        payload_map,
                    ));
                }
            }
        }

        // -- 7. METRICS TRACKING & QDRANT UPSERT --
        let anomaly_threshold = 0.88;
        let mut pending_alerts = Vec::new();

        for point in &points {
            if let Some(score_val) = point.payload.get("anomaly_score") {
                if let Some(score) = score_val.as_double() {
                    if score >= anomaly_threshold {
                        let vector_name = if let Some(VectorsEnum::Vectors(map)) = point.vectors.as_ref().and_then(|v| v.vectors_options.as_ref()) {
                            map.vectors.keys().next().cloned().unwrap_or_default()
                        } else {
                            String::new()
                        };

                        let source_type = point.payload.get("source_type")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "unknown".to_string());

                        let point_id_str = point.id.as_ref().map(|id| match &id.point_id_options {
                            Some(PointIdOptions::Uuid(s)) => s.clone(),
                            Some(PointIdOptions::Num(n))  => n.to_string(),
                            None => String::new(),
                        }).unwrap_or_default();

                        let sensor_id_str  = point.payload.get("nexus_sensor_id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string());
                        let endpoint_str   = point.payload.get("endpoint_id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string());
                        let timestamp_str  = point.payload.get("timestamp").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_default();

                        let trigger = serde_json::json!({
                            "event_id": point_id_str,
                            "sensor_id": sensor_id_str,
                            "endpoint_id": endpoint_str,
                            "anomaly_score": score,
                            "vector_name": vector_name,
                            "source_type": source_type,
                            "timestamp": timestamp_str,
                            "mitigation_status": "ready_pending_review"
                        });
                        pending_alerts.push((point_id_str, trigger));
                    }
                }
            }
        }

        let points_count = points.len() as u64;
        let start_time = std::time::Instant::now();

        match self.client.upsert_points(
            UpsertPointsBuilder::new(&self.collection, points)
        ).await {
            Ok(response) => {
                histogram!("nexus_qdrant_db_upsert_latency_seconds").record(start_time.elapsed().as_secs_f64());
                counter!("nexus_qdrant_points_upserted_total").increment(points_count);

                if response.time > 2.0 {
                    warn!("Database latency degradation detected: Upsert took {:.2}s", response.time);
                    counter!("nexus_qdrant_db_latency_warnings_total").increment(1);
                }

                if !pending_alerts.is_empty() {
                    let js = async_nats::jetstream::new(self.nats.clone());
                    for (point_id, trigger) in pending_alerts {
                        match js.publish("nexus.alerts.math", trigger.to_string().into()).await {
                            Ok(_) => warn!("[MATHEMATICAL TRIPWIRE] Durably routed NATS event for vector {}", point_id),
                            Err(e) => error!("CRITICAL: Failed to durably publish tripwire alert: {}", e),
                        }
                    }
                }

                Ok(())
            }
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("transport error") || err_msg.contains("Connection refused") {
                    counter!("nexus_qdrant_grpc_faults_total").increment(1);
                    error!("Systemic backend failure detected. Tripping circuit breaker. Alerts suppressed.");
                    Err(format!("Systemic Qdrant fault: {}", err_msg))
                } else {
                    counter!("nexus_qdrant_validation_faults_total").increment(1);
                    error!("Vector database rejected batch payload. Alerts suppressed: {}", err_msg);
                    Err(format!("Payload rejection: {}", err_msg))
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .with_target(false)
        .init();

    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], 9001))
        .install()
        .expect("Failed to install Prometheus exporter");

    let config_path = std::env::var("NEXUS_CONFIG")
        .unwrap_or_else(|_| "../config/nexus.toml".to_string());

    info!("Initializing Tier 5 Vector Worker | Metrics active on :9001");

    let conf_raw = fs::read_to_string(&config_path).expect("Failed to read nexus.toml");
    let conf: Config = toml::from_str(&conf_raw).expect("Failed to parse nexus.toml");
    let nats_client = async_nats::connect(&conf.global.nats_url).await.unwrap();
    let adapter = QdrantAdapter::initialize(&config_path, Some(nats_client));

    let worker_cfg = WorkerConfig {
        nats_url:      conf.global.nats_url.clone(),
        stream_name:   conf.global.telemetry_stream.clone(),
        subject:       conf.global.telemetry_subject.clone(),
        consumer_name: "Qdrant_Vector_Group".into(),
        dlq_prefix:    conf.global.dlq_subject_prefix.clone(),
        ..WorkerConfig::default()
    };

    start_durable_worker(adapter, worker_cfg).await;
}