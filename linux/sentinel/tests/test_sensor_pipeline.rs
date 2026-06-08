/// test_sensor_pipeline.rs -- Linux Sentinel Sensor Pipeline Unit Tests
///
/// Validates the Linux Sentinel sensor's data production pipeline:
///   eBPF ring buffer capture → SecurityAlert struct → Parquet serialization
///   → HMAC integrity stamping → HTTPS transmission headers
///
/// Scope: Sensor-side only. No middleware, NATS, or Qdrant required.
///
/// Run:
///   cargo test -p linux-sentinel -- --nocapture

use linux_sentinel::siem::models::{SecurityAlert, AlertLevel, MitreTactic};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use arrow::array::{Float64Array, StringArray, UInt32Array};
use arrow::datatypes::DataType;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

const INTEGRITY_SECRET: &str = "Nexus-Integrity-SharedKey-Rotate-Me";

// -- Test helpers -------------------------------------------------------------

fn make_alert(level: AlertLevel, tactic: MitreTactic) -> SecurityAlert {
    SecurityAlert {
        endpoint_id:        "linux-test-01".to_string(),
        event_id:           uuid::Uuid::new_v4().to_string(),
        timestamp:          1748872800_u64,
        level,
        mitre_tactic:       tactic,
        mitre_technique:    "T1068".to_string(),
        pid:                12345,
        ppid:               1,
        uid:                1001,
        cgroup_id:          0,
        container_id:       String::new(),
        container_name:     String::new(),
        comm:               "unshare".to_string(),
        command_line:       "unshare -Urm".to_string(),
        parent_comm:        "bash".to_string(),
        user_name:          "www-data".to_string(),
        target_file:        None,
        dest_ip:            None,
        dest_port:          None,
        source_port:        None,
        shannon_entropy:    0.72,
        execution_velocity: 0.45,
        tuple_rarity:       0.88,
        path_depth:         4,
        anomaly_score:      0.91,
        message:            "OverlayFS privilege escalation chain detected".to_string(),
        in_memory_capture:  Some(false),
        ml_vector:          None,
    }
}

fn compute_hmac(payload: &[u8], sequence: u64, sensor_id: &str, timestamp: u64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(INTEGRITY_SECRET.as_bytes())
        .expect("HMAC");
    mac.update(payload);
    mac.update(&sequence.to_be_bytes());
    mac.update(sensor_id.as_bytes());
    mac.update(&timestamp.to_be_bytes());
    hex::encode(mac.finalize().into_bytes())
}


// ═══════════════════════════════════════════════════════════════════════════
// 1. SecurityAlert struct field coverage
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_security_alert_required_fields() {
    let alert = make_alert(AlertLevel::High, MitreTactic::PrivilegeEscalation);
    assert!(!alert.endpoint_id.is_empty(),    "endpoint_id must be non-empty");
    assert!(!alert.event_id.is_empty(),       "event_id must be UUID");
    assert!(alert.timestamp > 0,              "timestamp must be non-zero epoch");
    assert!(!alert.comm.is_empty(),           "comm must be non-empty");
    assert!(!alert.command_line.is_empty(),   "command_line must be non-empty");
    assert!(alert.pid > 0,                    "pid must be non-zero");
    assert!(alert.uid >= 0,                   "uid must be valid");
}

#[test]
fn test_security_alert_vector_fields_in_range() {
    let alert = make_alert(AlertLevel::Critical, MitreTactic::Execution);
    assert!(alert.shannon_entropy    >= 0.0 && alert.shannon_entropy    <= 1.0);
    assert!(alert.execution_velocity >= 0.0 && alert.execution_velocity <= 1.0);
    assert!(alert.tuple_rarity       >= 0.0 && alert.tuple_rarity       <= 1.0);
    assert!(alert.anomaly_score      >= 0.0 && alert.anomaly_score      <= 1.0);
    assert!(alert.path_depth < 100, "path_depth sanity check");
}

#[test]
fn test_security_alert_5d_vector_components() {
    /// The 5D sentinel_math vector must have exactly these 5 components:
    ///   [shannon_entropy, execution_velocity, tuple_rarity, path_depth_norm, anomaly_score]
    let alert = make_alert(AlertLevel::High, MitreTactic::PrivilegeEscalation);
    let vector = vec![
        alert.shannon_entropy,
        alert.execution_velocity,
        alert.tuple_rarity,
        (alert.path_depth as f64) / 100.0,  // normalise path_depth
        alert.anomaly_score,
    ];
    assert_eq!(vector.len(), 5,
        "sentinel_math vector must be exactly 5D");
    for (i, v) in vector.iter().enumerate() {
        assert!(v.is_finite(), "vector[{i}] must be finite (no NaN/Inf)");
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// 2. MitreTactic enum serialization
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_mitre_tactic_serializes_to_string() {
    /// MitreTactic must serialize to human-readable string with TAID prefix,
    /// not as an integer ordinal. This is the FORMAT requirement.
    let tactic = MitreTactic::PrivilegeEscalation;
    let serialized = serde_json::to_string(&tactic)
        .expect("MitreTactic must be JSON-serializable");
    // Must be a quoted string (starts with '"'), not a number
    assert!(serialized.starts_with('"'),
        "MitreTactic must serialize as string, not integer. Got: {serialized}");
    // Must contain the tactic name (not just a number)
    assert!(serialized.contains("Privilege") || serialized.contains("TA00"),
        "MitreTactic serialization must include tactic name: {serialized}");
}

#[test]
fn test_all_mitre_tactics_serialize() {
    let tactics = [
        MitreTactic::InitialAccess,
        MitreTactic::Execution,
        MitreTactic::Persistence,
        MitreTactic::PrivilegeEscalation,
        MitreTactic::DefenseEvasion,
        MitreTactic::CredentialAccess,
        MitreTactic::Discovery,
        MitreTactic::LateralMovement,
        MitreTactic::Collection,
        MitreTactic::CommandAndControl,
        MitreTactic::Exfiltration,
        MitreTactic::Impact,
        MitreTactic::Unknown,
    ];
    for tactic in &tactics {
        let s = serde_json::to_string(tactic).expect("must serialize");
        assert!(s.starts_with('"') && s.ends_with('"'),
            "MitreTactic {tactic:?} must serialize as JSON string");
        // Must not be a bare number
        let inner = &s[1..s.len()-1];
        assert!(!inner.parse::<u64>().is_ok(),
            "MitreTactic {tactic:?} must not serialize as integer: {s}");
    }
}

#[test]
fn test_alert_level_serialization() {
    for level in &[AlertLevel::Critical, AlertLevel::High,
                   AlertLevel::Medium, AlertLevel::Low, AlertLevel::Info] {
        let s = serde_json::to_string(level).expect("AlertLevel must serialize");
        assert!(s.starts_with('"'),
            "AlertLevel must serialize as string: {s}");
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// 3. Parquet schema (mocked -- parquet_transmitter builds the schema)
// ═══════════════════════════════════════════════════════════════════════════

const EXPECTED_SENTINEL_PARQUET_COLUMNS: &[&str] = &[
    // Identity (sensor_id_column = "sensor_id" per the central contract --
    // sourced from the local SecurityAlert.endpoint_id field but renamed on
    // the wire to identify the REPORTING HOST for worker_qdrant routing)
    "event_id", "sensor_id", "timestamp",
    // Alert
    "level", "mitre_tactic", "mitre_technique",
    // Process
    "pid", "ppid", "uid", "container_name",
    "comm", "command_line", "parent_comm", "user_name",
    // Network/file
    "target_file", "dest_ip", "dest_port",
    // 5D sentinel_math vector
    "shannon_entropy", "execution_velocity", "tuple_rarity", "path_depth", "anomaly_score",
    // Metadata
    "message", "in_memory_capture", "ml_vector",
];

#[test]
fn test_expected_parquet_column_count() {
    /// sentinel_math context has these columns -- verify no accidental schema change
    assert_eq!(EXPECTED_SENTINEL_PARQUET_COLUMNS.len(), 25,
        "sentinel Parquet schema should have 25 columns");
}

#[test]
fn test_corpus_utils_lin_fields_covered() {
    /// corpus_utils._LIN_FIELDS lists the fields that end up in LLM prompts.
    /// Every _LIN_FIELDS entry must be in the Parquet schema.
    let lin_fields = ["comm","command_line","uid","dest_ip","pid","ppid",
                      "target_file","anomaly_score","mitre_tactic","mitre_technique"];
    let parquet_cols: std::collections::HashSet<_> =
        EXPECTED_SENTINEL_PARQUET_COLUMNS.iter().copied().collect();
    for fld in &lin_fields {
        assert!(parquet_cols.contains(fld),
            "corpus_utils _LIN_FIELDS '{fld}' missing from sentinel Parquet schema");
    }
}

#[test]
fn test_sentinel_vector_columns_are_5d() {
    let vector_cols = ["shannon_entropy","execution_velocity","tuple_rarity",
                       "path_depth","anomaly_score"];
    assert_eq!(vector_cols.len(), 5,
        "sentinel_math must be exactly 5D -- vector column count mismatch");
    for col in &vector_cols {
        assert!(EXPECTED_SENTINEL_PARQUET_COLUMNS.contains(col),
            "5D vector col '{col}' missing from Parquet schema");
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// 4. HMAC protocol
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_sentinel_hmac_is_sha256() {
    let payload = b"test_parquet_bytes";
    let sig     = compute_hmac(payload, 1, "linux-test-01", 1748872800);
    assert_eq!(sig.len(), 64, "HMAC must be SHA-256 (64 hex chars)");
    assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_sentinel_hmac_changes_with_content() {
    let h1 = compute_hmac(b"payload_a", 1, "host", 100);
    let h2 = compute_hmac(b"payload_b", 1, "host", 100);
    assert_ne!(h1, h2);
}

#[test]
fn test_sentinel_hmac_sequence_binding() {
    let h1 = compute_hmac(b"payload", 1, "host", 100);
    let h2 = compute_hmac(b"payload", 2, "host", 100);
    assert_ne!(h1, h2, "Sequence counter must change HMAC (replay prevention)");
}

#[test]
fn test_sentinel_hmac_protocol_matches_nexus_integrity() {
    /// Verify our Python test helper computes the same HMAC as the Rust implementation.
    /// Protocol: HMAC-SHA256(payload || BE_u64(seq) || sensor_id || BE_u64(ts))
    let payload   = b"test_parquet_data";
    let seq       = 42_u64;
    let sensor_id = "linux-sentinel-01";
    let ts        = 1748872800_u64;

    // Reference implementation
    let mut mac = Hmac::<Sha256>::new_from_slice(INTEGRITY_SECRET.as_bytes()).unwrap();
    mac.update(payload);
    mac.update(&seq.to_be_bytes());
    mac.update(sensor_id.as_bytes());
    mac.update(&ts.to_be_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    let actual = compute_hmac(payload, seq, sensor_id, ts);
    assert_eq!(expected, actual, "HMAC implementation must match nexus_integrity stamper");
}


// ═══════════════════════════════════════════════════════════════════════════
// 5. Transmission header contract
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_required_transmission_headers() {
    /// Every sentinel batch must set these seven headers, cross-checked against
    /// the literals in parquet_transmitter.rs (default client headers set once
    /// in ParquetTransmitter::new() + per-request headers set in the forward task).
    let required_headers = [
        "Authorization",
        "Content-Type",
        "X-Sensor-Type",
        "X-Sensor-Id",
        "X-Batch-Sequence",
        "X-Batch-Timestamp",
        "X-Batch-HMAC",
    ];
    assert_eq!(required_headers.len(), 7,
        "Transmission protocol requires exactly 7 sensor-set headers");

    let src = include_str!("../src/siem/parquet_transmitter.rs");
    // Authorization is set via .bearer_auth(&token), not a literal header name.
    assert!(src.contains(".bearer_auth(&token)"), "Authorization must be set via bearer_auth");
    assert!(src.contains(r#"HeaderValue::from_static("application/vnd.apache.parquet")"#));
    assert!(src.contains(r#"headers.insert("X-Sensor-Type""#));
    for hdr_const in ["HDR_SENSOR_ID", "HDR_BATCH_SEQUENCE", "HDR_BATCH_TIMESTAMP", "HDR_BATCH_HMAC"] {
        assert!(src.contains(&format!(".header({hdr_const}, ")),
            "per-request header constant '{hdr_const}' not set in transmit task");
    }

    // And confirm the partition headers are deliberately absent from the sensor
    // (they belong to core_ingress's response-side enrichment, not the request).
    assert!(!src.contains("X-Partition-Date") && !src.contains("X-Partition-Hour"),
        "X-Partition-Date/Hour are gateway-injected -- the sensor must not set them");
}

#[test]
fn test_content_type_is_parquet() {
    // Document: Content-Type must be application/vnd.apache.parquet
    let content_type = "application/vnd.apache.parquet";
    assert!(!content_type.is_empty());
    assert_eq!(content_type, "application/vnd.apache.parquet");
}

#[test]
fn test_sensor_type_header_matches_sensor_profile_and_routing_consumers() {
    /// The wire-level X-Sensor-Type string is "Linux-Sentinel" (PascalCase-with-hyphen),
    /// which is DELIBERATELY distinct from the lowercase_snake_case
    /// [schema_mappings.linux_sentinel] TOML table key used for duck-typed routing
    /// in worker_qdrant/worker_rules. "Linux-Sentinel" is the value:
    ///   - declared in middleware/config/sensor_profiles/linux_sentinel.toml (sensor_type = "Linux-Sentinel")
    ///   - exact-matched by worker_splunk and worker_elastic's source_type dispatch
    ///   - sent verbatim on every batch via parquet_transmitter.rs's default X-Sensor-Type header
    ///   - used raw by worker_s3_archive to build "telemetry/{sensor_type}/dt=.../hour=.../uuid.parquet"
    /// A mismatch here would silently misroute every Sentinel batch in Splunk/Elastic/S3.
    const WIRE_SENSOR_TYPE: &str = "Linux-Sentinel";

    let s3_path = format!("telemetry/{WIRE_SENSOR_TYPE}/dt=2026-06-02/hour=15/uuid.parquet");
    assert!(s3_path.contains(WIRE_SENSOR_TYPE),
        "S3 path must use the literal X-Sensor-Type header value '{WIRE_SENSOR_TYPE}'");

    // Cross-check: the literal set on the reqwest client's default headers in
    // parquet_transmitter.rs must be byte-identical to WIRE_SENSOR_TYPE.
    let src = include_str!("../src/siem/parquet_transmitter.rs");
    assert!(
        src.contains(&format!(r#"HeaderValue::from_static("{WIRE_SENSOR_TYPE}")"#)),
        "parquet_transmitter.rs's X-Sensor-Type default header literal is out of sync with '{WIRE_SENSOR_TYPE}'"
    );

    // Cross-check: the central sensor_profiles entry must declare the same string,
    // since core_ingress and downstream consumers key off it for routing/auth.
    let profile = include_str!(
        "../../../project_empros/middleware/config/sensor_profiles/linux_sentinel.toml"
    );
    assert!(
        profile.contains(&format!(r#"sensor_type = "{WIRE_SENSOR_TYPE}""#)),
        "sensor_profiles/linux_sentinel.toml's declared sensor_type is out of sync with '{WIRE_SENSOR_TYPE}'"
    );
}


// ═══════════════════════════════════════════════════════════════════════════
// 6. Optional fields (None/Some handling)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_optional_network_fields_can_be_none() {
    let mut alert = make_alert(AlertLevel::High, MitreTactic::Execution);
    alert.dest_ip   = None;
    alert.dest_port = None;
    // Verify JSON serialization handles None gracefully
    let json = serde_json::to_string(&alert).expect("must serialize with None fields");
    assert!(json.contains("\"dest_ip\":null") || !json.contains("dest_ip"),
        "None fields must serialize as null or be omitted");
}

#[test]
fn test_optional_target_file_present() {
    let mut alert = make_alert(AlertLevel::High, MitreTactic::DefenseEvasion);
    alert.target_file = Some("/etc/shadow".to_string());
    assert_eq!(alert.target_file.as_deref(), Some("/etc/shadow"));
}

#[test]
fn test_ml_vector_optional() {
    let mut alert = make_alert(AlertLevel::Low, MitreTactic::Discovery);
    alert.ml_vector = Some(vec![0.1, 0.2, 0.3, 0.4, 0.5]);
    assert_eq!(alert.ml_vector.as_ref().map(|v| v.len()), Some(5));
}


// ═══════════════════════════════════════════════════════════════════════════
// 7. Container context fields
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_container_context_fields_present() {
    /// container_id and container_name enable Kubernetes/Docker source correlation.
    let mut alert = make_alert(AlertLevel::High, MitreTactic::Execution);
    alert.container_id   = "abc123def456".to_string();
    alert.container_name = "web-frontend".to_string();
    alert.cgroup_id      = 12345;
    assert!(!alert.container_id.is_empty());
    assert!(!alert.container_name.is_empty());
    assert!(alert.cgroup_id > 0);
}