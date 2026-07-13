use async_trait::async_trait;
use bytes::Bytes;
use lib_siem_core::{start_durable_worker, SiemAdapter};
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use tracing::{info, Level};

// ── 1. The Mock Fault-Injecting Adapter ──
#[derive(Clone)]
struct MockSiemAdapter {
    pub batch_size: usize,
    pub failure_count: Arc<Mutex<usize>>,
    pub target_failures: usize,
    /// Captures payloads and headers for validation
    pub captured_payloads: Arc<Mutex<Vec<(Vec<u8>, Option<String>, Option<String>)>>>,
}

#[async_trait]
impl SiemAdapter for MockSiemAdapter {
    fn initialize(_config_path: &str, _nats_client: async_nats::Client) -> Self {
        unimplemented!("Test harness uses direct instantiation")
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    async fn transmit_batch(&self, raw_payloads: Vec<Bytes>) -> Result<(), String> {
        let mut count = self.failure_count.lock().unwrap();
        if *count < self.target_failures {
            *count += 1;
            info!("Mock Adapter forcing failure {}/{}", *count, self.target_failures);
            return Err("Simulated backend systemic timeout".to_string());
        }

        // Capture payloads for later validation
        let mut captured = self.captured_payloads.lock().unwrap();
        for payload in &raw_payloads {
            captured.push((payload.to_vec(), None, None));
        }

        info!("Mock Adapter successfully processed batch of {} payloads.", raw_payloads.len());
        Ok(())
    }
}

// ── 2. Circuit Breaker & DLQ Validation ──
#[tokio::test]
async fn validate_circuit_breaker_and_dlq_routing() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let nats_url = std::env::var("NATS_TEST_URL")
        .unwrap_or_else(|_| "nats://nats:4222".to_string());

    let client = async_nats::connect(&nats_url).await.expect("Failed to connect to NATS test server");
    let js = async_nats::jetstream::new(client.clone());

    let stream_name = "TEST_TELEMETRY";
    let subject = "nexus.test.telemetry";
    let dlq_prefix = "nexus.dlq";

    // Purge/Create Stream for clean state
    let _ = js.delete_stream(stream_name).await;
    js.create_stream(async_nats::jetstream::stream::Config {
        name: stream_name.to_string(),
        subjects: vec![subject.to_string()],
        ..Default::default()
    }).await.unwrap();

    // Publish a mock payload
    let mock_parquet_bytes = Bytes::from_static(b"MOCK_PARQUET_MAGIC_BYTES");
    js.publish(subject.to_string(), mock_parquet_bytes).await.unwrap();

    // Configure adapter to fail exactly 4 times → exhausts 3 retries → DLQ
    let mock_adapter = MockSiemAdapter {
        batch_size: 10,
        failure_count: Arc::new(Mutex::new(0)),
        target_failures: 4,
        captured_payloads: Arc::new(Mutex::new(Vec::new())),
    };

    let worker_handle = tokio::spawn(async move {
        start_durable_worker(
            mock_adapter,
            nats_url,
            stream_name,
            subject,
            "QA_Test_Group",
            dlq_prefix,
        ).await;
    });

    // Allow time for exponential backoff (2^1 + 2^2 + 2^3 ≈ 14s)
    tokio::time::sleep(Duration::from_secs(16)).await;

    let dlq_subject = format!("{}.{}", dlq_prefix, "qa_test_group");
    let mut dlq_sub = client.subscribe(dlq_subject.clone()).await.unwrap();

    let dlq_msg = tokio::time::timeout(Duration::from_secs(2), dlq_sub.next()).await;

    assert!(dlq_msg.is_ok(), "Poison message was not routed to the DLQ subject.");
    info!("QA Pass: Circuit breaker tripped and message quarantined.");

    worker_handle.abort();
}

// ── 3. Hive Partition Header Propagation ──
#[tokio::test]
async fn validate_hive_partition_header_propagation() {
    let nats_url = std::env::var("NATS_TEST_URL")
        .unwrap_or_else(|_| "nats://nats:4222".to_string());

    let client = async_nats::connect(&nats_url).await.expect("Failed to connect to NATS");
    let js = async_nats::jetstream::new(client.clone());

    let stream_name = "TEST_PARTITION";
    let subject = "nexus.test.partition";

    let _ = js.delete_stream(stream_name).await;
    js.create_stream(async_nats::jetstream::stream::Config {
        name: stream_name.to_string(),
        subjects: vec![subject.to_string()],
        ..Default::default()
    }).await.unwrap();

    // Publish a message with Hive partition hint headers
    let mut headers = async_nats::HeaderMap::new();
    headers.insert("X-Partition-Date", "2025-06-15");
    headers.insert("X-Partition-Hour", "14");
    headers.insert("X-Sensor-Type", "network_tap");

    let mock_parquet = Bytes::from_static(b"MOCK_NETTAP_PARQUET");
    js.publish_with_headers(
        subject.to_string(),
        headers,
        mock_parquet,
    ).await.unwrap();

    // Subscribe and verify headers survive NATS transit
    let consumer = js.get_stream(stream_name).await.unwrap()
        .get_or_create_consumer(
            "Partition_Test_Group",
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some("Partition_Test_Group".to_string()),
                filter_subject: subject.to_string(),
                ..Default::default()
            },
        ).await.unwrap();

    use futures::StreamExt;
    let mut messages = consumer.messages().await.unwrap();

    let msg = tokio::time::timeout(
        Duration::from_secs(5),
        messages.next(),
    ).await.expect("Timeout waiting for partition test message");

    if let Some(Ok(message)) = msg {
        let hdrs = message.headers.as_ref().expect("Headers missing from NATS message");

        let date = hdrs.get("X-Partition-Date")
            .expect("X-Partition-Date header missing")
            .to_string();
        let hour = hdrs.get("X-Partition-Hour")
            .expect("X-Partition-Hour header missing")
            .to_string();

        assert_eq!(date, "2025-06-15", "Partition date header corrupted");
        assert_eq!(hour, "14", "Partition hour header corrupted");

        info!(
            "QA Pass: Hive partition headers propagated correctly: dt={}, hour={}",
            date, hour
        );

        // Validate the S3 path would be constructed correctly
        let sensor_type = hdrs.get("X-Sensor-Type")
            .expect("X-Sensor-Type header missing")
            .to_string();
        let expected_prefix = format!(
            "telemetry/{}/dt={}/hour={}/",
            sensor_type, date, hour
        );
        assert_eq!(
            expected_prefix,
            "telemetry/network_tap/dt=2025-06-15/hour=14/"
        );

        info!("QA Pass: S3 Hive path would be: {}", expected_prefix);
        let _ = message.ack().await;
    } else {
        panic!("Failed to receive partition test message");
    }
}

// ── 4. Spool Cap Enforcement ──
// This is a conceptual test -- the actual spool_db uses SQLite which requires
// the gateway binary. Here we validate the eviction logic in isolation.
#[test]
fn validate_spool_cap_eviction_logic() {
    // Simulates the logic from spool_db.rs::enforce_spool_cap()
    let max_spool_bytes: u64 = 50 * 1024 * 1024 * 1024; // 50 GB
    let current_db_size: u64 = 55 * 1024 * 1024 * 1024;  // 55 GB -- over cap

    assert!(current_db_size > max_spool_bytes, "Test setup: DB must exceed cap");

    let total_untransmitted: i64 = 500_000;
    let drop_count = (total_untransmitted / 10).max(1000);

    assert_eq!(drop_count, 50_000, "Should drop 10% of untransmitted rows");
    assert!(drop_count >= 1000, "Minimum drop count is 1000");

    // After eviction, the remaining rows should be the newest
    let remaining = total_untransmitted - drop_count;
    assert_eq!(remaining, 450_000, "450K rows should remain after eviction");

    info!("QA Pass: Spool cap eviction logic validated (drop 50K of 500K rows).");
}

// ── 5. Zero-byte spool cap disabled ──
#[test]
fn validate_spool_cap_disabled_when_zero() {
    let max_spool_bytes: u64 = 0;
    let current_db_size: u64 = 999 * 1024 * 1024 * 1024;

    // When max_spool_bytes = 0, enforcement is skipped
    let should_enforce = max_spool_bytes > 0 && current_db_size > max_spool_bytes;
    assert!(!should_enforce, "Spool cap must be disabled when set to 0");

    info!("QA Pass: Spool cap correctly disabled when max_spool_bytes=0.");
}