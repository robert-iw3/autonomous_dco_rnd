use crate::config::GatewayConfig;
use crate::models::ArkimeSpi;
use crate::pipeline::{features, filters};
use crate::storage::{redis_lookup::RedisEntry, spool_db::SpoolDb};
use anyhow::Result;
use metrics::{counter, gauge};
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::ClientConfig;
use rdkafka::Message;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub async fn consume_loop(
    cfg: GatewayConfig,
    session_tx: mpsc::Sender<RedisEntry>,
    spool: Arc<SpoolDb>,
    cancel_token: CancellationToken,
) -> Result<()> {
    let mut kafka_cfg = ClientConfig::new();
    kafka_cfg
        .set("bootstrap.servers", &cfg.redpanda.brokers)
        .set("group.id", &cfg.redpanda.group_id)
        .set("enable.auto.commit", "false")
        // earliest, not latest: a cold start / new group must NOT skip a backlog
        // already queued in the broker (data-loss footgun). Committed offsets still
        // take precedence on normal restarts.
        .set("auto.offset.reset", "earliest")
        .set("fetch.min.bytes", "65536")
        .set("fetch.wait.max.ms", "100");

    // Optional mTLS for multi-VM deployments
    if let Some(ref ca) = cfg.redpanda.ssl_ca_location {
        kafka_cfg.set("security.protocol", "ssl");
        kafka_cfg.set("ssl.ca.location", ca);
        if let Some(ref cert) = cfg.redpanda.ssl_certificate_location {
            kafka_cfg.set("ssl.certificate.location", cert);
        }
        if let Some(ref key) = cfg.redpanda.ssl_key_location {
            kafka_cfg.set("ssl.key.location", key);
        }
    }

    let consumer: StreamConsumer = kafka_cfg.create()?;
    consumer.subscribe(&[&cfg.redpanda.topic])?;
    info!(topic = %cfg.redpanda.topic, brokers = %cfg.redpanda.brokers, "Consumer subscribed");

    let batch_size    = cfg.storage.batch_size;
    let flush_interval = Duration::from_secs(cfg.storage.flush_interval_sec);

    let mut payload_buffer: Vec<u8> = Vec::with_capacity(65536);
    let mut batch = Vec::with_capacity(batch_size);
    let mut last_flush = tokio::time::Instant::now();

    loop {
        // Liveness heartbeat -- the container healthcheck fails if this stops
        // advancing (loop dead or blocked), distinct from a process that is merely
        // "up". A halted/blocked consumer is otherwise a silent data blackhole.
        gauge!("gateway_consumer_heartbeat_seconds").set(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0),
        );

        if cancel_token.is_cancelled() {
            info!("Ingest loop shutting down -- flushing {} buffered records", batch.len());
            if !batch.is_empty() {
                if let Err(e) = spool.insert_batch(&batch).await {
                    error!("Final batch flush failed: {}", e);
                } else {
                    let _ = consumer.commit_consumer_state(CommitMode::Sync);
                }
            }
            break;
        }

        // Time-based flush
        if !batch.is_empty() && last_flush.elapsed() >= flush_interval {
            match spool.insert_batch(&batch).await {
                Ok(()) => {
                    info!(rows = batch.len(), "spooled batch to SQLite WAL (time flush)");
                    if let Err(e) = consumer.commit_consumer_state(CommitMode::Async) {
                        warn!("Kafka offset commit failed after time flush: {}", e);
                    }
                }
                Err(e) => {
                    error!("Time-flush failed -- Kafka offset not committed; data will replay: {}", e);
                }
            }
            batch.clear();
            last_flush = tokio::time::Instant::now();
        }

        match tokio::time::timeout(Duration::from_millis(200), consumer.recv()).await {
            Ok(Ok(msg)) => {
                if let Some(payload) = msg.payload() {
                    counter!("gateway.messages_received").increment(1);

                    payload_buffer.clear();
                    payload_buffer.extend_from_slice(payload);

                    match simd_json::from_slice::<ArkimeSpi>(&mut payload_buffer) {
                        Ok(spi) => {
                            if filters::is_noise(&spi) {
                                counter!("gateway.sessions_filtered_noise").increment(1);
                                continue;
                            }

                            counter!("gateway.sessions_accepted").increment(1);

                            // Non-blocking Redis registration -- drop on channel full
                            let entry = RedisEntry {
                                session_id: spi.id.to_string(),
                                src_ip:     spi.a1.to_string(),
                                dst_ip:     spi.a2.to_string(),
                            };
                            if session_tx.try_send(entry).is_err() {
                                counter!("gateway.redis_channel_full").increment(1);
                            }

                            if let Some(record) = features::extract(&spi, &cfg.extraction) {
                                batch.push(record);
                            }

                            // Size-based flush
                            if batch.len() >= batch_size {
                                match spool.insert_batch(&batch).await {
                                    Ok(()) => {
                                        info!(rows = batch.len(), "spooled batch to SQLite WAL");
                                        if let Err(e) = consumer.commit_consumer_state(CommitMode::Async) {
                                            warn!("Kafka offset commit failed: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        error!("Batch flush failed -- offset not committed; data will replay: {}", e);
                                    }
                                }
                                batch.clear();
                                last_flush = tokio::time::Instant::now();
                            }
                        }
                        Err(e) => {
                            counter!("gateway.json_parse_errors").increment(1);
                            warn!("SIMD-JSON parse error: {}", e);
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                counter!("gateway.kafka_read_errors").increment(1);
                warn!("Kafka read error: {}", e);
            }
            Err(_) => {}
        }
    }

    Ok(())
}
