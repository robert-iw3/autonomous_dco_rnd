mod cache;
mod config;
mod syslog;
mod transformer;
mod transmitter;

use crate::cache::TemporalCache;
use crate::config::Config;
use crate::transformer::{Transformer, UnifiedFlowRecord};
use crate::transmitter::Transmitter;

use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    let cache = Arc::new(TemporalCache::new());
    let transformer = Transformer::new((*cache).clone(), config.sensor_id.clone());
    let transmitter = Transmitter::new(config.clone());

    transmitter.replay_spool().await;

    let cache_clone = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(600)).await;
            cache_clone.remove_stale(3600);
        }
    });

    // Listener(s) -> raw line channel.
    let (tx, mut rx) = mpsc::channel::<String>(10_000);

    let tcp_bind = config.syslog_bind.clone();
    let tcp_tx = tx.clone();
    tokio::spawn(async move {
        if let Err(e) = syslog::serve_tcp(tcp_bind, tcp_tx).await {
            tracing::error!("TCP syslog listener exited: {}", e);
        }
    });

    if config.enable_udp {
        let udp_bind = config.syslog_bind.clone();
        let udp_tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = syslog::serve_udp(udp_bind, udp_tx).await {
                tracing::error!("UDP syslog listener exited: {}", e);
            }
        });
    }
    drop(tx); // only listeners hold senders now

    tracing::info!("Nexus VMware syslog connector online ({}).", config.syslog_bind);

    let mut batch: Vec<UnifiedFlowRecord> = Vec::with_capacity(config.batch_size);
    let mut batch_start = Instant::now();
    let timeout = Duration::from_secs(config.batch_timeout_secs);

    loop {
        let remaining = timeout.saturating_sub(batch_start.elapsed());
        match tokio::time::timeout(remaining.max(Duration::from_millis(50)), rx.recv()).await {
            Ok(Some(line)) => {
                if let Some(rec) = transformer.transform_line(&line) {
                    batch.push(rec);
                }
                if batch.len() >= config.batch_size {
                    flush(&transmitter, &mut batch).await;
                    batch_start = Instant::now();
                }
            }
            Ok(None) => {
                // All listeners gone; flush and exit.
                flush(&transmitter, &mut batch).await;
                break;
            }
            Err(_) => {
                // Quiet-timeout elapsed.
                if !batch.is_empty() {
                    flush(&transmitter, &mut batch).await;
                }
                batch_start = Instant::now();
            }
        }
    }

    Ok(())
}

async fn flush(transmitter: &Transmitter, batch: &mut Vec<UnifiedFlowRecord>) {
    if batch.is_empty() {
        return;
    }
    let records = std::mem::take(batch);
    let n = records.len();
    // On failure the batch is retained on disk by the transmitter and will be
    // replayed on next boot (spool_replay = true for this connector).
    if !transmitter.spool_and_transmit(records).await {
        tracing::error!("Transmit failed for {} records; retained in spool for replay.", n);
    }
}