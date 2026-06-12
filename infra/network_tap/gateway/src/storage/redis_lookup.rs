use anyhow::Result;
use metrics::counter;
use redis::aio::ConnectionManager;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

const SESSION_TTL_SECONDS: u64 = 172_800; // 48 hours
const RECONNECT_INTERVAL: Duration = Duration::from_secs(30);
const MAX_DRAIN: usize = 4096;

pub struct RedisEntry {
    pub session_id: String,
    pub src_ip:     String,
    pub dst_ip:     String,
}

pub async fn connect(url: &str) -> Result<ConnectionManager> {
    let client = redis::Client::open(url)?;
    Ok(ConnectionManager::new(client).await?)
}

/// Spawns the background Redis writer and returns a bounded sender. Redis is a
/// NON-CRITICAL enrichment cache: callers `try_send` (drop on full, never block
/// the ingest hot path), and if Redis is down the writer drains + drops entries
/// and retries the connection every 30s -- it never stalls or kills the gateway.
pub fn start_writer(
    mut client: Option<ConnectionManager>,
    url: String,
    cancel_token: CancellationToken,
) -> mpsc::Sender<RedisEntry> {
    let (tx, mut rx) = mpsc::channel::<RedisEntry>(8192);

    tokio::spawn(async move {
        let mut last_reconnect = Instant::now();

        loop {
            let entry = tokio::select! {
                biased;
                _ = cancel_token.cancelled() => break,
                e = rx.recv() => match e {
                    Some(e) => e,
                    None    => break,
                },
            };

            // Coalesce buffered entries into one pipeline.
            let mut entries = vec![entry];
            while let Ok(e) = rx.try_recv() {
                entries.push(e);
                if entries.len() >= MAX_DRAIN {
                    break;
                }
            }

            // Degraded path: no connection -- drop, and attempt a bounded reconnect.
            if client.is_none() {
                if last_reconnect.elapsed() >= RECONNECT_INTERVAL {
                    last_reconnect = Instant::now();
                    if let Ok(c) = connect(&url).await {
                        info!("Redis reconnected -- session enrichment resumed");
                        client = Some(c);
                    }
                }
                if client.is_none() {
                    counter!("gateway.redis_disabled_drops").increment(entries.len() as u64);
                    continue;
                }
            }

            let conn = client.as_mut().expect("client is Some on this path");
            let mut pipe = redis::pipe();
            for e in &entries {
                pipe.set_ex(&e.session_id, format!("{},{}", e.src_ip, e.dst_ip), SESSION_TTL_SECONDS);
            }

            // ConnectionManager reconnects internally on the next call after an error.
            let result: redis::RedisResult<Vec<redis::Value>> = pipe.query_async(conn).await;
            match result {
                Ok(_) => counter!("gateway.redis_writes").increment(entries.len() as u64),
                Err(_) => counter!("gateway.redis_write_errors").increment(1),
            }
        }
    });

    tx
}
