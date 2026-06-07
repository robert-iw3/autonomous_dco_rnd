use anyhow::Result;
use metrics::counter;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const SESSION_TTL_SECONDS: u64 = 172_800; // 48 hours

pub struct RedisEntry {
    pub session_id: String,
    pub src_ip:     String,
    pub dst_ip:     String,
}

pub async fn connect(url: &str) -> Result<ConnectionManager> {
    let client = redis::Client::open(url)?;
    Ok(ConnectionManager::new(client).await?)
}

/// Spawns a background Redis writer and returns a bounded sender.
/// Callers use `try_send` -- entries are dropped (with a metric) if the channel
/// is full rather than blocking the ingest hot path.
pub fn start_writer(
    mut client: ConnectionManager,
    cancel_token: CancellationToken,
) -> mpsc::Sender<RedisEntry> {
    let (tx, mut rx) = mpsc::channel::<RedisEntry>(8192);

    tokio::spawn(async move {
        loop {
            let entry = tokio::select! {
                biased;
                _ = cancel_token.cancelled() => break,
                e = rx.recv() => match e {
                    Some(e) => e,
                    None    => break,
                },
            };

            // Drain any additional buffered entries into the same pipeline
            let mut pipe = redis::pipe();
            pipe.set_ex(
                &entry.session_id,
                format!("{},{}", entry.src_ip, entry.dst_ip),
                SESSION_TTL_SECONDS,
            );
            let mut count = 1usize;

            while let Ok(e) = rx.try_recv() {
                pipe.set_ex(
                    &e.session_id,
                    format!("{},{}", e.src_ip, e.dst_ip),
                    SESSION_TTL_SECONDS,
                );
                count += 1;
            }

            let result: redis::RedisResult<Vec<redis::Value>> =
                pipe.query_async(&mut client).await;

            match result {
                Ok(_)  => counter!("gateway.redis_writes").increment(count as u64),
                Err(_) => counter!("gateway.redis_write_errors").increment(1),
            }
        }
    });

    tx
}
