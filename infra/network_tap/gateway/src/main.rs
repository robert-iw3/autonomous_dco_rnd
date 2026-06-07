use std::sync::Arc;
use tokio::signal;
use tokio::signal::unix::SignalKind;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod config;
mod integrity;
mod ingest;
mod models;
mod pipeline;
mod storage;
mod transmit;

fn main() -> anyhow::Result<()> {
    let config_path = std::env::var("GATEWAY_CONFIG")
        .unwrap_or_else(|_| "/data/config/config.toml".to_string());
    let cfg = config::GatewayConfig::load(&config_path)?;

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .json()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!(
        sensor  = %cfg.global.sensor_name,
        brokers = %cfg.redpanda.brokers,
        topic   = %cfg.redpanda.topic,
        gateway = %cfg.nexus.gateway_url,
        "Initializing Arkime ML Gateway"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.runtime.tokio_worker_threads)
        .enable_all()
        .thread_name("ml-gateway-worker")
        .build()?;

    runtime.block_on(async {
        // --- Prometheus metrics endpoint ---
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(([0, 0, 0, 0], cfg.metrics.port))
            .install()
            .expect("Failed to start Prometheus metrics endpoint");
        info!(port = cfg.metrics.port, "Prometheus metrics endpoint started");

        // --- Redis connection ---
        let redis_client = match storage::redis_lookup::connect(&cfg.redis.url).await {
            Ok(c) => {
                info!(url = %cfg.redis.url, "Connected to Redis");
                c
            }
            Err(e) => {
                error!("Failed to connect to Redis: {}", e);
                return;
            }
        };

        // --- SQLite WAL spool ---
        let spool = match storage::spool_db::SpoolDb::new(
            &cfg.storage.spool_db_path,
            cfg.storage.max_spool_bytes,
        )
        .await
        {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("Failed to initialize SQLite spool: {}", e);
                return;
            }
        };

        let cancel_token = CancellationToken::new();

        // --- Redis background writer ---
        let session_tx = storage::redis_lookup::start_writer(
            redis_client,
            cancel_token.clone(),
        );

        // --- Nexus transmitter (SQLite → Parquet → Axum gateway) ---
        let transmit_pool  = spool.pool();
        let transmit_cfg   = cfg.clone();
        let transmit_token = cancel_token.clone();
        let transmit_handle = tokio::spawn(async move {
            if let Err(e) = transmit::nexus::transmit_loop(
                transmit_pool, transmit_cfg, transmit_token,
            ).await {
                error!("Nexus transmitter halted: {}", e);
            }
        });

        // --- Redpanda consumer (Kafka → filter → extract → SQLite) ---
        let ingest_cfg    = cfg.clone();
        let ingest_spool  = spool.clone();
        let ingest_token  = cancel_token.clone();
        let ingest_handle = tokio::spawn(async move {
            if let Err(e) = ingest::redpanda::consume_loop(
                ingest_cfg, session_tx, ingest_spool, ingest_token,
            ).await {
                error!("Redpanda ingestion loop halted: {}", e);
            }
        });

        // --- Await SIGINT or SIGTERM ---
        let mut sigterm = match signal::unix::signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to register SIGTERM handler: {}", e);
                return;
            }
        };

        tokio::select! {
            result = signal::ctrl_c() => {
                if let Err(e) = result {
                    error!("Failed to listen for SIGINT: {}", e);
                }
            }
            _ = sigterm.recv() => {}
        }

        info!("Shutdown signal received -- draining pipelines...");
        cancel_token.cancel();

        // Ingest flushes its current batch on cancellation before exiting
        let _ = ingest_handle.await;
        // Transmit completes its current batch or honours the cancellation check
        let _ = transmit_handle.await;

        info!("Gateway shutdown complete.");
    });

    Ok(())
}
