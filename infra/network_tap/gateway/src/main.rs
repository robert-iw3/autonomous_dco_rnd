use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::signal::unix::SignalKind;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn, Level};
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
mod supervisor;
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

        // --- SQLite WAL spool (the durable core -- a hard dependency) ---
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

        // --- Redis (NON-critical enrichment) -- retry, then degrade, never block boot ---
        let redis_client = supervisor::retry(3, Duration::from_secs(2), || {
            storage::redis_lookup::connect(&cfg.redis.url)
        })
        .await;
        if redis_client.is_some() {
            info!(url = %cfg.redis.url, "Connected to Redis");
        } else {
            warn!("Redis unavailable at startup -- continuing WITHOUT session enrichment (will retry)");
        }
        let session_tx = storage::redis_lookup::start_writer(
            redis_client,
            cfg.redis.url.clone(),
            cancel_token.clone(),
        );

        // A pipeline that exhausts its restart budget is fatal: flag it, trip the
        // cancel token so main wakes, and exit non-zero so the orchestrator restarts.
        let fatal = Arc::new(AtomicBool::new(false));

        // --- Nexus transmitter (SQLite → Parquet → Axum gateway), supervised ---
        let transmit_handle = {
            let pool = spool.pool();
            let cfg = cfg.clone();
            let token = cancel_token.clone();
            let fatal = fatal.clone();
            let trip = cancel_token.clone();
            tokio::spawn(async move {
                let r = supervisor::supervise(
                    "transmit", token.clone(), 10,
                    Duration::from_secs(60), Duration::from_secs(1), Duration::from_secs(30),
                    move || {
                        let pool = pool.clone();
                        let cfg = cfg.clone();
                        let tok = token.clone();
                        async move { transmit::nexus::transmit_loop(pool, cfg, tok).await }
                    },
                )
                .await;
                if r.is_err() {
                    error!("transmit pipeline gave up: {:?}", r);
                    fatal.store(true, Ordering::SeqCst);
                    trip.cancel();
                }
            })
        };

        // --- Redpanda consumer (Kafka → filter → extract → SQLite), supervised ---
        let ingest_handle = {
            let cfg = cfg.clone();
            let spool = spool.clone();
            let token = cancel_token.clone();
            let tx = session_tx.clone();
            let fatal = fatal.clone();
            let trip = cancel_token.clone();
            tokio::spawn(async move {
                let r = supervisor::supervise(
                    "ingest", token.clone(), 10,
                    Duration::from_secs(60), Duration::from_secs(1), Duration::from_secs(30),
                    move || {
                        let cfg = cfg.clone();
                        let spool = spool.clone();
                        let tx = tx.clone();
                        let tok = token.clone();
                        async move { ingest::redpanda::consume_loop(cfg, tx, spool, tok).await }
                    },
                )
                .await;
                if r.is_err() {
                    error!("ingest pipeline gave up: {:?}", r);
                    fatal.store(true, Ordering::SeqCst);
                    trip.cancel();
                }
            })
        };

        // --- Await SIGINT / SIGTERM, or a supervisor giving up ---
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
            _ = cancel_token.cancelled() => {
                error!("A pipeline exhausted its restart budget -- shutting down for a clean restart");
            }
        }

        info!("Shutdown signal received -- draining pipelines...");
        cancel_token.cancel();

        let _ = ingest_handle.await;
        let _ = transmit_handle.await;

        if fatal.load(Ordering::SeqCst) {
            error!("Exiting non-zero after an unrecoverable pipeline failure (orchestrator will restart).");
            std::process::exit(1);
        }

        info!("Gateway shutdown complete.");
    });

    Ok(())
}
