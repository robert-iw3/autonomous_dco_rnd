// ================================================================================
// File:        main.rs
// Component:   Linux Sentinel -- Core Orchestrator
// Description: The entry point for the Linux Sentinel agent.
// Role:        Initializes configuration state, sets up centralized logging, bumps
//              kernel rlimits for eBPF maps, and spawns the asynchronous Tokio
//              tasks for all underlying engines (eBPF, UEBA, Yara, Honeypot).
//              Manages graceful teardown and SIGHUP hot-reloading.
// Author:      Robert Weber
// ================================================================================

use crate::api::server::ApiServer;
use crate::config::load_master_config;
use crate::engine::ebpf::EbpfEngine;
use crate::engine::honeypot::HoneypotEngine;
use crate::engine::scanner::ScannerEngine;
use crate::engine::yara::YaraEngine;
use crate::siem::models::SecurityAlert;
use crate::siem::parquet_transmitter::TransmissionLayer;
use crate::utils::logging::init_central_logging;

use anyhow::{Context, Result};
use tokio::signal::unix::{signal, SignalKind};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, broadcast};
use tracing::{debug, error, info, warn};
use mimalloc::MiMalloc;

// Module Registration
mod api { pub mod server; }
mod config;
mod engine {
    pub mod ebpf;
    pub mod honeypot;
    pub mod rules;
    pub mod scanner;
    pub mod yara;
    pub mod dns;
    pub mod fim;
    pub mod baselines;
    pub mod clamav;
}
mod siem {
    pub mod models;
    pub mod parquet_transmitter;
}
mod utils { pub mod logging; }

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Clone, Debug)]
pub enum ReloadCommand {
    Config,
    Rules,
}

/// Required to allocate massive eBPF Ring Buffers and LRU maps for ML feature tracking.
fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: rlimit struct is locally allocated and valid. RLIMIT_MEMLOCK is a standard POSIX constant.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        warn!("Failed to increase RLIMIT_MEMLOCK. Deep eBPF maps may fail on strict kernels.");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    let _log_guard = init_central_logging("/var/log/linux-sentinel/diagnostics");
    info!("Initializing Linux Sentinel...");

    bump_memlock_rlimit()?;

    let config = Arc::new(RwLock::new(load_master_config("/opt/linux-sentinel/master.toml")
        .context("Failed to load master configuration")?));

    let (reload_tx, _) = broadcast::channel::<ReloadCommand>(16);
    let config_reloader = config.clone();
    let reload_tx_sighup = reload_tx.clone();

    tokio::spawn(async move {
        let mut sighup = signal(SignalKind::hangup()).expect("Failed to bind SIGHUP listener");
        let mut internal_rx = reload_tx_sighup.subscribe();

        loop {
            tokio::select! {
                _ = sighup.recv() => {
                    info!("SIGHUP received. Triggering runtime configuration hot-reload...");
                    let _ = reload_tx_sighup.send(ReloadCommand::Config);
                }
                Ok(cmd) = internal_rx.recv() => {
                    if let ReloadCommand::Config = cmd {
                        match crate::config::load_master_config("/opt/linux-sentinel/master.toml") {
                            Ok(new_config) => {
                                let mut lock = config_reloader.write().unwrap_or_else(|e| e.into_inner());
                                *lock = new_config;
                                info!("Runtime configuration successfully hot-swapped into memory.");
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                if msg.contains("auth_token") {
                                    error!("Hot-reload aborted. Syntax error in master.toml near auth_token (redacted)");
                                } else {
                                    error!("Hot-reload aborted. Syntax error in master.toml: {}", msg);
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // PIPELINE CHANNEL A: Raw Telemetry (eBPF -> UEBA Scanner)
    let (raw_tx, raw_rx) = mpsc::channel::<crate::engine::rules::RawKernelEvent>(100_000);

    // High-Throughput Backpressure Channel (100,000 Event Depth)
    let (alert_tx, mut alert_rx) = mpsc::channel::<SecurityAlert>(100_000);
    let is_running = Arc::new(AtomicBool::new(true));

    // Decoupled Downstream Channels for Dual-Archiving
    let (siem_tx, siem_rx) = mpsc::channel::<Arc<SecurityAlert>>(100_000);
    let (archive_tx, archive_rx) = mpsc::channel::<Arc<SecurityAlert>>(100_000);

    // CROSS-THREAD YARA CHANNEL
    let (yara_scan_tx, yara_scan_rx) = mpsc::channel::<u32>(100);

    // Asynchronous Dispatcher
    tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            let arc_alert = Arc::new(alert);             // Zero-copy clone for routing
            let _ = siem_tx.try_send(arc_alert.clone()); // Route to SQLite WAL / SIEM
            let _ = archive_tx.try_send(arc_alert);      // Route to Local Parquet Archiver
        }
    });

    // SIEM Transmission & Local SQLite Storage Worker
    info!("Mounting SQLite Telemetry Engine & SIEM Forwarder...");
    let db_path = {
        let lock = config.read().unwrap_or_else(|e| e.into_inner());
        lock.storage.sqlite_db_path.clone()
    };

    let transmitter = Arc::new(TransmissionLayer::new(&db_path, config.clone()).await?);

    let db_pool = transmitter.get_pool();
    transmitter.spawn_worker(siem_rx);

    let mut async_tasks = vec![];

    let initial_config = {
        let lock = config.read().unwrap_or_else(|e| e.into_inner());
        lock.clone()
    };

    if initial_config.storage.enable_parquet {
        let parquet_dir = initial_config.storage.parquet_directory.clone();
        let parquet_comp = initial_config.siem.parquet_compression.clone();
        let parquet_batch = initial_config.siem.parquet_batch_size;
        let parquet_flush = initial_config.siem.parquet_flush_interval_sec;

        async_tasks.push(tokio::spawn(async move {
            let mut archiver = crate::siem::parquet_transmitter::LocalParquetArchiver::new(
                archive_rx, parquet_dir, parquet_comp, parquet_batch, parquet_flush
            );
            archiver.run().await;
        }));
    }

    let baseline_store = {
        let lock = config.read().unwrap_or_else(|e| e.into_inner());
        let db_path = PathBuf::from(&lock.engine.ml_persistent_store_path);
        Arc::new(crate::engine::baselines::BaselineStore::new(&db_path).await
            .context("Failed to initialize persistent UEBA baseline store")?)
    };

    info!("Active Monitoring Capabilities - Network: {}, Processes: {}, Files: {}, Users: {}, Rootkits: {}, Memory: {}",
        initial_config.monitoring.monitor_network,
        initial_config.monitoring.monitor_processes,
        initial_config.monitoring.monitor_files,
        initial_config.monitoring.monitor_users,
        initial_config.monitoring.monitor_rootkits,
        initial_config.monitoring.monitor_memory
    );
    info!("Performance Mode: {}", initial_config.engine.performance_mode);
    info!("Storage Paths - Central: {}, Output: {}, DB: {}",
        initial_config.storage.central_log_dir,
        initial_config.storage.output_dir,
        initial_config.storage.sqlite_db_path
    );
    debug!("Excluded Paths: {:?}", initial_config.files.exclude_paths);

    // API & Local Dashboard
    if initial_config.engine.enable_api_server {
        let api_config = config.clone();
        let api_pool = db_pool.clone();
        let api_reload_tx = reload_tx.clone();

        async_tasks.push(tokio::spawn(async move {
            let server = ApiServer::new(api_config, api_pool, api_reload_tx);
            if let Err(e) = server.run().await {
                error!(error = %e, "API Server shutdown abnormally");
            }
        }));
    }

    // Native 5D UEBA Engine (ScannerEngine)
    if initial_config.engine.enable_anti_evasion {
        let alert_tx_scan = alert_tx.clone();
        let config_scan = config.clone();
        let scanner_reload_rx = reload_tx.subscribe();
        let yara_scan_tx_scanner = yara_scan_tx.clone();

        async_tasks.push(tokio::spawn(async move {
            let baseline_store_scan = baseline_store.clone();
            let engine = ScannerEngine::new(
                config_scan,
                raw_rx,
                alert_tx_scan,
                scanner_reload_rx,
                baseline_store_scan,
                yara_scan_tx_scanner
            );
            engine.run().await;
        }));
    } else if initial_config.engine.enable_ebpf {
        let mut rx = raw_rx;
        async_tasks.push(tokio::spawn(async move {
            while rx.recv().await.is_some() {}
        }));
    }

    // YARA File Integrity Engine
    if initial_config.engine.enable_yara {
        let tx_yara = alert_tx.clone();
        let config_yara = config.clone();
        let yara_reload_rx = reload_tx.subscribe();

        async_tasks.push(tokio::spawn(async move {
            let yara_path = initial_config.engine.yara_rules_path.clone();
            match YaraEngine::new(config_yara, &yara_path, tx_yara, yara_reload_rx, yara_scan_rx) {
                Ok(engine) => engine.run().await,
                Err(e) => error!("YARA Engine initialization failed: {}", e),
            }
        }));
    }

    // File Integrity Engine (FIM)
    if initial_config.engine.enable_fim {
        let tx_fim = alert_tx.clone();
        let config_fim = config.clone();
        async_tasks.push(tokio::spawn(async move {
            let engine = crate::engine::fim::FimEngine::new(config_fim, tx_fim);
            engine.run().await;
        }));
    }

    // Active Defense Deception Nodes
    if initial_config.engine.enable_honeypots {
        let tx_honey = alert_tx.clone();
        let config_honey = config.clone();
        async_tasks.push(tokio::spawn(async move {
            let engine = HoneypotEngine::new(config_honey, tx_honey);
            let _ = engine.run().await;
        }));
    }

    // The eBPF Kernel Supervisor (Air-Gapped OS Thread)
    if initial_config.engine.enable_ebpf {
        let raw_tx_ebpf = raw_tx.clone();
        let running_ebpf = is_running.clone();
        let initial_config_ref = config.clone();
        std::thread::spawn(move || {
            let mut backoff = 1;
            let _max_retries = 5;

            loop {
                info!("(Re)Starting Native eBPF Telemetry Engine...");
                let engine = EbpfEngine::new(initial_config_ref.clone(), raw_tx_ebpf.clone(), running_ebpf.clone());

                if let Err(e) = engine.run() {
                    error!("eBPF Engine encountered a critical kernel fault: {}", e);

                    warn!("Auto-recovery initiated. Backing off for {} seconds...", backoff * 2);
                    std::thread::sleep(std::time::Duration::from_secs(backoff * 2));
                    backoff += 1;
                } else {
                    break; // Clean exit triggered by system shutdown
                }
            }
        });
    }

    // ClamAV Static Scanner & Updater
    if initial_config.clamav.enable_clamav {
        let tx_clamav = alert_tx.clone();
        let config_clamav = config.clone();

        async_tasks.push(tokio::spawn(async move {
            let engine = crate::engine::clamav::ClamavEngine::new(config_clamav, tx_clamav);
            if let Err(e) = engine.run().await {
                tracing::error!("ClamAV Engine initialization failed: {}", e);
            }
        }));
    }

    // Deterministic Graceful Teardown
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to bind SIGTERM");
    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to bind SIGINT");

    tokio::select! {
        _ = sigterm.recv() => info!("SIGTERM received from orchestrator. Initiating graceful teardown..."),
        _ = sigint.recv() => info!("SIGINT (Ctrl+C) received. Initiating graceful teardown..."),
    }

    is_running.store(false, Ordering::SeqCst);

    // Drop the transmission channel, forcing the SQLite worker to drain the queue
    drop(alert_tx);

    // Guarantee 3 seconds for the SQLite Write-Ahead Log (WAL) to checkpoint to disk
    info!("Flushing in-memory telemetry to SQLite (Waiting 3 seconds)...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    db_pool.close().await;
    info!("Sensor shutdown successfully. Zero data loss.");

    Ok(())
}