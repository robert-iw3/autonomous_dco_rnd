use shared_models::config::CONFIG;
use api_server::run_server;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(&CONFIG.global.log_level)
        .init();

    tracing::info!("[+] API Server starting...");

    if let Err(e) = run_server().await {
        tracing::error!("[-] FATAL: API Server crashed: {}", e);
    }
}