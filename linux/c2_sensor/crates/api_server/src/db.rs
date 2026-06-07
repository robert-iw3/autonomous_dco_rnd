use rusqlite::{Connection, OpenFlags};
use std::sync::Mutex;
use shared_models::config::CONFIG;

pub struct DatabaseManager {
    pub telemetry_db: Mutex<Connection>,
    pub auth_db: Option<Mutex<Connection>>,
}

impl DatabaseManager {
    pub fn new() -> Self {
        let db_path = &CONFIG.global.db_path;

        for attempt in 1..=30 {
            if std::path::Path::new(db_path).exists() {
                break;
            }
            if attempt == 30 {
                panic!("[-] FATAL: Database not created at {} after 60s.", db_path);
            }
            tracing::warn!("[!] Waiting for database at {} (attempt {}/30)...", db_path, attempt);
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        ).unwrap_or_else(|e| panic!("[-] Failed to mount database: {}", e));

        conn.execute_batch(
            "PRAGMA temp_store=MEMORY;
             PRAGMA mmap_size=268435456;
             PRAGMA cache_size=-64000;"
        ).expect("[-] Failed to optimize PRAGMA");

        conn.busy_handler(Some(busy_retry))
            .expect("[-] Failed to set busy handler");

        let auth_db = CONFIG.global.auth_db_path.as_ref().map(|path| {
            let auth_conn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_URI,
            ).unwrap_or_else(|e| panic!("[-] Failed to open auth database at {}: {}", path, e));

            auth_conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA busy_timeout=10000;"
            ).expect("[-] Failed to set auth PRAGMA");

            auth_conn.busy_handler(Some(busy_retry))
                .expect("[-] Failed to set auth busy handler");

            tracing::info!("[+] Auth database mounted at {}", path);
            Mutex::new(auth_conn)
        });

        Self {
            telemetry_db: Mutex::new(conn),
            auth_db,
        }
    }
}

fn busy_retry(attempts: i32) -> bool {
    if attempts >= 100 { return false; }
    std::thread::sleep(std::time::Duration::from_millis(
        (1u64 << attempts.min(7)).min(200)
    ));
    true
}