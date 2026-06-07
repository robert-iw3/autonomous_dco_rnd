use libbpf_rs::MapHandle;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use rusqlite::{Connection, OpenFlags};
use shared_models::config::CONFIG;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tracing::{error, info, warn};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn busy_retry(attempts: i32) -> bool {
    if attempts >= 50 { return false; }
    let delay_ms = (1u64 << attempts.min(7)).min(100);
    std::thread::sleep(Duration::from_millis(delay_ms));
    true
}

fn main() {
    tracing_subscriber::fmt().with_env_filter(&CONFIG.global.log_level).init();
    info!("[+] Active Defender Initializing...");

    if !CONFIG.mitigation.enabled {
        warn!("[-] Mitigation is disabled. Entering standby mode to satisfy supervisor.");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    if CONFIG.mitigation.dry_run {
        info!("[!] Defender running in DRY-RUN mode. No actual mitigations will be applied.");
    }

    let db_path = &CONFIG.global.db_path;
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI,
    ).expect("[-] FATAL: Defender failed to connect to telemetry broker");

    conn.busy_handler(Some(busy_retry))
        .expect("[-] FATAL: Failed to set busy handler");

    let map_v4_path = "/sys/fs/bpf/c2_blocklist_v4";
    let blocklist_v4 = MapHandle::from_pinned_path(map_v4_path)
        .unwrap_or_else(|_| panic!("[-] FATAL: Failed to load pinned eBPF map at {}", map_v4_path));

    let map_v6_path = "/sys/fs/bpf/c2_blocklist_v6";
    let blocklist_v6 = MapHandle::from_pinned_path(map_v6_path)
        .unwrap_or_else(|_| panic!("[-] FATAL: Failed to load pinned eBPF map at {}", map_v6_path));

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mitigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT,
            target_value TEXT,
            mitigated_at REAL,
            reason TEXT
        )"
    ).unwrap_or_else(|e| warn!("[-] Failed to create mitigations table: {}", e));

    info!("[+] Attached to XDP blocklist maps (v4 + v6). Commencing threat monitoring loop.");

    let mut mitigated_pids: HashSet<u32> = HashSet::new();
    let mut mitigated_ips: HashSet<String> = HashSet::new();

    if let Ok(mut stmt) = conn.prepare("SELECT target_type, target_value FROM mitigations") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                match row.0.as_str() {
                    "pid" => { if let Ok(pid) = row.1.parse::<u32>() { mitigated_pids.insert(pid); } },
                    "ip" => { mitigated_ips.insert(row.1); },
                    _ => {}
                }
            }
        }
    }
    info!("[+] Restored {} PIDs and {} IPs from mitigation history", mitigated_pids.len(), mitigated_ips.len());

    let threshold = CONFIG.mitigation.containment_threshold;

    loop {
        let mut stmt = match conn.prepare(
            "SELECT pid, dst_ip, process_name, score
             FROM flows
             WHERE score >= ?1 AND suppressed = 0
             ORDER BY timestamp DESC LIMIT 50"
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Database query preparation failed: {}", e);
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        let rows = stmt.query_map([threshold], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?,
            ))
        });

        if let Ok(iterator) = rows {
            for row in iterator.flatten() {
                let (pid, dst_ip, process_name, score) = row;

                if pid > 0 && !mitigated_pids.contains(&pid) {
                    mitigate_process(pid, &process_name, score, CONFIG.mitigation.dry_run);
                    mitigated_pids.insert(pid);
                    let _ = conn.execute(
                        "INSERT OR IGNORE INTO mitigations (target_type, target_value, mitigated_at, reason)
                         VALUES ('pid', ?1, unixepoch(), ?2)",
                        rusqlite::params![pid.to_string(), format!("score={}", score)],
                    );
                }

                if !mitigated_ips.contains(&dst_ip) {
                    mitigate_network(&blocklist_v4, &blocklist_v6, &dst_ip, CONFIG.mitigation.dry_run);
                    mitigated_ips.insert(dst_ip.clone());
                    let _ = conn.execute(
                        "INSERT OR IGNORE INTO mitigations (target_type, target_value, mitigated_at, reason)
                         VALUES ('ip', ?1, unixepoch(), ?2)",
                        rusqlite::params![dst_ip, format!("score={}", score)],
                    );
                }
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn mitigate_process(pid: u32, process_name: &str, score: u32, dry_run: bool) {
    if dry_run {
        warn!("[DRY-RUN] Would terminate PID {} ({}) - Score: {}", pid, process_name, score);
        return;
    }

    let target_pid = Pid::from_raw(pid as i32);
    match signal::kill(target_pid, Signal::SIGKILL) {
        Ok(_) => info!("[DEFENSE] Terminated malicious PID {} ({})", pid, process_name),
        Err(nix::errno::Errno::ESRCH) => (), // Process already exited normally
        Err(e) => error!("Failed to terminate PID {}: {}", pid, e),
    }
}

fn mitigate_network(blocklist_v4: &MapHandle, blocklist_v6: &MapHandle, ip_str: &str, dry_run: bool) {
    if dry_run {
        warn!("[DRY-RUN] Would inject {} into XDP hardware blocklist", ip_str);
        return;
    }

    let value = [1u8];

    match IpAddr::from_str(ip_str) {
        Ok(IpAddr::V4(v4)) => {
            let key = u32::from_ne_bytes(v4.octets()).to_ne_bytes();
            match blocklist_v4.update(&key, &value, libbpf_rs::MapFlags::ANY) {
                Ok(_) => info!("[DEFENSE] Network Blackholed (v4): Injected {} into XDP Map", ip_str),
                Err(e) => error!("Failed to update XDP v4 map for {}: {}", ip_str, e),
            }
        }
        Ok(IpAddr::V6(v6)) => {
            let key = v6.octets();
            match blocklist_v6.update(&key, &value, libbpf_rs::MapFlags::ANY) {
                Ok(_) => info!("[DEFENSE] Network Blackholed (v6): Injected {} into XDP Map", ip_str),
                Err(e) => error!("Failed to update XDP v6 map for {}: {}", ip_str, e),
            }
        }
        Err(_) => warn!("[!] Could not parse IP for mitigation: {}", ip_str),
    }
}