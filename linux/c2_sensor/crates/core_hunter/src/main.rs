use procfs::process::Process;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use shared_models::config::CONFIG;
use std::time::Duration;
use tracing::{error, info, warn};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const SENSOR_BINARIES: &[&str] = &[
    "api_server", "telemetry_ingest", "core_hunter", "active_defender",
    "c2-ml-engine", "baseline_learn", "nexus_forwarder",
    "tokio-rt-worker", "conmon",
];

fn is_sensor_process(name: &str, tree: &str) -> bool {
    SENSOR_BINARIES.iter().any(|s| name.contains(s) || tree.contains(s))
}

// ==============================================================================
// DESTINATION REPUTATION
// ==============================================================================
// Returns 0.0–1.0 based on how likely the destination is a C2 server.
// Loopback/unspecified can never be C2. RFC1918 is possible (lateral movement)
// but rare for C2. External IPs are the primary C2 indicator.
fn destination_weight(ip: &str) -> f64 {
    if ip == "0.0.0.0" || ip == "::" || ip.is_empty() {
        return 0.0; // Unspecified -- local syscall, not network C2
    }
    if ip.starts_with("127.") || ip == "::1" {
        return 0.0; // Loopback -- process talking to itself
    }
    if ip.starts_with("169.254.") || ip.starts_with("fe80:") {
        return 0.05; // Link-local -- mDNS, neighbor discovery
    }
    // RFC1918 / ULA -- possible lateral movement, unlikely C2 egress
    if ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("fc") || ip.starts_with("fd")
    {
        return 0.3;
    }
    // 172.16-31.x
    if ip.starts_with("172.") {
        if let Some(octet) = ip.split('.').nth(1).and_then(|s| s.parse::<u8>().ok()) {
            if (16..=31).contains(&octet) {
                return 0.3;
            }
        }
    }
    // Multicast
    if ip.starts_with("224.") || ip.starts_with("ff") {
        return 0.0;
    }
    1.0 // External -- the C2 threat surface
}

// ==============================================================================
// LINEAGE ANALYSIS -- process spawn chain as a signal
// ==============================================================================
// Returns a modifier (0.5–2.0) based on how suspicious the process lineage is.
// Normal desktop chains score low. Shell→binary chains score high.
fn lineage_weight(process_tree: &str, cmd_snippet: &str) -> f64 {
    let tree_lower = process_tree.to_lowercase();

    // Suspicious spawning: shell → network tool = potential C2 stager
    let shell_parent = tree_lower.contains("bash(") || tree_lower.contains("sh(")
        || tree_lower.contains("zsh(") || tree_lower.contains("python(")
        || tree_lower.contains("perl(");

    // Binary executed from world-writable or temp directories
    let suspicious_path = cmd_snippet.starts_with("/tmp/")
        || cmd_snippet.starts_with("/dev/shm/")
        || cmd_snippet.starts_with("/var/tmp/")
        || cmd_snippet.contains("/.local/share/")
        || cmd_snippet.starts_with("/run/user/");

    if shell_parent && suspicious_path {
        return 2.0; // Shell launched something from /tmp → high suspicion
    }
    if suspicious_path {
        return 1.5; // Unusual execution path
    }
    if shell_parent {
        return 1.3; // Shell parent with normal path
    }
    1.0 // Neutral
}

// ==============================================================================
// BINARY NAME EXTRACTION
// ==============================================================================
fn extract_binary_name(cmd_snippet: &str) -> String {
    if cmd_snippet.is_empty() { return String::new(); }
    let first_token = cmd_snippet.split_whitespace().next().unwrap_or("");
    first_token.rsplit('/').next().unwrap_or(first_token).to_string()
}

fn busy_retry(attempts: i32) -> bool {
    if attempts >= 50 { return false; }
    std::thread::sleep(Duration::from_millis((1u64 << attempts.min(7)).min(100)));
    true
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(&CONFIG.global.log_level).init();
    info!("[+] Core Hunter Orchestrator Initializing...");

    let db_path = &CONFIG.global.db_path;
    let mut conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI,
    ).expect("[-] FATAL: Core Hunter failed to connect to telemetry broker");

    conn.busy_handler(Some(busy_retry))
        .expect("[-] FATAL: Failed to set busy handler");

    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA auto_vacuum=INCREMENTAL;
         PRAGMA wal_autocheckpoint=1000;
         PRAGMA journal_size_limit=67108864;"
    ).unwrap_or_else(|e| warn!("[-] Failed to set optimizations: {}", e));

    info!("[+] Waiting for flows table...");
    for attempt in 1..=120 {
        match conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='flows'",
            [],
            |row| row.get::<_, u32>(0),
        ) {
            Ok(1) => {
                info!("[+] flows table ready after {}s", attempt);
                break;
            }
            _ => {
                if attempt == 120 {
                    error!("[-] FATAL: flows table not created after 120s");
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    info!("[+] Monitoring for raw telemetry flows...");

    loop {
        let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Watchdog]);

        let results = {
            let mut stmt = match conn.prepare(
                "SELECT rowid, pid, process_name, dst_port, interval, entropy,
                        outbound_ratio, dst_ip, dns_query, process_hash, dns_flags, cv
                 FROM flows
                 WHERE score = 0 AND suppressed = 0
                 LIMIT 100"
            ) {
                Ok(s) => s,
                Err(e) => {
                    error!("Database query prep failed: {}", e);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u16>(3)?,
                    row.get::<_, f64>(4)?,
                    row.get::<_, f64>(5)?,
                    row.get::<_, f64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8).unwrap_or_default(),
                    row.get::<_, String>(9).unwrap_or_default(),
                    row.get::<_, u16>(10).unwrap_or(0),
                    row.get::<_, f64>(11).unwrap_or(0.0),
                ))
            });

            match rows {
                Ok(iter) => iter.flatten().collect::<Vec<_>>(),
                Err(_) => vec![],
            }
        };

        if results.is_empty() {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }

        let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(t) => t,
            Err(e) => {
                warn!("[-] Failed to begin transaction: {}. Retrying next cycle.", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        for row in results {
            let (rowid, pid, process_name, dst_port, interval, entropy,
                 outbound_ratio, dst_ip, dns_query, _process_hash, dns_flags, cv) = row;

            let (process_tree, cmd_snippet) = reconstruct_lineage(pid as i32);

            // --- Self-process filter (architectural, not behavioral) ---
            if is_sensor_process(&process_name, &process_tree) {
                let _ = tx.execute(
                    "UPDATE flows SET suppressed = 1, score = 0 WHERE rowid = ?1",
                    rusqlite::params![rowid],
                );
                continue;
            }

            // --- Contextual weights (applied to rule scores, not as filters) ---
            let dst_w = destination_weight(&dst_ip);
            let lineage_w = lineage_weight(&process_tree, &cmd_snippet);

            let mut score: f64 = 0.0;
            let mut reasons = Vec::new();

            let mut tactic = "Command and Control".to_string();
            let mut technique = "T1071".to_string();
            let mut name = "Application Layer Protocol".to_string();
            let mut description = "Standard network connection".to_string();
            let mut masquerade_detected = false;

            // ==============================================================
            // RULE 1: High Payload Entropy (Encrypted C2)
            // ==============================================================
            // Entropy > 7.5 on captured payload bytes is strong on its own
            // but destination weight still modulates -- encrypted loopback
            // traffic is not C2.
            if entropy > 7.5 {
                let base = 40.0;
                let w = dst_w.max(0.2); // Entropy is still noteworthy even on internal
                score += base * w * lineage_w;
                reasons.push(format!(
                    "High payload entropy ({:.2} bits) → {:.0}pt [dst:{:.1}, lineage:{:.1}]",
                    entropy, base * w * lineage_w, dst_w, lineage_w
                ));
                technique = "T1573".to_string();
                name = "Encrypted Channel".to_string();
                description = "Payload matches Shannon entropy signatures of encrypted C2 frameworks.".to_string();
            }

            // ==============================================================
            // RULE 2: Beaconing Detection (signal convergence)
            // ==============================================================
            // Beaconing requires OUTBOUND activity. outbound_ratio = 0 means
            // the process is only receiving -- servers responding to clients,
            // not implants calling home. This is physics, not exclusion.
            //
            // CV windows:
            //   < 0.05  = mechanical (keep-alive, heartbeat, mDNS)
            //   0.05–0.35 = C2 jitter (attacker evasion range)
            //   > 0.40  = organic/human/bursty
            //
            // Scoring: base × corroboration × destination × lineage
            if interval > 0.0 && outbound_ratio > 0.0 {
                let mut beacon_base: f64 = 0.0;
                let mut beacon_reason = String::new();

                if cv >= 0.05 && cv <= 0.35 && interval < 120.0 {
                    // C2 jitter window -- the highest-confidence beaconing signal
                    beacon_base = 30.0;

                    // Corroboration: encrypted payload amplifies confidence
                    if entropy >= 5.0 {
                        beacon_base += 15.0;
                    }
                    // Corroboration: heavily outbound = calling home, not responding
                    if outbound_ratio > 0.7 {
                        beacon_base += 10.0;
                    }

                    beacon_reason = format!(
                        "Jittered beacon: {:.1}s interval, {:.1}% jitter, ent:{:.1}, out:{:.0}%",
                        interval, cv * 100.0, entropy, outbound_ratio * 100.0
                    );
                } else if cv < 0.05 && interval < 10.0 {
                    // Sub-10s mechanical -- only interesting if also encrypted + external
                    if entropy >= 6.0 && outbound_ratio > 0.5 {
                        beacon_base = 20.0;
                        beacon_reason = format!(
                            "Rapid mechanical + encrypted ({:.1}s, ent:{:.1})",
                            interval, entropy
                        );
                    }
                    // else: browser polling, keep-alive → score stays 0
                } else if interval >= 120.0 && interval <= 3600.0 && cv <= 0.30 {
                    // Long-sleep beaconing
                    beacon_base = 15.0;
                    if entropy >= 5.0 { beacon_base += 10.0; }
                    beacon_reason = format!(
                        "Long-sleep beacon: {:.0}s, CV:{:.3}",
                        interval, cv
                    );
                }

                if beacon_base > 0.0 {
                    let beacon_score = beacon_base * dst_w * lineage_w;
                    if beacon_score >= 5.0 {
                        score += beacon_score;
                        reasons.push(format!(
                            "{} → {:.0}pt [dst:{:.1}, lineage:{:.1}]",
                            beacon_reason, beacon_score, dst_w, lineage_w
                        ));
                    }
                }
            }

            // ==============================================================
            // RULE 3: LOLBin Detection
            // ==============================================================
            let lolbins = ["curl", "wget", "python", "python3", "bash", "sh", "nc", "ncat", "socat"];
            if lolbins.contains(&process_name.as_str()) && outbound_ratio > 0.8 {
                let base = 25.0 * dst_w * lineage_w;
                if base >= 5.0 {
                    score += base;
                    reasons.push(format!(
                        "LOLBin '{}' outbound-heavy ({:.0}%) → {:.0}pt",
                        process_name, outbound_ratio * 100.0, base
                    ));
                    technique = "T1059".to_string();
                    name = "Command and Scripting Interpreter".to_string();
                }
            }

            // ==============================================================
            // RULE 4: DNS Tunneling (Port 53 + high entropy)
            // ==============================================================
            // DNS tunneling works regardless of destination (uses recursive
            // resolvers), so dst_w gets a floor of 0.5 here.
            if dst_port == 53 && entropy > 6.0 {
                let w = dst_w.max(0.5);
                score += 50.0 * w;
                reasons.push(format!(
                    "DNS tunneling (port 53, entropy {:.2}) → {:.0}pt",
                    entropy, 50.0 * w
                ));
                technique = "T1071.004".to_string();
                name = "DNS".to_string();
                description = "High-entropy queries over port 53, indicating C2 over DNS.".to_string();
            }

            // ==============================================================
            // RULE 5: DGA Detection
            // ==============================================================
            if !dns_query.is_empty() {
                let domain_ent = domain_entropy(&dns_query);
                let label_count = dns_query.matches('.').count() + 1;
                let longest_label = dns_query.split('.').map(|l| l.len()).max().unwrap_or(0);

                if domain_ent > 3.5 && longest_label > 20 {
                    score += 45.0;
                    reasons.push(format!(
                        "DGA-suspected domain (entropy:{:.2}, label len:{}) → {}",
                        domain_ent, longest_label, dns_query
                    ));
                    technique = "T1568.002".to_string();
                    name = "Domain Generation Algorithms".to_string();
                    description = "DNS query exhibits high character entropy and anomalous label length consistent with DGA.".to_string();
                } else if label_count > 5 {
                    score += 30.0;
                    reasons.push(format!("Deeply nested subdomain (depth: {}): {}", label_count, dns_query));
                }
            }

            // NXDOMAIN frequency
            if dns_flags & 0x000F == 3 {
                if let Ok(nx_count) = tx.query_row(
                    "SELECT COUNT(*) FROM flows
                     WHERE process_name = ?1 AND dns_flags & 15 = 3
                       AND timestamp > unixepoch() - 3600 AND suppressed = 0",
                    rusqlite::params![process_name],
                    |row| row.get::<_, u32>(0),
                ) {
                    if nx_count > 20 {
                        score += 50.0;
                        reasons.push(format!(
                            "High NXDOMAIN rate ({}/hr) -- DGA-C2 correlation",
                            nx_count
                        ));
                        technique = "T1568.002".to_string();
                        name = "Domain Generation Algorithms".to_string();
                        description = format!(
                            "Process {} generated {} NXDOMAIN DNS failures in the last hour.",
                            process_name, nx_count
                        );
                    } else if nx_count > 5 {
                        score += 20.0;
                        reasons.push(format!("Elevated NXDOMAIN rate ({}/hr)", nx_count));
                    }
                }
            }

            // ==============================================================
            // RULE 6: Process Masquerading
            // ==============================================================
            // True masquerade: comm doesn't match the binary. But the
            // LOCATION of the binary matters more than a hard exclusion list.
            // - Binary from /usr/bin, /usr/lib → expected system path
            // - Binary from /tmp, /dev/shm → suspicious path
            // Thread-name mismatch in multi-threaded apps is handled by
            // checking whether the real binary (from process_tree) is in
            // a standard system path -- not by listing app names.
            {
                let binary_from_cmd = extract_binary_name(&cmd_snippet);
                let comm_lower = process_name.to_lowercase();
                let binary_lower = binary_from_cmd.to_lowercase();

                let name_mismatch = !binary_lower.is_empty()
                    && !binary_lower.contains(&comm_lower)
                    && !comm_lower.contains(&binary_lower)
                    && binary_lower != "unknown";

                if name_mismatch {
                    // Check if the binary is in a standard system path
                    let in_system_path = cmd_snippet.starts_with("/usr/")
                        || cmd_snippet.starts_with("/opt/")
                        || cmd_snippet.starts_with("/snap/")
                        || cmd_snippet.starts_with("/nix/");

                    let in_suspicious_path = cmd_snippet.starts_with("/tmp/")
                        || cmd_snippet.starts_with("/dev/shm/")
                        || cmd_snippet.starts_with("/var/tmp/")
                        || cmd_snippet.contains("/.cache/");

                    if in_suspicious_path {
                        // Strong masquerade: name mismatch + suspicious execution path
                        score += 50.0;
                        masquerade_detected = true;
                        reasons.push(format!(
                            "Masquerade from suspicious path: comm='{}', binary='{}', path='{}'",
                            process_name, binary_from_cmd, cmd_snippet.chars().take(80).collect::<String>()
                        ));
                        tactic = "Defense Evasion".to_string();
                        technique = "T1036".to_string();
                        name = "Masquerading".to_string();
                    } else if !in_system_path {
                        // Moderate: name mismatch + non-standard path
                        score += 25.0;
                        masquerade_detected = true;
                        reasons.push(format!(
                            "Name mismatch (non-standard path): comm='{}', binary='{}'",
                            process_name, binary_from_cmd
                        ));
                        tactic = "Defense Evasion".to_string();
                        technique = "T1036".to_string();
                        name = "Masquerading".to_string();
                    }
                    // System path + name mismatch → thread name, not masquerade. No score.
                }
            }

            // ==============================================================
            // RULE 7: Exfiltration
            // ==============================================================
            if let Ok(total_bytes) = tx.query_row(
                "SELECT COALESCE(SUM(packet_size_mean), 0) FROM flows
                 WHERE process_name = ?1 AND dst_ip = ?2 AND outbound_ratio > 0.5
                   AND timestamp > unixepoch() - 3600 AND suppressed = 0",
                rusqlite::params![process_name, dst_ip],
                |row| row.get::<_, f64>(0),
            ) {
                if total_bytes > 10_000_000.0 {
                    let exfil_score = 35.0 * dst_w.max(0.3) * lineage_w;
                    score += exfil_score;
                    reasons.push(format!(
                        "Exfiltration: {:.1} MB to {} in 1h → {:.0}pt",
                        total_bytes / 1_000_000.0, dst_ip, exfil_score
                    ));
                    if tactic == "Command and Control" {
                        tactic = "Exfiltration".to_string();
                        technique = "T1041".to_string();
                        name = "Exfiltration Over C2 Channel".to_string();
                        description = format!(
                            "Process {} transferred {:.1} MB to {} in the last hour.",
                            process_name, total_bytes / 1_000_000.0, dst_ip
                        );
                    }
                }
            }

            // ==============================================================
            // FINAL SCORING
            // ==============================================================
            let final_score = (score.round() as u32).min(100);

            let reasons_json = serde_json::to_string(&reasons).unwrap_or_else(|_| "[]".to_string());

            let update_res = tx.execute(
                "UPDATE flows
                 SET score = ?1,
                     cmd_snippet = ?2,
                     process_tree = ?3,
                     masquerade_detected = ?4,
                     reasons = ?5,
                     mitre_tactic = ?6,
                     mitre_technique = ?7,
                     mitre_name = ?8,
                     description = ?9
                 WHERE rowid = ?10",
                rusqlite::params![
                    final_score, cmd_snippet, process_tree, masquerade_detected,
                    reasons_json, tactic, technique, name, description, rowid
                ],
            );

            if let Err(e) = update_res {
                warn!("Failed to update enriched flow rowid {}: {}", rowid, e);
            }
        }
        if let Err(e) = tx.commit() {
            warn!("[-] Batch enrichment commit failed: {}", e);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

// ==============================================================================
// HELPERS
// ==============================================================================

fn domain_entropy(domain: &str) -> f64 {
    if domain.is_empty() { return 0.0; }
    let bytes = domain.as_bytes();
    let mut counts = [0u32; 256];
    for &b in bytes { counts[b as usize] += 1; }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn reconstruct_lineage(pid: i32) -> (String, String) {
    let mut tree = Vec::new();
    let mut current_pid = pid;
    let mut initial_cmd = String::from("");

    for depth in 0..10 {
        if let Ok(process) = Process::new(current_pid) {
            let comm = process.stat().map(|s| s.comm).unwrap_or_else(|_| "unknown".to_string());

            if depth == 0 {
                if let Ok(cmdline) = process.cmdline() {
                    if !cmdline.is_empty() {
                        initial_cmd = cmdline.join(" ").chars().take(255).collect();
                    }
                }
            }

            tree.push(format!("{}({})", comm, current_pid));

            if let Ok(stat) = process.stat() {
                if stat.ppid == 0 || stat.ppid == 1 {
                    tree.push("systemd(1)".to_string());
                    break;
                }
                current_pid = stat.ppid;
            } else {
                break;
            }
        } else {
            tree.push(format!("PID_{}_EXITED", current_pid));
            break;
        }
    }

    tree.reverse();
    (tree.join(" -> "), initial_cmd)
}