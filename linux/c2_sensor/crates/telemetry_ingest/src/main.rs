use crossbeam_channel::{bounded, Receiver, Sender};
use libbpf_rs::{RingBufferBuilder, ObjectBuilder};
use rusqlite::{Connection, OpenFlags};
use shared_models::config::CONFIG;
use shared_models::telemetry::KernelEvent;
use std::collections::HashMap;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{info, warn, error};
use mimalloc::MiMalloc;
use moka::sync::Cache;
use sha2::{Sha256, Digest};
use md5;
use std::{env, fs};
use once_cell::sync::Lazy;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Maps PID → most recent dns_query, expires after 30 seconds.
/// Used to correlate DNS lookups with subsequent TCP connections from the same process.
static DNS_PID_CACHE: Lazy<Cache<u32, String>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(50_000)
        .time_to_live(std::time::Duration::from_secs(30))
        .build()
});

/// Maps file path → SHA256 hash to prevent re-hashing the same binaries.
static HASH_CACHE: Lazy<Cache<String, String>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(10_000)
        .time_to_live(std::time::Duration::from_secs(3600)) // 1 hour TTL
        .build()
});

static SENSOR_IDENTITY: Lazy<String> = Lazy::new(|| {
    let machine_id = fs::read_to_string("/etc/machine-id")
        .unwrap_or_else(|_| "unknown-machine".to_string())
        .trim()
        .to_string();

    let node_name = env::var("KUBE_NODE_NAME").unwrap_or_default();
    let pod_uid = env::var("POD_UID").unwrap_or_default();

    let raw_identity = format!("{}-{}-{}", machine_id, node_name, pod_uid);
    let mut hasher = Sha256::new();
    hasher.update(raw_identity.as_bytes());
    hex::encode(hasher.finalize())
});

/// Must match the eBPF event_t struct exactly (repr(C) layout).
/// Field order, types, and padding must be identical to c2_probe.bpf.c.
#[repr(C)]
struct RawEvent {
    pid: u32,
    uid: u32,
    event_type: u32,
    af: u8,
    dns_flags: u16,
    _pad: [u8; 1],
    saddr: [u8; 16],
    daddr: [u8; 16],
    dport: u16,
    is_outbound: u16,
    packet_size: u32,
    ts: u64,
    interval_ns: u64,
    comm: [u8; 16],
    payload: [u8; 256],
}

fn get_process_hash(path: &str) -> String {
    HASH_CACHE.get_with(path.to_string(), || {
        if let Ok(bytes) = fs::read(path) {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            format!("{:x}", hasher.finalize())
        } else {
            "UNKNOWN".to_string()
        }
    })
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let mut nonzero = 0;
    for &c in &counts { if c > 0 { nonzero += 1; } }
    if nonzero <= 1 { return 0.0; }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn parse_dns_query(payload: &[u8]) -> String {
    if payload.len() < 13 { return String::new(); }
    let mut offset = 12;
    let mut labels: Vec<String> = Vec::new();

    for _ in 0..32 {
        if offset >= payload.len() { break; }
        let len = payload[offset] as usize;
        if len == 0 { break; }
        offset += 1;
        if offset + len > payload.len() { break; }
        if let Ok(label) = std::str::from_utf8(&payload[offset..offset + len]) {
            labels.push(label.to_string());
        } else {
            labels.push(hex::encode(&payload[offset..offset + len]));
        }
        offset += len;
    }
    labels.join(".")
}

/// Compute JA3 hash from TLS Client Hello payload.
/// Returns empty string if payload is not a Client Hello or is truncated.
/// JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
fn compute_ja3(payload: &[u8]) -> String {
    // Minimum: content type (1) + version (2) + length (2) + handshake type (1) = 6 bytes
    if payload.len() < 6 { return String::new(); }

    // TLS Record Layer: 0x16 = Handshake
    if payload[0] != 0x16 { return String::new(); }

    // Handshake type at offset 5: 0x01 = Client Hello
    if payload[5] != 0x01 { return String::new(); }

    // Client Hello body starts at offset 9 (record header 5 + handshake header 4)
    if payload.len() < 44 { return String::new(); } // minimum Client Hello

    let mut off = 9;

    // Client Hello Version (2 bytes)
    if off + 2 > payload.len() { return String::new(); }
    let version = u16::from_be_bytes([payload[off], payload[off + 1]]);
    off += 2;

    // Random (32 bytes)
    off += 32;
    if off >= payload.len() { return String::new(); }

    // Session ID (1-byte length + variable)
    let sid_len = payload[off] as usize;
    off += 1 + sid_len;
    if off + 2 > payload.len() { return String::new(); }

    // Cipher Suites (2-byte length + list of 2-byte values)
    let cs_len = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
    off += 2;
    if off + cs_len > payload.len() { return String::new(); }

    let mut ciphers = Vec::new();
    let cs_end = off + cs_len;
    while off + 1 < cs_end {
        let cs = u16::from_be_bytes([payload[off], payload[off + 1]]);
        // Skip GREASE values (0x_a_a pattern)
        if cs & 0x0F0F != 0x0A0A {
            ciphers.push(cs.to_string());
        }
        off += 2;
    }
    off = cs_end;

    // Compression Methods (1-byte length + variable)
    if off >= payload.len() { return String::new(); }
    let cm_len = payload[off] as usize;
    off += 1 + cm_len;

    // Extensions (2-byte total length + list)
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();

    if off + 2 <= payload.len() {
        let ext_total = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
        off += 2;
        let ext_end = (off + ext_total).min(payload.len());

        while off + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([payload[off], payload[off + 1]]);
            let ext_len = u16::from_be_bytes([payload[off + 2], payload[off + 3]]) as usize;
            off += 4;

            // Skip GREASE
            if ext_type & 0x0F0F != 0x0A0A {
                extensions.push(ext_type.to_string());
            }

            let ext_data_end = (off + ext_len).min(ext_end);

            // Extension 0x000A: Supported Groups (Elliptic Curves)
            if ext_type == 0x000A && off + 2 <= ext_data_end {
                let list_len = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
                let mut eoff = off + 2;
                let list_end = (eoff + list_len).min(ext_data_end);
                while eoff + 1 < list_end {
                    let curve = u16::from_be_bytes([payload[eoff], payload[eoff + 1]]);
                    if curve & 0x0F0F != 0x0A0A {
                        elliptic_curves.push(curve.to_string());
                    }
                    eoff += 2;
                }
            }

            // Extension 0x000B: EC Point Formats
            if ext_type == 0x000B && off < ext_data_end {
                let list_len = payload[off] as usize;
                let mut eoff = off + 1;
                let list_end = (eoff + list_len).min(ext_data_end);
                while eoff < list_end {
                    ec_point_formats.push(payload[eoff].to_string());
                    eoff += 1;
                }
            }

            off = ext_data_end;
        }
    }

    let ja3_str = format!("{},{},{},{},{}",
        version,
        ciphers.join("-"),
        extensions.join("-"),
        elliptic_curves.join("-"),
        ec_point_formats.join("-"),
    );

    format!("{:x}", md5::compute(ja3_str.as_bytes()))
}

fn parse_ip_addr(af: u8, raw: &[u8; 16]) -> IpAddr {
    if af == 6 {
        IpAddr::V6(Ipv6Addr::from(*raw))
    } else {
        IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
    }
}

fn busy_retry(attempts: i32) -> bool {
    if attempts >= 100 { return false; }
    let delay_ms = (1u64 << attempts.min(7)).min(200);
    std::thread::sleep(Duration::from_millis(delay_ms));
    true
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter(&CONFIG.global.log_level).init();
    info!("[+] Initializing Telemetry Ingest Pipeline");

    let (tx, rx): (Sender<KernelEvent>, Receiver<KernelEvent>) = bounded(100_000);

    let db_path = CONFIG.global.db_path.clone();
    std::thread::spawn(move || {
        start_database_writer(db_path, rx);
    });

    let bpf_path = &CONFIG.ebpf.bpf_object_path;
    let mut obj = ObjectBuilder::default()
        .open_file(bpf_path)?
        .load()?;

    let mut links = Vec::new();
    for prog in obj.progs_iter_mut() {
        if prog.section().starts_with("xdp") {
            info!("[*] Skipping XDP program '{}' -- attach via active_defender when mitigation is enabled", prog.name());
            continue;
        }
        links.push(prog.attach()?);
    }

    {
        let trusted_map = obj.map_mut("trusted_pids").expect("trusted_pids map not found");
        let val: [u8; 1] = [1u8];
        let my_pid = std::process::id();
        let _ = trusted_map.update(&my_pid.to_ne_bytes(), &val, libbpf_rs::MapFlags::ANY);

        if let Ok(my_proc) = procfs::process::Process::new(my_pid as i32) {
            if let Ok(stat) = my_proc.stat() {
                let ppid = stat.ppid as u32;
                let _ = trusted_map.update(&ppid.to_ne_bytes(), &val, libbpf_rs::MapFlags::ANY);
                if let Ok(all) = procfs::process::all_processes() {
                    for proc in all.flatten() {
                        if let Ok(s) = proc.stat() {
                            if s.ppid == ppid as i32 {
                                let pid = s.pid as u32;
                                let _ = trusted_map.update(&pid.to_ne_bytes(), &val, libbpf_rs::MapFlags::ANY);
                            }
                        }
                    }
                }
            }
        }
        info!("[+] Trusted PID filter populated with sensor processes");
    }

    let mut builder = RingBufferBuilder::new();
    let map = obj.map("rb").expect("[-] Ring buffer map 'rb' not found");

    builder.add(map, move |data| {
        if data.len() < std::mem::size_of::<RawEvent>() {
            return 0;
        }

        let raw = unsafe { &*(data.as_ptr() as *const RawEvent) };
        let dst_ip = parse_ip_addr(raw.af, &raw.daddr).to_string();

        let event_type = match raw.event_type {
            1 => "exec", 2 => "connect", 3 => "send", 4 => "recv",
            5 => "memfd", 6 => "dns", 7 => "tcp_payload",
            8 => "openat", 9 => "dns_response", _ => "unknown",
        }.to_string();

        let entropy = match raw.event_type {
            6 | 7 => shannon_entropy(&raw.payload),
            _ => 0.0,
        };

        let dns_query = match raw.event_type {
            6 | 9 => parse_dns_query(&raw.payload),
            _ => String::new(),
        };

        // Populate PID→domain cache on DNS events
        if (raw.event_type == 6 || raw.event_type == 9) && !dns_query.is_empty() {
            DNS_PID_CACHE.insert(raw.pid, dns_query.clone());
        }

        let dns_flags = match raw.event_type {
            6 | 9 => raw.dns_flags,
            _ => 0,
        };

        let binary_path = format!("/proc/{}/exe", raw.pid);
        let process_hash = get_process_hash(&binary_path);

        // Compute JA3 for TLS Client Hello events
        let ja3_hash = match raw.event_type {
            7 if raw.dport == 443 || raw.dport == 8443 || raw.dport == 8080 => {
                compute_ja3(&raw.payload)
            }
            _ => String::new(),
        };

        // For non-DNS outbound connections, attempt PID-based DNS correlation
        let dns_query = if dns_query.is_empty()
            && raw.is_outbound == 1
            && matches!(raw.event_type, 2 | 3 | 7)
        {
            DNS_PID_CACHE.get(&raw.pid).or_else(|| {
                procfs::process::Process::new(raw.pid as i32)
                    .ok()
                    .and_then(|p| p.stat().ok())
                    .and_then(|s| DNS_PID_CACHE.get(&(s.ppid as u32)))
            }).unwrap_or_default()
        } else {
            dns_query
        };

        let event = KernelEvent {
            pid: raw.pid,
            uid: raw.uid,
            comm: String::from_utf8_lossy(&raw.comm).trim_matches(char::from(0)).to_string(),
            hash: process_hash,
            event_type,
            packet_size: raw.packet_size,
            is_outbound: raw.is_outbound as u8,
            dst_ip,
            dst_port: raw.dport,
            interval_ns: raw.interval_ns,
            entropy,
            dns_query,
            dns_flags,
            ja3_hash,
            sensor_id: SENSOR_IDENTITY.clone(),
        };

        if let Err(e) = tx.try_send(event) {
            warn!("[!] Backpressure engaged. Telemetry channel full, dropping event: {}", e);
        }
        0
    })?;

    let ring_buffer = builder.build()?;
    info!("[+] Ring Buffer mapped. Monitoring interface: {}", CONFIG.ebpf.target_interface);

    loop {
        if let Err(e) = ring_buffer.poll(Duration::from_millis(100)) {
            error!("Ring buffer poll error: {}", e);
            break;
        }
    }

    Ok(())
}

fn start_database_writer(db_path: String, rx: Receiver<KernelEvent>) {
    let mut conn = match Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_URI,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("[-] Failed to open database: {}", e);
            return;
        }
    };

    conn.busy_handler(Some(busy_retry))
        .expect("[-] FATAL: Failed to set busy handler");

    if let Err(e) = conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=10000;
         PRAGMA temp_store=MEMORY;
         PRAGMA wal_autocheckpoint=1000;
         PRAGMA journal_size_limit=67108864;"
    ) {
        error!("[-] PRAGMA config failed: {}", e);
    }

    tracing::info!("[+] Waiting for ML Engine to finalize schema migrations...");
    for attempt in 1..=120 {
        let check = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('flows') WHERE name='sensor_id'",
            [],
            |row| row.get::<_, u32>(0),
        );
        match check {
            Ok(1) => {
                tracing::info!("[+] Schema fully verified (sensor_id column found).");
                break;
            }
            _ => {
                if attempt == 120 {
                    tracing::error!("[-] FATAL: Database schema migration timed out.");
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    let mut batch = Vec::with_capacity(500);

    loop {
        if let Ok(event) = rx.recv_timeout(Duration::from_millis(500)) {
            batch.push(event);
        }

        while batch.len() < 500 {
            if let Ok(event) = rx.try_recv() {
                batch.push(event);
            } else {
                break;
            }
        }

        if !batch.is_empty() {
            match conn.transaction() {
                Ok(tx_db) => {
                    let mut flow_cache: HashMap<String, shared_models::telemetry::FlowEvent> = HashMap::new();

                    for ev in batch.drain(..) {
                        let flow_key = format!("{}-{}-{}", ev.pid, ev.dst_ip, ev.dst_port);
                        let current_ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();

                        flow_cache.entry(flow_key)
                            .and_modify(|existing| {
                                existing.packet_count += 1;
                                let delta = ev.packet_size as f64 - existing.packet_size_mean;
                                existing.packet_size_mean += delta / existing.packet_count as f64;
                                let delta2 = ev.packet_size as f64 - existing.packet_size_mean;
                                existing.packet_size_std += delta * delta2;
                                existing.packet_size_min = existing.packet_size_min.min(ev.packet_size);
                                existing.packet_size_max = existing.packet_size_max.max(ev.packet_size);
                                existing.entropy = existing.entropy.max(ev.entropy);
                                existing.timestamp = current_ts;
                                if ev.dns_flags != 0 {
                                    existing.dns_flags = ev.dns_flags;
                                }
                                if existing.ja3_hash.is_empty() && !ev.ja3_hash.is_empty() {
                                    existing.ja3_hash = ev.ja3_hash.clone();
                                }
                                if existing.dns_query.is_empty() && !ev.dns_query.is_empty() {
                                    existing.dns_query = ev.dns_query.clone();
                                }
                                if (existing.event_type == "send" || existing.event_type == "recv" || existing.event_type == "dns_response")
                                    && (ev.event_type == "dns" || ev.event_type == "tcp_payload")
                                {
                                    existing.event_type = ev.event_type.clone();
                                }
                            })
                            .or_insert(shared_models::telemetry::FlowEvent {
                                timestamp: current_ts,
                                pid: ev.pid,
                                uid: ev.uid,
                                comm: ev.comm.clone(),
                                hash: ev.hash.clone(),
                                event_type: ev.event_type.clone(),
                                is_outbound: ev.is_outbound,
                                dst_ip: ev.dst_ip.clone(),
                                dst_port: ev.dst_port,
                                interval_sec: ev.interval_ns as f64 / 1_000_000_000.0,
                                entropy: ev.entropy,
                                cmd_entropy: if ev.event_type == "exec" { shannon_entropy(ev.comm.as_bytes()) } else { 0.0 },
                                packet_count: 1,
                                packet_size_mean: ev.packet_size as f64,
                                packet_size_std: 0.0,
                                packet_size_min: ev.packet_size,
                                packet_size_max: ev.packet_size,
                                cv: 0.0,
                                dns_query: ev.dns_query.clone(),
                                dns_flags: ev.dns_flags,
                                ja3_hash: ev.ja3_hash.clone(),
                                sensor_id: SENSOR_IDENTITY.clone(),
                            });
                    }

                    match tx_db.prepare_cached(
                        "INSERT INTO flows (
                            timestamp, process_name, dst_ip, dst_port, interval,
                            cv, outbound_ratio, entropy, packet_size_mean,
                            packet_size_std, packet_size_min, packet_size_max,
                            packet_count, pid, uid, cmd_entropy, process_hash, dns_query,
                            event_type, dns_flags, ja3_hash, sensor_id
                        ) VALUES (
                            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22
                        )"
                    ) {
                        Ok(mut stmt) => {
                            for (_, mut flow) in flow_cache {
                                // Finalize Welford's: M2 → sample std_dev, then CV
                                if flow.packet_count > 1 {
                                    flow.packet_size_std = (flow.packet_size_std / (flow.packet_count - 1) as f64).sqrt();
                                    if flow.packet_size_mean > 0.0 {
                                        flow.cv = flow.packet_size_std / flow.packet_size_mean;
                                    }
                                }
                                let outbound_ratio = if flow.is_outbound == 1 { 1.0 } else { 0.0 };
                                if let Err(e) = stmt.execute(rusqlite::params![
                                    flow.timestamp, flow.comm, flow.dst_ip, flow.dst_port, flow.interval_sec,
                                    flow.cv, outbound_ratio, flow.entropy, flow.packet_size_mean,
                                    flow.packet_size_std, flow.packet_size_min, flow.packet_size_max,
                                    flow.packet_count, flow.pid, flow.uid, flow.cmd_entropy, flow.hash, flow.dns_query,
                                    flow.event_type, flow.dns_flags, flow.ja3_hash, flow.sensor_id
                                ]) {
                                    warn!("[!] Intermittent lock contention, dropping aggregated flow: {}", e);
                                }
                            }
                        }
                        Err(e) => error!("[-] Failed to prepare batch statement: {}", e),
                    }

                    if let Err(e) = tx_db.commit() {
                        error!("[-] Batch commit failed, dropping telemetry slice to maintain pipeline: {}", e);
                    }
                }
                Err(e) => {
                    error!("[-] Failed to acquire SQLite transaction lock: {}. Retrying next cycle.", e);
                    batch.clear();
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}