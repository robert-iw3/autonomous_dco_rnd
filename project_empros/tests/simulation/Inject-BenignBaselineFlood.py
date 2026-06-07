"""
Objective: Validate two false-positive suppression layers simultaneously:
    1. Model A (serve_baseline.py) must NOT fire nexus.alerts.baseline for organic
       internal traffic (backup jobs, DNS lookups, NTP sync, WSUS updates).
    2. The DPO Critic must veto any containment action that the LLM swarm proposes
       for high-volume administrative commands (Ansible, SCCM, apt-get).

Also validates the fleet-aware circuit breaker: if 200 hosts are flagged simultaneously,
the circuit breaker must demote to MANUAL_REVIEW even if each individual alert looks real.

Validation:
    - serve_baseline.py produces ZERO alerts from the organic traffic burst.
    - Critic vetoes containment on the Ansible simulation (DismissFalsePositive).
    - Circuit breaker fires if fleet coverage exceeds 20%.
"""
import requests
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import io
import os
import time
import uuid
import json
import redis

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://nexus-edge:8080/api/v1/telemetry")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
NATS_URL = os.getenv("NATS_URL", "nats://nats:4222")

HEADERS_SENTINEL = {
    "Authorization": "Bearer LinuxTier5-Secret-Token-Rotate-Me",
    "Content-Type": "application/vnd.apache.parquet",
    "X-Sensor-Type": "linux_sentinel"
}

HEADERS_NETTAP = {
    "Authorization": "Bearer LinuxTier5-Secret-Token-Rotate-Me",
    "Content-Type": "application/vnd.apache.parquet",
    "X-Sensor-Type": "network_tap",
    "X-Partition-Date": time.strftime("%Y-%m-%d"),
    "X-Partition-Hour": time.strftime("%H"),
}

print("[*] Initiating Benign Baseline Flood (Multi-Layer FP Validation)...")

# ── Phase 1: Model A False-Positive Stress ──
print("\n[*] Phase 1: Organic internal traffic flood (Model A must stay silent)...")

organic_flows = []
for i in range(200):
    organic_flows.append({
        "session_id": str(uuid.uuid4())[:16],
        "src_ip": f"10.0.1.{50 + (i % 50)}",
        "dst_ip": "10.0.2.10",                    # Internal backup server
        "src_port": 49152 + i,
        "dst_port": 445,                           # SMB (well_known)
        "protocol": 6,
        "protocol_name": "tcp",
        "timestamp_start": time.time() - (i * 0.5),
        "timestamp_end": time.time() - (i * 0.5) + 2.0,
        "session_duration_ms": 2000,
        "bytes_src": 1024 * (10 + (i % 50)),
        "bytes_dst": 1024 * (50 + (i % 100)),
        "data_bytes_src": 1024 * 8,
        "data_bytes_dst": 1024 * 40,
        "packets_src": 20 + (i % 10),
        "packets_dst": 40 + (i % 20),
        "byte_ratio": 0.3,                        # Normal download-heavy ratio
        "avg_inter_arrival": 50.0 + (i % 30),     # High variance (organic)
        "variance_inter_arrival": 800.0,           # High variance = NOT beaconing
        "ratio_small_packets": 0.2,
        "ratio_large_packets": 0.6,
        "payload_entropy": 4.2,
        "tcp_syn": 1, "tcp_rst": 0, "tcp_fin": 1,
        "dns_query": None, "dns_status": None,
        "http_method": None, "http_uri": None, "http_useragent": None, "http_status_code": None,
        "tls_ja3": None, "tls_ja3s": None, "tls_version": None, "tls_cipher": None,
        "cert_cn": None, "cert_issuer_cn": None, "cert_self_signed": None, "cert_valid_days": None,
        "hostname": None, "src_geo_country": None, "dst_geo_country": None, "dst_asn_org": None,
        "sensor_name": "arkime-sensor-01", "sensor_type": "network_tap",
        "is_internal_dst": True,                   # Both IPs are RFC-1918
        "port_class": "well_known",                # SMB = 445
    })

df = pd.DataFrame(organic_flows)
table = pa.Table.from_pandas(df)
buf = io.BytesIO()
pq.write_table(table, buf, compression='ZSTD')

response = requests.post(GATEWAY_URL, headers=HEADERS_NETTAP, data=buf.getvalue())
print(f"    -> Injected {len(organic_flows)} organic network_tap flows. Gateway: {response.status_code}")
print("    -> serve_baseline.py MUST produce ZERO alerts (high inter-arrival variance = organic)")

# ── Phase 2: Ansible Admin Simulation (Critic Must Veto) ──
print("\n[*] Phase 2: Ansible admin burst (Critic must veto containment)...")

events = [
    {"event_id": str(uuid.uuid4()), "timestamp": time.time(), "dest_ip": "10.0.0.50",
     "comm": "sshd", "command_line": "sshd: admin [priv]", "uid": 0,
     "shannon_entropy": 3.2, "execution_velocity": 0.1, "tuple_rarity": 0.05,
     "path_depth": 1.0, "anomaly_score": 0.1},
    {"event_id": str(uuid.uuid4()), "timestamp": time.time(), "dest_ip": "10.0.0.50",
     "comm": "bash", "command_line": "-c whoami", "uid": 1000,
     "shannon_entropy": 2.1, "execution_velocity": 0.2, "tuple_rarity": 0.1,
     "path_depth": 2.0, "anomaly_score": 0.4},
    {"event_id": str(uuid.uuid4()), "timestamp": time.time(), "dest_ip": "10.0.0.50",
     "comm": "apt-get", "command_line": "apt-get update -y", "uid": 0,
     "shannon_entropy": 4.5, "execution_velocity": 0.05, "tuple_rarity": 0.02,
     "path_depth": 1.0, "anomaly_score": 0.2},
    {"event_id": str(uuid.uuid4()), "timestamp": time.time(), "dest_ip": "10.0.0.50",
     "comm": "ping", "command_line": "ping -c 4 8.8.8.8", "uid": 1000,
     "shannon_entropy": 1.8, "execution_velocity": 0.01, "tuple_rarity": 0.01,
     "path_depth": 1.0, "anomaly_score": 0.1},
]

df2 = pd.DataFrame(events)
buf2 = io.BytesIO()
pq.write_table(pa.Table.from_pandas(df2), buf2, compression='ZSTD')

response2 = requests.post(GATEWAY_URL, headers=HEADERS_SENTINEL, data=buf2.getvalue())
print(f"    -> Ansible burst injected. Gateway: {response2.status_code}")
print("    -> Critic MUST veto containment (low anomaly scores, admin context).")

# ── Phase 3: Fleet Circuit Breaker ──
print("\n[*] Phase 3: Fleet coverage stress test...")
try:
    r = redis.from_url(REDIS_URL)
    # Simulate 200 active hosts in the fleet (small fleet to trigger 20% threshold easily)
    for i in range(200):
        r.sadd("nexus:fleet:active", f"ws-generic-{i:04d}")
    fleet_size = r.scard("nexus:fleet:active")
    print(f"    -> Fleet size set to {fleet_size} via Redis SCARD.")
    print(f"    -> If swarm tries to contain >40 hosts (20%), circuit breaker MUST demote to MANUAL_REVIEW.")
except Exception as e:
    print(f"    -> Redis unavailable ({e}). Skipping fleet circuit breaker validation.")

print("\n[+] Benign Baseline Flood complete. Validate:")
print("    [ ] Model A: zero alerts from Phase 1 organic flows")
print("    [ ] Critic: DISMISS_FALSE_POSITIVE on Phase 2 admin burst")
print("    [ ] Circuit breaker: MANUAL_REVIEW if fleet coverage >20%")