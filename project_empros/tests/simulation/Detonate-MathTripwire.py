"""
Objective: Bypass the edge sensors and inject a mathematically perfect anomaly.
           Three modes: 'gateway' (tests Axum/Qdrant), 'nats' (tests Orchestrator directly),
           'baseline' (tests Model A → nettap_expert routing).

Validation:
    gateway  → worker_qdrant must calculate cosine distance and push to Redis alert queue.
    nats     → Orchestrator must intercept and correctly task the net_expert.
    baseline → Orchestrator must route the reconstruction-error alert to nettap_expert (not net_expert).
"""
import argparse
import requests
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import io
import time
import uuid
import json
import asyncio
import os

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://nexus-edge:8080/api/v1/telemetry")
NATS_URL = os.getenv("NATS_URL", "nats://nats:4222")

# Partition hints for Hive-style S3 paths
PARTITION_DATE = time.strftime("%Y-%m-%d")
PARTITION_HOUR = time.strftime("%H")

HEADERS = {
    "Authorization": "Bearer LinuxTier5-Secret-Token-Rotate-Me",
    "Content-Type": "application/vnd.apache.parquet",
    "X-Sensor-Type": "windows_c2",
    "X-Partition-Date": PARTITION_DATE,
    "X-Partition-Hour": PARTITION_HOUR,
}

# 8D C2 vector -- programmatic beaconing with zero jitter
synthetic_c2_event = [{
    "event_id": str(uuid.uuid4()),
    "timestamp": time.time(),
    "host": "WIN-FINANCE-01",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -nop -w hidden -ep bypass -c \"...\"",
    "DestIp": "185.10.68.22",
    "Port": 443,
    "outbound_ratio": 0.95,
    "packet_size_mean": 0.88,
    "packet_size_std": 0.05,
    "interval": 0.10,
    "cv": 0.05,
    "entropy": 0.80,
    "cmd_entropy": 0.90,
    "score": 0.98,
}]

def detonate_gateway():
    print("[*] Initiating Math Tripwire Detonation via Axum Gateway...")
    print(f"    -> source_type: windows_c2 | vector_name: c2_math")
    print(f"    -> Partition hints: dt={PARTITION_DATE}/hour={PARTITION_HOUR}")

    df = pd.DataFrame(synthetic_c2_event)
    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pandas(df), buf, compression='ZSTD')

    response = requests.post(GATEWAY_URL, headers=HEADERS, data=buf.getvalue())
    print(f"[+] Synthetic 8D Vector injected. Gateway Response: {response.status_code}")
    print("[!] Check Redis queue `nexus:qdrant:alerts`. Orchestrator should trigger within 5 seconds.")
    print(f"    S3 path: telemetry/windows_c2/dt={PARTITION_DATE}/hour={PARTITION_HOUR}/")

async def detonate_nats():
    print("[*] Initiating Direct NATS JetStream Detonation (Bypassing Gateway)...")
    import nats
    nc = await nats.connect(NATS_URL)
    js = nc.jetstream()

    event_id = synthetic_c2_event[0]["event_id"]

    nats_payload = {
        "event_id": event_id,
        "timestamp": synthetic_c2_event[0]["timestamp"],
        "sensor_id": synthetic_c2_event[0]["host"],
        "source_type": "windows_c2",
        "vector_name": "c2_math",
        "anomaly_score": 0.99,
        "triggering_vector": [0.95, 0.88, 0.05, 0.10, 0.05, 0.80, 0.90, 0.98],
        "raw_event": synthetic_c2_event[0],
    }

    ack = await js.publish(
        "nexus.alerts.synthetic",
        json.dumps(nats_payload).encode(),
        headers={"Nats-Msg-Id": event_id}
    )

    print(f"[+] NATS Seq: {ack.seq}. Orchestrator should route to net_expert (source_type: windows_c2).")
    await nc.close()

async def detonate_baseline():
    """Inject a pre-formed Model A reconstruction-error alert directly onto NATS."""
    print("[*] Initiating Model A Baseline Alert Injection...")
    import nats
    nc = await nats.connect(NATS_URL)
    js = nc.jetstream()

    event_id = f"baseline-10.0.1.50|185.10.68.22-{int(time.time())}"

    baseline_alert = {
        "event_id": event_id,
        "sensor_id": "arkime-sensor-01",
        "source_type": "network_tap",
        "vector_name": "baseline_reconstruction",
        "anomaly_score": 0.85,
        "reconstruction_error": 0.25,
        "threshold": 0.05,
        "timestamp": time.time(),
        "src_ip": "10.0.1.50",
        "dst_ip": "185.10.68.22",
        "window_size": 64,
        "raw_event": {
            "src_ip": "10.0.1.50",
            "dst_ip": "185.10.68.22",
            "dst_port": 8443,
            "protocol_name": "tcp",
            "byte_ratio": 0.48,
            "avg_inter_arrival": 2050.0,
            "variance_inter_arrival": 15.0,
            "tls_ja3": "a0e9f5d64349fb13191bc781f81f42e1",
            "cert_self_signed": True,
            "cert_valid_days": 30,
            "is_internal_dst": False,
            "port_class": "registered",
        },
    }

    ack = await js.publish(
        "nexus.alerts.baseline",
        json.dumps(baseline_alert).encode(),
        headers={"Nats-Msg-Id": event_id}
    )

    print(f"[+] Baseline alert published. NATS Seq: {ack.seq}")
    print("[!] Orchestrator MUST route to nettap_expert (vector_name: baseline_reconstruction).")
    print("    nettap_expert should:")
    print("      [1] Query network_tap Parquet for 10.0.1.50 → 185.10.68.22 sessions")
    print("      [2] Cross-reference JA3 fingerprint against known C2 profiles")
    print("      [3] Flag cert_self_signed=true + short validity (30 days) as anomalous")
    print("      [4] Note is_internal_dst=false (external target) + port_class=registered (non-standard)")
    await nc.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nexus Math Tripwire Detonator")
    parser.add_argument("--mode", choices=["gateway", "nats", "baseline"], default="gateway",
                        help="Injection target: gateway (Axum), nats (direct), baseline (Model A)")
    args = parser.parse_args()

    if args.mode == "gateway":
        detonate_gateway()
    elif args.mode == "nats":
        asyncio.run(detonate_nats())
    else:
        asyncio.run(detonate_baseline())