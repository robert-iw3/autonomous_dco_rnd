"""
Objective: Concurrently blast 34 Windows, 33 Linux, and 33 network_tap payloads into the
           gateway at the exact same time (100 total, three distinct schemas).

Validation:
    - Zero schema cross-pollination across DuckDB queries.
    - network_tap records must NOT leak is_internal_dst/port_class into windows_deepsensor queries.
    - Each sensor_type routes to its correct NATS subject and vector space.
    - The Python Swarm must not crash due to DuckDB schema mismatches.
"""
import asyncio
import aiohttp
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import io
import os
import time
import uuid

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://nexus-edge:8080/api/v1/telemetry")


def create_parquet_buffer(os_type: str):
    if os_type == "windows":
        data = [{
            "event_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "destination_ip": "10.0.0.100",
            "Image": "cmd.exe",
            "CommandLine": "cmd.exe /c net user",
            "score": 0.9,
            "max_velocity": 0.8,
            "avg_entropy": 0.5,
            "event_count": 1,
        }]
    elif os_type == "linux":
        data = [{
            "event_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "dest_ip": "10.0.0.200",
            "comm": "bash",
            "command_line": "-c cat /etc/shadow",
            "shannon_entropy": 5.5,
            "execution_velocity": 0.8,
            "tuple_rarity": 0.9,
            "path_depth": 3.0,
            "anomaly_score": 0.9,
        }]
    else:
        # network_tap -- 44-column schema (42 raw + 2 derived)
        data = [{
            "session_id": str(uuid.uuid4())[:16],
            "src_ip": "10.0.1.50",
            "dst_ip": "185.10.68.22",
            "src_port": 49200,
            "dst_port": 8443,
            "protocol": 6,
            "protocol_name": "tcp",
            "timestamp_start": time.time() - 5.0,
            "timestamp_end": time.time(),
            "session_duration_ms": 5000,
            "bytes_src": 2048,
            "bytes_dst": 15360,
            "data_bytes_src": 1800,
            "data_bytes_dst": 14000,
            "packets_src": 15,
            "packets_dst": 45,
            "byte_ratio": 0.12,
            "avg_inter_arrival": 120.5,
            "variance_inter_arrival": 45.0,
            "ratio_small_packets": 0.3,
            "ratio_large_packets": 0.5,
            "payload_entropy": 5.8,
            "tcp_syn": 1, "tcp_rst": 0, "tcp_fin": 1,
            "dns_query": None, "dns_status": None,
            "http_method": None, "http_uri": None, "http_useragent": None, "http_status_code": None,
            "tls_ja3": "a0e9f5d64349fb13191bc781f81f42e1",
            "tls_ja3s": "eb1d94daa7e0344597e756a1fb6e7054",
            "tls_version": "TLSv1.3", "tls_cipher": "TLS_AES_256_GCM_SHA384",
            "cert_cn": "*.malicious-infra.xyz", "cert_issuer_cn": "*.malicious-infra.xyz",
            "cert_self_signed": True, "cert_valid_days": 30,
            "hostname": "malicious-infra.xyz",
            "src_geo_country": None, "dst_geo_country": "RU", "dst_asn_org": "BulletProof-AS",
            "sensor_name": "arkime-sensor-01", "sensor_type": "network_tap",
            # Derived ML features (ONLY present on network_tap -- cross-pollination canary)
            "is_internal_dst": False,
            "port_class": "registered",
        }]

    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pandas(pd.DataFrame(data)), buf, compression='ZSTD')
    return buf.getvalue()


async def fire_payload(session: aiohttp.ClientSession, os_type: str):
    sensor_map = {
        "windows": "windows_deepsensor",
        "linux": "linux_sentinel",
        "nettap": "network_tap",
    }
    headers = {
        "Authorization": "Bearer LinuxTier5-Secret-Token-Rotate-Me",
        "Content-Type": "application/vnd.apache.parquet",
        "X-Sensor-Type": sensor_map[os_type],
    }

    # Add partition hints for network_tap
    if os_type == "nettap":
        headers["X-Partition-Date"] = time.strftime("%Y-%m-%d")
        headers["X-Partition-Hour"] = time.strftime("%H")

    payload = create_parquet_buffer(os_type)
    async with session.post(GATEWAY_URL, headers=headers, data=payload) as response:
        return os_type, response.status


async def main():
    print("[*] Initiating Cross-Pollination Stress Test (3 schemas x 100 payloads)...")
    print("    -> 34 windows_deepsensor (4D windows_math)")
    print("    -> 33 linux_sentinel     (5D sentinel_math)")
    print("    -> 33 network_tap        (8D network_tap + is_internal_dst + port_class)")
    print("")

    async with aiohttp.ClientSession() as session:
        tasks = []

        # Interleave all three schema types
        for i in range(34):
            tasks.append(fire_payload(session, "windows"))
        for i in range(33):
            tasks.append(fire_payload(session, "linux"))
        for i in range(33):
            tasks.append(fire_payload(session, "nettap"))

        # Shuffle to maximize interleaving
        import random
        random.shuffle(tasks)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Tally results by schema type
        counts = {"windows": 0, "linux": 0, "nettap": 0, "errors": 0}
        for result in results:
            if isinstance(result, Exception):
                counts["errors"] += 1
            else:
                os_type, status = result
                if status == 202:
                    counts[os_type] += 1

        print(f"\n[+] Results:")
        print(f"    windows_deepsensor : {counts['windows']}/34 accepted (→ windows_math 4D)")
        print(f"    linux_sentinel     : {counts['linux']}/33 accepted  (→ sentinel_math 5D)")
        print(f"    network_tap        : {counts['nettap']}/33 accepted (→ network_tap 8D)")
        print(f"    Errors             : {counts['errors']}")
        print("")
        print("[!] Monitor Swarm output for schema/DuckDB routing errors:")
        print("    - is_internal_dst must NOT appear in windows_deepsensor DuckDB queries")
        print("    - port_class must NOT appear in linux_sentinel DuckDB queries")
        print("    - windows_math (4D) and sentinel_math (5D) vectors must NOT cross-pollinate")
        print("    - Each sensor_type must route to its correct NATS subject")

if __name__ == "__main__":
    asyncio.run(main())