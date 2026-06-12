#!/usr/bin/env python3
"""
Mock Gigamon tap + Arkime, for the data-flow stress lab.

Stands in for the hardware tap → Arkime capture engine: generates synthetic
Arkime SPI sessions and DUAL-WRITES them exactly as Arkime does --
  * SPI JSON  → Redpanda topic  (the ML training path the gateway consumes)
  * SPI docs  → OpenSearch      (the forensic path analysts query)

Emits a JSON ledger on stdout (produced / noise / expected_accepted) so the
driver can assert conservation across the whole pipeline.
"""
import argparse
import json
import sys
import time

import requests
from confluent_kafka import Producer

# ~1 in NOISE_EVERY sessions is broadcast/zero-byte noise the ML gateway drops.
# (The forensic path keeps everything; Arkime does not pre-filter to OpenSearch.)
NOISE_EVERY = 7


def make_session(i: int) -> dict:
    if i % NOISE_EVERY == 0:
        # zero-byte mDNS multicast -- dropped by the gateway's is_noise()
        return {
            "id": f"n{i}", "a1": f"10.0.0.{i % 254 + 1}", "a2": "224.0.0.251",
            "p1": 5353, "p2": 5353, "pr": 17, "by1": 0, "by2": 0,
            "fp": 1700000000, "lp": 1700000001,
        }
    dport = (443, 80, 53, 22)[i % 4]
    proto = 17 if i % 4 == 2 else 6
    a2 = "192.168.1.50" if i % 3 == 0 else "8.8.8.8"
    doc = {
        "id": f"s{i}", "a1": f"10.0.{(i // 254) % 254}.{i % 254 + 1}", "a2": a2,
        "p1": 1024 + (i % 60000), "p2": dport, "pr": proto,
        "by1": 1000 + (i % 5000), "by2": 2000 + (i % 5000), "db1": 800, "db2": 1800,
        "pa1": 10, "pa2": 12, "fp": 1700000000, "lp": 1700000005,
        "pa": [1, 2, 3, 4], "ps": [60, 1400, 800, 120],
        "tcpflags": {"syn": 1, "ack": 5, "rst": 0, "fin": 1, "psh": 2},
    }
    branch = i % 4
    if branch == 0:
        doc["tls"] = {"ja3": ["771,4866-4867"], "version": ["TLSv1.3"]}
        doc["cert"] = {"cn": ["example.com"], "self_signed": [False], "valid_days": [90]}
    elif branch == 1:
        doc["http"] = {"method": ["GET"], "uri": ["/index.html"], "useragent": ["curl/8.7"], "statuscode": [200]}
    elif branch == 2:
        doc["dns"] = {"host": ["example.com"], "status": ["NOERROR"]}
    return doc


def produce(count, brokers, topic, os_url, os_index, forensic):
    producer = Producer({
        "bootstrap.servers": brokers,
        "queue.buffering.max.messages": 1_000_000,
        "linger.ms": 50, "batch.num.messages": 10000, "compression.type": "lz4",
    })
    noise = 0
    bulk_buf, bulk_rows = [], 0
    os_sess = requests.Session()

    def flush_bulk():
        nonlocal bulk_buf
        if not bulk_buf:
            return
        body = "".join(bulk_buf)
        r = os_sess.post(f"{os_url}/{os_index}/_bulk", data=body,
                         headers={"Content-Type": "application/x-ndjson"}, timeout=120)
        r.raise_for_status()
        bulk_buf = []

    t0 = time.time()
    for i in range(count):
        doc = make_session(i)
        if doc["by1"] == 0 and doc["by2"] == 0:
            noise += 1
        payload = json.dumps(doc)
        producer.produce(topic, value=payload.encode())
        if i % 20000 == 0:
            producer.poll(0)
        if forensic:
            bulk_buf.append(json.dumps({"index": {"_id": doc["id"]}}) + "\n")
            bulk_buf.append(payload + "\n")
            bulk_rows += 1
            if bulk_rows % 5000 == 0:
                flush_bulk()

    producer.flush(120)
    if forensic:
        flush_bulk()
        os_sess.post(f"{os_url}/{os_index}/_refresh", timeout=60)

    ledger = {
        "produced": count,
        "noise": noise,
        "expected_accepted": count - noise,
        "to_opensearch": bulk_rows if forensic else 0,
        "elapsed_sec": round(time.time() - t0, 2),
    }
    print(json.dumps(ledger), flush=True)
    return ledger


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--brokers", default="redpanda:9092")
    ap.add_argument("--topic", default="arkime-spi-raw")
    ap.add_argument("--os-url", default="http://opensearch:9200")
    ap.add_argument("--os-index", default="arkime_sessions3-lab")
    ap.add_argument("--no-forensic", action="store_true")
    args = ap.parse_args()
    try:
        produce(args.count, args.brokers, args.topic, args.os_url, args.os_index, not args.no_forensic)
    except Exception as e:  # surface failures to the driver
        print(json.dumps({"error": str(e)}), file=sys.stderr, flush=True)
        sys.exit(1)
