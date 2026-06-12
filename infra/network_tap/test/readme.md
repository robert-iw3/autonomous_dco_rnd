# network_tap — infrastructure + deployment test workbench

Tests the whole stack (Arkime sensor → Redpanda → ML gateway → OpenSearch + Nexus),
not just the gateway crate (that's `gateway/test/`). Pure Python over the real
compose/config/scripts.

- **tier0** (no containers):
  - `test_pcap_retention.py` — **executes** the real `pcap_retention.sh` against
    synthetic captures: only pcaps >72h purged, dry-run is a no-op, non-pcap files
    untouched, a 0h window is refused; plus the ISM **retains** SPI (no delete state)
    so metadata stays for historical analysis while only packets age out.
  - `test_security_posture.py` — mTLS end to end (OpenSearch http+transport, Arkime
    client cert, dashboards verify, gateway→Nexus HTTPS enforced in code), drop-
    privileges, loopback-bound management ports, redis auth, no committed secrets,
    default-deny firewall, passive capture interface.
  - `test_performance_posture.py` — host sysctl + NIC offloads-off + ring buffers,
    AF_PACKET ring/threads + NUMA pinning, Redpanda/OpenSearch sizing + memlock,
    gateway batching + spool cap.
  - `test_interop_contract.py` — the seams agree: Arkime↔gateway SPI topic + broker
    port, gateway `sensor_type=network_tap` + 48-col Parquet + HTTPS egress,
    OpenSearch endpoints + ISM template/alias, firewall opens exactly the service ports.

- **lab** (`lab/`, containerized end-to-end) — `compose.lab.yml` spins up the whole
  pipeline (mock Gigamon tap → Redpanda → gateway → mock nexus + OpenSearch) and the
  driver drives escalating load (low→very-high), logging a per-component conservation
  ledger and asserting **no data loss on either path**. See `lab/readme.md`.

Run: `bash test/run.sh` (tier0) · `pytest test/lab/test_pipeline_stress.py -s -v` (lab)
