"""
Performance posture of the stack (paramount at 10G+ line rate).

Pins the host/NIC tuning, capture-engine parallelism, broker/cluster sizing, and
gateway batching that let the sensor keep up without softirq/packet drops. Parses
the real tuning script + configs, so a regression that re-enables an offload or
shrinks a ring buffer fails here.
"""

import re

import pytest

pytestmark = pytest.mark.tier0


# -- host kernel + NIC tuning -------------------------------------------------
def test_host_sysctl_tuned_for_capture(paths):
    h = paths["host_tuning"].read_text()
    assert '["net.core.rmem_max"]="134217728"' in h, "128MB socket rx buffer for burst absorption"
    assert '["net.core.netdev_max_backlog"]="300000"' in h, "deep backlog prevents softirq drops at 10G+"
    assert '["vm.max_map_count"]="262144"' in h, "OpenSearch mmap requirement"
    assert '["vm.swappiness"]="1"' in h, "hot data must not swap"


def test_nic_offloads_disabled(paths):
    h = paths["host_tuning"].read_text()
    # offloads coalesce/segment packets in hardware -> corrupts capture fidelity
    assert re.search(r"ethtool -K .* gro off lro off tso off gso off", h), \
        "GRO/LRO/TSO/GSO must be OFF on the capture interface"
    assert re.search(r"ethtool -G .* rx 4096", h), "NIC rx ring buffer must be maximized"


# -- Arkime capture engine ----------------------------------------------------
def test_arkime_afpacket_zero_copy_and_threads(paths):
    ini = paths["arkime_ini"].read_text()
    assert "pcapReadMethod=afpacket" in ini, "AF_PACKET zero-copy capture"
    assert "afpacketRingSize=" in ini and "afpacketBlockSize=" in ini
    m = re.search(r"packetThreads=(\d+)", ini)
    assert m and int(m.group(1)) >= 2, "multiple packet-processing threads"


def test_capture_is_numa_pinned(paths):
    txt = paths["startarkime"].read_text()
    assert "numactl" in txt and "numa_node" in txt, "capture must be NUMA-pinned to the NIC's node"
    assert "coreBase=" in txt, "packet threads pinned to the local NUMA cores"


# -- broker + cluster sizing --------------------------------------------------
def test_redpanda_thread_per_core(paths):
    compose = paths["compose"].read_text()
    assert "--smp 4" in compose and "--memory 8G" in compose, "Redpanda sized thread-per-core"
    assert "nofile: { soft: 1048576" in compose, "broker fd ceiling raised"


def test_opensearch_heap_and_memlock(paths):
    compose = paths["compose"].read_text()
    assert "bootstrap.memory_lock=true" in compose, "heap must be memory-locked (no swap)"
    assert "OPENSEARCH_JAVA_OPTS=-Xms8g -Xmx8g" in compose, "data-node heap Xms==Xmx"
    assert "memlock:  { soft: -1,     hard: -1     }" in compose, "unlimited memlock for the heap"


# -- gateway throughput -------------------------------------------------------
def test_gateway_batches_and_caps_spool(paths):
    toml = paths["gateway_toml"].read_text()
    assert "tokio_worker_threads = 4" in toml
    assert re.search(r"batch_size\s*=\s*\d{3,}", toml), "spool writes are batched"
    assert "max_spool_bytes" in toml, "spool is size-capped so a Nexus outage can't fill the disk"
    assert "parquet_row_group_size" in toml


def test_retention_loop_is_not_hot(paths):
    # purge runs hourly by default, not in a tight loop
    assert "PCAP_RETENTION_INTERVAL_S:-3600" in paths["startarkime"].read_text()
