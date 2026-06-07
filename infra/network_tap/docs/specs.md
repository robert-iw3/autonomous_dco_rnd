# Network Defense Stack -- System Requirements & Multi-VM Deployment Guide

## Deployment Topology

The stack splits across five roles, each on dedicated infrastructure. All inter-component links use mutual TLS from a single offline root CA. A dedicated data VLAN carries OpenSearch transport, Kafka traffic, and PCAP metadata. A separate management VLAN handles SSH, Prometheus scraping, and analyst UI access. The capture NIC has no IP address -- it is a passive tap/SPAN port.

```
┌---------------------------------------------------------------------┐
│                         DATA VLAN (10.10.2.0/24)                    │
│                                                                     │
│  ┌----------┐  ┌----------┐  ┌----------┐  ┌---------┐  ┌-------┐   │
│  │os-manager│  │ os-data1 │  │ os-data2 │  │redpanda │  │gateway│   │
│  │ .10      │  │  .11     │  │   .12    │  │  .20    │  │  .30  │   │
│  └----------┘  └----------┘  └----------┘  └---------┘  └-------┘   │
│                                                                     │
│  ┌----------┐                                                       │
│  │ sensor   │ data NIC: .40   capture NIC: no IP (tap port)         │
│  └----------┘                                                       │
└---------------------------------------------------------------------┘

┌---------------------------------------------------------------------┐
│                      MGMT VLAN (10.10.1.0/24)                       │
│  SSH, Prometheus, analyst Arkime Viewer + Dashboards                │
│  ┌----------┐                                                       │
│  │ ui-proxy │  reverse proxy: nginx/HAProxy → Dashboards + Viewer   │
│  └----------┘                                                       │
└---------------------------------------------------------------------┘
```

## System Specifications by Role

### 1. OpenSearch Manager Node

Handles cluster state, shard allocation, and ISM policy enforcement. Does not store data. Light workload.

| Resource  | Minimum          | Recommended       |
|-----------|------------------|--------------------|
| vCPU      | 4 cores          | 8 cores            |
| RAM       | 8 GB             | 16 GB              |
| JVM Heap  | 2 GB             | 4 GB               |
| Disk      | 50 GB SSD        | 100 GB NVMe        |
| Network   | 1 Gbps           | 10 Gbps            |

VMware: 1 socket × 4 cores, 8 GB RAM, thin-provisioned VMDK on SSD datastore.
KVM: 4 vCPU, 8 GB, virtio-blk on NVMe-backed LVM.


### 2. OpenSearch Data Node (× 2)

Ingests, indexes, and serves queries for all Arkime session data. I/O and memory intensive. Two data nodes provide redundancy with replica count of 1.

| Resource  | Minimum          | Recommended        |
|-----------|------------------|--------------------|
| vCPU      | 8 cores          | 16 cores           |
| RAM       | 32 GB            | 64 GB              |
| JVM Heap  | 16 GB            | 31 GB (compressed oops limit) |
| Disk      | 500 GB NVMe      | 2 TB NVMe (direct-attached) |
| Network   | 10 Gbps          | 25 Gbps            |

Critical: JVM heap must never exceed 31 GB (compressed ordinary object pointers). The remaining RAM serves as filesystem cache for Lucene segment reads. Disk IOPS matter more than capacity -- NVMe is strongly preferred over SATA SSD. Each data node should be on a separate physical host or at minimum a separate failure domain (different ESXi host, different KVM hypervisor).

VMware: 2 sockets × 8 cores, 64 GB RAM, dedicated NVMe RDM or thick-provisioned VMDK on NVMe datastore. Enable memory reservation to prevent ballooning.
KVM: 16 vCPU (host-passthrough CPU model), 64 GB (hugepages), virtio-blk on dedicated NVMe with io_uring.

Disk throughput target: sustained 500 MB/s write for bulk indexing, burst 1 GB/s for force-merge operations.


### 3. Arkime Sensor (Packet Capture)

Captures raw packets from a hardware tap or SPAN port at line rate, writes PCAPs to local storage, and emits SPI JSON to Redpanda via the Kafka plugin. The most hardware-sensitive role -- packet drops at the NIC or kernel level mean permanent data loss.

| Resource  | Minimum          | Recommended        |
|-----------|------------------|--------------------|
| vCPU      | 8 cores          | 16 cores (single NUMA node) |
| RAM       | 16 GB            | 32 GB              |
| Capture NIC | 10 Gbps (Intel X520/X710) | 25-40 Gbps (Mellanox CX-5/6) |
| PCAP Disk | 2 TB NVMe        | 10+ TB NVMe RAID-0 |
| Mgmt NIC  | 1 Gbps           | 10 Gbps            |

**Strongly recommended: bare metal, not virtualized.** SR-IOV or PCI passthrough can work for 10G but adds latency. At 25G+ or in production, direct hardware access eliminates the hypervisor overhead that causes packet drops under sustained load.

Bare metal: Capture NIC IRQs pinned to the same NUMA node where Arkime runs (the deploy script handles this). AF_PACKET with a 2 GB ring buffer. All hardware offloads disabled (GRO, LRO, TSO, GSO). Jumbo frames enabled (MTU 9216) if the tap/SPAN path supports it.

VMware (10G only): PCI passthrough for the capture NIC, reserve all memory, pin vCPUs to a single NUMA node. Performance mode in BIOS (no C-states).
KVM (10G only): PCI passthrough via VFIO, host-passthrough CPU, hugepages, CPU pinning with `cset shield`.

PCAP retention calculation: At 1 Gbps average utilization, Arkime writes ~10 TB/day of PCAPs. At 10 Gbps average, ~100 TB/day. Size storage for your target retention window.


### 4. Redpanda Broker

Kafka-compatible streaming broker that buffers SPI JSON between Arkime (producer) and the ML gateway plus OpenSearch (consumers). Thread-per-core architecture eliminates JVM pauses.

| Resource  | Minimum          | Recommended        |
|-----------|------------------|--------------------|
| vCPU      | 4 cores          | 8 cores            |
| RAM       | 8 GB             | 16 GB              |
| Disk      | 100 GB NVMe      | 500 GB NVMe        |
| Network   | 10 Gbps          | 25 Gbps            |

Redpanda uses direct I/O and bypasses the page cache. NVMe latency directly impacts end-to-end pipeline latency. The `--smp` flag should match the physical core count (not hyperthreads).

VMware: 4 vCPU, 16 GB, dedicated NVMe VMDK (thick eager-zeroed). Latency-sensitive VM setting enabled.
KVM: 4 vCPU (pinned, no overcommit), 16 GB hugepages, virtio-blk with io_uring on dedicated NVMe.


### 5. ML Gateway + Redis (Co-located)

Rust binary consuming from Redpanda, extracting 42-field flow records, spooling to SQLite WAL, and transmitting Zstd Parquet payloads to the upstream Axum gateway. Redis provides a short-TTL session→IP cache.

| Resource  | Minimum          | Recommended        |
|-----------|------------------|--------------------|
| vCPU      | 4 cores          | 8 cores            |
| RAM       | 8 GB (4 gateway + 2 Redis + 2 OS) | 16 GB (8 + 4 + 4) |
| Disk      | 50 GB SSD (SQLite WAL spool) | 200 GB NVMe |
| Network   | 1 Gbps           | 10 Gbps            |

Redis is configured with `maxmemory 2gb` and LRU eviction, no persistence. The SQLite WAL spool needs enough disk to buffer records during extended Axum gateway outages (at 50K sessions/sec × 2 KB/row average, 72 hours of buffering = ~25 TB, which exceeds reasonable disk). In practice, set `max_spool_bytes` in config to cap the spool at the available disk.

VMware: 4 vCPU, 16 GB, standard VMDK.
KVM: 4 vCPU, 16 GB, virtio-blk.


### 6. UI Proxy (Analyst Access)

Reverse proxy (nginx or HAProxy) fronting OpenSearch Dashboards and the Arkime Viewer. Terminates TLS for analyst browsers.

| Resource  | Minimum          | Recommended        |
|-----------|------------------|--------------------|
| vCPU      | 2 cores          | 4 cores            |
| RAM       | 4 GB             | 8 GB               |
| Disk      | 20 GB SSD        | 50 GB SSD          |
| Network   | 1 Gbps           | 1 Gbps             |

Can run on the same host as OpenSearch Dashboards. Minimal resource requirements.


## Aggregate Hardware Summary

| Deployment | Hosts | Total vCPU | Total RAM | Total NVMe |
|------------|-------|------------|-----------|------------|
| Minimum    | 6 VMs | 38 cores   | 116 GB    | ~3.3 TB    |
| Recommended| 6 hosts (sensor bare metal) | 72 cores | 240 GB | ~15 TB |

For a proof-of-concept on a single hypervisor: a server with 2× Xeon Gold 6248R (48 cores total), 256 GB RAM, and 4× 2 TB NVMe drives can host all VMs with appropriate resource reservations.


## Network Architecture

### VLANs

| VLAN | Purpose | Subnet | Members |
|------|---------|--------|---------|
| 100  | Management | 10.10.1.0/24 | All hosts (SSH, Prometheus, UI) |
| 200  | Data plane | 10.10.2.0/24 | OS cluster, Redpanda, sensor, gateway |
| --    | Capture    | No IP | Sensor capture NIC only (tap/SPAN) |

### Port Matrix

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| os-manager | os-data{1,2} | 9300/tcp | TLS | OpenSearch transport |
| os-data{1,2} | os-manager | 9300/tcp | TLS | OpenSearch transport |
| os-data1 | os-data2 | 9300/tcp | TLS | OpenSearch transport (peer) |
| sensor | os-manager | 9200/tcp | TLS | Arkime session indexing |
| sensor | os-data{1,2} | 9200/tcp | TLS | Arkime session indexing |
| sensor | redpanda | 9092/tcp | SASL/TLS | Kafka SPI publish |
| gateway | redpanda | 9092/tcp | SASL/TLS | Kafka SPI consume |
| gateway | redis (local) | 6379/tcp | AUTH | Session cache |
| gateway | nexus-edge | 443/tcp | mTLS | Parquet payload POST |
| ui-proxy | os-manager | 9200/tcp | TLS | Dashboards backend |
| ui-proxy | sensor | 8005/tcp | TLS | Arkime Viewer |
| analyst | ui-proxy | 443/tcp | TLS | Browser access |
| prometheus | all hosts | 9090,9100/tcp | HTTP | Metrics scraping |


## Deployment Order

1. Generate PKI:  `./generate_pki.sh 10.10.2.10 10.10.2.11 10.10.2.12`
2. Distribute certs to each host's `/etc/opensearch/certs/` or `/data/config/certs/`
3. Deploy OS manager:  `./deploy_os_node.sh os-manager cluster_manager 10.10.2.10 ...`
4. Deploy OS data nodes (wait for manager to be green first)
5. Run bootstrap:  `./bootstrap_os.sh` from any host that can reach the manager on 9200
6. Deploy Redpanda
7. Deploy Arkime sensor (verify Kafka topic creation with `rpk topic list`)
8. Deploy ML gateway + Redis
9. Deploy UI proxy
10. Apply firewall rules per host:  `./firewall_rules.sh os_data 10.10.1.0/24 10.10.2.0/24`


## VMware-Specific Notes

- Enable CPU hot-add and memory hot-add on data node VMs for future scaling.
- Use PVSCSI controller for NVMe VMDKs (higher queue depth than LSI).
- Set power management to "High Performance" in both BIOS and ESXi host profile.
- Disable transparent huge pages (THP) on the ESXi host: `echo never > /sys/kernel/mm/transparent_hugepage/enabled` inside each VM.
- For the sensor VM, use DirectPath I/O (PCI passthrough) for the capture NIC and reserve all memory to prevent ballooning during packet bursts.
- Place data node VMDKs on separate NVMe datastores to avoid I/O contention.


## QEMU/KVM-Specific Notes

- Use `host-passthrough` CPU model for all VMs to expose SIMD instructions (AVX2 for simd-json, AES-NI for TLS).
- Allocate hugepages: `echo 131072 > /proc/sys/vm/nr_hugepages` (for 256 GB of 2 MB pages).
- Pin vCPUs with `virsh vcpupin` to dedicated physical cores. Avoid cross-NUMA scheduling.
- For the sensor, pass the capture NIC via VFIO: `vfio-pci` driver binding, IOMMU groups verified.
- Use `virtio-blk` with `io_uring` backend for NVMe-backed disk images.
- Set `cache=none,discard=unmap` on all disk devices for direct I/O.
- Consider `macvtap` in `bridge` mode for the data VLAN interfaces if you need VM-to-VM traffic to stay on the hypervisor without traversing a physical switch.