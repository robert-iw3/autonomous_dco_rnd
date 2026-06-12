---
title: "Data Retention & Decommissioning Policy"
subtitle: "Sentinel Nexus — AI Data Lifecycle"
author: "RW"
date: "June 2026"
version: "1.0"
---

\newpage

## Purpose

Per NIST AI 600-1 **GV-1.7-002** (decommissioning factors), **MS-2.10-001**
(membership-inference / training-data extraction), and **MS-2.2-004** (privacy-enhancing
techniques), this policy governs retention, expiry, and secure decommissioning of the
AI-relevant data stores in Sentinel Nexus. It addresses control item **NC-4**.

## Data stores in scope

| Store | Contents | Sensitivity |
|---|---|---|
| Cold storage (Parquet on MinIO/S3) | Normalized sensor telemetry (Hive-partitioned) | High |
| Qdrant vector index | UEBA math vectors + payloads (per-investigation) | High |
| **`nexus_swarm_memory`** (Qdrant) | Verdict/immunity signatures + embeddings + incident reports | High |
| RSI / calibration / bias-audit ledgers | Cycle outcomes, calibration points, audit reports | Moderate |
| MLOps staging / training corpora | Synthetic + sanitized telemetry SFT records | Moderate |

## Retention & expiry

| Store | Retention | Mechanism |
|---|---|---|
| Cold storage | Per data-classification schedule (operator-set) | S3 lifecycle / partition pruning |
| DR snapshots | 7 days local | `dr_snapshot` timer |
| `nexus_swarm_memory` immunity points | **TTL-bounded** (default 30 d, `NEXUS_MEMORY_TTL_SECONDS`) | A point past TTL no longer grants auto-dismissal (control implemented; recall delegates to `memory_is_actionable`) |
| Calibration / bias ledgers | Rolling; archived not deleted | Append-only files |

**Membership-inference posture (MS-2.10-001).** `nexus_swarm_memory` stores embeddings
of alert signatures. Risk: an adversary with read access could infer prior incidents.
Mitigations: the store is inside the access-controlled enclave (no external exposure);
the signature is keyed on stable *pattern identity* (sensor|source_type|vector), not raw
PII; the TTL bounds the window. **Open action (POA&M-4):** add a periodic
membership-inference review and evaluate differential-privacy / anonymization on the
memory vectors.

## Decommissioning (GV-1.7-002)

When a model, sensor source, or the system is retired, the following are verified:

1. **Data retention requirements** — confirm legal/operational holds before purge.
2. **Secure erasure** — cryptographic erase of weights/secrets; purge of the relevant
   `nexus_swarm_memory` signatures and cold-storage partitions; revoke Vault paths.
3. **Data leakage after decommission** — confirm no residual in DR snapshots beyond the
   retention window; rotate the `integrity_secret` and any shared keys.
4. **Dependencies** — check upstream/downstream IoT/AI/data dependencies before removal
   (e.g. a retired sensor's `source_type` routing and SIEM fanout mapping).
5. **Open-source / model artifacts** — remove from the model registry per the N=3 +
   referenced-version retention rule.
6. **Operator entanglement** — communicate deactivation, reasons, and alternative
   process to affected operators (per MG-2.4-001).

## Privacy-enhancing handling

- Training corpora are **credential-scrubbed** at staging (`01_spool_chatml`,
  `01_spool_datasets`) — passwords/keys/tokens masked before any record enters the
  corpus.
- Outbound DLP scrubs RFC-1918 ranges and high-entropy secrets before any frontier
  egress; the cognitive sanitizer wraps adversary-controlled data as untrusted.
- TEVV / report retention follows the document-retention rule (GV-1.5-003): raw `.log`
  files are not committed; structured `.md`/`.xml` reports are retained for audit.

## Review

Reviewed annually and on any change to a data store's contents, classification, or the
external interconnection set.
