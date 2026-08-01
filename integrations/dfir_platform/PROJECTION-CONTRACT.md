# The projection contract

What the DFIR platform publishes outward, and what this stack accepts. This document is the
specification both sides implement; [`contract.py`](contract.py) is the executable half of
it and refuses anything this document does not describe.

## Why a projection and not an API call

The platform is the system of record for memory evidence. It collects it, seals it, stores
it, and adjudicates it — inside an enclave whose whole design is that evidence moves inward
and nothing moves outward on its own. Its network policy permits exactly one connection into
the enclave: a brokered analyst session terminating at the SSO gate. There is no flow for an
external consumer to query the API, and adding one would be the failure its security model
names explicitly — a second inbound path arriving as one more network membership, for a
reason that seemed local at the time.

So the swarm does not reach in. The platform writes a **projection** outward to its DMZ edge
and this stack pulls it from there, the same way the platform's own puller reaches outward to
its receiver: the low-trust tier holds an opaque artifact, the connection is initiated from
one side only, and neither end holds a credential for the other's interior.

What crosses is derived, not evidential: adjudicated findings and the run context that makes
them interpretable. No capture bytes, no object keys, no carved regions, no extracted
configuration, no credential material. The bundle is small enough to read in full, and it is
meant to be read in full during review.

## Direction and transport

```
  enclave                        DMZ                        this stack
  ───────                        ───                        ──────────
  publisher  ──── PUT ────▶  dispatcher  ◀──── GET ────  worker_memory
  (initiates)                (holds only)                  (initiates)
```

Neither arrow enters the enclave. The dispatcher holds sealed bundles as opaque blobs and
holds no credential for anything inside.

The dispatcher's shape mirrors the platform's existing receiver, because that is the code the
platform already runs in that tier:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/pending` | JSON array of held bundle references |
| `GET` | `/fetch/<ref>` | the sealed bundle |
| `DELETE` | `/fetch/<ref>` | release after the consumer has acted on it |

TLS is required and the dispatcher's certificate is **pinned** by the consumer
(`NEXUS_PROJECTION_CA_BUNDLE`); there is exactly one server this should ever talk to, and a
public CA would vouch for anyone holding a certificate for that name.

A projection may also be carried on removable media and dropped into a directory
(`NEXUS_PROJECTION_DIR`). The seal is what makes that legitimate — the same reasoning that
lets an evidence bundle arrive on media at the platform's receiver. Consumed bundles are moved
aside, not deleted, so the drop remains a record of what was carried.

## Bundle

A single JSON object. UTF-8, no enclosing archive.

```json
{
  "contract": "dfir-platform.projection",
  "version": "1.0",
  "produced_at": "2026-08-01T12:00:00Z",
  "seal": { "alg": "HMAC-SHA256", "value": "<hex>" },
  "payload": {
    "run": { ... },
    "findings": [ { ... } ]
  }
}
```

### `payload.run` — the run context

| Field | Source | Notes |
|---|---|---|
| `run_id` | `CollectionRun.id` | required |
| `incident_id` | `Investigation.incident_id` | required; the correlation key on this side |
| `investigation` | `Investigation.name` | |
| `hostname` | `Host.hostname` | required |
| `machine_id` | `Host.machine_id` | |
| `platform` | `Host.platform` | required; `linux` / `windows` / `cloud` |
| `run_kind` | `CollectionRun.run_kind` | `initial` / `rescan` / `baseline` |
| `overall_status` | `CollectionRun.overall_status` | required; `COMPLETED` / `PARTIAL` / `FAILED` |
| `tp_count` | `CollectionRun.tp_count` | the platform's own adjudicated count, never recomputed here |
| `compromised` | `CollectionRun.compromised` | |
| `custody_verified` | `CollectionRun.custody_verified` | |
| `collected_at` | `CollectionRun.collected_at` | ISO 8601 |
| `toolkit_version` | `CollectionRun.toolkit_version` | |

### `payload.findings[]` — the adjudicated findings

| Field | Source | Notes |
|---|---|---|
| `finding_type` | `Finding.finding_type` | required; the toolkit schema's `Type` |
| `target` | `Finding.target` | required; the toolkit schema's `Target` |
| `verdict` | `Finding.verdict` | required; **must** be on the shared ladder |
| `confidence` | `Finding.confidence` | |
| `mitre` | `Finding.mitre` | list of ATT&CK technique ids, or a comma-joined string |
| `tier` | `Finding.tier` | |
| `source` | `Finding.source` | `collector` / `memory` / `LLM` |

The verdict ladder is owned by the toolkit's `reporting/finding_schema.py`, mirrored by the
platform's `cases/models.py`, and mirrored a third time in [`contract.py`](contract.py):

```
False Positive · Likely False Positive · Indeterminate · Likely True Positive · True Positive
```

A verdict outside it is refused rather than treated as non-TP. A verdict this consumer does
not understand is not evidence of innocence.

## Rules the bundle must satisfy

**Sealed.** `seal.value` is HMAC-SHA256 over the canonical encoding of `payload` — JSON with
sorted keys and no whitespace — under a key shared out of band. The key is never carried in
the bundle. An unsealed bundle is refused; a consumer that quietly accepted one would make
the seal decorative.

**Flat.** Every value in `payload` is a scalar or a list of scalars. There is no nested object
anywhere. The content is derived from a compromised host's RAM, so the question is not whether
the platform sent something reasonable but whether there is any shape in which it could carry
something else — and a structure with no containers has no smuggling channel.

**Allow-listed.** The fields above are exhaustive. An unknown key is a refusal, not an
ignored extra, so a widening of the projection is a decision rather than an accident.

**Bounded.** Strings are capped at 2048 characters and a bundle at 10 000 findings. A field
longer than that has stopped being an identifier and started being a payload.

**Never present.** Memory image bytes or offsets, object-store buckets/keys/etags, the
verbatim `Finding.raw`, `Finding.subject_path`, carved regions, `RegionAnalysis` content
(extracted C2 configuration, crypto material, strings of interest, YARA matches), notes,
audit entries, credentials, tokens. These are excluded by the allow-list rather than by
filtering, so nothing is omitted only because someone remembered to omit it.

## Identity and re-delivery

A bundle's identity is the SHA-256 of its canonical payload. Republishing the same run
produces the same id, so re-delivery is idempotent: the consumer records ids it has acted on
and does not emit a second enrichment for one it has seen. This is what makes the dispatcher
safe to retry and the directory drop safe to re-mount.

## What the consumer does with it

[`worker_memory`](../../services/worker_memory) validates the bundle, maps it into the
toolkit's own finding schema, and passes it through the enrichment core that already existed
— so the swarm receives `nexus.memory.enrichment` in exactly the shape it always did, and
nothing downstream changes. The enrichment is flagged `source: memory_forensics`: it is
evidence for the swarm to reason over, never instructions to follow.

A bundle that fails validation goes to `nexus.dlq.memory_projection` with the reason. It is
not dropped, and it is not partially accepted.

## Versioning and drift

`version` is `major.minor`. A consumer accepts any bundle whose **major** matches; a minor
bump may add optional fields to the allow-list and nothing else. Removing a field, renaming
one, or changing the verdict ladder is a major bump.

The platform changes on its own track, and most of its changes are irrelevant here. The ones
that are not are pinned: [`platform_drift.py`](platform_drift.py) reads a platform checkout,
extracts the contract surface — both verdict ladders and the model fields this document maps
— and diffs it against [`platform_baseline.json`](platform_baseline.json).

```bash
python integrations/dfir_platform/platform_drift.py --check
```

Contract-affecting drift fails the check. The procedure is: read what moved, revise this
document and `contract.py` together, then re-pin with `--update`. The baseline is a reviewed
statement about another repository, so it changes by decision, never as a side effect.

## Status of the platform side

The publisher and dispatcher are **specified here, not built**. The platform tree is developed
on its own track and is not modified from this repository. Until they exist, the directory
drop is the working transport: a bundle conforming to this document, dropped into
`NEXUS_PROJECTION_DIR`, is consumed exactly as one pulled from a dispatcher would be.
