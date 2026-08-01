"""
worker_memory — the pure core that turns adjudicated memory findings into swarm
enrichment.

`to_enrichment` and the verdict-ladder helpers around it are the contract between the IR
memory-forensics workflow and the agentic stack, and they are indifferent to who ran the
analyzer. The DFIR platform runs it now: it collects the RAM image, seals it, holds it in
its enclave and adjudicates it with the toolkit both projects share, then publishes a
projection of the findings. `main.py` consumes that projection and passes it through here,
so the enrichment the swarm reads has the same shape it always did — the analyzer's
`Memory_Findings_<stamp>.json` (the shared finding_schema) and `_status.json` (tp_count),
mapped to TP-class findings + MITRE techniques. The swarm, on that enriched ground truth,
decides whether containment is warranted and initiates the established eradication
playbooks.

The image-format routing, analyzer invocation and S3 WORM helpers below belong to the
collect-and-store path this stack no longer runs. They are retired together with the
`nexus.memory.intake` producer in core_ingress, not before it.

Pure / stdlib; `main.py` is the IO shell.
"""
from __future__ import annotations

import time

# Ephemeral analysis container per OS family (the offline-staged IR toolkit lives
# inside). Pinned-by-digest in production via NEXUS_MEM_IMAGE_*; defaults shown.
ANALYSIS_IMAGES = {
    "linux": "docker.io/library/ubuntu:latest",                  # staged: Volatility 3 + ISF + AVML tools
    "windows": "mcr.microsoft.com/windows/servercore:ltsc2022",  # staged: MemProcFS + Volatility 3 + Python
}

# The EXISTING analyzers we drive (relative to the staged toolkit root). We extend
# these, never replace them.
ANALYZERS = {
    "linux": "linux/threat_hunting/Analyze-Memory-Linux.sh",
    "windows": "windows/threat_hunting/Analyze-Memory.ps1",
}

# Volatile-memory image formats the toolkit accepts; the analyzer routes by format
# (.aff4 → MemProcFS, the default winpmem capture; raw/lime/dmp/vmem → Volatility 3).
SUPPORTED_IMAGE_FORMATS = {"raw", "mem", "lime", "aff4", "dmp", "vmem", "core"}
_MEMPROCFS_FORMATS = {"aff4"}

# The single shared verdict ladder (mirrors operations/playbooks reporting/
# finding_schema.VERDICTS). TP-class = the actionable end of the ladder.
VERDICTS = ("False Positive", "Likely False Positive", "Indeterminate",
            "Likely True Positive", "True Positive")
_VERDICT_RANK = {v: i for i, v in enumerate(VERDICTS)}
_TP_CLASS_RANK = _VERDICT_RANK["Likely True Positive"]


class MemoryAnalysisError(ValueError):
    """Unknown os_family / unanalysable image."""


# -- image-format routing -----------------------------------------------------
def image_format(image_uri: str) -> str:
    """Lower-cased format extension of an image URI/path ('' if none)."""
    s = str(image_uri or "")
    return s.rsplit(".", 1)[-1].lower() if "." in s.rsplit("/", 1)[-1] else ""


def is_supported_image(image_uri: str) -> bool:
    return image_format(image_uri) in SUPPORTED_IMAGE_FORMATS


def analysis_engine(image_uri: str) -> str:
    """Which engine the existing analyzer will route to for this image format:
    MemProcFS for AFF4 (the default winpmem capture), Volatility 3 otherwise."""
    return "memprocfs" if image_format(image_uri) in _MEMPROCFS_FORMATS else "volatility3"


def select_analysis_image(os_family: str) -> str:
    try:
        return ANALYSIS_IMAGES[str(os_family).strip().lower()]
    except KeyError:
        raise MemoryAnalysisError(f"no memory-analysis image for os_family {os_family!r}")


def build_analyzer_command(os_family: str, image_path: str, host_folder: str,
                           fetch_symbols: bool = False) -> list:
    """The command line to run the EXISTING analyzer inside the container against a
    captured image, with `--adjudicate` so its findings pass the verdict ladder and
    land as `Memory_Findings_<stamp>.json` in `host_folder`. Never a free-form
    command — only the bundled analyzer for this OS."""
    osf = str(os_family).strip().lower()
    if osf not in ANALYZERS:
        raise MemoryAnalysisError(f"no analyzer for os_family {os_family!r}")
    if not image_path:
        raise MemoryAnalysisError("image_path required")
    script = ANALYZERS[osf]
    if osf == "linux":
        cmd = ["bash", script, "--image", image_path, "--host-folder", host_folder, "--adjudicate"]
        if fetch_symbols:
            cmd.append("--fetch-symbols")
    else:  # windows analyzer (routes .aff4→MemProcFS, raw/dmp→Volatility 3 itself)
        cmd = ["pwsh", "-File", script, "-ImagePath", image_path,
               "-OutputDir", host_folder, "-Adjudicate"]
    return cmd


# -- consume the toolkit's output (shared schema) → swarm enrichment ----------
def _ci(finding: dict, name: str):
    """Case-insensitive field fetch (the shared schema is matched case-insensitively)."""
    for k, v in (finding or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def is_tp_class(finding: dict) -> bool:
    """A finding the analyzer adjudicated at/above 'Likely True Positive'."""
    v = _ci(finding, "Verdict")
    return v in _VERDICT_RANK and _VERDICT_RANK[v] >= _TP_CLASS_RANK


def tp_class_findings(findings) -> list:
    return [f for f in (findings or []) if is_tp_class(f)]


def memory_threat(findings, status: dict = None) -> bool:
    """Memory is a confirmed threat when the analyzer adjudicated a TP-class memory
    finding, or the run's _status.json reports tp_count > 0 — the same signal the
    toolkit's own eradication `-MinVerdict` gate uses. Never a hand-rolled count."""
    if tp_class_findings(findings):
        return True
    return int((status or {}).get("tp_count", 0) or 0) > 0


def summarize_memory_findings(findings) -> str:
    tp = tp_class_findings(findings)
    if not tp:
        return "no true-positive-class memory findings"
    by_type = {}
    for f in tp:
        t = str(_ci(f, "Type") or "finding")
        by_type[t] = by_type.get(t, 0) + 1
    return "; ".join(f"{n}× {t}" for t, n in sorted(by_type.items(), key=lambda kv: -kv[1]))


def to_enrichment(incident_id: str, host: str, os_family: str,
                  findings, status: dict = None) -> dict:
    """The advisory enrichment the swarm re-ingests to make the verdict (flagged
    source → treated as evidence, never instructions). Carries the adjudicated
    TP-class memory findings + MITRE techniques + tp_count, mirroring what the
    detonation-enrichment loop feeds the swarm."""
    tp = tp_class_findings(findings)
    mitre = sorted({str(_ci(f, "MITRE")) for f in tp if _ci(f, "MITRE")} - {"", "None"})
    status = status or {}
    return {
        "source": "memory_forensics",
        "incident_id": str(incident_id),
        "host": str(host),
        "os_family": str(os_family),
        "memory_threat": memory_threat(findings, status),
        "tp_count": len(tp) or int(status.get("tp_count", 0) or 0),
        "status": status.get("status", ""),
        "findings": [{"Type": _ci(f, "Type"), "Target": _ci(f, "Target"),
                      "Verdict": _ci(f, "Verdict"), "MITRE": _ci(f, "MITRE")} for f in tp],
        "mitre": mitre,
        "summary": summarize_memory_findings(findings),
        "ts": time.time(),
    }


# -- Locked-down S3 historical archive (object-lock / WORM + KMS) --------------
def archive_key(incident_id: str, host: str, kind: str) -> str:
    """Deterministic, namespaced object key. `kind` ∈ {image, findings, custody, status}."""
    safe_host = "".join(c if (c.isalnum() or c in "-._") else "_" for c in str(host))[:64]
    return f"memory/{incident_id}/{safe_host}/{kind}"


# The RAM image holds cleartext creds/keys and must be operator-purgeable after a
# case → GOVERNANCE lock (deletable with the audited s3:BypassGovernanceRetention
# privilege). Findings/status/custody are the permanent record → COMPLIANCE.
_GOVERNANCE_KINDS = {"image"}


def lock_mode_for(kind: str) -> str:
    return "GOVERNANCE" if str(kind) in _GOVERNANCE_KINDS else "COMPLIANCE"


def s3_object_lock_params(bucket: str, key: str, retain_days: int = 365,
                          kms_key_id: str = "", kind: str = "findings") -> dict:
    """PUT params for the WORM archive: object-lock (GOVERNANCE for the image,
    COMPLIANCE for the record) + KMS/SSE. Bucket has object-lock + deny-delete
    out of band."""
    retain_days = max(1, int(retain_days))
    until = time.gmtime(time.time() + retain_days * 86400)
    params = {
        "Bucket": bucket,
        "Key": key,
        "ObjectLockMode": lock_mode_for(kind),
        "ObjectLockRetainUntilDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", until),
        "ServerSideEncryption": "aws:kms" if kms_key_id else "AES256",
    }
    if kms_key_id:
        params["SSEKMSKeyId"] = kms_key_id
    return params


# ── Operator-gated image deletion (post-investigation cleanup) ───────────────
# The case findings/custody persist; the privacy-sensitive RAM image is purged by
# an OPERATOR once the investigation is concluded — never autonomously.
_CONCLUDED = {"closed", "concluded", "resolved", "completed"}


def cleanup_eligible(investigation_status: str) -> bool:
    """The image may be purged only after the investigation is concluded."""
    return str(investigation_status or "").strip().lower() in _CONCLUDED


def operator_delete_image_params(bucket: str, key: str) -> dict:
    """delete_object params for the operator purge of a GOVERNANCE-locked image.
    BypassGovernanceRetention requires the operator's s3:BypassGovernanceRetention
    privilege; COMPLIANCE objects (the record) are unaffected and never bypassed."""
    return {"Bucket": bucket, "Key": key, "BypassGovernanceRetention": True}


def deletion_audit_record(incident_id: str, host: str, key: str, operator: str) -> dict:
    """Tamper-evident audit line for an operator image purge (→ custody log)."""
    return {
        "action": "memory_image_deleted",
        "incident_id": str(incident_id),
        "host": str(host),
        "s3_key": str(key),
        "operator": str(operator),
        "ts": time.time(),
    }
