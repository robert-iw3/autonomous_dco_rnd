"""
NIST AI 600-1 risk-management controls

This module is intentionally dependency-free (stdlib only) so it imports without
the heavy agents package __init__ and its decision logic can be exercised
deterministically in tests.

Implements:
  P3  Confabulated-evidence grounding     (Confabulation / NIST MS-2.5-003)
  P3  Confidence-calibration logging      (Confabulation / NIST MS-2.13-001)
  P1  Immunity-memory TTL / expiry        (Harmful Bias & Homogenization / GV-1.3-005)
  P5  AI-origin provenance disclosure     (Human-AI Configuration / MP-5.1-003)
  P2  Frontier model version pinning      (Value Chain & Component Integration / MP-4.1-007)
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re

# ---------------------------------------------------------------------------
# P3 -- Confabulated-evidence grounding (NIST MS-2.5-003, Risk 2.2 Confabulation)
#
# A confirmed True Positive whose justification names a high-confidence artifact
# (IP / file hash / PID / cloud ARN) that the swarm never actually retrieved is a
# confabulation. We re-resolve every such cited artifact against the union of all
# evidence the investigation saw; an ungrounded citation fails the verdict CLOSED
# to `monitor` -- never autonomous containment on fabricated evidence.
# ---------------------------------------------------------------------------

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_PID = re.compile(r"\bpid[=:\s]+(\d{2,7})\b", re.IGNORECASE)
_ARN = re.compile(r"\barn:aws:[a-z0-9\-]*:[a-z0-9\-]*:\d*:[^\s\"'<>]+", re.IGNORECASE)


def extract_artifacts(text) -> set:
    """Pull traceable forensic artifacts (IPv4, file hashes, PIDs, AWS ARNs) from
    free text. Deliberately conservative: prose numerics like confidence scores
    (`0.92`) or durations (`60s`) are NOT artifacts and must not be extracted."""
    if not text:
        return set()
    text = str(text)
    found: set = set()
    found |= set(_IPV4.findall(text))
    found |= {m.lower() for m in _SHA256.findall(text)}
    found |= {m.lower() for m in _SHA1.findall(text)}
    found |= {m.lower() for m in _MD5.findall(text)}
    found |= set(_PID.findall(text))
    found |= {m.lower() for m in _ARN.findall(text)}
    return found


def build_evidence_corpus(state: dict) -> set:
    """Union of every artifact the investigation actually observed: entity ids +
    notes, message contents, and the raw alert. This is the ground truth a
    confirmed verdict's citations must resolve against."""
    state = state or {}
    corpus: set = set()
    for eid, edata in (state.get("entities_of_interest", {}) or {}).items():
        corpus.add(str(eid))
        corpus |= extract_artifacts(eid)
        corpus |= extract_artifacts((edata or {}).get("notes", ""))
    for m in state.get("messages", []) or []:
        corpus |= extract_artifacts(getattr(m, "content", "") or "")
    alert = state.get("alert", {}) or {}
    corpus |= extract_artifacts(alert.get("raw_event", ""))
    if alert.get("sensor_id"):
        corpus.add(str(alert["sensor_id"]))
    return {c for c in corpus if c}


def grounding_violations(verdict: dict, corpus: set) -> list:
    """Artifacts cited in the verdict's justification that are absent from the
    evidence corpus (i.e. confabulated)."""
    cited = extract_artifacts((verdict or {}).get("justification", ""))
    return sorted(a for a in cited if a not in (corpus or set()))


def enforce_grounding(board_result: dict, state: dict):
    """If the board CONFIRMED a TP but the supervisor's finding cited artifacts the
    swarm never retrieved, demote to `monitor` (fail-closed). Returns
    (possibly-overridden result, violations)."""
    board_result = board_result or {}
    if not (board_result.get("verdict") or {}).get("is_true_positive"):
        return board_result, []
    supervisor_verdict = state.get("verdict") or {}
    violations = grounding_violations(supervisor_verdict, build_evidence_corpus(state))
    if not violations:
        return board_result, []
    prior = (board_result.get("verdict") or {}).get("justification", "")
    demoted = dict(board_result)
    demoted["verdict"] = {
        "is_true_positive": False,
        "confidence": 0.0,
        "recommended_action": "monitor",
        "justification": (
            "GROUNDING OVERRIDE: confirmed TP cited artifacts not found in the "
            f"investigation evidence ({', '.join(violations)}) -- treated as "
            f"confabulation; failing closed to monitor. {prior}"
        )[:1000],
    }
    return demoted, violations


# ---------------------------------------------------------------------------
# P3 -- Confidence calibration logging (NIST MS-2.13-001)
# Pairs the swarm's predicted verdict/confidence with the operator's realized
# disposition so calibration (and over/under-confidence) can be measured.
# ---------------------------------------------------------------------------

_REALIZED_TP = {"true_positive", "tp", "confirmed", "malicious", "escalated"}


def calibration_record(verdict: dict, operator_disposition: str) -> dict:
    """Build one calibration data point. `brier` is the squared error of the
    predicted probability of the realized class (lower is better-calibrated)."""
    v = verdict or {}
    predicted_tp = bool(v.get("is_true_positive"))
    confidence = float(v.get("confidence", 0.0) or 0.0)
    realized_tp = str(operator_disposition).strip().lower() in _REALIZED_TP
    p_tp = confidence if predicted_tp else (1.0 - confidence)
    actual = 1.0 if realized_tp else 0.0
    return {
        "predicted_tp": predicted_tp,
        "predicted_confidence": confidence,
        "realized_tp": realized_tp,
        "correct": predicted_tp == realized_tp,
        "brier": (p_tp - actual) ** 2,
    }


# ---------------------------------------------------------------------------
# P1 -- Immunity-memory TTL / expiry (NIST GV-1.3-005, Risk 2.6 Homogenization)
# Caps how long a stored False Positive can auto-dismiss future alerts, so a
# stale or wrong FP cannot entrench a permanent blind spot in the immunity loop.
# ---------------------------------------------------------------------------

def memory_ttl_seconds() -> int:
    return int(os.getenv("NEXUS_MEMORY_TTL_SECONDS", str(30 * 24 * 3600)))  # 30 days


def memory_is_actionable(payload: dict, now: float, ttl_seconds: int = None) -> bool:
    """Whether a recalled memory point may auto-dismiss a fresh alert. Only an
    eligible, non-expired False Positive qualifies. Legacy points written before
    the TTL existed (no `created_at`) preserve prior behavior and do not expire."""
    p = payload or {}
    if p.get("is_true_positive", True):          # only FPs grant immunity
        return False
    if not p.get("immunity_eligible", True):     # legacy default: eligible
        return False
    ttl = memory_ttl_seconds() if ttl_seconds is None else ttl_seconds
    created = p.get("created_at")
    if created is None:
        return True                              # backward-compat: no expiry info
    try:
        return (float(now) - float(created)) <= ttl
    except (TypeError, ValueError):
        return True


# ---------------------------------------------------------------------------
# P5 -- AI-origin provenance disclosure (NIST MP-5.1-003, Risk 2.7 Human-AI Config)
# Every analyst-facing incident report is stamped as AI-generated so a human
# consumer is never misled about the source of the verdict.
# ---------------------------------------------------------------------------

AI_PROVENANCE_BANNER = (
    "> 🤖 **AI-GENERATED** — produced by the Sentinel Nexus agentic swarm. "
    "Verify forensic claims against source telemetry before acting."
)


def stamp_ai_provenance(report: str) -> str:
    """Prepend the AI-origin disclosure banner once (idempotent)."""
    report = report or ""
    if AI_PROVENANCE_BANNER in report:
        return report
    return f"{AI_PROVENANCE_BANNER}\n\n{report}"


# ---------------------------------------------------------------------------
# P2 -- Frontier model version pinning (NIST MP-4.1-007, Risk 2.12 Value Chain)
# Frontier (external SaaS) models must be pinned to an explicit version; a
# floating alias lets a provider silently change verdict behavior with no gate.
# ---------------------------------------------------------------------------

_FRONTIER_API_TYPES = {"anthropic", "openai"}


def is_floating_model(model: str) -> bool:
    """A model id is 'floating' if empty or it resolves to a moving target
    (e.g. an alias ending in '-latest')."""
    if not model:
        return True
    return "latest" in str(model).strip().lower()


def unpinned_frontier_models(llm_cfg: dict) -> list:
    """Names of frontier (external) providers whose `model` is not version-pinned.
    Internal/sovereign providers (`internal_*`, or non-frontier api types) are out
    of scope -- their weights are hash-verified by the supply-chain control."""
    out = []
    for name, cfg in (llm_cfg or {}).items():
        cfg = cfg or {}
        if str(name).startswith("internal_"):
            continue
        if cfg.get("api_type") not in _FRONTIER_API_TYPES:
            continue
        if is_floating_model(cfg.get("model", "")):
            out.append(name)
    return out


# ───────────────────────────────────────────────────────────────────────────
# P1 -- Disaggregated fairness / disparity over verdict history
#       (NIST MS-2.11-002, Risk 2.6 Harmful Bias & Homogenization)
#
# Because the swarm makes AUTONOMOUS containment decisions, a subgroup that is
# systematically over- or under-contained is an allocative harm. This computes
# disaggregated containment/TP rates per subgroup (e.g. by source_type or asset
# class) and flags any group, with enough support, whose containment rate
# deviates from the fleet baseline by more than `max_disparity`.
# ───────────────────────────────────────────────────────────────────────────

_CONTAINMENT_ACTIONS = {"contain", "isolate_host", "block_ip"}


def _is_contained(rec: dict) -> bool:
    if "contained" in rec:
        return bool(rec["contained"])
    return str(rec.get("action", "")).strip().lower() in _CONTAINMENT_ACTIONS


def fairness_report(records, dimension: str = "source_type",
                    min_support: int = 5, max_disparity: float = 0.2) -> dict:
    """Disaggregated fairness audit over historical verdict records.

    Each record is a dict carrying the grouping `dimension` plus either an
    `action` string or a `contained` bool, and (optionally) `is_true_positive`.
    A subgroup with at least `min_support` samples whose containment rate differs
    from the overall baseline by more than `max_disparity` (absolute) is flagged.
    """
    records = list(records or [])
    total = len(records)
    if total == 0:
        return {"dimension": dimension, "total": 0, "baseline_tp_rate": 0.0,
                "baseline_contain_rate": 0.0, "groups": {}, "flagged": []}

    contained_total = sum(1 for r in records if _is_contained(r))
    tp_total = sum(1 for r in records if r.get("is_true_positive"))
    baseline_contain = contained_total / total
    baseline_tp = tp_total / total

    buckets: dict = {}
    for r in records:
        key = str(r.get(dimension, "<unknown>"))
        b = buckets.setdefault(key, {"n": 0, "contained": 0, "tp": 0})
        b["n"] += 1
        b["contained"] += 1 if _is_contained(r) else 0
        b["tp"] += 1 if r.get("is_true_positive") else 0

    groups, flagged = {}, []
    for key, b in buckets.items():
        contain_rate = b["contained"] / b["n"]
        delta = contain_rate - baseline_contain
        is_flagged = b["n"] >= min_support and abs(delta) > max_disparity
        groups[key] = {
            "n": b["n"],
            "tp_rate": round(b["tp"] / b["n"], 4),
            "contain_rate": round(contain_rate, 4),
            "delta": round(delta, 4),
            "flagged": is_flagged,
        }
        if is_flagged:
            flagged.append(key)

    return {
        "dimension": dimension,
        "total": total,
        "baseline_tp_rate": round(baseline_tp, 4),
        "baseline_contain_rate": round(baseline_contain, 4),
        "groups": groups,
        "flagged": sorted(flagged),
    }


# ───────────────────────────────────────────────────────────────────────────
# P1 -- Immunity-memory homogenization / model-collapse monitor
#       (NIST GV-1.3-005 / MS-2.11-005, Risk 2.6)
#
# The immunity loop feeds the swarm's own prior verdicts back into future
# analysis. If the stored signature distribution over-concentrates on a single
# pattern, that is a homogenization / model-collapse indicator worth alerting on.
# ───────────────────────────────────────────────────────────────────────────

def memory_homogenization(signatures, top_share_threshold: float = 0.5,
                          min_entropy: float = 0.5) -> dict:
    """Distribution health of the immunity memory. Accepts a list of signatures
    or a {signature: count} mapping. Flags `homogenized` when one signature owns
    more than `top_share_threshold` of the memory, or normalized Shannon entropy
    drops below `min_entropy`."""
    if isinstance(signatures, dict):
        counts = {k: int(v) for k, v in signatures.items() if int(v) > 0}
    else:
        counts = {}
        for s in (signatures or []):
            counts[s] = counts.get(s, 0) + 1

    total = sum(counts.values())
    distinct = len(counts)
    if total == 0:
        return {"total": 0, "distinct": 0, "top_share": 0.0,
                "normalized_entropy": 0.0, "homogenized": False}

    top_share = max(counts.values()) / total
    if distinct <= 1:
        norm_entropy = 0.0
    else:
        h = -sum((c / total) * math.log(c / total) for c in counts.values())
        norm_entropy = h / math.log(distinct)

    homogenized = top_share > top_share_threshold or (distinct > 1 and norm_entropy < min_entropy)
    return {
        "total": total,
        "distinct": distinct,
        "top_share": round(top_share, 4),
        "normalized_entropy": round(norm_entropy, 4),
        "homogenized": bool(homogenized),
    }


# ───────────────────────────────────────────────────────────────────────────
# NC-7 -- Automation-bias / over-reliance measurement
#         (NIST MG-1.3-002, MP-3.4-005; Risk 2.7 Human-AI Configuration)
#
# Structural HitL is not enough: if operators rubber-stamp the swarm's verdicts
# (especially confident ones), the human review is theatre. These measure the
# *human side* -- whether operators accept or override, and, once ground truth is
# known, how often a wrong AI call was accepted (automation bias) vs caught.
# ───────────────────────────────────────────────────────────────────────────

_OVERRIDE_ACTIONS = {"override", "overrode", "overruled", "reject", "rejected",
                     "escalate", "escalated", "manual", "correct", "corrected"}


def reliance_record(verdict: dict, operator_action: str,
                    ground_truth_disposition=None) -> dict:
    """One human-AI reliance data point: the AI verdict, whether the operator
    accepted or overrode it, and (optionally) the eventual ground truth. Anything
    not an explicit override counts as acceptance (the default, riskier posture)."""
    v = verdict or {}
    act = str(operator_action).strip().lower()
    rec = {
        "ai_tp": bool(v.get("is_true_positive")),
        "ai_confidence": float(v.get("confidence", 0.0) or 0.0),
        "accepted": act not in _OVERRIDE_ACTIONS,
    }
    if ground_truth_disposition is not None:
        truth_tp = str(ground_truth_disposition).strip().lower() in _REALIZED_TP
        rec["ground_truth_tp"] = truth_tp
        rec["ai_correct"] = (rec["ai_tp"] == truth_tp)
    return rec


def over_reliance_report(records, high_conf: float = 0.8, min_support: int = 5,
                         max_automation_bias: float = 0.5) -> dict:
    """Automation-bias / over-reliance metrics over reliance records.

    `automation_bias` = P(operator accepted | AI was wrong) -- the share of the
    swarm's mistakes the human rubber-stamped (only defined where ground truth
    exists). `caught_rate` = P(override | AI wrong). Acceptance is also split by AI
    confidence band as a complementary automation-bias signal. A run is flagged
    when automation_bias exceeds `max_automation_bias` with enough wrong-call
    support.
    """
    recs = list(records or [])
    n = len(recs)
    base = {"n": n, "accept_rate": None, "override_rate": None,
            "accept_rate_high_conf": None, "accept_rate_low_conf": None,
            "n_ai_wrong": 0, "n_ai_correct": 0, "automation_bias": None,
            "caught_rate": None, "over_distrust": None, "flagged": False, "reasons": []}
    if n == 0:
        return base

    accepts = sum(1 for r in recs if r.get("accepted"))
    base["accept_rate"] = round(accepts / n, 4)
    base["override_rate"] = round((n - accepts) / n, 4)

    hi = [r for r in recs if r.get("ai_confidence", 0.0) >= high_conf]
    lo = [r for r in recs if r.get("ai_confidence", 0.0) < high_conf]
    if hi:
        base["accept_rate_high_conf"] = round(sum(1 for r in hi if r.get("accepted")) / len(hi), 4)
    if lo:
        base["accept_rate_low_conf"] = round(sum(1 for r in lo if r.get("accepted")) / len(lo), 4)

    truthed = [r for r in recs if "ai_correct" in r]
    wrong = [r for r in truthed if not r["ai_correct"]]
    right = [r for r in truthed if r["ai_correct"]]
    base["n_ai_wrong"], base["n_ai_correct"] = len(wrong), len(right)
    if wrong:
        base["automation_bias"] = round(sum(1 for r in wrong if r.get("accepted")) / len(wrong), 4)
        base["caught_rate"] = round(sum(1 for r in wrong if not r.get("accepted")) / len(wrong), 4)
    if right:
        base["over_distrust"] = round(sum(1 for r in right if not r.get("accepted")) / len(right), 4)

    reasons = []
    if base["automation_bias"] is not None and len(wrong) >= min_support \
            and base["automation_bias"] > max_automation_bias:
        reasons.append(f"automation-bias {base['automation_bias']} of {len(wrong)} wrong AI calls "
                       f"were accepted (> {max_automation_bias})")
    base["reasons"] = reasons
    base["flagged"] = bool(reasons)
    return base


# ───────────────────────────────────────────────────────────────────────────
# NC-8 -- Active-learning failure capture (NIST MG-4.1-004, Risk 2.2 Confabulation)
#
# Turn the swarm's mistakes into training signal: when an operator's ground truth
# contradicts the verdict, or the verdict cited ungrounded evidence, emit a
# structured hard example for the MLOps continuous-improvement corpus.
# ───────────────────────────────────────────────────────────────────────────

def is_model_failure(verdict: dict, ground_truth_disposition=None,
                     grounding_violation: bool = False) -> bool:
    """True if this verdict is a captured failure: an ungrounded citation, or a
    class mismatch against operator ground truth (when ground truth is known)."""
    if grounding_violation:
        return True
    if ground_truth_disposition is None:
        return False
    truth_tp = str(ground_truth_disposition).strip().lower() in _REALIZED_TP
    return bool((verdict or {}).get("is_true_positive")) != truth_tp


def failure_record(verdict: dict, ground_truth_disposition=None,
                   grounding_violation: bool = False, event_id: str = "",
                   artifacts=None) -> dict | None:
    """Structured hard-example record, or None if the verdict was not a failure."""
    if not is_model_failure(verdict, ground_truth_disposition, grounding_violation):
        return None
    v = verdict or {}
    realized = None
    if ground_truth_disposition is not None:
        realized = str(ground_truth_disposition).strip().lower() in _REALIZED_TP
    return {
        "event_id": event_id,
        "predicted_tp": bool(v.get("is_true_positive")),
        "predicted_confidence": float(v.get("confidence", 0.0) or 0.0),
        "realized_tp": realized,
        "reason": "ungrounded_evidence" if grounding_violation else "misclassification",
        "artifacts": sorted(set(artifacts or [])),
    }


# ───────────────────────────────────────────────────────────────────────────
# NC-9 -- Tamper-evident verdict lineage (Risk 2.8 Information Integrity)
#
# An append-only SHA-256 hash chain over verdict/audit records: each entry binds
# the previous entry's hash, so any post-hoc edit, deletion, or reorder breaks the
# chain. Gives autonomous-containment decisions a verifiable, tamper-evident trail.
# ───────────────────────────────────────────────────────────────────────────

GENESIS_HASH = "0" * 64


def _canonical(record) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(prev_hash: str, record) -> str:
    return hashlib.sha256((prev_hash + _canonical(record)).encode("utf-8")).hexdigest()


def lineage_entry(prev_hash, record) -> dict:
    """Build one chain entry linking `record` to `prev_hash` (genesis if None)."""
    prev = prev_hash or GENESIS_HASH
    return {"record": record, "prev_hash": prev, "entry_hash": _entry_hash(prev, record)}


def verify_lineage(entries) -> dict:
    """Verify the hash chain. Returns the first broken index (or None if valid)."""
    prev = GENESIS_HASH
    for i, e in enumerate(entries or []):
        if e.get("prev_hash") != prev:
            return {"valid": False, "broken_at": i, "reason": "prev_hash mismatch"}
        if e.get("entry_hash") != _entry_hash(prev, e.get("record")):
            return {"valid": False, "broken_at": i, "reason": "entry_hash mismatch"}
        prev = e["entry_hash"]
    return {"valid": True, "broken_at": None, "reason": ""}


# ───────────────────────────────────────────────────────────────────────────
# NC-10 -- Per-run inference energy accounting (NIST MS-2.12-003, Risk 2.5)
#
# Folds the one-time footprint estimate (NC-6) into a per-run measurement:
# energy = power x time x PUE; carbon from a grid intensity factor. Deterministic;
# assumptions are documented in governance/environmental_impact_estimate.md.
# ───────────────────────────────────────────────────────────────────────────

def estimate_inference_energy(duration_s, avg_power_w, pue: float = 1.5,
                              grid_gco2_per_kwh: float = 400.0) -> dict:
    """Per-run energy (Wh) and carbon (gCO2e) estimate. Negative inputs clamp to 0."""
    duration_s = max(0.0, float(duration_s))
    avg_power_w = max(0.0, float(avg_power_w))
    pue = float(pue)
    energy_wh = avg_power_w * (duration_s / 3600.0) * pue
    co2e_g = (energy_wh / 1000.0) * float(grid_gco2_per_kwh)
    return {
        "energy_wh": round(energy_wh, 6),
        "co2e_g": round(co2e_g, 6),
        "duration_s": duration_s,
        "avg_power_w": avg_power_w,
        "pue": pue,
    }
