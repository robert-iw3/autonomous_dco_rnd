"""
Detonation enrichment -- maps a nexus.alerts.detonation result to a follow-up action.

When the Det Chamber returns a verdict for an acquired file, the swarm reacts:
  * malicious      -> contain the host (evidence-backed, not just score-backed),
  * benign + prior containment -> RESTORE (it was a false positive),
  * custody_failed -> manual review (never silently trust a broken chain),
  * benign / unknown with no containment -> no action (monitor).

The decision is pure and unit-tested; the orchestrator's listener calls it and
dispatches the returned action through the normal SOAR pipeline.
"""

from typing import Optional


def interpret_summary(summary) -> str:
    """Reduce a detonation summary to 'malicious' | 'benign' | 'unknown'."""
    if not isinstance(summary, dict):
        return "unknown"
    verdict = str(summary.get("verdict", "")).lower()
    if verdict in ("malicious", "benign"):
        return verdict
    static = summary.get("static", {}) or {}
    if static.get("yara_matches"):
        return "malicious"
    return "unknown"


def enrichment_decision(result: dict, *, had_containment: bool) -> Optional[dict]:
    """Return a SoarExecutionSchema-shaped action dict, or None for no action."""
    incident_id = result.get("incident_id", "")
    host = result.get("host", "")
    sha = str(result.get("sha256", ""))[:12]

    if result.get("status") == "custody_failed":
        return {
            "incident_id": incident_id, "action_type": "manual_review_required",
            "target_sensor": host, "targets": [host] if host else [],
            "confidence": 0.0, "reason": "detonation custody verification failed; review required",
        }

    verdict = interpret_summary(result.get("summary"))
    if verdict == "malicious":
        return {
            "incident_id": incident_id, "action_type": "isolate_host",
            "target_sensor": host, "targets": [host] if host else [],
            "confidence": 0.95, "reason": f"detonation confirmed malicious (sha {sha})"[:200],
        }
    if verdict == "benign" and had_containment:
        return {
            "incident_id": incident_id, "action_type": "restore",
            "target_sensor": host, "targets": [host] if host else [],
            "confidence": 0.90, "reason": f"detonation benign (false positive, sha {sha}); restore"[:200],
        }
    # benign/unknown with no containment in place -> nothing to undo, keep monitoring.
    return None
