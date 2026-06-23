"""
Playbook planner — turn a swarm verdict + typed entities into the host IR
playbooks to initiate, plus the IOC parameters those playbooks consume.

Pure / stdlib-only (like `controls.py`) so the response agent's
playbook-initiation logic is exercised deterministically in unit tests without
the heavy agents package. The on-host agent (`operations/agent/response_executor.py`)
maps each `action_type` to a FIXED bundled playbook and reads the IOC params as
`NEXUS_*` env — this module decides *which* playbooks fire for a confirmed true
positive and assembles the typed IOCs from the investigation's entities.

Contract (mirrors operations/agent/response_executor.RESPONSE_ACTIONS):
    isolate_host · collect_forensics · block_ip · eradicate_process ·
    eradicate_persistence   (restore is operator/detonation-driven, not planned here)
"""
from __future__ import annotations

# -- os_family inference (host playbooks exist only for windows + linux) ------
# Cloud / network / generic sources have no on-host agent playbook; they route
# to the cloud/EDR/firewall path instead, so they yield no os_family here.
_WINDOWS_SOURCES = {"sysmon_sensor", "windows_deepsensor", "windows_c2", "trellix_ens"}
_LINUX_SOURCES = {"linux_sentinel", "linux_c2"}


def infer_os_family(alert: dict):
    """windows | linux | None. None means 'no on-host playbook applies' (cloud,
    network, macOS, or generic vector source) — the cloud/EDR path handles those."""
    st = str((alert or {}).get("source_type", "")).strip().lower()
    if st in _WINDOWS_SOURCES:
        return "windows"
    if st in _LINUX_SOURCES:
        return "linux"
    return None


# -- typed-IOC extraction from the investigation's entities -------------------
def _file_path(eid: str, edata: dict) -> str:
    """A 'file' entity tracks a confirmed-TP artifact with its path in `notes`
    (see state.EntityTracking); fall back to the id if no note path is present."""
    notes = str((edata or {}).get("notes", "")).strip()
    return notes or str(eid)


def extract_iocs(entities: dict) -> dict:
    """Bucket the *malicious* entities by type into the IOC sets the playbooks
    consume. Only entities whose status is 'malicious' are actioned; pending /
    investigating / cleared are never turned into a containment parameter."""
    iocs = {"c2_ips": [], "c2_domains": [], "pids": [],
            "hashes": [], "file_paths": [], "users": []}
    for eid, edata in (entities or {}).items():
        edata = edata or {}
        if edata.get("status") != "malicious":
            continue
        etype = str(edata.get("type", "")).strip().lower()
        sid = str(eid)
        if etype == "ip":
            iocs["c2_ips"].append(sid)
        elif etype == "domain":
            iocs["c2_domains"].append(sid)
        elif etype == "pid":
            iocs["pids"].append(sid)
        elif etype == "hash":
            iocs["hashes"].append(sid)
        elif etype == "file":
            iocs["file_paths"].append(_file_path(sid, edata))
        elif etype == "user":
            iocs["users"].append(sid)
    # de-dup, preserve first-seen order
    return {k: list(dict.fromkeys(v)) for k, v in iocs.items()}


# -- action planning ----------------------------------------------------------
# Ordered so volatile evidence is captured before anything destructive runs:
# isolate (stop spread, host stays up) → collect_forensics (RAM/disk capture) →
# block C2 → eradicate process → eradicate persistence. (RFC 3227 order of
# volatility: never eradicate before the memory image is taken.)
def plan_response_actions(recommended_action: str, iocs: dict, os_family) -> list:
    """The ordered host playbooks to initiate for this verdict. Empty unless the
    verdict is 'contain' on a host with a supported os_family — cloud/network
    targets and monitor/dismiss verdicts initiate no on-host playbook here."""
    if os_family not in ("windows", "linux"):
        return []
    if str(recommended_action).strip().lower() != "contain":
        return []
    iocs = iocs or {}
    actions = ["isolate_host", "collect_forensics"]
    if iocs.get("c2_ips") or iocs.get("c2_domains"):
        actions.append("block_ip")
    if iocs.get("pids"):
        actions.append("eradicate_process")
    if iocs.get("file_paths") or iocs.get("hashes"):
        actions.append("eradicate_persistence")
    return actions


# -- Two-phase (evidence-first) gating ----------------------------------------
# Wave 1 contains the host and captures volatile evidence; the RAM image then goes
# to worker_memory, whose findings re-enter the swarm as enrichment. Eradication
# (Wave 2) is held until that memory ground truth confirms the threat — so the
# swarm never destroys evidence or acts before a thorough investigation.
_WAVE1_ACTIONS = ("isolate_host", "collect_forensics")


def plan_response_waves(recommended_action: str, iocs: dict, os_family) -> dict:
    """Split the ordered plan into wave 1 (contain + collect) and wave 2
    (eradication). Either may be empty."""
    full = plan_response_actions(recommended_action, iocs, os_family)
    return {
        "wave1": [a for a in full if a in _WAVE1_ACTIONS],
        "wave2": [a for a in full if a not in _WAVE1_ACTIONS],
    }


def actions_for_phase(waves: dict, memory_enriched: bool, memory_threat: bool) -> list:
    """Which wave fires now. First pass (no memory enrichment yet) → wave 1
    (contain + collect). After the memory-forensics enrichment returns: wave 2
    (eradicate) only if the memory ground truth confirmed a threat; if memory
    cleared it, nothing is eradicated (the verdict can even flip to restore)."""
    waves = waves or {"wave1": [], "wave2": []}
    if not memory_enriched:
        return list(waves.get("wave1", []))
    return list(waves.get("wave2", [])) if memory_threat else []


def build_playbook_plan(alert: dict, verdict: dict, entities: dict,
                        memory_enriched: bool = False, memory_threat: bool = False) -> dict:
    """Full plan for the response agent: os_family + typed IOCs + both waves + the
    phase-appropriate `response_actions` to initiate now. First pass emits wave 1
    (contain + collect); a memory-enriched re-entry emits wave 2 (eradicate) iff the
    memory analysis confirmed the threat. `response_actions == []` ⇒ nothing fires."""
    os_family = infer_os_family(alert)
    iocs = extract_iocs(entities)
    waves = plan_response_waves((verdict or {}).get("recommended_action", ""), iocs, os_family)
    actions = actions_for_phase(waves, memory_enriched, memory_threat)
    return {"os_family": os_family, "iocs": iocs, "waves": waves,
            "memory_enriched": bool(memory_enriched), "response_actions": actions}
