"""
Response executor -- the canonical contract the on-host agent uses to run a
Nexus-determined SOAR playbook locally (outbound-only endpoints; DC-N11).

Same pattern as det_chamber/agents/acquire_core.py: this is the tested Python
spec; the on-host agents mirror it (linux/sentinel in Rust, windows/windows_xdr_dev
in C#). worker_soar emits a signed RESPONSE TASK; the agent polls it (GET
/api/v1/tasks), verifies it, runs the matching playbook from a FIXED allowlist with
NEXUS_* env, and reports the outcome outbound (→ nexus.soar.callback).

SECURITY: the agent NEVER runs a path supplied by the task. The action_type selects
one of the fixed `operations/playbooks/{os}/0X_*` scripts; the task only carries
parameters (incident id, targets). A poisoned task therefore cannot make the agent
execute an arbitrary command.
"""

import hashlib
import hmac
import json
from typing import Dict, Tuple

# action_type → playbook stem. Only these run; nothing else is executable.
_PLAYBOOK_STEM = {
    "isolate_host":          ("00", "01_contain_host",        "01_Contain-Host"),
    "eradicate_process":     ("02", "02_eradicate_process",   "02_Eradicate-Process"),
    "eradicate_persistence": ("03", "03_eradicate_persistence", "03_Eradicate-Persistence"),
    "block_ip":              ("04", "04_block_c2",            "04_Block-C2"),
    "acquire_artifact":      ("05", "05_acquire_artifact",    "05_Acquire-Artifact"),
    "restore":               ("06", "06_restore",             "06_Restore-Host"),
    "collect_forensics":     ("00", "00_collect_forensics",   "00_Collect-Forensics"),
}
# The allowlist of basenames the agent may execute (defense in depth).
ALLOWED_PLAYBOOKS = frozenset(
    [f"{lin}.sh" for _, lin, _ in _PLAYBOOK_STEM.values()]
    + [f"{win}.ps1" for _, _, win in _PLAYBOOK_STEM.values()]
)


class ResponseTaskError(Exception):
    """Unknown action, bad os_family, or an unsigned/forged task."""


def select_playbook(action_type: str, os_family: str) -> str:
    """Return the FIXED playbook filename for an action (never a task-supplied path)."""
    try:
        _, lin, win = _PLAYBOOK_STEM[action_type]
    except KeyError:
        raise ResponseTaskError(f"no response playbook for action {action_type!r}")
    if os_family == "linux":
        return f"{lin}.sh"
    if os_family == "windows":
        return f"{win}.ps1"
    raise ResponseTaskError(f"unknown os_family {os_family!r}")


def build_env(task: dict) -> Dict[str, str]:
    """Map a response task to the NEXUS_* env the playbooks read. Targets/params
    only -- never a command or path the playbook would execute."""
    targets = task.get("targets", []) or []
    env = {"NEXUS_INCIDENT_ID": str(task["incident_id"])}
    action = task["action_type"]
    if action == "isolate_host":
        env["NEXUS_MGMT_IPS"] = ",".join(task.get("mgmt_ips", []))
    elif action == "block_ip":
        env["NEXUS_C2_IPS"] = ",".join(targets)
        env["NEXUS_C2_DOMAINS"] = ",".join(task.get("c2_domains", []))
    elif action == "eradicate_process":
        env["NEXUS_MALICIOUS_PIDS"] = ",".join(str(p) for p in task.get("pids", []))
        env["NEXUS_MALICIOUS_PROCESSES"] = ",".join(task.get("processes", []))
        env["NEXUS_MALICIOUS_HASHES"] = ",".join(task.get("hashes", []))
    elif action == "acquire_artifact":
        env["NEXUS_TARGET_PATH"] = str(task.get("file_path", ""))
        env["NEXUS_HOST"] = str(task.get("host", ""))
    return env


def _canonical(task: dict) -> bytes:
    body = {k: task[k] for k in sorted(task) if k != "signature"}
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def sign_task(task: dict, secret: bytes) -> str:
    """HMAC-SHA256 over the canonical task -- proves it came from Nexus worker_soar."""
    return hmac.new(secret, _canonical(task), hashlib.sha256).hexdigest()


def verify_task(task: dict, secret: bytes) -> None:
    """Raise ResponseTaskError unless the task carries a valid Nexus signature."""
    provided = task.get("signature", "")
    if not provided or not hmac.compare_digest(provided, sign_task(task, secret)):
        raise ResponseTaskError("response task signature invalid -- refusing to execute")


def prepare_execution(task: dict, *, secret: bytes) -> Tuple[str, Dict[str, str]]:
    """The agent's entrypoint: verify the task is from Nexus, pick the fixed
    playbook, build the env. Returns (playbook_filename, env). The agent then runs
    operations/playbooks/<os>/<playbook_filename> with this env -- nothing else."""
    verify_task(task, secret)
    playbook = select_playbook(task["action_type"], task["os_family"])
    if playbook not in ALLOWED_PLAYBOOKS:                # belt-and-suspenders
        raise ResponseTaskError(f"playbook {playbook!r} not in the allowlist")
    return playbook, build_env(task)
