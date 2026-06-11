"""
Python tier0 mirror of linux-sentinel's SOAR RESPONSE module (DC-N11, Phase B).

linux-sentinel is detection + outbound telemetry today; the response side is the
integration this mirrors so tier0 can prove the logic without a Rust runtime. The
real Rust module (to build) reuses the sentinel's existing outbound HTTP client +
nexus_integrity HMAC to: poll core_ingress GET /api/v1/tasks, VERIFY the Nexus
signature, select a FIXED bundled playbook by action (never a task-supplied path),
set NEXUS_* env, run it locally, and report the outcome to nexus.soar.callback.

Every constant is annotated with its source of truth so drift fails loudly:
  # src: linux/sentinel/src/response/mod.rs                    (the Rust module to build)
  # src: project_empros/operations/agent/response_executor.py  (canonical contract)
  # src: project_empros/operations/agent/task_dispatch.py      (signed task envelope)
  # src: project_empros/operations/playbooks/linux/0X_*.sh     (the bundled playbooks)
"""

import hashlib
import hmac
import json
import os
import subprocess
from pathlib import Path

# src: response_executor._PLAYBOOK_STEM (linux column). Fixed allowlist -- the
# action_type selects the script; the task never supplies a path.
LINUX_PLAYBOOK = {
    "isolate_host":          "01_contain_host.sh",
    "eradicate_process":     "02_eradicate_process.sh",
    "eradicate_persistence": "03_eradicate_persistence.sh",
    "block_ip":              "04_block_c2.sh",
    "acquire_artifact":      "05_acquire_artifact.sh",
    "restore":               "06_restore.sh",
    "collect_forensics":     "00_collect_forensics.sh",
}


class ResponseError(Exception):
    pass


def _canonical(task: dict) -> bytes:
    body = {k: task[k] for k in sorted(task) if k != "signature"}
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def verify_task(task: dict, secret: bytes) -> None:
    # src: nexus_integrity HMAC-SHA256, same primitive as outbound telemetry.
    expected = hmac.new(secret, _canonical(task), hashlib.sha256).hexdigest()
    if not task.get("signature") or not hmac.compare_digest(task["signature"], expected):
        raise ResponseError("response task signature invalid -- refusing to execute")


def select_playbook(action_type: str) -> str:
    try:
        return LINUX_PLAYBOOK[action_type]
    except KeyError:
        raise ResponseError(f"no linux playbook for action {action_type!r}")


def build_env(task: dict) -> dict:
    env = {"NEXUS_INCIDENT_ID": str(task["incident_id"])}
    a, targets = task["action_type"], task.get("targets", []) or []
    if a == "isolate_host":
        env["NEXUS_MGMT_IPS"] = ",".join(task.get("mgmt_ips", []))
    elif a == "block_ip":
        env["NEXUS_C2_IPS"] = ",".join(targets)
        env["NEXUS_C2_DOMAINS"] = ",".join(task.get("c2_domains", []))
    elif a == "eradicate_process":
        env["NEXUS_MALICIOUS_PIDS"] = ",".join(str(p) for p in task.get("pids", []))
        env["NEXUS_MALICIOUS_PROCESSES"] = ",".join(task.get("processes", []))
        env["NEXUS_MALICIOUS_HASHES"] = ",".join(task.get("hashes", []))
    elif a == "acquire_artifact":
        env["NEXUS_TARGET_PATH"] = str(task.get("file_path", ""))
        env["NEXUS_HOST"] = str(task.get("host", ""))
    return env


def execute_task(task: dict, *, secret: bytes, playbooks_dir, runner=subprocess.run) -> dict:
    """Verify → pick the FIXED bundled playbook → run with NEXUS_* env → report.
    `runner` is injected so tests never actually run a containment script."""
    verify_task(task, secret)
    playbook = select_playbook(task["action_type"])
    path = Path(playbooks_dir) / playbook
    if not path.exists():
        raise ResponseError(f"playbook not bundled on host: {playbook}")
    env = {**os.environ, **build_env(task)}
    result = runner(["bash", str(path)], env=env, capture_output=True)
    rc = getattr(result, "returncode", 0)
    return {
        "incident_id": task["incident_id"], "host": task["host"],
        "action_type": task["action_type"], "playbook": playbook,
        "status": "completed" if rc == 0 else "failed",
        # → POSTed outbound to core_ingress, relayed to nexus.soar.callback.
    }
