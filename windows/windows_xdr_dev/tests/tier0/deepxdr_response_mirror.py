"""
Python tier0 mirror of DeepXDR's Nexus SOAR RESPONSE channel (DC-N11, Phase C).

DeepXDR today runs LOCAL mitigations off its OWN detections (ActiveDefenseModule:
QuarantinePid / Process.Kill / netsh BlockIp / ReleaseQuarantine). This mirrors the
new integration: a C# task channel that consumes a SIGNED Nexus response task over
the existing outbound HTTPS + HDR_BATCH_HMAC path, verifies it, and dispatches a
FIXED bundled Windows playbook (0X_*.ps1) -- the cloud-driven counterpart of the
in-proc ActiveDefense actions. No C# runtime here, so this re-derives the contract.

  # src: windows/windows_xdr_dev/agent/ResponseChannel.cs        (the C# module to build)
  # src: windows/windows_xdr_dev/agent/ActiveDefenseModule.cs    (in-proc mitigation today)
  # src: project_empros/operations/agent/response_executor.py    (canonical contract)
  # src: project_empros/operations/playbooks/windows/0X_*.ps1    (the bundled playbooks)
"""

import hashlib
import hmac
import json
import os
import subprocess
from pathlib import Path

# src: response_executor._PLAYBOOK_STEM (windows column). action_type -> fixed
# script; the task never supplies a path or command.
WIN_PLAYBOOK = {
    "isolate_host":          "01_Contain-Host.ps1",
    "eradicate_process":     "02_Eradicate-Process.ps1",
    "eradicate_persistence": "03_Eradicate-Persistence.ps1",
    "block_ip":              "04_Block-C2.ps1",
    "acquire_artifact":      "05_Acquire-Artifact.ps1",
    "restore":               "06_Restore-Host.ps1",
    "collect_forensics":     "00_Collect-Forensics.ps1",
}


class ResponseError(Exception):
    pass


def _canonical(task: dict) -> bytes:
    body = {k: task[k] for k in sorted(task) if k != "signature"}
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def verify_task(task: dict, secret: bytes) -> None:
    # src: HDR_BATCH_HMAC -- same HMAC-SHA256 primitive as the outbound batch path.
    expected = hmac.new(secret, _canonical(task), hashlib.sha256).hexdigest()
    if not task.get("signature") or not hmac.compare_digest(task["signature"], expected):
        raise ResponseError("response task signature invalid -- refusing to execute")


def select_playbook(action_type: str) -> str:
    try:
        return WIN_PLAYBOOK[action_type]
    except KeyError:
        raise ResponseError(f"no windows playbook for action {action_type!r}")


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
    """Verify → pick the FIXED bundled .ps1 → run via powershell with NEXUS_* env →
    report. `runner` is injected so tests never run a real mitigation."""
    verify_task(task, secret)
    playbook = select_playbook(task["action_type"])
    path = Path(playbooks_dir) / playbook
    if not path.exists():
        raise ResponseError(f"playbook not bundled on host: {playbook}")
    env = {**os.environ, **build_env(task)}
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)]
    result = runner(cmd, env=env, capture_output=True)
    rc = getattr(result, "returncode", 0)
    return {
        "incident_id": task["incident_id"], "host": task["host"],
        "action_type": task["action_type"], "playbook": playbook,
        "status": "completed" if rc == 0 else "failed",
        # → POSTed outbound (HDR_BATCH_HMAC) → core_ingress → nexus.soar.callback.
    }
