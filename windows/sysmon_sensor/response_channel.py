"""
SOAR response channel for the Sysmon sensor (DC-N11).

A Windows endpoint that runs ONLY the lightweight Sysmon sensor (no full DeepXDR
agent) still needs a way to act on a Nexus verdict. This is that mechanism -- the
same outbound-only model as DeepXDR's ResponseChannel and linux-sentinel's
response module:

  poll  core_ingress GET /api/v1/tasks   (reusing the shipper's gateway + bearer
                                           token + HMAC secret; no inbound reach)
  verify the Nexus HMAC-SHA256 signature (the secret stays on the host)
  select a FIXED bundled Windows playbook by action_type (never a task path)
  run   powershell -File <playbook>       with NEXUS_* env
  report the outcome outbound

Canonical contract (kept byte-identical): project_empros/operations/agent/
response_executor.py -- the same signer worker_soar uses. The cross-component test
signs with that module and asserts this channel accepts it.
"""

import hashlib
import hmac
import json
import os
import socket
import subprocess
import threading
import time

try:
    import requests
except ImportError:  # requests is a sensor runtime dep; tests inject a session
    requests = None

# action_type -> fixed bundled Windows playbook. Mirror of response_executor's
# windows column; the action selects the script, never a task-supplied path.
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


def execute_task(task: dict, *, secret: bytes, playbooks_dir, runner=None) -> dict:
    """Verify -> pick the FIXED .ps1 -> run with NEXUS_* env -> outcome dict.
    `runner` is injectable so tests never spawn a real mitigation; defaults to
    subprocess.run (late-bound so it stays patchable)."""
    verify_task(task, secret)
    playbook = select_playbook(task["action_type"])
    path = os.path.join(str(playbooks_dir), playbook)
    if not os.path.exists(path):
        raise ResponseError(f"playbook not bundled on host: {playbook}")
    env = {**os.environ, **build_env(task)}
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path]
    result = (runner or subprocess.run)(cmd, env=env, capture_output=True)
    rc = getattr(result, "returncode", 0)
    return {
        "incident_id": task["incident_id"], "host": task.get("host", ""),
        "action_type": task["action_type"], "playbook": playbook,
        "status": "completed" if rc == 0 else "failed",
    }


def _tasks_url(middleware_url: str) -> str:
    """Derive the task-poll endpoint from the telemetry gateway URL."""
    base = middleware_url.rstrip("/")
    for suffix in ("/api/v1/telemetry", "/telemetry"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return f"{base.rstrip('/')}/api/v1/tasks"


class ResponseChannel:
    """Outbound poll loop. Reuses the shipper's env config so a Sysmon-only host
    needs no extra wiring beyond enabling NEXUS_ENABLE_RESPONSE=true."""

    def __init__(self):
        self.tasks_url = _tasks_url(os.environ.get(
            "NEXUS_MIDDLEWARE_URL", "https://middleware.internal:8443/api/v1/telemetry"))
        self.outcome_url = f"{self.tasks_url}/outcome"
        self.auth_token = os.environ.get("NEXUS_AUTH_TOKEN", "")
        self.secret = os.environ.get(
            "NEXUS_INTEGRITY_SECRET", "Nexus-Integrity-SharedKey-Rotate-Me").encode()
        self.sensor_id = os.environ.get("NEXUS_SENSOR_ID", socket.gethostname())
        self.playbooks_dir = os.environ.get(
            "NEXUS_PLAYBOOKS_DIR", r"C:\ProgramData\NexusSysmonSensor\playbooks\windows")
        self.tls_verify = os.environ.get("NEXUS_TLS_VERIFY", "true").lower() == "true"
        self.poll_interval_s = int(os.environ.get("NEXUS_RESPONSE_POLL_S", "15"))
        self._running = True

    def poll_once(self, session) -> list:
        """One outbound poll: fetch, verify, execute, report. Returns the outcomes
        (for tests/metrics). A forged/unknown task is logged and skipped, not run."""
        outcomes = []
        resp = session.get(self.tasks_url, headers={"Authorization": f"Bearer {self.auth_token}"},
                           verify=self.tls_verify, timeout=30)
        if resp.status_code != 200:
            return outcomes
        for task in resp.json().get("tasks", []):
            try:
                outcome = execute_task(task, secret=self.secret, playbooks_dir=self.playbooks_dir)
                session.post(self.outcome_url, json=outcome,
                             headers={"Authorization": f"Bearer {self.auth_token}"},
                             verify=self.tls_verify, timeout=30)
                outcomes.append(outcome)
            except ResponseError as e:
                # refuse + continue; never let a bad task stop the loop
                print(f"[response] task rejected/failed: {e}")
        return outcomes

    def run(self) -> None:
        session = requests.Session()
        print(f"[response] sysmon response channel polling {self.tasks_url}")
        while self._running:
            try:
                self.poll_once(session)
            except Exception as e:  # network/transient -- keep polling
                print(f"[response] poll failed: {e}")
            time.sleep(self.poll_interval_s)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="sysmon-response", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._running = False
