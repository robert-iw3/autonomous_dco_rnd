"""
Lab operations -- SOAR response execution (NEXUS side).

Validates the contract that lets an outbound-only endpoint run a Nexus-determined
playbook (DC-N11): the canonical response_executor maps a signed SOAR task to a
FIXED `operations/playbooks/{os}/0X_*` script + NEXUS_* env, and every SOAR action
the swarm can emit has a runnable playbook. Proves the safety property too: an
unsigned/forged task, an unknown action, or any attempt to steer execution off the
allowlist is refused.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "operations" / "agent"))
import response_executor as rx   # noqa: E402

# Bundled playbooks live under operations/playbooks/playbooks/<os>/ (the inner
# `playbooks/` is the script tree; the outer dir is the toolkit root with the
# builder, docker, tests, planning). This is what gets staged to the air-gapped host.
PLAYBOOKS = ROOT / "operations" / "playbooks" / "playbooks"
SECRET = b"nexus-soar-task-secret"


def _task(action="isolate_host", os_family="linux", **over):
    t = {"incident_id": "INC-R", "host": "EP-1", "os_family": os_family,
         "action_type": action, "targets": ["10.0.0.9"]}
    t.update(over)
    t["signature"] = rx.sign_task(t, SECRET)
    return t


# ── action → a REAL, allowlisted playbook ────────────────────────────────────
@pytest.mark.parametrize("action,os_family,subdir,fname", [
    ("isolate_host", "linux", "linux", "01_contain_host.sh"),
    ("isolate_host", "windows", "windows", "01_Contain-Host.ps1"),
    ("block_ip", "linux", "linux", "04_block_c2.sh"),
    ("restore", "windows", "windows", "06_Restore-Host.ps1"),
    ("acquire_artifact", "linux", "linux", "05_acquire_artifact.sh"),
    ("collect_forensics", "linux", "linux", "00_collect_forensics.sh"),
    ("collect_forensics", "windows", "windows", "00_Collect-Forensics.ps1"),
    ("eradicate_persistence", "linux", "linux", "03_eradicate_persistence.sh"),
    ("eradicate_persistence", "windows", "windows", "03_Eradicate-Persistence.ps1"),
    ("eradicate_process", "linux", "linux", "02_eradicate_process.sh"),
])
def test_action_maps_to_real_playbook(action, os_family, subdir, fname):
    pb = rx.select_playbook(action, os_family)
    assert pb == fname
    assert pb in rx.ALLOWED_PLAYBOOKS
    assert (PLAYBOOKS / subdir / pb).exists(), f"the mapped playbook must exist on disk: {fname}"


def test_unknown_action_or_os_refused():
    with pytest.raises(rx.ResponseTaskError):
        rx.select_playbook("rm_rf_slash", "linux")
    with pytest.raises(rx.ResponseTaskError):
        rx.select_playbook("isolate_host", "solaris")


# ── env construction per action ──────────────────────────────────────────────
# The playbooks read IR_* (same names playbooks/run_containment.sh exports); the
# agent must set those, NOT a divergent NEXUS_* set, or playbooks run param-less.
def test_build_env_uses_the_ir_contract_the_playbooks_read():
    assert rx.build_env(_task("block_ip"))["IR_C2_IPS"] == "10.0.0.9"
    erad = rx.build_env(_task("eradicate_process", pids=[1337], processes=["evil.exe"], hashes=["ab"]))
    assert erad["IR_MALICIOUS_PIDS"] == "1337" and erad["IR_MALICIOUS_PROCESSES"] == "evil.exe"
    acq = rx.build_env(_task("acquire_artifact", file_path="/tmp/x", host="EP-1"))
    assert acq["IR_TARGET_PATH"] == "/tmp/x"
    assert all(e["IR_INCIDENT_ID"] == "INC-R" for e in
               (rx.build_env(_task()), erad, acq))
    # no stray NEXUS_* keys leak (would be silently ignored by the playbooks)
    assert not any(k.startswith("NEXUS_") for k in erad)

def test_build_env_eradicate_persistence_and_collect():
    persist = rx.build_env(_task("eradicate_persistence", file_paths=["/tmp/.x/p.bin"], hashes=["abc"]))
    assert persist["IR_MALICIOUS_PATHS"] == "/tmp/.x/p.bin"
    assert persist["IR_MALICIOUS_HASHES"] == "abc"
    collect = rx.build_env(_task("collect_forensics", host="EP-7"))
    assert collect["IR_HOST"] == "EP-7" and collect["IR_INCIDENT_ID"] == "INC-R"


# ── SAFETY: only signed tasks run; the task can't choose the command ─────────
def test_unsigned_or_forged_task_refused():
    t = _task()
    t["signature"] = "deadbeef"                          # forged
    with pytest.raises(rx.ResponseTaskError):
        rx.prepare_execution(t, secret=SECRET)
    t2 = _task(); del t2["signature"]                    # unsigned
    with pytest.raises(rx.ResponseTaskError):
        rx.prepare_execution(t2, secret=SECRET)


def test_prepare_execution_happy_path():
    pb, env = rx.prepare_execution(_task("isolate_host", "linux", mgmt_ips=["10.0.0.0/24"]), secret=SECRET)
    assert pb == "01_contain_host.sh" and env["IR_MGMT_IPS"] == "10.0.0.0/24"


def test_task_cannot_inject_an_arbitrary_path():
    # Even if a poisoned task smuggles a 'playbook'/'command' field, execution is
    # selected ONLY from the action_type → fixed allowlist.
    t = _task(action="isolate_host", playbook="/etc/evil.sh", command="rm -rf /")
    t["signature"] = rx.sign_task(t, SECRET)
    pb, _ = rx.prepare_execution(t, secret=SECRET)
    assert pb == "01_contain_host.sh"                    # not the injected path


# ── NEXUS ↔ agent contract: every SOAR action_type is runnable on the host ───
def test_every_swarm_soar_action_has_a_playbook():
    # Action types the swarm's SoarExecutionSchema can emit that target a host.
    for action in ("isolate_host", "block_ip", "restore", "acquire_artifact"):
        for os_family, sub in (("linux", "linux"), ("windows", "windows")):
            pb = rx.select_playbook(action, os_family)
            assert (PLAYBOOKS / sub / pb).exists(), f"{action}/{os_family} → {pb} missing"
