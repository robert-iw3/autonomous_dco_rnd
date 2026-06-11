"""
Lab operations -- Phase A: Nexus-side task dispatch (shared), end to end.

Proves the shared path that tasks an outbound-only endpoint: a SOAR action (or an
acquisition) becomes a SIGNED task in a per-host store; the agent polls it and the
canonical response_executor turns it into a fixed playbook + NEXUS_* env. Includes
the E2E seam (dispatch → store → poll → prepare_execution) and the safety property
(a forged/unsigned polled task is refused).
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "operations" / "agent"))
import task_dispatch as td       # noqa: E402
import response_executor as rx   # noqa: E402

PLAYBOOKS = ROOT / "operations" / "playbooks"
SECRET = b"nexus-task-dispatch-secret"


# -- Task build + signature ---------------------------------------------------
def test_response_task_is_signed_and_verifiable():
    t = td.build_response_task(incident_id="INC", host="EP-1", os_family="linux",
                               action_type="isolate_host", mgmt_ips=["10.0.0.0/24"], secret=SECRET)
    rx.verify_task(t, SECRET)                      # signed by Nexus → verifies
    assert t["kind"] == "response" and t["action_type"] == "isolate_host"


def test_acquisition_task_built():
    t = td.build_acquisition_task(incident_id="INC", host="EP", os_family="windows",
                                  file_path="C:\\Users\\Public\\evil.exe", secret=SECRET)
    assert t["action_type"] == "acquire_artifact"
    rx.verify_task(t, SECRET)


def test_non_response_action_rejected():
    with pytest.raises(ValueError):
        td.build_response_task(incident_id="X", host="h", os_family="linux",
                               action_type="rm_rf", secret=SECRET)


# -- Per-host store -----------------------------------------------------------
def test_store_enqueue_poll_drains_per_host():
    store = td.TaskStore()
    store.enqueue("EP-1", td.build_response_task(incident_id="A", host="EP-1",
                  os_family="linux", action_type="block_ip", targets=["1.2.3.4"], secret=SECRET))
    store.enqueue("EP-2", td.build_response_task(incident_id="B", host="EP-2",
                  os_family="linux", action_type="restore", secret=SECRET))
    assert store.pending("EP-1") == 1
    got = store.poll("EP-1")
    assert len(got) == 1 and got[0]["incident_id"] == "A"
    assert store.poll("EP-1") == []               # drained
    assert store.poll("EP-2")[0]["incident_id"] == "B"   # other host untouched


# -- E2E: SOAR action → task → store → poll → agent prepares execution --------
def _dispatch_and_execute(action, os_family, **params):
    store = td.TaskStore()
    host = "EP-9"
    task = td.build_response_task(incident_id="INC-E2E", host=host, os_family=os_family,
                                  action_type=action, secret=SECRET, **params)
    store.enqueue(host, task)
    polled = store.poll(host)                      # core_ingress GET /api/v1/tasks
    assert len(polled) == 1
    return rx.prepare_execution(polled[0], secret=SECRET)   # agent side


def test_e2e_isolate_host_linux():
    pb, env = _dispatch_and_execute("isolate_host", "linux", mgmt_ips=["10.0.0.0/24"])
    assert pb == "01_contain_host.sh" and (PLAYBOOKS / "linux" / pb).exists()
    assert env["NEXUS_MGMT_IPS"] == "10.0.0.0/24" and env["NEXUS_INCIDENT_ID"] == "INC-E2E"


def test_e2e_block_ip_windows():
    pb, env = _dispatch_and_execute("block_ip", "windows", targets=["8.8.8.8"])
    assert pb == "04_Block-C2.ps1" and (PLAYBOOKS / "windows" / pb).exists()
    assert env["NEXUS_C2_IPS"] == "8.8.8.8"


def test_e2e_acquisition_task():
    store = td.TaskStore()
    store.enqueue("EP-9", td.build_acquisition_task(
        incident_id="INC", host="EP-9", os_family="linux", file_path="/tmp/evil", secret=SECRET))
    pb, env = rx.prepare_execution(store.poll("EP-9")[0], secret=SECRET)
    assert pb == "05_acquire_artifact.sh" and env["NEXUS_TARGET_PATH"] == "/tmp/evil"


# -- containment.toml wires the outbound agent-task executor ------------------
def test_containment_has_agent_task_executor():
    import tomllib
    conf = tomllib.loads((ROOT / "operations" / "infra" / "containment.toml").read_text())
    assert conf["global"]["active_agent_executor"] == "agent_task_v1", \
        "the outbound agent-task executor must be the preferred path for sensor-agent hosts"
    agent = conf["providers"]["agent_task_v1"]["actions"]
    for action in ("isolate_host", "block_ip", "restore"):
        assert agent[action]["delivery"] == "agent_poll", f"{action} must deliver via agent poll"


def test_e2e_forged_polled_task_refused():
    store = td.TaskStore()
    task = td.build_response_task(incident_id="INC", host="EP-9", os_family="linux",
                                  action_type="isolate_host", secret=SECRET)
    task["targets"] = ["attacker-added"]           # tamper after signing (MITM on the poll)
    store.enqueue("EP-9", task)
    with pytest.raises(rx.ResponseTaskError):
        rx.prepare_execution(store.poll("EP-9")[0], secret=SECRET)


# -- Transport contract: worker → ingress store (by host) → agent poll (by id) --
# Models the production loop end to end: worker_soar publishes a signed task that
# core_ingress files by `host`; the agent's GET /api/v1/tasks drains ONLY its own
# queue (keyed by its JWT subject == host). This is the behavioural pin for the
# routing/identity/drain properties the Rust transport must satisfy -- it fails if
# a task is mis-routed, leaks to another host, redelivers, or arrives corrupted.
def test_transport_routes_to_correct_host_and_isolates_others():
    store = td.TaskStore()                          # == the ingress per-host DashMap
    sensor_a, sensor_b = "sentinel-linux-01", "deepxdr-win-09"
    # worker_soar signs for sensor_a and "publishes" (host keys the store)
    task = td.build_response_task(incident_id="INC-T", host=sensor_a, os_family="linux",
                                  action_type="isolate_host", mgmt_ips=["10.0.0.0/24"], secret=SECRET)
    store.enqueue(task["host"], task)

    assert store.poll(sensor_b) == []               # isolation: other host sees nothing
    delivered = store.poll(sensor_a)                # sensor_a's outbound poll
    assert len(delivered) == 1 and delivered[0]["incident_id"] == "INC-T"
    assert store.poll(sensor_a) == []               # drained: no redelivery

    # the delivered task still verifies and resolves to the right local action
    pb, env = rx.prepare_execution(delivered[0], secret=SECRET)
    assert pb == "01_contain_host.sh" and env["NEXUS_MGMT_IPS"] == "10.0.0.0/24"


def test_transport_rejects_task_corrupted_in_transit():
    # A task whose bytes are altered between publish and poll fails verification on
    # the host -- the ingress routes blindly, so integrity must hold end to end.
    store = td.TaskStore()
    host = "sentinel-linux-01"
    task = td.build_response_task(incident_id="INC", host=host, os_family="linux",
                                  action_type="block_ip", targets=["8.8.8.8"], secret=SECRET)
    store.enqueue(host, task)
    polled = store.poll(host)[0]
    polled["targets"].append("1.1.1.1")             # corruption in transit
    with pytest.raises(rx.ResponseTaskError):
        rx.prepare_execution(polled, secret=SECRET)
