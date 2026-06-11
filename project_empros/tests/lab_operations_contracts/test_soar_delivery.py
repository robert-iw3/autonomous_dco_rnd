"""
Lab operations -- SOAR delivery: HOW worker_soar actually reaches an endpoint.

Same question the Det Chamber raised: a response (isolate / eradicate / block) has
to get to a host the platform may not be able to reach inbound. worker_soar has
several delivery paths; these contracts pin which are OUTBOUND-compatible vs. which
assume inbound reach.

  OUTBOUND-compatible (control-plane → already-connected agent / network):
    • cloud providers  -- AWS/Azure/GCP isolate APIs (no host reach)
    • EDR API          -- platform calls the EDR control plane; the on-host EDR
                          agent (outbound) receives the order
    • firewall API     -- network-level block (no host reach)

  INBOUND-assuming (the gap -- DC-N11):
    • ssh_playbook_v1  -- n8n Fallback_Containment SSHes INTO the host to run the
                          01-06 playbooks. Works only where inbound SSH/WinRM is
                          allowed; for outbound-only endpoints this needs the same
                          agent-task model the Det Chamber acquisition now uses.
"""

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOAR = (ROOT / "services" / "worker_soar" / "src" / "main.rs").read_text()
CONTAINMENT = tomllib.loads((ROOT / "operations" / "infra" / "containment.toml").read_text())
FALLBACK = json.loads((ROOT / "operations" / "n8n" / "workflows" / "Fallback_Containment.json").read_text())
CLOUD_WF = json.loads((ROOT / "operations" / "n8n" / "workflows" / "Cloud_Containment.json").read_text())


# -- Provider routing: worker_soar picks the delivery mechanism ---------------
def test_worker_soar_routes_cloud_edr_firewall():
    # cloud source_type → cloud provider; host action → EDR; otherwise firewall.
    assert "cloud_routing" in SOAR and "provider_for" in SOAR
    assert "active_edr" in SOAR and 'action_type.contains("host")' in SOAR
    assert "active_firewall" in SOAR


# -- OUTBOUND-compatible paths ------------------------------------------------
def test_edr_api_native_path_is_outbound():
    # worker_soar calls the EDR control-plane API directly (bearer-auth) -- the
    # host's EDR agent receives it outbound; no inbound reach to the endpoint.
    assert "/api/v1/isolate" in SOAR and "bearer_auth" in SOAR


def test_containment_edr_provider_is_an_api():
    edr = CONTAINMENT["providers"]["custom_edr_v1"]["actions"]["isolate_host"]
    assert edr["method"] in ("POST", "PUT")
    assert edr["endpoint"].startswith("http"), "EDR isolate must be a control-plane API call"


def test_cloud_containment_uses_provider_apis_not_host_reach():
    blob = json.dumps(CLOUD_WF).lower()
    assert "ssh" not in blob, "cloud containment must use cloud APIs, never SSH into a host"
    for p in ("aws_containment_v1", "azure_containment_v1", "gcp_containment_v1"):
        assert p in CONTAINMENT["providers"], f"{p} cloud provider must exist"


# -- INBOUND-assuming fallback (the gap, documented) --------------------------
def test_ssh_playbook_fallback_routes_to_n8n():
    sp = CONTAINMENT["providers"]["ssh_playbook_v1"]["actions"]["isolate_host"]
    assert "fallback-containment" in sp["endpoint"], "ssh_playbook routes to the n8n fallback workflow"


def test_fallback_workflow_reaches_host_over_ssh_inbound():
    # DC-N11: the fallback SSHes INTO the host. This pins the current behaviour so
    # the gap is explicit -- for outbound-only endpoints this path must move to the
    # agent-task model (the agent polls + runs the playbook locally), like the Det
    # Chamber acquisition does.
    nodes = {n.get("name", ""): n for n in FALLBACK.get("nodes", [])}
    blob = json.dumps(FALLBACK).lower()
    assert "ssh" in blob and any("ssh" in n.lower() for n in nodes), \
        "fallback currently builds + runs an SSH command (inbound reach -- DC-N11)"
    assert any(n.get("type", "").endswith("executeCommand") for n in FALLBACK["nodes"])


def test_fallback_reports_outcome_outbound_to_orchestrator():
    # Whatever the delivery, the OUTCOME flows back out to the orchestrator callback.
    blob = json.dumps(FALLBACK)
    assert "/api/v1/callback" in blob or "callback" in blob.lower()


# -- PREFERRED agent-task emission (DC-N11 closed) ----------------------------
AGENT_TASK = (ROOT / "services" / "worker_soar" / "src" / "agent_task.rs").read_text()


def test_worker_soar_emits_signed_agent_task():
    # worker_soar SIGNS a task for outbound-only hosts and PUBLISHES it to NATS
    # (core_ingress drains it to the polling host) instead of the inbound SSH
    # fallback. Pinned: reads the executor, signs only response actions, publishes
    # to the agent-task subject, and never on the cloud path.
    assert "mod agent_task;" in SOAR
    assert "active_agent_executor" in SOAR, "must read the preferred agent executor"
    assert "agent_task::is_response_action" in SOAR, "only response actions become agent tasks"
    assert "build_signed_task" in SOAR, "signs the task"
    assert 'publish("nexus.agent.tasks"' in SOAR, "publishes the signed task over NATS"
    assert "is_cloud" in SOAR and "!is_cloud" in SOAR, "cloud incidents must not take the host path"


# -- INGRESS closes the loop: subscribe → per-host store → drain on poll -------
INGRESS = (ROOT / "services" / "core_ingress" / "src" / "main.rs").read_text()


def test_ingress_routes_agent_tasks_to_polling_host():
    # core_ingress subscribes to the agent-task subject, files each task by its
    # host, and GET /api/v1/tasks drains by the agent's JWT subject. The ingress
    # ROUTES only -- the signature is verified on the host, never here.
    assert 'subscribe("nexus.agent.tasks"' in INGRESS, "must consume the agent-task subject"
    assert "task_store" in INGRESS and 'task.get("host")' in INGRESS, "file tasks by host"
    assert "handle_task_poll" in INGRESS
    assert "claims.sub" in INGRESS and ".remove(&claims.sub)" in INGRESS, \
        "poll drains the agent's own queue by JWT subject"


def test_agent_task_signer_matches_python_contract():
    # The Rust signer mirrors task_dispatch/response_executor and carries the
    # cross-language golden vector that proves byte-identical HMAC signing (CI).
    assert "HmacSha256" in AGENT_TASK and "fn sign" in AGENT_TASK
    assert "RESPONSE_ACTIONS" in AGENT_TASK
    assert "signing_matches_python_golden" in AGENT_TASK, "golden parity test must be present"


def test_containment_agent_executor_is_preferred_over_ssh():
    g = CONTAINMENT["global"]
    assert g["active_agent_executor"] == "agent_task_v1", "agent-task is the preferred executor"
    assert g.get("active_playbook_executor") == "ssh_playbook_v1", "ssh fallback retained as legacy"
