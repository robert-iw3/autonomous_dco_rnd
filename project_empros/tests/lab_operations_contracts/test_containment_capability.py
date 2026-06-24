"""
Containment Capability Contract + reconciliation.

The matrix is the single source of truth the swarm planner reads. These tests
prove it is internally valid AND that every declared capability is actually
executable downstream - an agent_task action must be a real on-host playbook, a
provider action must exist in containment.toml. This the planner
can never emit an action no executor can run.
"""
import importlib.util as ilu
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
AGENTS = ROOT / "analytics" / "llm_hunter" / "agents"
INFRA = ROOT / "operations" / "infra"


def _load(path, name):
    spec = ilu.spec_from_file_location(name, str(path))
    mod = ilu.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cc = _load(AGENTS / "containment_capability.py", "containment_capability")
rx = _load(ROOT / "operations" / "agent" / "response_executor.py", "response_executor")
CAPS = cc.load_capabilities(INFRA / "capability_matrix.toml")
CONTAINMENT = tomllib.loads((INFRA / "containment.toml").read_text())


class TestMatrixValidity:
    def test_loads_nonempty(self):
        assert len(CAPS) >= 20

    def test_structurally_valid(self):
        assert cc.validate_capabilities(CAPS) == []

    def test_endpoint_action_set_and_wave_order(self):
        acts = cc.actions_for(CAPS, "endpoint", "windows")
        assert {"isolate_host", "collect_forensics", "block_ip",
                "eradicate_process", "eradicate_persistence", "restore"} <= set(acts)
        # wave-1 (contain/collect) must precede wave-2 (eradicate)
        assert acts.index("isolate_host") < acts.index("eradicate_process")

    def test_meets_floor(self):
        assert cc.meets_floor("confirmed", "corroborated") is True
        assert cc.meets_floor("malicious", "confirmed") is False
        assert cc.meets_floor("corroborated", "corroborated") is True


class TestReconciliation:
    """Every capability must be runnable by its declared executor."""

    def test_every_capability_is_executable_downstream(self):
        providers = CONTAINMENT.get("providers", {})
        onhost = set(rx._PLAYBOOK_STEM)
        unrunnable = []
        for (tc, env, action), e in CAPS.items():
            ex = e["executor"]
            if ex == "agent_task_v1":
                if action not in onhost:
                    unrunnable.append(f"{tc}/{env}/{action}: no on-host playbook")
            else:
                pactions = providers.get(ex, {}).get("actions", {})
                if ex not in providers:
                    unrunnable.append(f"{tc}/{env}/{action}: executor {ex} not in containment.toml")
                elif action not in pactions:
                    unrunnable.append(f"{tc}/{env}/{action}: {ex} has no action {action}")
        assert not unrunnable, unrunnable

    def test_containment_toml_bodies_well_formed(self):
        # a body_template must not have swallowed its own validation table, and every
        # cloud action must keep a validation sub-table with required_fields.
        bad = []
        for pname, prov in CONTAINMENT.get("providers", {}).items():
            for aname, action in prov.get("actions", {}).items():
                body = action.get("body_template", "")
                if "[providers" in body or "validation]" in body or "required_fields" in body:
                    bad.append(f"{pname}.{aname}: validation table embedded in body_template")
                if pname.endswith("_containment_v1") and aname in ("isolate_host", "block_ip",
                                                                    "release_host", "unblock_ip"):
                    val = action.get("validation", {})
                    if "required_fields" not in val:
                        bad.append(f"{pname}.{aname}: missing validation.required_fields")
        assert not bad, bad

    def test_referenced_n8n_webhooks_have_workflows(self):
        # every n8n webhook a provider posts to must have a workflow that serves it
        import re
        import json
        toml_text = (INFRA / "containment.toml").read_text()
        referenced = set(re.findall(r"http://n8n:5678/webhook/([a-z0-9-]+)", toml_text))
        defined = set()
        for wf in (ROOT / "operations" / "n8n" / "workflows").glob("*.json"):
            for n in json.loads(wf.read_text()).get("nodes", []):
                path = (n.get("parameters") or {}).get("path")
                if path:
                    defined.add(path)
        missing = referenced - defined
        assert not missing, f"containment.toml references n8n webhooks with no workflow: {sorted(missing)}"

    def test_external_endpoints_are_https_or_env(self):
        # F-4: a containment endpoint that leaves the deepnet must be https or an
        # env placeholder (never a plaintext hardcoded URL that could be redirected).
        bad = []
        for pname, prov in CONTAINMENT.get("providers", {}).items():
            for aname, action in prov.get("actions", {}).items():
                ep = action.get("endpoint", "")
                if "n8n:5678" in ep:
                    continue  # internal deepnet webhook (network-isolated)
                if ep.startswith(("${", "https://", "taskstore://")):
                    continue
                bad.append(f"{pname}.{aname}: {ep}")
        assert not bad, f"plaintext/insecure external containment endpoints: {bad}"

    def test_cloud_providers_referenced_exist(self):
        # vmware is intentionally uncovered (no [providers.vmware_containment_v1])
        envs = {env for (_tc, env, _a) in CAPS}
        assert {"aws", "azure", "gcp"} <= envs
        assert "vmware" not in envs, "vmware has no provider block - must stay uncovered"
