"""Cloud-executor action vocabulary: dispatch config vs the code behind it.

test_containment_capability.py proves matrix -> containment.toml; this suite
proves the next hop: every wire action a provider body sends must be handled by
the executor source it targets (AWS lambdas, GCP function, Azure runbook), and
the executors must fail loudly (non-2xx) on unknown actions. A provider action
the executor silently 200s away is a containment step the protocol wrongly
records as done.
"""
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
INFRA = ROOT / "operations" / "infra"
CONTAINMENT_DIR = INFRA / "terraform" / "containment"

CONTAINMENT = tomllib.loads((INFRA / "containment.toml").read_text())

AWS_ISOLATE_SRC = (CONTAINMENT_DIR / "lambda" / "isolate.py").read_text()
AWS_BLOCKIP_SRC = (CONTAINMENT_DIR / "lambda" / "block_ip.py").read_text()
GCP_SRC = (CONTAINMENT_DIR / "gcp_function" / "main.py").read_text()
AZURE_TF_SRC = (CONTAINMENT_DIR / "azure.tf").read_text()

# endpoint env var -> the source implementing it
_ENDPOINT_SRC = {
    "${AWS_ISOLATE_LAMBDA_URL}": ("aws lambda isolate.py", AWS_ISOLATE_SRC),
    "${AWS_BLOCKIP_LAMBDA_URL}": ("aws lambda block_ip.py", AWS_BLOCKIP_SRC),
    "${AWS_BLOCK_IP_LAMBDA_URL}": ("aws lambda block_ip.py", AWS_BLOCKIP_SRC),
    "${GCP_ISOLATE_FUNCTION_URL}": ("gcp function main.py", GCP_SRC),
    "${AZURE_NSG_WEBHOOK_URL}": ("azure nsg runbook", AZURE_TF_SRC),
}


def _wire_action(body_template: str):
    """The literal action value a provider body sends ('' when templated)."""
    m = re.search(r'"[aA]ction":\s*"([^"{]+)"', body_template)
    return m.group(1) if m else ""


def _handled(src_name: str, src: str, wire: str) -> bool:
    """Does the executor source dispatch on this wire action value?

    Accepts either inline comparison (`action == "x"`, PowerShell `-eq "x"`) or a
    dispatch-table key (`"x":`), so the contract does not dictate control-flow style."""
    w = re.escape(wire)
    if "runbook" in src_name:
        return bool(re.search(rf'\$Action\s+-eq\s+"{w}"', src))
    return bool(re.search(rf'action\s*==\s*"{w}"', src)
                or re.search(rf'"{w}"\s*:', src))


def _cloud_provider_actions():
    """(provider, action, wire, src_name, src) for every env-var cloud endpoint."""
    out = []
    for pname, p in (CONTAINMENT.get("providers") or {}).items():
        for aname, a in (p.get("actions") or {}).items():
            ep = a.get("endpoint", "")
            if ep in _ENDPOINT_SRC:
                src_name, src = _ENDPOINT_SRC[ep]
                out.append((pname, aname, _wire_action(a.get("body_template", "")),
                            src_name, src))
    return out


class TestWireActionsHandled:
    def test_every_cloud_wire_action_has_a_dispatcher_branch(self):
        missing = [
            f"{p}.{a}: '{wire}' not handled by {src_name}"
            for p, a, wire, src_name, src in _cloud_provider_actions()
            if wire and not _handled(src_name, src, wire)
        ]
        assert not missing, missing

    def test_aws_isolate_lambda_covers_snapshot_and_role_revocation(self):
        for wire in ("isolate", "release", "snapshot_volume", "revoke_instance_role"):
            assert _handled("aws", AWS_ISOLATE_SRC, wire), f"lambda missing '{wire}'"


class TestUnknownActionsFailLoudly:
    def test_aws_isolate_lambda_returns_non_2xx_on_unknown_action(self):
        # A bare-dict return is served as HTTP 200 by the Lambda URL -- the exact
        # silent-success failure this suite exists to prevent. The unknown-action
        # branch must respond with a 4xx status envelope.
        assert re.search(r'Unknown action', AWS_ISOLATE_SRC)
        assert re.search(r'_respond\(\s*4\d\d', AWS_ISOLATE_SRC) or \
            re.search(r'"statusCode":\s*4\d\d', AWS_ISOLATE_SRC), \
            "unknown action must produce a 4xx statusCode envelope"

    def test_aws_isolate_lambda_no_instance_is_non_2xx(self):
        assert re.search(r'_respond\(\s*404', AWS_ISOLATE_SRC) or "404" in AWS_ISOLATE_SRC, \
            "instance-not-found must not be a 200 (protocol would record success)"

    def test_aws_isolate_lambda_success_is_explicit_200(self):
        assert re.search(r'_respond\(\s*200', AWS_ISOLATE_SRC), \
            "success path must set an explicit 200 envelope, not a bare dict"

    def test_gcp_function_returns_400_on_unknown_action(self):
        assert re.search(r"unknown action.*400|400.*unknown action", GCP_SRC,
                         re.IGNORECASE | re.DOTALL)

    def test_azure_runbook_errors_on_unknown_action(self):
        assert re.search(r"Unknown action", AZURE_TF_SRC)


class TestMatrixOnlyDeclaresImplementedCloudActions:
    """The planner matrix must not promise a cloud action whose executor cannot
    run it -- an unimplementable step must become an operator escalation."""

    def test_matrix_cloud_actions_resolve_to_handled_wire_actions(self):
        matrix = tomllib.loads((INFRA / "capability_matrix.toml").read_text())
        providers = CONTAINMENT.get("providers") or {}
        broken = []
        for cap in matrix.get("capability", []):
            ex = cap.get("executor", "")
            if ex not in ("aws_containment_v1", "azure_containment_v1",
                          "gcp_containment_v1"):
                continue
            action = cap.get("action", "")
            pa = (providers.get(ex, {}).get("actions") or {}).get(action)
            if pa is None:
                broken.append(f"{ex}.{action}: matrix declares it, toml lacks it")
                continue
            ep = pa.get("endpoint", "")
            wire = _wire_action(pa.get("body_template", ""))
            if ep in _ENDPOINT_SRC and wire:
                src_name, src = _ENDPOINT_SRC[ep]
                if not _handled(src_name, src, wire):
                    broken.append(f"{ex}.{action}: '{wire}' unimplemented in {src_name}")
        assert not broken, broken
