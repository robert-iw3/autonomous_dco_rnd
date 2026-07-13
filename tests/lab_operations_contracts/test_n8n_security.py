"""
Threat-model F-2: every containment webhook must authenticate its inbound request
(HMAC over the raw body against NEXUS_HMAC_SECRET) before taking any action, so a
deepnet-reachable attacker cannot drive containment by POSTing to the webhook.

Detection: a containment workflow must contain a node that computes an HMAC
(crypto.createHmac) and rejects on mismatch, wired between the webhook and the
first action node.
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
WF = ROOT / "operations" / "n8n" / "workflows"


def _containment_workflows():
    out = []
    for f in sorted(WF.glob("*.json")):
        d = json.loads(f.read_text())
        paths = [(n.get("parameters") or {}).get("path", "") for n in d.get("nodes", [])]
        if any(p.endswith("-containment") for p in paths):
            out.append((f.name, d))
    return out


def test_there_are_containment_workflows():
    assert _containment_workflows(), "no containment workflows found"


def test_every_containment_webhook_verifies_inbound_hmac():
    missing = []
    for name, d in _containment_workflows():
        code = " ".join((n.get("parameters") or {}).get("jsCode", "") for n in d.get("nodes", []))
        # an inbound verification computes an HMAC and reads the request signature header
        verifies = "createHmac" in code and "x-nexus-signature" in code.lower()
        if not verifies:
            missing.append(name)
    assert not missing, f"containment webhooks with no inbound HMAC verification: {missing}"


def test_verify_node_runs_before_any_action():
    # the webhook's first downstream node must be the verifier, not an action/httpRequest
    for name, d in _containment_workflows():
        conns = d.get("connections", {})
        webhook = next(n for n in d["nodes"] if n["type"].endswith(".webhook"))
        first = conns.get(webhook["name"], {}).get("main", [[{}]])[0][0].get("node", "")
        first_node = next((n for n in d["nodes"] if n["name"] == first), {})
        assert "verif" in first.lower() or "verif" in (first_node.get("id", "")).lower(), \
            f"{name}: webhook does not flow into a verification node first (got {first!r})"
