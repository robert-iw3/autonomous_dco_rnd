"""
Lab det_chamber -- Phase 6: resource renames (DC-N4) + intake metrics (DC-F5).

The deploy manifests dropped the legacy "malware-sandbox" naming for "det-chamber",
and the intake service exposes Prometheus metrics so the platform can scrape it.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
K8S = REPO / "det_chamber" / "deploy" / "kubernetes-deployment.yaml"
TF_DIR = REPO / "infrastructure" / "terraform" / "det_chamber"
INTAKE = REPO / "det_chamber" / "intake" / "intake_service.py"


# --- DC-N4: legacy naming removed --------------------------------------------
def test_k8s_dropped_legacy_malware_sandbox_naming():
    t = K8S.read_text()
    # Forbid the legacy hyphenated RESOURCE/namespace naming. The engine script it
    # runs is genuinely named malware_sandbox.py (with its malware_sandbox.log) --
    # that's an engine artifact, not a k8s resource name, so it stays.
    assert "malware-sandbox" not in t, \
        "k8s resources/namespace must be det-chamber, not the legacy malware-sandbox"
    assert "det-chamber" in t, "k8s resources should be named det-chamber"


def test_k8s_namespace_is_det_chamber():
    t = K8S.read_text()
    assert "name: det-chamber" in t, "namespace should be det-chamber"


def test_terraform_dropped_legacy_vm_name():
    blob = "\n".join(p.read_text() for p in TF_DIR.glob("*.tf"))
    assert "malware-sandbox" not in blob and "malware_sandbox" not in blob, \
        "terraform must not retain the legacy malware-sandbox VM/resource names"


# --- DC-F5: intake exposes Prometheus metrics --------------------------------
def test_intake_exposes_prometheus_metrics():
    t = INTAKE.read_text()
    assert "prometheus_client" in t, "intake must expose Prometheus metrics"
    assert "start_http_server" in t or "make_asgi_app" in t, "intake must serve a /metrics endpoint"
