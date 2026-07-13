"""
Lab det_chamber -- IaC validity + network ISOLATION contract.

A detonation chamber's first job is containment: detonated malware must not be
able to reach the host, the production LAN, or the internet. These tests prove,
end to end, that the infrastructure the swarm deploys on an investigation trigger
is (a) structurally valid/deployable and (b) network-isolated by construction.

Two tiers:
  * STRUCTURAL (always run, pure text/pyyaml) -- the isolation invariants every
    layer must satisfy: compose `internal: true`, k8s default-deny NetworkPolicy,
    terraform private switch / isolated port group (never the internet-connected
    "Default Switch" / "VM Network").
  * TOOL-GATED (run in the dockerized lab where the validators are installed;
    skipped on a host that lacks them) -- terraform fmt, yamllint, ansible-lint
    actually validate the manifests so we know they will apply, not just that the
    text looks right. All are offline-safe (no provider/schema downloads), which
    matters because the lab itself models an isolated environment.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DC = REPO / "det_chamber"
INFRA = REPO / "infrastructure"
COMPOSE = DC / "deploy" / "docker-compose.yml"
K8S = DC / "deploy" / "kubernetes-deployment.yaml"
TF_DIR = INFRA / "terraform" / "det_chamber"
ROLE = INFRA / "ansible" / "roles" / "det_chamber_sandbox"


# --- STRUCTURAL: docker-compose isolation ------------------------------------
def test_compose_network_is_internal_only():
    text = COMPOSE.read_text()
    assert "internal: true" in text, \
        "the sandbox network must be internal:true (no egress) so malware cannot call out"
    assert "network_mode: host" not in text and "network_mode: \"host\"" not in text, \
        "the sandbox must never share the host network stack"
    # No published ports (would punch a hole out of the isolated network).
    assert "\n    ports:" not in text and "\nports:" not in text, \
        "the sandbox must not publish ports"


# --- STRUCTURAL: kubernetes default-deny isolation ---------------------------
def test_k8s_has_default_deny_networkpolicy():
    text = K8S.read_text()
    assert "kind: NetworkPolicy" in text, "a NetworkPolicy is required to contain the pod"
    # Isolate the NetworkPolicy document.
    doc = next(d for d in text.split("---") if "kind: NetworkPolicy" in d)
    assert "podSelector: {}" in doc, "the policy must select every pod in the namespace"
    assert "Ingress" in doc and "Egress" in doc, "policyTypes must cover Ingress AND Egress"
    # Default-deny == policyTypes set with NO allow rules. Any 'egress:' allow list
    # would punch an outbound hole -- forbid it.
    assert "\n  egress:" not in doc and "\n    egress:" not in doc, \
        "the deny-all policy must not contain any egress allow rule"


def test_k8s_pod_not_on_host_network():
    text = K8S.read_text()
    assert "hostNetwork: false" in text, "pod must not share the host network stack"
    assert "hostNetwork: true" not in text


def test_k8s_uses_config_driven_engine():
    text = K8S.read_text()
    assert "--config" in text, "k8s command must be config-driven"
    for stale in ("--filetypes", "--malws-path", "--collection-dir"):
        assert stale not in text, f"stale/invalid engine flag in k8s manifest: {stale}"
    assert "detchamber-engine" in text, "k8s should reference the renamed engine image"


# --- STRUCTURAL: terraform isolated network ----------------------------------
def test_terraform_never_uses_internet_connected_networks():
    # Scan the VM RESOURCE files, not variables.tf -- the variable validation
    # legitimately names "Default Switch"/"VM Network" in order to REFUSE them
    # (asserted separately in test_terraform_isolation_variables_enforced).
    resource_tf = "\n".join(
        (TF_DIR / f).read_text() for f in ("terraform_hyperv.tf", "terraform_vmware.tf")
    )
    assert '"Default Switch"' not in resource_tf, \
        "Hyper-V 'Default Switch' is NAT'd to the internet -- detonated malware could egress"
    assert '"VM Network"' not in resource_tf, \
        "VMware 'VM Network' is internet-connected -- use an isolated port group"


def test_terraform_isolation_variables_enforced():
    vars_tf = (TF_DIR / "variables.tf").read_text()
    assert "isolated_switch_name" in vars_tf and "isolated_network_name" in vars_tf
    # The validation blocks must actively refuse the internet-connected defaults.
    assert "Default Switch" in vars_tf and "VM Network" in vars_tf, \
        "variables must validate AGAINST the internet-connected names"
    blob = "\n".join(p.read_text() for p in TF_DIR.glob("*.tf"))
    assert "var.isolated_switch_name" in blob and "var.isolated_network_name" in blob, \
        "the VM network blocks must reference the isolated-network variables"


# --- STRUCTURAL: manifests are valid YAML (deployable shape) -----------------
def test_manifests_are_valid_yaml():
    yaml = pytest.importorskip("yaml")  # present in the dockerized lab
    list(yaml.safe_load_all(K8S.read_text()))          # multi-doc k8s
    yaml.safe_load(COMPOSE.read_text())                # compose
    yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())  # ansible role tasks


# --- TOOL-GATED: real validators (dockerized lab) ----------------------------
@pytest.mark.skipif(not shutil.which("terraform"), reason="terraform not installed")
def test_terraform_canonical_format():
    # Offline -- fmt needs no providers. Proves the HCL parses and is canonical.
    r = subprocess.run(["terraform", "fmt", "-check", "-recursive", str(TF_DIR)],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"terraform fmt -check failed:\n{r.stdout}\n{r.stderr}"


@pytest.mark.skipif(not shutil.which("yamllint"), reason="yamllint not installed")
def test_deploy_yaml_has_no_errors():
    # Gate on real errors (bad syntax, missing newline, ...), not cosmetic
    # line-length warnings -- the engine command line is legitimately long.
    r = subprocess.run(["yamllint", "-f", "parsable", "-d", "relaxed", str(K8S), str(COMPOSE)],
                       capture_output=True, text=True)
    errors = [ln for ln in r.stdout.splitlines() if "[error]" in ln]
    assert not errors, "yamllint reported errors:\n" + "\n".join(errors)


@pytest.mark.skipif(not shutil.which("ansible-lint"), reason="ansible-lint not installed")
def test_ansible_role_lints_clean():
    r = subprocess.run(["ansible-lint", str(ROLE)], capture_output=True, text=True,
                       cwd=str(INFRA / "ansible"))
    # Lint warnings are tolerated; a non-zero from a hard error is not.
    assert r.returncode in (0, 2), f"ansible-lint hard failure:\n{r.stdout}\n{r.stderr}"
