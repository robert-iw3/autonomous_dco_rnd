"""
Lab det_chamber -- Phase 1 refactor: repository layout & boundary contract.

Encodes the decisions from planning_docs/DET_CHAMBER_INTEGRATION_PLAN.md §3/§5 about
what det_chamber owns vs. what belongs to infrastructure/, written test-first so the
refactor is provable and stays enforced:

  * ONE canonical engine -- the PowerShell clone is gone; Python is the engine.
  * No standalone-repo CI carried into the monorepo (superseded by run_tests.sh +
    orchestration/pipelines).
  * Deploy manifests only pass CLI flags the engine actually defines (kills the
    --filetypes/--malware flag-drift, finding F4).
  * VM provisioning / IaC lives under infrastructure/, not det_chamber/.
  * The Windows engine image includes the new config-drive modules.

These are structural/source assertions -- no heavy deps, runnable on Linux CI and
in the dockerized lab.
"""

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]          # .../project_empros
DC = REPO / "det_chamber"
INFRA = REPO / "infrastructure"
ENGINE = DC / "engine"
DEPLOY = DC / "deploy"


# --- 1. Single canonical engine ----------------------------------------------
def test_python_engine_is_canonical():
    assert (ENGINE / "malware_sandbox.py").exists(), "the Python engine must exist"


def test_powershell_engine_clone_removed():
    assert not (ENGINE / "malware_sandbox.ps1").exists(), \
        "malware_sandbox.ps1 is a duplicate engine; Python is canonical -- drop it"


def test_engine_build_assets_retained():
    # YARA ruleset build stays with the engine (used at image build).
    assert (ENGINE / "compile_yara_rules.py").exists()
    assert (ENGINE / "filter_yara_rules.ps1").exists()


def test_engine_has_no_runtime_provisioning_hook():
    # DC-N6: provisioning moved to infrastructure/. The engine must not try to run
    # provision_sandbox.ps1 at runtime (it no longer ships with the engine), and the
    # --bootstrap hook is gone -- provisioning is the platform's job, not the engine's.
    src = (ENGINE / "malware_sandbox.py").read_text()
    assert "provision_sandbox.ps1" not in src, "engine must not invoke the moved provisioning script"
    assert "--bootstrap" not in src, "engine --bootstrap hook removed (provisioning is infra's job)"


# --- 2. No standalone-repo CI carried in -------------------------------------
def test_no_orphan_standalone_ci():
    leftovers = [p for p in DC.rglob("*github-ci*")]
    assert not leftovers, \
        f"standalone-repo CI superseded by run_tests.sh/orchestration; remove {leftovers}"


# --- 3. Deploy manifests use only flags the engine defines -------------------
def _engine_flags():
    tree = ast.parse((ENGINE / "malware_sandbox.py").read_text())
    flags = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("--"):
                    flags.add(arg.value)
    return flags


def test_compose_uses_only_defined_engine_flags():
    compose = DEPLOY / "docker-compose.yml"
    assert compose.exists(), "deploy/docker-compose.yml must exist"
    defined = _engine_flags()
    # Only the container `command:` passes engine flags -- not comments (which may
    # mention docker's own flags like --build) or env keys.
    command_lines = [ln for ln in compose.read_text().splitlines()
                     if re.match(r"\s*command\s*:", ln)]
    used = set()
    for ln in command_lines:
        used.update(re.findall(r"--[a-zA-Z][a-zA-Z0-9-]+", ln))
    unknown = used - defined
    assert not unknown, (
        f"docker-compose command passes flags the engine does not define: {sorted(unknown)}. "
        f"Defined: {sorted(defined)}"
    )


def test_filetypes_flag_drift_is_gone():
    # The specific flag-drift bug (F4): compose passed --filetypes that main() never had.
    assert "--filetypes" not in (DEPLOY / "docker-compose.yml").read_text()


# --- 4. VM provisioning / IaC relocated to infrastructure/ -------------------
def test_iac_removed_from_det_chamber():
    assert not (DEPLOY / "terraform").exists(), "terraform belongs in infrastructure/"
    assert not (DEPLOY / "provisioning").exists(), "packer/vagrant belong in infrastructure/"
    assert not (DEPLOY / "ansible-playbook.yml").exists(), "ansible belongs in infrastructure/"
    assert not (ENGINE / "provision_sandbox.ps1").exists(), \
        "VM bootstrap belongs with provisioning, not the engine runtime"


def test_iac_landed_in_infrastructure():
    tf = INFRA / "terraform" / "det_chamber"
    assert tf.is_dir() and list(tf.glob("*.tf")), "infrastructure/terraform/det_chamber/*.tf must exist"
    assert (INFRA / "det_chamber" / "provisioning").is_dir(), \
        "infrastructure/det_chamber/provisioning/ (packer+vagrant) must exist"
    role = INFRA / "ansible" / "roles" / "det_chamber_sandbox"
    assert (role / "tasks" / "main.yml").exists(), "det_chamber_sandbox role tasks must exist"
    assert (role / "files" / "provision_sandbox.ps1").exists(), \
        "the Windows bootstrap script must live in the role's files/"


# --- 5. Windows engine image ships the config-drive modules ------------------
def test_windows_engine_dockerfile_present_and_complete():
    df = DEPLOY / "Dockerfile.windows-engine"
    assert df.exists(), "deploy/Dockerfile.windows-engine must exist (moved out of engine/)"
    assert not (ENGINE / "Dockerfile").exists(), "engine/Dockerfile moved to deploy/"
    text = df.read_text()
    for mod in ("malware_sandbox.py", "sandbox_config.py", "targets.py"):
        assert mod in text, f"Windows engine image must COPY {mod}"
