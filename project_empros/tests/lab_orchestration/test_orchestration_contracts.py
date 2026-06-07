"""
Lab 14: Orchestration CI/CD Contracts

Validates:
  - All 7 pipeline scripts (01-07) are present
  - 02b-build-inventory.py is syntactically valid Python
  - master-ci.yml stages are correct and ordered
  - TRIGGER_MLOPS gate on training stage (prevent accidental retraining)
  - Shell scripts have shebangs
  - production.yaml required keys match master-ci.yml expectations

All offline -- reads source files only.
"""
import ast
import yaml
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
ORCH_DIR = PROJECT_ROOT / "orchestration"
SCRIPTS_DIR = ORCH_DIR / "scripts"
MASTER_CI = ORCH_DIR / "pipelines/master-ci.yml"
PROD_ENV = ORCH_DIR / "environments/production.yaml"


def _ci():
    return yaml.safe_load(MASTER_CI.read_text())


def _env():
    return yaml.safe_load(PROD_ENV.read_text())


# ── Script existence ──────────────────────────────────────────────────────────

class TestPipelineScriptsExist:
    """All numbered pipeline scripts must be present -- gaps break CI stage dependencies."""

    def test_01_render_templates(self):
        assert (SCRIPTS_DIR / "01-render-templates.sh").exists()

    def test_02_provision_infra(self):
        assert (SCRIPTS_DIR / "02-provision-infra.sh").exists()

    def test_02b_build_inventory(self):
        assert (SCRIPTS_DIR / "02b-build-inventory.py").exists()

    def test_03_harden_os(self):
        assert (SCRIPTS_DIR / "03-harden-os.sh").exists()

    def test_04_deploy_core(self):
        assert (SCRIPTS_DIR / "04-deploy-core.sh").exists()

    def test_05_deploy_middleware(self):
        assert (SCRIPTS_DIR / "05-deploy-middleware.sh").exists()

    def test_06_trigger_mlops(self):
        assert (SCRIPTS_DIR / "06-trigger-mlops.sh").exists()

    def test_07_deploy_inference(self):
        assert (SCRIPTS_DIR / "07-deploy-inference.sh").exists()


# ── 02b-build-inventory.py ───────────────────────────────────────────────────

class TestBuildInventoryScript:
    """02b-build-inventory.py Terraform → Ansible inventory bridge."""

    def test_valid_python_syntax(self):
        src = (SCRIPTS_DIR / "02b-build-inventory.py").read_text()
        try:
            ast.parse(src)
        except SyntaxError as e:
            raise AssertionError(f"02b-build-inventory.py syntax error: {e}")

    def test_accepts_tf_outputs_arg(self):
        src = (SCRIPTS_DIR / "02b-build-inventory.py").read_text()
        assert "--tf-outputs" in src, "build-inventory must accept --tf-outputs argument"

    def test_accepts_env_file_arg(self):
        src = (SCRIPTS_DIR / "02b-build-inventory.py").read_text()
        assert "--env-file" in src, "build-inventory must accept --env-file argument"

    def test_accepts_output_arg(self):
        src = (SCRIPTS_DIR / "02b-build-inventory.py").read_text()
        assert "--output" in src, "build-inventory must accept --output argument"

    def test_ansible_user_map_defined(self):
        src = (SCRIPTS_DIR / "02b-build-inventory.py").read_text()
        assert "ANSIBLE_USER_MAP" in src, \
            "build-inventory must map infra_target values to Ansible SSH users"

    def test_aws_ec2_user_in_map(self):
        src = (SCRIPTS_DIR / "02b-build-inventory.py").read_text()
        assert "aws-ec2" in src, "ANSIBLE_USER_MAP must include aws-ec2 → admin"


# ── master-ci.yml ─────────────────────────────────────────────────────────────

class TestMasterCIYAML:
    """master-ci.yml pipeline structure contracts."""

    REQUIRED_STAGES = [
        "configure",
        "provision",
        "harden",
        "deploy_core",
        "deploy_middleware",
        "mlops_train",
        "mlops_deploy",
    ]

    def test_valid_yaml(self):
        assert isinstance(_ci(), dict)

    def test_all_required_stages_present(self):
        stages = _ci().get("stages", [])
        for s in self.REQUIRED_STAGES:
            assert s in stages, f"CI stage '{s}' must be defined"

    def test_stage_count(self):
        stages = _ci().get("stages", [])
        assert len(stages) == 7, f"Expected 7 CI stages, found {len(stages)}"

    def test_configure_is_first_stage(self):
        stages = _ci().get("stages", [])
        assert stages[0] == "configure", "configure must be the first stage"

    def test_mlops_deploy_is_last_stage(self):
        stages = _ci().get("stages", [])
        assert stages[-1] == "mlops_deploy", "mlops_deploy must be the last stage"

    def test_harden_comes_after_provision(self):
        stages = _ci().get("stages", [])
        assert stages.index("harden") > stages.index("provision"), \
            "harden must come after provision"

    def test_deploy_core_comes_after_harden(self):
        stages = _ci().get("stages", [])
        assert stages.index("deploy_core") > stages.index("harden")

    def test_environment_file_variable_defined(self):
        assert "ENVIRONMENT_FILE" in _ci().get("variables", {}), \
            "ENVIRONMENT_FILE variable must be defined -- missing it causes all scripts to fail"

    def test_mlops_training_gated_on_trigger_variable(self):
        ci = _ci()
        for key, value in ci.items():
            if isinstance(value, dict) and value.get("stage") == "mlops_train":
                rules = value.get("rules", [])
                trigger_guarded = any("TRIGGER_MLOPS" in str(r) for r in rules)
                assert trigger_guarded, \
                    f"MLOps training job '{key}' must be gated on TRIGGER_MLOPS " \
                    "to prevent accidental retraining on every deploy"
                return
        # If no mlops_train job found via stage lookup, check for it in job definitions
        assert any(
            isinstance(v, dict) and "TRIGGER_MLOPS" in str(v.get("rules", []))
            for v in ci.values()
            if isinstance(v, dict)
        ), "At least one job must be gated on TRIGGER_MLOPS"

    def test_inference_deploy_job_exists(self):
        ci = _ci()
        deploy_jobs = [
            k for k, v in ci.items()
            if isinstance(v, dict) and v.get("stage") == "mlops_deploy"
        ]
        assert len(deploy_jobs) >= 1, "At least one job must exist in mlops_deploy stage"


# ── Shell script safety ───────────────────────────────────────────────────────

class TestShellScriptSafety:
    """All shell scripts must have a shebang line (execution contract)."""

    def test_01_has_shebang(self):
        assert (SCRIPTS_DIR / "01-render-templates.sh").read_text().startswith("#!/")

    def test_02_has_shebang(self):
        assert (SCRIPTS_DIR / "02-provision-infra.sh").read_text().startswith("#!/")

    def test_03_has_shebang(self):
        assert (SCRIPTS_DIR / "03-harden-os.sh").read_text().startswith("#!/")

    def test_04_has_shebang(self):
        assert (SCRIPTS_DIR / "04-deploy-core.sh").read_text().startswith("#!/")

    def test_05_has_shebang(self):
        assert (SCRIPTS_DIR / "05-deploy-middleware.sh").read_text().startswith("#!/")

    def test_06_has_shebang(self):
        assert (SCRIPTS_DIR / "06-trigger-mlops.sh").read_text().startswith("#!/")

    def test_07_has_shebang(self):
        assert (SCRIPTS_DIR / "07-deploy-inference.sh").read_text().startswith("#!/")


# ── production.yaml ───────────────────────────────────────────────────────────

class TestProductionEnvironmentYAML:
    """production.yaml keys referenced by master-ci.yml and pipeline scripts."""

    def test_valid_yaml(self):
        assert isinstance(_env(), dict)

    def test_environment_field(self):
        assert "environment" in _env()

    def test_release_version(self):
        assert "release_version" in _env()

    def test_cluster_name(self):
        assert "cluster_name" in _env()

    def test_infra_target_valid(self):
        assert _env()["infra_target"] in ("aws-ec2", "vmware", "aws-eks")

    def test_endpoint_count_positive(self):
        assert _env().get("endpoint_count", 0) > 0

    def test_deployment_tier_valid(self):
        assert _env()["deployment_tier"] in ("small", "medium", "large")

    def test_mlops_registry_defined(self):
        assert "mlops_registry" in _env(), \
            "mlops_registry must be defined -- Stage 7 pulls OCI artifacts from this address"

    def test_mlops_model_version_defined(self):
        assert "mlops_model_version" in _env()

    def test_ssh_key_file_defined(self):
        assert "ansible_ssh_key_file" in _env()

    def test_mlops_inference_ssh_key_defined(self):
        assert "mlops_inference_ssh_key" in _env(), \
            "mlops_inference_ssh_key must be defined for Stage 7 GPU node access"
