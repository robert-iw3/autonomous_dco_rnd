"""
Lab 13: MLOps Pipeline + Serving Contracts

Validates:
  - model_config.toml structure and critical invariants (hidden_dim, sections)
  - All pipeline scripts exist (spool, train, eval, merge, serve)
  - Key scripts are syntactically valid Python
  - Air-gap compliance (no TRANSFORMERS_OFFLINE=0 override)

All offline -- reads source files, no GPU or model weights required.
"""
import ast
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
MLOPS_DIR = PROJECT_ROOT / "mlops"
MODEL_CONFIG = MLOPS_DIR / "model_config.toml"
SCRIPTS_DIR = MLOPS_DIR / "scripts"


def _config():
    return tomllib.loads(MODEL_CONFIG.read_text())


# ── model_config.toml ─────────────────────────────────────────────────────────

class TestModelConfigStructure:
    """model_config.toml is the single source of truth for all model IDs."""

    def test_valid_toml(self):
        assert isinstance(_config(), dict)

    def test_models_section_exists(self):
        assert "models" in _config()

    def test_model_b_section_exists(self):
        assert "b" in _config()["models"], "[models.b] must exist (network adversarial classifier)"

    def test_model_c_section_exists(self):
        assert "c" in _config()["models"], "[models.c] must exist (spatial endpoint expert)"

    def test_model_d_section_exists(self):
        assert "d" in _config()["models"], "[models.d] must exist (SOAR critic)"

    def test_adapters_section_exists(self):
        assert "adapters" in _config(), "[adapters] must exist"

    def test_paths_section_exists(self):
        assert "paths" in _config(), "[paths] must exist"

    def test_model_b_has_hf_id(self):
        assert "hf_id" in _config()["models"]["b"]

    def test_model_b_has_local_path(self):
        assert "local_path" in _config()["models"]["b"]

    def test_model_c_has_hf_id(self):
        assert "hf_id" in _config()["models"]["c"]

    def test_model_c_has_local_path(self):
        assert "local_path" in _config()["models"]["c"]

    def test_model_d_has_hf_id(self):
        assert "hf_id" in _config()["models"]["d"]

    def test_model_c_hidden_dim_is_4096(self):
        assert _config()["models"]["c"]["hidden_dim"] == 4096, \
            "Model C hidden_dim must be 4096 (Llama-3.1-8B). Changing this requires " \
            "SpatialProjector retraining from scratch."

    def test_adapters_use_role_based_names(self):
        adapters = _config()["adapters"]
        for key in ("model_b_lora", "model_b_final", "model_c_lora", "model_c_final",
                    "model_d_dpo", "model_d_final"):
            assert key in adapters, f"Adapter path '{key}' must be defined"

    def test_adapters_contain_no_model_family_names(self):
        """Adapter paths must use role-based names so base model swaps don't require path changes."""
        adapters = _config()["adapters"]
        family_keywords = ("mistral", "llama", "gemma", "qwen", "falcon")
        for key, value in adapters.items():
            for kw in family_keywords:
                assert kw not in value.lower(), \
                    f"Adapter path '{key}={value}' must not contain model family name '{kw}'"


# ── Script existence ──────────────────────────────────────────────────────────

class TestPipelineScriptsExist:
    """All pipeline stages (spool→train→eval→merge→serve) must have scripts."""

    def test_01_spool_datasets(self):
        assert (SCRIPTS_DIR / "01_spool_datasets.py").exists()

    def test_02_train_qlora(self):
        assert (SCRIPTS_DIR / "02_train_qlora.py").exists()

    def test_02_train_sft_cot(self):
        assert (SCRIPTS_DIR / "02_train_sft_cot.py").exists()

    def test_02_train_dpo_critic(self):
        assert (SCRIPTS_DIR / "02_train_dpo_critic.py").exists()

    def test_02_train_network(self):
        assert (SCRIPTS_DIR / "02_train_network.py").exists()

    def test_03_eval_model(self):
        assert (SCRIPTS_DIR / "03_eval_model.py").exists()

    def test_03_eval_critic(self):
        assert (SCRIPTS_DIR / "03_eval_critic.py").exists()

    def test_03_eval_network(self):
        assert (SCRIPTS_DIR / "03_eval_network.py").exists()

    def test_04_merge_weights(self):
        assert (SCRIPTS_DIR / "04_merge_weights.py").exists()

    def test_05_serve_sovereign(self):
        assert (SCRIPTS_DIR / "05_serve_sovereign.py").exists(), \
            "05_serve_sovereign.py (Model C vLLM server) must exist"

    def test_05_serve_critic(self):
        assert (SCRIPTS_DIR / "05_serve_critic.py").exists()

    def test_05_serve_network(self):
        assert (SCRIPTS_DIR / "05_serve_network.py").exists()

    def test_serve_baseline(self):
        assert (SCRIPTS_DIR / "serve_baseline.py").exists(), \
            "serve_baseline.py (Model A LSTM-AE) must exist"

    def test_projector(self):
        assert (SCRIPTS_DIR / "projector.py").exists(), \
            "projector.py (SpatialProjector definition) must exist"


# ── Staging scripts ───────────────────────────────────────────────────────────

class TestStagingScriptsExist:
    """Behavioral staging scripts generate the SFT/DPO corpus."""

    STAGING_SCRIPTS = [
        "stage_c2_behavioral.py",
        "stage_lotl_behavioral.py",
        "stage_persistence_behavioral.py",
        "stage_exfiltration_behavioral.py",
        "stage_lateral_movement_behavioral.py",
        "stage_recon_behavioral.py",
        "stage_malware_behavioral.py",
    ]

    def test_all_staging_scripts_exist(self):
        for script in self.STAGING_SCRIPTS:
            assert (SCRIPTS_DIR / script).exists(), f"{script} must exist"


# ── Python syntax validation ──────────────────────────────────────────────────

class TestScriptSyntax:
    """Critical scripts must be syntactically valid Python before any GPU run."""

    def _parse(self, name: str):
        path = SCRIPTS_DIR / name
        try:
            ast.parse(path.read_text())
        except SyntaxError as e:
            raise AssertionError(f"{name} has Python syntax error: {e}")

    def test_projector_syntax(self):
        self._parse("projector.py")

    def test_train_qlora_syntax(self):
        self._parse("02_train_qlora.py")

    def test_train_sft_cot_syntax(self):
        self._parse("02_train_sft_cot.py")

    def test_spool_datasets_syntax(self):
        self._parse("01_spool_datasets.py")

    def test_serve_baseline_syntax(self):
        self._parse("serve_baseline.py")

    def test_eval_model_syntax(self):
        self._parse("03_eval_model.py")


# ── Air-gap compliance ────────────────────────────────────────────────────────

class TestAirGapCompliance:
    """Production scripts must not disable offline mode (TRANSFORMERS_OFFLINE=1 required)."""

    def _no_offline_zero(self, script_name: str):
        src = (SCRIPTS_DIR / script_name).read_text()
        assert 'TRANSFORMERS_OFFLINE", "0"' not in src, \
            f"{script_name} must not override TRANSFORMERS_OFFLINE to 0"
        assert "TRANSFORMERS_OFFLINE=0" not in src, \
            f"{script_name} must not disable offline mode via shell syntax"

    def test_train_qlora_no_online_override(self):
        self._no_offline_zero("02_train_qlora.py")

    def test_serve_sovereign_no_online_override(self):
        self._no_offline_zero("05_serve_sovereign.py")

    def test_spool_datasets_no_online_override(self):
        self._no_offline_zero("01_spool_datasets.py")

    def test_model_config_paths_use_local_paths(self):
        """Model paths must be local filesystem paths, not HuggingFace URLs."""
        models = _config()["models"]
        for name, cfg in models.items():
            local = cfg.get("local_path", "")
            assert not local.startswith("https://"), \
                f"Model {name} local_path must not be an HTTPS URL -- air-gap violation"
