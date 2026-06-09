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


# ── Phase 4 performance enhancements ─────────────────────────────────────────

class TestPhase4PerformanceEnhancements:
    """P4-A Lance, P4-C DeepSpeed, P4-D Qdrant gRPC contract tests."""

    # P4-C: DeepSpeed ZeRO-2
    def test_deepspeed_zero2_config_exists(self):
        cfg = MLOPS_DIR / "config" / "deepspeed_zero2.json"
        assert cfg.exists(), "mlops/config/deepspeed_zero2.json must exist (P4-C)"

    def test_deepspeed_zero2_config_valid_json(self):
        import json
        cfg = MLOPS_DIR / "config" / "deepspeed_zero2.json"
        data = json.loads(cfg.read_text())
        assert "zero_optimization" in data, "deepspeed_zero2.json must have zero_optimization key"
        assert data["zero_optimization"]["stage"] == 2, "ZeRO stage must be 2"

    def test_train_network_deepspeed_arg(self):
        src = (SCRIPTS_DIR / "02_train_network.py").read_text()
        assert "--deepspeed" in src, \
            "02_train_network.py must expose --deepspeed argument (P4-C)"
        assert "deepspeed=args.deepspeed" in src, \
            "02_train_network.py must wire deepspeed into TrainingArguments (P4-C)"

    # P4-D: Qdrant gRPC
    def test_spool_datasets_grpc_vars(self):
        src = (SCRIPTS_DIR / "01_spool_datasets.py").read_text()
        assert "QDRANT_GRPC_PORT" in src, \
            "01_spool_datasets.py must define QDRANT_GRPC_PORT env var (P4-D)"
        assert "prefer_grpc=True" in src, \
            "01_spool_datasets.py must pass prefer_grpc=True to QdrantClient (P4-D)"

    # P4-A: Lance format
    def test_corpus_utils_has_write_lance(self):
        src = (SCRIPTS_DIR / "corpus_utils.py").read_text()
        assert "write_lance_dataset" in src, \
            "corpus_utils.py must define write_lance_dataset() helper (P4-A)"
        assert "_LANCE_AVAILABLE" in src, \
            "corpus_utils.py must have _LANCE_AVAILABLE graceful fallback (P4-A)"

    def test_stage_scripts_have_output_lance_flag(self):
        stage_scripts = [
            "stage_recon_behavioral.py", "stage_c2_behavioral.py",
            "stage_bypass_behavioral.py", "stage_persistence_behavioral.py",
            "stage_lateral_movement_behavioral.py", "stage_exfiltration_behavioral.py",
            "stage_active_directory_behavioral.py", "stage_malware_behavioral.py",
            "stage_linux_exploitation_behavioral.py", "stage_lotl_behavioral.py",
            "stage_windows_exploitation_behavioral.py",
        ]
        for script in stage_scripts:
            src = (SCRIPTS_DIR / script).read_text()
            assert "--output-lance" in src, \
                f"{script} must have --output-lance argument (P4-A)"
            assert "write_lance_dataset" in src, \
                f"{script} must call write_lance_dataset (P4-A)"

    def test_train_sft_cot_lance_detection(self):
        src = (SCRIPTS_DIR / "02_train_sft_cot.py").read_text()
        assert "_LANCE" in src, \
            "02_train_sft_cot.py must have Lance detection flag (P4-A)"
        assert "TTP_LANCE_SOURCES" in src, \
            "02_train_sft_cot.py must define TTP_LANCE_SOURCES dict (P4-A)"
        assert "_load_ttp_dataset" in src, \
            "02_train_sft_cot.py must define _load_ttp_dataset() helper (P4-A)"

    def test_corpus_config_has_lance_paths(self):
        import tomllib
        cfg = (MLOPS_DIR / "corpus_config.toml").read_bytes()
        data = tomllib.loads(cfg.decode())
        ttp = data.get("ttp_corpus", {})
        assert "recon_lance" in ttp, \
            "corpus_config.toml [ttp_corpus] must have lance path entries (P4-A)"
        assert ttp["recon_lance"].endswith(".lance"), \
            "recon_lance must point to a .lance file (P4-A)"

    # P4-C upgrade: DeepSpeed ZeRO-3 (primary for Model B 24B multi-GPU)
    def test_deepspeed_zero3_config_exists(self):
        cfg = MLOPS_DIR / "config" / "deepspeed_zero3.json"
        assert cfg.exists(), "mlops/config/deepspeed_zero3.json must exist (P4-C ZeRO-3)"

    def test_deepspeed_zero3_config_valid_json(self):
        import json
        cfg = MLOPS_DIR / "config" / "deepspeed_zero3.json"
        data = json.loads(cfg.read_text())
        assert "zero_optimization" in data, "deepspeed_zero3.json must have zero_optimization key"
        assert data["zero_optimization"]["stage"] == 3, "ZeRO-3 stage must be 3"
        assert data["zero_optimization"].get("contiguous_gradients") is True, \
            "ZeRO-3 must set contiguous_gradients=true for memory-safe gradient accumulation"

    def test_deepspeed_zero3_is_primary_train_all(self):
        makefile = (MLOPS_DIR / "Makefile").read_text()
        assert "train-network-zero3" in makefile, \
            "Makefile must have train-network-zero3 target (P4-C ZeRO-3)"
        train_all_line = [l for l in makefile.splitlines() if l.startswith("train-all:")][0]
        assert "train-network-zero3" in train_all_line, \
            "train-all must call train-network-zero3 (ZeRO-3 is primary for 24B multi-GPU)"

    def test_train_network_zero3_uses_correct_config(self):
        makefile = (MLOPS_DIR / "Makefile").read_text()
        assert "deepspeed_zero3.json" in makefile, \
            "Makefile train-network-zero3 must reference deepspeed_zero3.json"
