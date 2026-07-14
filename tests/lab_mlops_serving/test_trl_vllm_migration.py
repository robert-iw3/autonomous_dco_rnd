"""
Lab MLOps Serving: trl 1.x / vLLM 0.25 migration contracts (2026-07 bump).

Source-level guards that the full-stack dependency bump (vllm 0.4->0.25,
transformers 4->5, trl 0.8->1.8) was applied consistently and that no
removed/renamed API lingers. These are static checks — the GPU training/serve
runs themselves still need validation on Node Beta — but they catch the
mechanical regressions (old kwarg names, removed imports, version drift)
without a GPU.

Run:
    pytest tests/lab_mlops_serving/test_trl_vllm_migration.py -v
"""
import re
from pathlib import Path

import pytest

MLOPS = Path(__file__).parent.parent.parent / "mlops"
SCRIPTS = MLOPS / "scripts"
REQS = MLOPS / "requirements.in"
MODEL_CONFIG = MLOPS / "model_config.toml"

TRAIN_SCRIPTS = [
    "02_train_qlora.py",
    "02_train_network.py",
    "02_train_dpo_critic.py",
    "02_train_sft_cot.py",
    "04_reward_model.py",
]
SERVE_SCRIPTS = ["05_serve_network.py", "05_serve_critic.py"]


def _read(name: str) -> str:
    return (SCRIPTS / name).read_text()


def _code(name: str) -> str:
    """Source with comments and docstrings stripped, so 'the old API name must
    not appear' assertions don't trip over migration notes that cite it."""
    src = _read(name)
    # drop full-line and inline comments
    no_comments = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
    # drop triple-quoted blocks (docstrings / block explanations)
    no_docstrings = re.sub(r'"""[\s\S]*?"""', "", no_comments)
    return re.sub(r"'''[\s\S]*?'''", "", no_docstrings)


class TestRequirementPins:
    def test_pins_are_the_bumped_versions(self):
        reqs = REQS.read_text()
        for pin in ("vllm==0.25.1", "transformers==5.13.1", "trl==1.8.0",
                    "peft==0.19.1", "torch==2.11.0"):
            assert pin in reqs, f"requirements.in missing bumped pin {pin}"

    def test_no_stale_pins(self):
        reqs = REQS.read_text()
        for stale in ("vllm==0.4", "transformers==4.40", "trl==0.8", "torch==2.3"):
            assert stale not in reqs, f"stale pin {stale} still present"


class TestTrainingScriptMigration:
    @pytest.mark.parametrize("name", TRAIN_SCRIPTS)
    def test_no_removed_evaluation_strategy_kwarg(self, name):
        """transformers 5.x removed evaluation_strategy (use eval_strategy)."""
        assert "evaluation_strategy" not in _code(name), (
            f"{name}: evaluation_strategy was removed in transformers 5.x; "
            "use eval_strategy"
        )

    @pytest.mark.parametrize("name", TRAIN_SCRIPTS)
    def test_trainer_uses_processing_class(self, name):
        """trl 1.x trainers take processing_class, not tokenizer=. (A vendored
        DataCollatorForLanguageModeling may still legitimately take tokenizer=,
        so the positive processing_class check is the migration signal.)"""
        assert "processing_class=tokenizer" in _code(name), (
            f"{name}: trainer must pass processing_class=tokenizer (trl 1.x)"
        )

    @pytest.mark.parametrize("name", ["02_train_network.py", "02_train_sft_cot.py"])
    def test_no_max_seq_length_trainer_kwarg(self, name):
        """max_seq_length moved into SFTConfig and was renamed to max_length."""
        assert "max_seq_length=" not in _code(name) or "FastLanguageModel" in _code(name), (
            f"{name}: SFTTrainer no longer accepts max_seq_length (SFTConfig.max_length)"
        )

    def test_dpo_loss_type_is_list(self):
        """trl 1.x DPOConfig.loss_type is a list[str]."""
        assert 'loss_type=["ipo"]' in _read("02_train_dpo_critic.py"), (
            "DPO loss_type must be a list in trl 1.x"
        )
        assert "max_prompt_length" not in _code("02_train_dpo_critic.py"), (
            "max_prompt_length was removed from DPOConfig in trl 1.8"
        )

    def test_completion_only_collator_vendored_not_imported(self):
        """DataCollatorForCompletionOnlyLM was removed from trl 1.8; the sft_cot
        script must define its own, not import it."""
        src = _read("02_train_sft_cot.py")
        assert "from trl import" in src
        trl_import = next(l for l in src.splitlines() if l.startswith("from trl import"))
        assert "DataCollatorForCompletionOnlyLM" not in trl_import, (
            "DataCollatorForCompletionOnlyLM must not be imported from trl 1.8"
        )
        assert "class DataCollatorForCompletionOnlyLM" in src, (
            "the collator must be vendored locally to preserve masking behavior"
        )

    def test_ppo_path_guarded(self):
        """The trl-0.x PPO API is gone; the opt-in PPO loop must raise until re-ported."""
        src = _read("02_train_qlora.py")
        assert "NotImplementedError" in src
        assert "AutoModelForCausalLMWithValueHead" in src  # only inside the guarded/unreachable block


class TestServeScriptMigration:
    @pytest.mark.parametrize("name", SERVE_SCRIPTS)
    def test_disable_log_requests_removed(self, name):
        """AsyncEngineArgs.disable_log_requests was removed in the vLLM v1 path."""
        assert "disable_log_requests" not in _code(name)

    @pytest.mark.parametrize("name", SERVE_SCRIPTS)
    def test_tokenizer_loaded_once_at_boot(self, name):
        """Tokenizer must be module-level (TOKENIZER), not reloaded per request."""
        src = _read(name)
        assert "TOKENIZER = AutoTokenizer.from_pretrained" in src
        # no per-request reload
        assert "tok = AutoTokenizer.from_pretrained" not in src

    def test_network_serve_supports_quantization(self):
        """Model B (Scout MoE) must be servable 4-bit — a QUANTIZATION knob exists."""
        src = _read("05_serve_network.py")
        assert "QUANTIZATION" in src
        assert '"quantization"' in src


class TestModelConfigUpgrade:
    """Assert the ACTIVE [models.*] values (parsed), not raw text — the file's
    'Previous:' comments legitimately still name the old bases."""

    @staticmethod
    def _models():
        try:
            import tomllib as toml
        except ModuleNotFoundError:
            import tomli as toml
        return toml.loads(MODEL_CONFIG.read_text())["models"]

    def test_model_b_is_scout(self):
        b = self._models()["b"]
        assert b["hf_id"] == "meta-llama/Llama-4-Scout-17B-16E-Instruct"
        assert "scout" in b["local_path"].lower()

    def test_model_d_is_gemma_9b(self):
        d = self._models()["d"]
        assert d["hf_id"] == "google/gemma-3-9b-it"

    def test_model_c_held_at_4096(self):
        c = self._models()["c"]
        assert c["hf_id"] == "meta-llama/Llama-3.1-8B-Instruct"
        assert c["hidden_dim"] == 4096, (
            "Model C must stay hidden_dim 4096 — any change forces a "
            "SpatialProjector retrain (out of scope for a deployment bump)"
        )

    def test_network_quadlet_declares_quant(self):
        quad = (MLOPS / "deployment/vllm-network.container").read_text()
        assert "QUANTIZATION=bitsandbytes" in quad
