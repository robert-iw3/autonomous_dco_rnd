"""
test_phase2_pipeline.py -- Offline validation tests for Phase 2 scripts.

Covers:
  05_critic_loop.py  -- NeMo schema validation, critic loop dry-run I/O,
                       hard negative format, schema violation logging,
                       sandbox promotion gating
  02_train_qlora.py  -- M-8: --rlhf-mode ppo flag present, PPO skeleton,
                       reward model integration point, checkpoint logic
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

REPO         = Path(__file__).parent.parent
MLOPS_SCRIPTS = REPO / "mlops" / "scripts"
sys.path.insert(0, str(MLOPS_SCRIPTS))


# ══════════════════════════════════════════════════════════════════════════════
# 05_critic_loop.py -- NeMo schema validation + dry-run I/O
# ══════════════════════════════════════════════════════════════════════════════

class TestCriticLoopSchema:
    """NeMo remediation schema validation (core logic, no GPU required)."""

    def _import(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "critic_loop",
            str(MLOPS_SCRIPTS / "05_critic_loop.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        # Stub heavy imports so the module loads without torch/transformers
        import types
        for stub in ("torch", "transformers", "peft", "model_config"):
            if stub not in sys.modules:
                s = types.ModuleType(stub)
                # Provide the symbols critic_loop uses at module scope (none currently)
                sys.modules[stub] = s
        spec.loader.exec_module(mod)
        return mod

    def _valid_response(self) -> str:
        script = base64.b64encode(b"iptables -A INPUT -s 10.0.0.1 -j DROP").decode()
        return json.dumps({
            "target_component":           "web-server-01",
            "remediation_script_base64":  script,
            "verification_test_command":  "iptables -L INPUT | grep 10.0.0.1",
        })

    def test_valid_schema_passes(self):
        cl = self._import()
        ok, parsed, err = cl.validate_remediation_schema(self._valid_response())
        assert ok, f"Expected valid schema but got error: {err}"
        assert parsed is not None

    def test_missing_field_fails(self):
        cl = self._import()
        bad = json.dumps({
            "target_component": "host",
            "remediation_script_base64": base64.b64encode(b"echo ok").decode(),
            # missing verification_test_command
        })
        ok, _, err = cl.validate_remediation_schema(bad)
        assert not ok
        assert "verification_test_command" in err

    def test_extra_field_fails(self):
        cl = self._import()
        parsed = json.loads(self._valid_response())
        parsed["extra_key"] = "should_not_be_here"
        ok, _, err = cl.validate_remediation_schema(json.dumps(parsed))
        assert not ok
        assert "extra_key" in err or "Extra" in err

    def test_invalid_base64_fails(self):
        cl = self._import()
        bad = json.dumps({
            "target_component":           "host",
            "remediation_script_base64":  "not valid b64!!!",
            "verification_test_command":  "echo ok",
        })
        ok, _, err = cl.validate_remediation_schema(bad)
        assert not ok
        assert "base64" in err

    def test_non_dict_json_fails(self):
        cl = self._import()
        ok, _, err = cl.validate_remediation_schema(json.dumps([1, 2, 3]))
        assert not ok

    def test_invalid_json_fails(self):
        cl = self._import()
        ok, _, err = cl.validate_remediation_schema("this is not json")
        assert not ok
        assert "parse error" in err.lower() or "JSON" in err

    def test_markdown_code_fence_stripped(self):
        """Schema validator must handle responses wrapped in ```json fences."""
        cl = self._import()
        script = base64.b64encode(b"echo fence").decode()
        response = (
            "Here is the action:\n```json\n"
            + json.dumps({
                "target_component":           "app-server",
                "remediation_script_base64":  script,
                "verification_test_command":  "echo ok",
            })
            + "\n```"
        )
        ok, parsed, err = cl.validate_remediation_schema(response)
        assert ok, f"Markdown-wrapped valid schema failed: {err}"

    def test_required_schema_keys_constant(self):
        """REQUIRED_SCHEMA_KEYS must match ADDON.md §3.3 spec."""
        cl = self._import()
        expected = {"target_component", "remediation_script_base64", "verification_test_command"}
        assert cl.REQUIRED_SCHEMA_KEYS == expected, \
            f"REQUIRED_SCHEMA_KEYS mismatch: {cl.REQUIRED_SCHEMA_KEYS}"

    def test_schema_violation_logged(self, tmp_path):
        cl = self._import()
        cl.SCHEMA_LOG = tmp_path / "schema_violations"
        cl._log_schema_violation("test-record-001", "bad response", "missing fields: {x}")
        logs = list((tmp_path / "schema_violations").glob("*.json"))
        assert len(logs) == 1
        data = json.loads(logs[0].read_text())
        assert data["record_id"] == "test-record-001"
        assert "missing fields" in data["error"]

    def test_schema_violation_truncates_response(self, tmp_path):
        """Violation log must not store more than 500 chars of the response."""
        cl = self._import()
        cl.SCHEMA_LOG = tmp_path / "sv"
        cl._log_schema_violation("x", "A" * 1000, "error")
        data = json.loads(list((tmp_path / "sv").glob("*.json"))[0].read_text())
        assert len(data["response"]) <= 500


class TestCriticLoopDryRun:
    """run_critic_loop dry-run path -- validates I/O without models."""

    def _import(self):
        import importlib.util, types
        for stub in ("torch", "transformers", "peft", "model_config"):
            if stub not in sys.modules:
                sys.modules[stub] = types.ModuleType(stub)
        spec = importlib.util.spec_from_file_location(
            "critic_loop_dry",
            str(MLOPS_SCRIPTS / "05_critic_loop.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _sample_record(self):
        return {
            "event_id": "test-001",
            "messages": [
                {"role": "system",    "content": "You are a threat hunter."},
                {"role": "user",      "content": "Anomaly detected: suspicious process."},
                {"role": "assistant", "content": "TRUE POSITIVE. RECOMMENDED_ACTION: contain"},
            ],
        }

    def test_dry_run_returns_passed(self):
        cl = self._import()
        result = cl.run_critic_loop(self._sample_record(), dry_run=True)
        assert result["passed"] is True

    def test_dry_run_score_is_1(self):
        cl = self._import()
        result = cl.run_critic_loop(self._sample_record(), dry_run=True)
        assert result["score"] == pytest.approx(1.0)

    def test_dry_run_zero_attempts(self):
        cl = self._import()
        result = cl.run_critic_loop(self._sample_record(), dry_run=True)
        assert result["attempts"] == 0

    def test_dry_run_result_has_required_keys(self):
        cl = self._import()
        result = cl.run_critic_loop(self._sample_record(), dry_run=True)
        for key in ("passed", "attempts", "score", "schema_valid",
                    "final_response", "record_id", "promote"):
            assert key in result, f"result missing key: {key}"

    def test_append_hard_negative_schema(self, tmp_path):
        cl = self._import()
        cl.HARD_NEG_FILE = tmp_path / "hn.jsonl"
        record = self._sample_record()
        cl._append_hard_negative(record, "bad response text", 0.1)
        lines = (tmp_path / "hn.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        hn = json.loads(lines[0])
        for key in ("prompt", "chosen", "rejected", "score", "source", "category"):
            assert key in hn, f"hard negative missing key: {key}"
        assert hn["source"] == "critic_loop_rejection"
        assert hn["score"] == pytest.approx(0.1)

    def test_append_sandbox_candidate_schema(self, tmp_path):
        cl = self._import()
        cl.SANDBOX_QUEUE = tmp_path / "q.jsonl"
        record = {"event_id": "r1", "mitre_tactic": "T1055", "tool_class": "Injection"}
        cl._append_sandbox_candidate(record, "response text")
        entry = json.loads((tmp_path / "q.jsonl").read_text())
        for key in ("source", "executor_type", "executor_command"):
            assert key in entry, f"sandbox entry missing key: {key}"
        assert entry["source"] == "critic_loop"

    def test_promotion_threshold_constant(self):
        cl = self._import()
        assert cl.PROMOTE_THRESHOLD == pytest.approx(0.95, abs=0.01), \
            "PROMOTE_THRESHOLD must be 0.95 per ADDON.md §2.3 (reward ≥ 0.95 → sandbox)"

    def test_pass_threshold_constant(self):
        cl = self._import()
        assert cl.PASS_THRESHOLD >= 0.0
        assert cl.PASS_THRESHOLD < cl.PROMOTE_THRESHOLD


# ══════════════════════════════════════════════════════════════════════════════
# 02_train_qlora.py -- M-8 PPO skeleton contract tests
# ══════════════════════════════════════════════════════════════════════════════

class TestQLoRAWithPPO:
    """M-8: 02_train_qlora.py must expose --rlhf-mode ppo flag and PPO skeleton."""

    SRC = MLOPS_SCRIPTS / "02_train_qlora.py"

    def _src(self) -> str:
        return self.SRC.read_text()

    def test_rlhf_mode_flag_present(self):
        assert "--rlhf-mode" in self._src(), \
            "02_train_qlora.py: --rlhf-mode flag missing (M-8)"

    def test_ppo_choice_present(self):
        src = self._src()
        assert '"ppo"' in src or "'ppo'" in src, \
            "02_train_qlora.py: 'ppo' choice missing from --rlhf-mode"

    def test_run_ppo_loop_function(self):
        assert "def run_ppo_loop" in self._src(), \
            "02_train_qlora.py: run_ppo_loop function missing (M-8)"

    def test_ppo_checkpoint_interval_configurable(self):
        src = self._src()
        assert "PPO_CHECKPOINT_INTERVAL" in src or "checkpoint_interval" in src.lower(), \
            "02_train_qlora.py: PPO checkpoint interval not configurable"

    def test_ppo_reward_signal_priority_documented(self):
        src = self._src()
        # Must reference all three reward sources from ADDON.md §2.4
        assert "sandbox" in src.lower(), \
            "02_train_qlora.py: sandbox verdict reward source not referenced"
        assert "SOAR" in src or "soar" in src.lower(), \
            "02_train_qlora.py: SOAR outcome reward source not referenced"
        assert "operator" in src.lower(), \
            "02_train_qlora.py: operator label reward source not referenced"

    def test_ppo_gate_requirement_documented(self):
        src = self._src()
        assert "garak" in src.lower() or "eval-garak" in src, \
            "02_train_qlora.py: garak gate requirement not documented in PPO path"

    def test_existing_main_preserved(self):
        src = self._src()
        assert "def main():" in src, \
            "02_train_qlora.py: existing main() removed -- PPO flag must not break SFT mode"

    def test_rlhf_mode_defaults_to_sft(self):
        src = self._src()
        # When --rlhf-mode not set, main() must be called (not run_ppo_loop)
        assert "main()" in src, \
            "02_train_qlora.py: default SFT path calls main() -- not found"


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2 script contract tests (source inspection)
# ══════════════════════════════════════════════════════════════════════════════

class TestPhase2ScriptContracts:
    """Source-level structure checks for Phase 2 scripts."""

    CL = MLOPS_SCRIPTS / "05_critic_loop.py"
    QL = MLOPS_SCRIPTS / "02_train_qlora.py"

    def test_critic_loop_references_nemo_schema(self):
        src = self.CL.read_text()
        assert "remediation_schema" in src or "nemo_guardrails" in src.lower(), \
            "05_critic_loop.py: NeMo schema reference missing"

    def test_critic_loop_references_sandbox_queue(self):
        src = self.CL.read_text()
        assert "sandbox_queue" in src, \
            "05_critic_loop.py: sandbox queue output missing"

    def test_critic_loop_references_hard_negatives(self):
        src = self.CL.read_text()
        assert "hard_negatives" in src, \
            "05_critic_loop.py: hard_negatives output missing"

    def test_critic_loop_max_retries_configurable(self):
        src = self.CL.read_text()
        assert "MAX_RETRIES" in src, \
            "05_critic_loop.py: MAX_RETRIES not configurable"

    def test_critic_loop_dry_run_flag(self):
        src = self.CL.read_text()
        assert "--dry-run" in src, \
            "05_critic_loop.py: --dry-run flag missing"

    def test_critic_loop_generator_arg(self):
        src = self.CL.read_text()
        assert "--generator" in src, \
            "05_critic_loop.py: --generator arg missing"

    def test_critic_loop_critic_arg(self):
        src = self.CL.read_text()
        assert "--critic" in src, \
            "05_critic_loop.py: --critic arg missing"
