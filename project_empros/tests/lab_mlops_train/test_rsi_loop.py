"""
Lab ADDON Phase 4: RSI Loop Offline Contracts

Validates mlops/scripts/08_rsi_loop.py and the skill_library schema
without live subprocesses, NATS, GPU, or a real sandbox.

All tests run with RSI_DRY_RUN=1. No subprocess.run calls are made.

Coverage:
  A. SkillEntry schema validation (required fields, confidence floor, base64)
  B. Remediation action schema (3 required fields, extras rejected)
  C. Skill library I/O (promote_skill writes JSONL, load returns typed entries)
  D. Safety invariants (air-gap, safety invariant list, RSISafetyViolation raised)
  E. Sandbox verdict counter (cursor arithmetic, file-absent returns 0)
  F. rsi_loop threshold guard (returns 3 when below SANDBOX_BATCH_THRESHOLD)
  G. rsi_loop dry-run full cycle (returns 0 in dry-run mode)
  H. Schema violation logging (writes to violations dir)
  I. Source-level contracts (SANDBOX_BATCH_THRESHOLD, NATS subject, env vars)
  J. Skill library file location matches ADDON spec
"""

import sys
import os
import json
import base64
import importlib.util as _ilu
from pathlib import Path
import pytest

SCRIPTS_DIR = Path(__file__).parent.parent.parent / "mlops/scripts"

# ── Load 08_rsi_loop.py in dry-run / offline mode ────────────────────────────
os.environ["RSI_DRY_RUN"]           = "1"
os.environ["TRANSFORMERS_OFFLINE"]  = "1"
os.environ["HF_DATASETS_OFFLINE"]   = "1"

_spec = _ilu.spec_from_file_location("rsi_loop", str(SCRIPTS_DIR / "08_rsi_loop.py"))
_mod  = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

SkillEntry                   = _mod.SkillEntry
RSISafetyViolation           = _mod.RSISafetyViolation
SAFETY_INVARIANTS            = _mod.SAFETY_INVARIANTS
REQUIRED_REMEDIATION_FIELDS  = _mod.REQUIRED_REMEDIATION_FIELDS
_validate_remediation_action = _mod._validate_remediation_action
_log_schema_violation        = _mod._log_schema_violation
_count_new_verdicts          = _mod._count_new_verdicts
_read_new_verdicts           = _mod._read_new_verdicts
promote_skill                = _mod.promote_skill
load_skill_library           = _mod.load_skill_library
rsi_loop                     = _mod.rsi_loop
main                         = _mod.main

RSI_SRC = (SCRIPTS_DIR / "08_rsi_loop.py").read_text()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _good_action() -> dict:
    script = base64.b64encode(b"#!/bin/bash\necho mitigated").decode()
    return {
        "target_component":         "sysmon-agent-host-01",
        "remediation_script_base64": script,
        "verification_test_command": "systemctl is-active sysmon",
    }


def _good_skill(**overrides) -> SkillEntry:
    base = dict(
        skill_id        = "a1b2c3d4-0000-0000-0000-000000000001",
        trigger_pattern = "T1055.001",
        action          = _good_action(),
        confidence      = 0.97,
        sandbox_verdict = "mitigated",
        promoted_at     = "2026-06-05T00:00:00+00:00",
    )
    base.update(overrides)
    return SkillEntry(**base)


# ── A. SkillEntry schema ──────────────────────────────────────────────────────

class TestSkillEntrySchema:

    def test_valid_skill_passes(self):
        _good_skill().validate()  # must not raise

    def test_empty_skill_id_rejected(self):
        try:
            _good_skill(skill_id="").validate()
            assert False
        except ValueError:
            pass

    def test_empty_trigger_pattern_rejected(self):
        try:
            _good_skill(trigger_pattern="").validate()
            assert False
        except ValueError:
            pass

    def test_confidence_below_floor_rejected(self):
        try:
            _good_skill(confidence=0.94).validate()
            assert False
        except ValueError:
            pass

    def test_confidence_floor_exactly_passes(self):
        _good_skill(confidence=0.95).validate()

    def test_invalid_sandbox_verdict_rejected(self):
        try:
            _good_skill(sandbox_verdict="unknown").validate()
            assert False
        except ValueError:
            pass

    def test_all_valid_sandbox_verdicts_accepted(self):
        for v in ("mitigated", "partial", "failed"):
            _good_skill(sandbox_verdict=v).validate()

    def test_empty_action_dict_rejected(self):
        try:
            _good_skill(action={}).validate()
            assert False
        except ValueError:
            pass


# ── B. Remediation action schema ──────────────────────────────────────────────

class TestRemediationSchema:

    def test_valid_action_passes(self):
        _validate_remediation_action(_good_action())

    def test_missing_field_rejected(self):
        action = _good_action()
        del action["remediation_script_base64"]
        try:
            _validate_remediation_action(action)
            assert False
        except ValueError as e:
            assert "missing" in str(e)

    def test_extra_field_rejected(self):
        action = {**_good_action(), "extra_field": "should not be here"}
        try:
            _validate_remediation_action(action)
            assert False
        except ValueError as e:
            assert "extra" in str(e)

    def test_invalid_base64_script_rejected(self):
        action = {**_good_action(), "remediation_script_base64": "not!base64!!"}
        try:
            _validate_remediation_action(action)
            assert False
        except ValueError:
            pass

    def test_empty_target_component_rejected(self):
        action = {**_good_action(), "target_component": ""}
        try:
            _validate_remediation_action(action)
            assert False
        except ValueError:
            pass

    def test_empty_verification_command_rejected(self):
        action = {**_good_action(), "verification_test_command": ""}
        try:
            _validate_remediation_action(action)
            assert False
        except ValueError:
            pass

    def test_required_fields_match_spec(self):
        assert REQUIRED_REMEDIATION_FIELDS == frozenset([
            "target_component",
            "remediation_script_base64",
            "verification_test_command",
        ])


# ── C. Skill library I/O ──────────────────────────────────────────────────────

class TestSkillLibraryIO:

    @pytest.fixture(autouse=True)
    def _reset_dedup_singleton(self):
        """Reset the SkillDeduplicator singleton before/after each test so
        promotes in one test don't block unrelated skills in the next."""
        _mod._skill_dedup = None
        yield
        _mod._skill_dedup = None

    def test_promote_skill_writes_jsonl(self, tmp_path, monkeypatch):
        lib = tmp_path / "skills_v1.jsonl"
        monkeypatch.setattr(_mod, "SKILL_LIBRARY_FILE", lib)
        promote_skill(_good_skill())
        assert lib.exists()
        record = json.loads(lib.read_text().strip())
        assert record["skill_id"] == "a1b2c3d4-0000-0000-0000-000000000001"

    def test_promote_skill_appends_multiple(self, tmp_path, monkeypatch):
        lib = tmp_path / "skills_v1.jsonl"
        monkeypatch.setattr(_mod, "SKILL_LIBRARY_FILE", lib)
        # Two genuinely distinct skills: different target, script content, and verification.
        # Skills sharing only trigger-class but different remediation action are not duplicates.
        action1 = {
            "target_component":          "sysmon-agent-host-01",
            "remediation_script_base64": base64.b64encode(b"systemctl stop sysmon").decode(),
            "verification_test_command": "systemctl is-active sysmon",
        }
        action2 = {
            "target_component":          "identity-provider-entra",
            "remediation_script_base64": base64.b64encode(b"Revoke-AzureADUserAllRefreshToken -ObjectId $userId").decode(),
            "verification_test_command": "Get-AzureADUser -ObjectId $userId | Select-Object AccountEnabled",
        }
        promote_skill(_good_skill(skill_id="id-1", trigger_pattern="T1055.001", action=action1))
        promote_skill(_good_skill(skill_id="id-2", trigger_pattern="T1078.004", action=action2))
        lines = lib.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_load_skill_library_empty(self, tmp_path, monkeypatch):
        lib = tmp_path / "skills_v1.jsonl"
        lib.write_text("")
        monkeypatch.setattr(_mod, "SKILL_LIBRARY_FILE", lib)
        assert load_skill_library() == []

    def test_load_skill_library_roundtrip(self, tmp_path, monkeypatch):
        lib = tmp_path / "skills_v1.jsonl"
        monkeypatch.setattr(_mod, "SKILL_LIBRARY_FILE", lib)
        original = _good_skill()
        promote_skill(original)
        loaded = load_skill_library()
        assert len(loaded) == 1
        assert loaded[0].skill_id == original.skill_id
        assert loaded[0].trigger_pattern == original.trigger_pattern

    def test_load_skill_library_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_mod, "SKILL_LIBRARY_FILE", tmp_path / "nonexistent.jsonl")
        assert load_skill_library() == []

    def test_skill_library_file_path_matches_spec(self):
        # ADDON.md §4.2: mlops/data/skill_library/skills_v1.jsonl
        assert "skill_library" in str(_mod.SKILL_LIBRARY_FILE)
        assert "skills_v1.jsonl" in str(_mod.SKILL_LIBRARY_FILE)


# ── D. Safety invariants ──────────────────────────────────────────────────────

class TestSafetyInvariants:

    def test_invariant_list_has_all_six_plus_alignment_gate(self):
        assert len(SAFETY_INVARIANTS) >= 6

    def test_airgap_invariant_present(self):
        text = " ".join(SAFETY_INVARIANTS)
        assert "TRANSFORMERS_OFFLINE" in text
        assert "HF_DATASETS_OFFLINE" in text

    def test_credential_invariant_present(self):
        text = " ".join(SAFETY_INVARIANTS)
        assert "Ansible Vault" in text or "plaintext" in text

    def test_nats_quorum_invariant_present(self):
        text = " ".join(SAFETY_INVARIANTS)
        assert "quorum" in text or "NATS" in text

    def test_alignment_gate_invariant_present(self):
        text = " ".join(SAFETY_INVARIANTS)
        assert "alignment" in text.lower() or "gate" in text.lower()

    def test_rsi_safety_violation_is_runtime_error(self):
        assert issubclass(RSISafetyViolation, RuntimeError)

    def test_airgap_violation_raises(self, monkeypatch):
        monkeypatch.setenv("TRANSFORMERS_OFFLINE", "0")
        try:
            rsi_loop(dry_run=False, max_retrain=1)
            assert False, "Expected RSISafetyViolation"
        except RSISafetyViolation:
            pass

    def test_airgap_env_injected_into_subprocess_env(self):
        assert "TRANSFORMERS_OFFLINE" in RSI_SRC
        assert "HF_DATASETS_OFFLINE" in RSI_SRC
        assert "_AIRGAP_ENV" in RSI_SRC


# ── E. Sandbox verdict counter ────────────────────────────────────────────────

class TestSandboxVerdictCounter:

    def test_absent_file_returns_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_mod, "SANDBOX_RESULTS_FILE", tmp_path / "nope.jsonl")
        assert _count_new_verdicts(0) == 0

    def test_count_from_cursor_zero(self, tmp_path, monkeypatch):
        f = tmp_path / "results.jsonl"
        f.write_text('{"verdict": "mitigated"}\n{"verdict": "failed"}\n')
        monkeypatch.setattr(_mod, "SANDBOX_RESULTS_FILE", f)
        assert _count_new_verdicts(0) == 2

    def test_count_from_cursor_one(self, tmp_path, monkeypatch):
        f = tmp_path / "results.jsonl"
        f.write_text('{"verdict": "mitigated"}\n{"verdict": "failed"}\n')
        monkeypatch.setattr(_mod, "SANDBOX_RESULTS_FILE", f)
        assert _count_new_verdicts(1) == 1

    def test_count_at_end_returns_zero(self, tmp_path, monkeypatch):
        f = tmp_path / "results.jsonl"
        f.write_text('{"verdict": "mitigated"}\n')
        monkeypatch.setattr(_mod, "SANDBOX_RESULTS_FILE", f)
        assert _count_new_verdicts(1) == 0

    def test_read_new_verdicts_returns_dicts(self, tmp_path, monkeypatch):
        f = tmp_path / "results.jsonl"
        f.write_text('{"verdict": "mitigated", "technique": "T1055"}\n')
        monkeypatch.setattr(_mod, "SANDBOX_RESULTS_FILE", f)
        records = _read_new_verdicts(0)
        assert len(records) == 1
        assert records[0]["verdict"] == "mitigated"


# ── F. Threshold guard ────────────────────────────────────────────────────────

class TestThresholdGuard:

    def test_returns_3_when_below_threshold(self, tmp_path, monkeypatch):
        f = tmp_path / "results.jsonl"
        f.write_text("")  # 0 verdicts
        monkeypatch.setattr(_mod, "SANDBOX_RESULTS_FILE", f)
        rc = rsi_loop(dry_run=False, max_retrain=1)
        assert rc == 3

    def test_sandbox_batch_threshold_constant_present(self):
        assert "SANDBOX_BATCH_THRESHOLD" in RSI_SRC

    def test_threshold_default_is_50(self):
        assert _mod.SANDBOX_BATCH_THRESHOLD == 50 or "50" in RSI_SRC


# ── G. Dry-run full cycle returns 0 ──────────────────────────────────────────

class TestDryRunCycle:

    def test_dry_run_returns_zero(self, monkeypatch):
        monkeypatch.setattr(_mod, "SANDBOX_BATCH_THRESHOLD", 0)
        rc = rsi_loop(dry_run=True, max_retrain=1)
        assert rc == 0

    def test_main_dry_run_returns_zero(self, monkeypatch):
        monkeypatch.setattr(_mod, "SANDBOX_BATCH_THRESHOLD", 0)
        rc = main(["--dry-run", "--max-retrain", "1"])
        assert rc == 0


# ── H. Schema violation logging ───────────────────────────────────────────────

class TestSchemaViolationLogging:

    def test_violation_written_to_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_mod, "SCHEMA_VIOLATIONS_DIR", tmp_path / "violations")
        _log_schema_violation({"bad": "action"}, "missing required fields")
        files = list((tmp_path / "violations").glob("*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["reason"] == "missing required fields"

    def test_violation_log_contains_action(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_mod, "SCHEMA_VIOLATIONS_DIR", tmp_path / "v")
        _log_schema_violation({"k": "v"}, "test reason")
        data = json.loads(list((tmp_path / "v").glob("*.json"))[0].read_text())
        assert "action" in data
        assert data["action"] == {"k": "v"}


# ── I. Source-level contracts ─────────────────────────────────────────────────

class TestSourceContracts:

    def test_nats_skill_update_subject_present(self):
        assert "skill.update" in RSI_SRC

    def test_rsi_dry_run_env_var_documented(self):
        assert "RSI_DRY_RUN" in RSI_SRC

    def test_max_retrain_env_var_documented(self):
        assert "RSI_MAX_RETRAIN_ATTEMPTS" in RSI_SRC

    def test_airgap_env_dict_present(self):
        assert "_AIRGAP_ENV" in RSI_SRC

    def test_alignment_gate_called_before_deploy(self):
        fn_start = RSI_SRC.find("def rsi_loop(")
        fn_end   = RSI_SRC.find("\ndef ", fn_start + 1)
        fn_body  = RSI_SRC[fn_start:fn_end]
        gate_pos  = fn_body.find("_run_alignment_gate(")
        deploy_pos = fn_body.find('"deploy"')
        assert gate_pos < deploy_pos, \
            "Alignment gate must be checked before deploy make target"

    def test_safety_violation_halts_before_training(self):
        fn_start = RSI_SRC.find("def rsi_loop(")
        fn_end   = RSI_SRC.find("\ndef ", fn_start + 1)
        fn_body  = RSI_SRC[fn_start:fn_end]
        safety_check_pos = fn_body.find("RSISafetyViolation")
        train_pos = fn_body.find("train-ppo")
        assert safety_check_pos < train_pos, \
            "Safety check must occur before training"


# ── J. Skill library file location ────────────────────────────────────────────

class TestSkillLibraryLocation:

    def test_skills_jsonl_file_exists(self):
        skill_lib = Path(__file__).parent.parent.parent / "mlops/data/skill_library/skills_v1.jsonl"
        assert skill_lib.exists(), \
            "mlops/data/skill_library/skills_v1.jsonl must be created at repo init"

    def test_skills_jsonl_is_empty_or_valid_jsonl(self):
        skill_lib = Path(__file__).parent.parent.parent / "mlops/data/skill_library/skills_v1.jsonl"
        content = skill_lib.read_text().strip()
        if content:
            for line in content.splitlines():
                json.loads(line)  # each line must be valid JSON


# ── K. Cycle ledger (loop memory) ─────────────────────────────────────────────

_load_ledger             = _mod._load_ledger
_append_ledger           = _mod._append_ledger
_last_cursor             = _mod._last_cursor
_batch_hash              = _mod._batch_hash
_batch_failure_count     = _mod._batch_failure_count
_deployed_baseline_scores = _mod._deployed_baseline_scores
_load_candidate_scores   = _mod._load_candidate_scores
_regression_gate         = _mod._regression_gate


def _record(**overrides) -> dict:
    base = {
        "cycle_id": "abcd1234", "started_at": "2026-06-09T00:00:00+00:00",
        "finished_at": "2026-06-09T01:00:00+00:00", "batch_hash": "deadbeefdeadbeef",
        "verdict_cursor_start": 0, "verdict_cursor_end": 50, "retrain_count": 1,
        "gate_scores": {}, "outcome": "deployed", "deployed": True,
        "halt_reason": None,
    }
    base.update(overrides)
    return base


class TestRSILedger:

    def _live(self, monkeypatch, tmp_path):
        monkeypatch.setattr(_mod, "RSI_LEDGER_FILE", tmp_path / "rsi_ledger_v1.jsonl")
        monkeypatch.setattr(_mod, "RSI_DRY_RUN", False)

    def test_load_missing_ledger_returns_empty(self, tmp_path, monkeypatch):
        self._live(monkeypatch, tmp_path)
        assert _load_ledger() == []

    def test_append_and_load_roundtrip(self, tmp_path, monkeypatch):
        self._live(monkeypatch, tmp_path)
        _append_ledger(_record(cycle_id="c1"))
        _append_ledger(_record(cycle_id="c2", outcome="gate_failed", deployed=False))
        records = _load_ledger()
        assert [r["cycle_id"] for r in records] == ["c1", "c2"]

    def test_append_skipped_in_dry_run(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_mod, "RSI_LEDGER_FILE", tmp_path / "rsi_ledger_v1.jsonl")
        monkeypatch.setattr(_mod, "RSI_DRY_RUN", True)
        _append_ledger(_record())
        assert not (tmp_path / "rsi_ledger_v1.jsonl").exists()

    def test_corrupt_lines_skipped(self, tmp_path, monkeypatch):
        self._live(monkeypatch, tmp_path)
        ledger = tmp_path / "rsi_ledger_v1.jsonl"
        ledger.write_text(json.dumps(_record()) + "\n{not json}\n")
        assert len(_load_ledger()) == 1

    def test_last_cursor_zero_without_ledger(self, tmp_path, monkeypatch):
        self._live(monkeypatch, tmp_path)
        assert _last_cursor() == 0

    def test_last_cursor_resumes_from_max(self, tmp_path, monkeypatch):
        self._live(monkeypatch, tmp_path)
        _append_ledger(_record(verdict_cursor_end=50))
        _append_ledger(_record(verdict_cursor_end=120))
        _append_ledger(_record(verdict_cursor_end=80))
        assert _last_cursor() == 120


class TestBatchQuarantine:

    def _live(self, monkeypatch, tmp_path):
        monkeypatch.setattr(_mod, "RSI_LEDGER_FILE", tmp_path / "rsi_ledger_v1.jsonl")
        monkeypatch.setattr(_mod, "RSI_DRY_RUN", False)

    def test_batch_hash_stable(self):
        lines = ['{"a": 1}', '{"b": 2}']
        assert _batch_hash(lines) == _batch_hash(list(lines))
        assert len(_batch_hash(lines)) == 16

    def test_batch_hash_differs_on_content(self):
        assert _batch_hash(['{"a": 1}']) != _batch_hash(['{"a": 2}'])

    def test_failure_count_counts_only_gate_failed_same_hash(self, tmp_path, monkeypatch):
        self._live(monkeypatch, tmp_path)
        _append_ledger(_record(batch_hash="aaaa", outcome="gate_failed", deployed=False))
        _append_ledger(_record(batch_hash="aaaa", outcome="gate_failed", deployed=False))
        _append_ledger(_record(batch_hash="aaaa", outcome="deployed"))
        _append_ledger(_record(batch_hash="bbbb", outcome="gate_failed", deployed=False))
        assert _batch_failure_count("aaaa") == 2
        assert _batch_failure_count("bbbb") == 1
        assert _batch_failure_count("cccc") == 0

    def test_quarantine_threshold_default_is_2(self):
        assert _mod.RSI_BATCH_QUARANTINE_THRESHOLD == 2


class TestRegressionGate:

    def test_no_baseline_passes(self):
        ok, regressions = _regression_gate({"t2_acc": 0.50}, {})
        assert ok and regressions == []

    def test_no_candidate_scores_passes(self):
        ok, _ = _regression_gate({}, {"t2_acc": 0.99})
        assert ok

    def test_equal_scores_pass(self):
        ok, _ = _regression_gate({"t2_acc": 0.99}, {"t2_acc": 0.99})
        assert ok

    def test_drop_within_epsilon_passes(self):
        ok, _ = _regression_gate({"t2_acc": 0.985}, {"t2_acc": 0.99}, epsilon=0.02)
        assert ok

    def test_drop_beyond_epsilon_fails(self):
        ok, regressions = _regression_gate({"t2_acc": 0.95}, {"t2_acc": 0.99}, epsilon=0.02)
        assert not ok
        assert "t2_acc" in regressions[0]

    def test_unshared_metrics_ignored(self):
        ok, _ = _regression_gate({"new_metric": 0.10}, {"t2_acc": 0.99})
        assert ok

    def test_deployed_baseline_picks_latest_deployed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_mod, "RSI_LEDGER_FILE", tmp_path / "rsi_ledger_v1.jsonl")
        monkeypatch.setattr(_mod, "RSI_DRY_RUN", False)
        _append_ledger(_record(gate_scores={"t2_acc": 0.97}, deployed=True))
        _append_ledger(_record(gate_scores={"t2_acc": 0.99}, deployed=True))
        _append_ledger(_record(gate_scores={"t2_acc": 0.10}, outcome="gate_failed",
                               deployed=False))
        assert _deployed_baseline_scores() == {"t2_acc": 0.99}

    def test_candidate_scores_missing_file_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_mod, "EVAL_SCORES_FILE", tmp_path / "absent.json")
        assert _load_candidate_scores() == {}

    def test_candidate_scores_reads_flat_floats(self, tmp_path, monkeypatch):
        scores = tmp_path / "latest.json"
        scores.write_text(json.dumps({"t2_acc": 0.99, "note": "ignored", "f1": 1}))
        monkeypatch.setattr(_mod, "EVAL_SCORES_FILE", scores)
        assert _load_candidate_scores() == {"t2_acc": 0.99, "f1": 1.0}


class TestLedgerSourceContracts:

    def test_exit_code_4_documented(self):
        assert "4 on batch quarantine" in RSI_SRC or "4 batch quarantined" in RSI_SRC

    def test_cursor_resumes_from_ledger_in_loop(self):
        fn_start = RSI_SRC.find("def rsi_loop(")
        fn_body = RSI_SRC[fn_start:]
        assert "_last_cursor()" in fn_body

    def test_quarantine_checked_before_training(self):
        fn_start = RSI_SRC.find("def rsi_loop(")
        fn_body = RSI_SRC[fn_start:]
        assert fn_body.find("_batch_failure_count") < fn_body.find("train-ppo")

    def test_regression_gate_between_alignment_gate_and_deploy(self):
        fn_start = RSI_SRC.find("def rsi_loop(")
        fn_body = RSI_SRC[fn_start:]
        align_pos  = fn_body.find("_run_alignment_gate(")
        reg_pos    = fn_body.find("_regression_gate(")
        deploy_pos = fn_body.find('"deploy"')
        assert align_pos < reg_pos < deploy_pos, \
            "Regression gate must run after the alignment gate and before deploy"

    def test_every_terminal_outcome_writes_ledger(self):
        fn_start = RSI_SRC.find("def rsi_loop(")
        fn_body = RSI_SRC[fn_start:]
        for outcome in ("quarantined", "spool_failed", "deployed", "deploy_failed",
                        "gate_failed"):
            assert f'"{outcome}"' in fn_body, f"outcome {outcome} not recorded"

    def test_makefile_has_rsi_loop_target(self):
        makefile_path = SCRIPTS_DIR.parent / "Makefile"
        if not makefile_path.exists():
            pytest.skip("Makefile not shipped in this test container")
        makefile = makefile_path.read_text()
        assert "rsi-loop:" in makefile
        assert "08_rsi_loop.py" in makefile
