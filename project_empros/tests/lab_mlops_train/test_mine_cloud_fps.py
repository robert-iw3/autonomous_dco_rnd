"""
test_mine_cloud_fps.py — Offline contracts for 05_mine_cloud_fps.py (M-17)

Validates the cloud FP mining skeleton without requiring S3 access, a live
ITSM API, or operator dismissal data.

All tests run offline. The stub returns empty dismissed-alert lists, so we
verify the pipeline contract (argument parsing, output shape, format correctness)
rather than record counts.

Coverage:
  A. Module structure — script exists, valid syntax, public functions callable
  B. mine() contract — returns list, handles empty corpus, dry-run safe
  C. _format_fp_record() — correct SFT shape, FALSE POSITIVE label, dismiss action
  D. _verify_change_ticket() — returns False when API unconfigured
  E. main() CLI — --dry-run, --source, --limit args parse correctly
  F. Vault pattern — _vault_secret fallback works without VAULT_TOKEN
  G. Air-gap compliance — no TRANSFORMERS_OFFLINE=0 override
"""

import ast
import importlib.util as _ilu
import os
import sys
from pathlib import Path

REPO         = Path(__file__).parent.parent.parent
SCRIPTS_DIR  = REPO / "mlops/scripts"
SCRIPT_PATH  = SCRIPTS_DIR / "05_mine_cloud_fps.py"

sys.path.insert(0, str(SCRIPTS_DIR))

_spec = _ilu.spec_from_file_location("mine_cloud_fps", str(SCRIPT_PATH))
_mod  = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


# ── A. Module structure ───────────────────────────────────────────────────────

class TestModuleStructure:

    def test_script_exists(self):
        assert SCRIPT_PATH.is_file(), "mlops/scripts/05_mine_cloud_fps.py is missing"

    def test_valid_python_syntax(self):
        ast.parse(SCRIPT_PATH.read_text())

    def test_mine_function_is_callable(self):
        assert callable(_mod.mine)

    def test_format_fp_record_is_callable(self):
        assert callable(_mod._format_fp_record)

    def test_verify_change_ticket_is_callable(self):
        assert callable(_mod._verify_change_ticket)

    def test_output_dir_uses_file_relative_path(self):
        src = SCRIPT_PATH.read_text()
        assert 'Path("../data/' not in src and "Path('../data/" not in src, \
            "05_mine_cloud_fps.py must use Path(__file__).parent.parent not ../data/"

    def test_supported_sources_defined(self):
        assert hasattr(_mod, "SUPPORTED_SOURCES")
        assert set(_mod.SUPPORTED_SOURCES) == {"aws", "azure", "gcp"}


# ── B. mine() contract ───────────────────────────────────────────────────────

class TestMineContract:

    def test_mine_returns_list(self):
        result = _mod.mine(source="all", limit=10, dry_run=True)
        assert isinstance(result, list)

    def test_mine_empty_corpus_returns_empty_list(self):
        result = _mod.mine(source="all", limit=100)
        assert result == [], "Stub should return empty list — no live corpus"

    def test_mine_all_sources_returns_list(self):
        result = _mod.mine(source="all")
        assert isinstance(result, list)

    def test_mine_single_source_aws(self):
        result = _mod.mine(source="aws")
        assert isinstance(result, list)

    def test_mine_single_source_azure(self):
        result = _mod.mine(source="azure")
        assert isinstance(result, list)

    def test_mine_single_source_gcp(self):
        result = _mod.mine(source="gcp")
        assert isinstance(result, list)

    def test_mine_limit_respected_in_stub(self):
        # Stub returns empty so limit doesn't matter — just ensure no crash
        result = _mod.mine(limit=1)
        assert isinstance(result, list)


# ── C. _format_fp_record() shape ─────────────────────────────────────────────

class TestFormatFpRecord:

    def _sample_alert(self, source: str = "aws_cloudtrail") -> dict:
        return {
            "alert_id": "test-alert-001",
            "sensor": source,
            "event": {"event_name": "ListBuckets", "user_identity": "svc-backup@corp.com"},
            "dismiss_reason": "Authorized backup service account performing routine scan.",
            "change_ticket": "CHG-20260609-0099",
            "dismissed_by": "analyst-01",
        }

    def test_returns_dict(self):
        result = _mod._format_fp_record(self._sample_alert())
        assert isinstance(result, dict)

    def test_required_keys_present(self):
        result = _mod._format_fp_record(self._sample_alert())
        for key in ("ttp_category", "tool_class", "classification", "messages",
                    "source_type", "vector_name"):
            assert key in result, f"Missing key: {key}"

    def test_classification_is_false_positive(self):
        result = _mod._format_fp_record(self._sample_alert())
        assert result["classification"] == "false_positive"

    def test_vector_name_is_cloud_flow(self):
        result = _mod._format_fp_record(self._sample_alert())
        assert result["vector_name"] == "cloud_flow"

    def test_messages_is_three_turn(self):
        result = _mod._format_fp_record(self._sample_alert())
        msgs = result["messages"]
        assert isinstance(msgs, list) and len(msgs) == 3
        assert [m["role"] for m in msgs] == ["system", "user", "assistant"]

    def test_assistant_says_false_positive(self):
        result = _mod._format_fp_record(self._sample_alert())
        asst = result["messages"][2]["content"]
        assert "FALSE POSITIVE" in asst

    def test_assistant_says_dismiss(self):
        result = _mod._format_fp_record(self._sample_alert())
        asst = result["messages"][2]["content"]
        assert "RECOMMENDED_ACTION: dismiss" in asst

    def test_user_contains_sensor_name(self):
        result = _mod._format_fp_record(self._sample_alert("azure_activity"))
        user = result["messages"][1]["content"]
        assert "azure_activity" in user

    def test_change_ticket_appears_in_assistant_cot(self):
        result = _mod._format_fp_record(self._sample_alert())
        asst = result["messages"][2]["content"]
        assert "CHG-20260609-0099" in asst

    def test_missing_change_ticket_handled_gracefully(self):
        alert = self._sample_alert()
        del alert["change_ticket"]
        result = _mod._format_fp_record(alert)
        assert result["classification"] == "false_positive"

    def test_ttp_category_is_cloud_false_positive(self):
        result = _mod._format_fp_record(self._sample_alert())
        assert result["ttp_category"] == "CloudFalsePositive"


# ── D. _verify_change_ticket() ───────────────────────────────────────────────

class TestVerifyChangeTicket:

    def test_returns_false_when_api_not_configured(self):
        # CHANGE_TICKET_API env not set in CI
        result = _mod._verify_change_ticket("CHG-20260609-0001")
        assert result is False

    def test_returns_false_for_empty_ticket(self):
        result = _mod._verify_change_ticket("")
        assert result is False

    def test_returns_false_without_api_url(self, monkeypatch):
        monkeypatch.setattr(_mod, "CHANGE_TICKET_API", "")
        result = _mod._verify_change_ticket("CHG-TEST")
        assert result is False


# ── E. CLI argument parsing ───────────────────────────────────────────────────

class TestCliArgParsing:

    def test_dry_run_flag_does_not_write_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_mod, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(_mod, "OUTPUT_FILE", tmp_path / "out.jsonl")
        _mod.mine(dry_run=True)
        assert not (tmp_path / "out.jsonl").exists()

    def test_main_dry_run_does_not_crash(self, monkeypatch):
        import sys
        monkeypatch.setattr(sys, "argv", ["05_mine_cloud_fps.py", "--dry-run"])
        _mod.main()


# ── F. Vault pattern ─────────────────────────────────────────────────────────

class TestVaultPattern:

    def test_vault_secret_falls_back_to_env(self, monkeypatch):
        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        monkeypatch.setenv("S3_SECRET_KEY", "test-secret-value")
        result = _mod._vault_secret("nexus/s3/secret_key", "S3_SECRET_KEY", "default")
        assert result == "test-secret-value"

    def test_vault_secret_returns_default_when_env_missing(self, monkeypatch):
        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        monkeypatch.delenv("S3_SECRET_KEY", raising=False)
        result = _mod._vault_secret("nexus/s3/secret_key", "S3_SECRET_KEY", "fallback")
        assert result == "fallback"


# ── G. Air-gap compliance ─────────────────────────────────────────────────────

class TestAirGapCompliance:

    def test_no_transformers_offline_override(self):
        src = SCRIPT_PATH.read_text()
        assert "TRANSFORMERS_OFFLINE=0" not in src
        assert "HF_DATASETS_OFFLINE=0" not in src

    def test_no_hf_hub_import_without_offline_guard(self):
        src = SCRIPT_PATH.read_text()
        assert "from huggingface_hub" not in src, \
            "05_mine_cloud_fps.py must not import huggingface_hub (air-gap violation)"
