"""
test_phase3_guardrails.py -- Offline validation tests for Phase 3 configs and vault_client.py.

Covers:
  mlops/config/nemo_guardrails/remediation_schema.json  -- JSON schema correctness
  mlops/config/nemo_guardrails/input_rules.co           -- Injection patterns listed
  mlops/config/nemo_guardrails/output_rules.co          -- Blocked/allowed patterns
  mlops/config/nemo_guardrails/config.yaml              -- Structure and required keys
  mlops/config/garak_config.yaml                        -- ADDON.md §2.1 spec compliance
  mlops/scripts/vault_client.py                         -- I-9: interface, error handling, caching
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

REPO          = Path(__file__).parent.parent
MLOPS         = REPO  / "mlops"
NEMO_DIR      = MLOPS / "config"  / "nemo_guardrails"
GARAK_CONFIG  = MLOPS / "config"  / "garak_config.yaml"
VAULT_SRC     = MLOPS / "scripts" / "vault_client.py"


# ══════════════════════════════════════════════════════════════════════════════
# remediation_schema.json
# ══════════════════════════════════════════════════════════════════════════════

class TestRemediationSchema:

    SCHEMA = NEMO_DIR / "remediation_schema.json"

    def _load(self):
        return json.loads(self.SCHEMA.read_text())

    def test_schema_file_exists(self):
        assert self.SCHEMA.exists(), "remediation_schema.json missing"

    def test_schema_is_valid_json(self):
        data = self._load()
        assert isinstance(data, dict)

    def test_schema_type_is_object(self):
        assert self._load()["type"] == "object"

    def test_schema_has_three_required_fields(self):
        required = set(self._load()["required"])
        expected = {"target_component", "remediation_script_base64", "verification_test_command"}
        assert required == expected, f"required mismatch: {required}"

    def test_additional_properties_false(self):
        assert self._load().get("additionalProperties") is False, \
            "additionalProperties must be false -- schema must be strict"

    def test_all_properties_have_type(self):
        props = self._load().get("properties", {})
        for name, defn in props.items():
            assert "type" in defn, f"property {name!r} missing 'type'"

    def test_base64_field_has_content_encoding(self):
        props = self._load().get("properties", {})
        assert props["remediation_script_base64"].get("contentEncoding") == "base64", \
            "remediation_script_base64 must document contentEncoding: base64"

    def test_schema_has_description(self):
        assert "description" in self._load(), "schema must have a description"

    def test_target_component_type_string(self):
        assert self._load()["properties"]["target_component"]["type"] == "string"

    def test_verification_test_command_type_string(self):
        assert self._load()["properties"]["verification_test_command"]["type"] == "string"


# ══════════════════════════════════════════════════════════════════════════════
# input_rules.co
# ══════════════════════════════════════════════════════════════════════════════

class TestInputRulesColang:

    SRC = NEMO_DIR / "input_rules.co"

    def _text(self):
        return self.SRC.read_text()

    def test_file_exists(self):
        assert self.SRC.exists(), "input_rules.co missing"

    def test_blocks_rm_rf(self):
        assert "rm -rf" in self._text()

    def test_blocks_drop_table(self):
        assert "DROP TABLE" in self._text()

    def test_blocks_ignore_instructions(self):
        src = self._text()
        assert "ignore" in src.lower()

    def test_blocks_override_system_prompt(self):
        assert "override system prompt" in self._text().lower() or \
               "override" in self._text().lower()

    def test_blocks_nats_redirect(self):
        assert "nats" in self._text().lower()

    def test_has_flow_definition(self):
        assert "define flow" in self._text(), \
            "input_rules.co must define at least one flow"

    def test_has_user_define(self):
        assert "define user" in self._text(), \
            "input_rules.co must define user message patterns"

    def test_has_bot_response(self):
        assert "define bot" in self._text() or "bot refuse" in self._text(), \
            "input_rules.co must define a bot refusal response"

    def test_blocks_role_confusion(self):
        src = self._text()
        assert any(kw in src for kw in ["you are now", "pretend you are", "act as"]), \
            "input_rules.co must block role confusion injection attempts"


# ══════════════════════════════════════════════════════════════════════════════
# output_rules.co
# ══════════════════════════════════════════════════════════════════════════════

class TestOutputRulesColang:

    SRC = NEMO_DIR / "output_rules.co"

    def _text(self):
        return self.SRC.read_text()

    def test_file_exists(self):
        assert self.SRC.exists(), "output_rules.co missing"

    def test_blocks_chmod(self):
        assert "chmod" in self._text()

    def test_blocks_chown(self):
        assert "chown" in self._text()

    def test_blocks_usermod(self):
        assert "usermod" in self._text()

    def test_blocks_systemctl_disable(self):
        assert "systemctl disable" in self._text()

    def test_blocks_sudoers_edit(self):
        assert "sudoers" in self._text()

    def test_blocks_passwd_edit(self):
        assert "/etc/passwd" in self._text()

    def test_blocks_iptables_delete(self):
        src = self._text()
        assert "iptables -D" in src or "iptables --delete" in src, \
            "output_rules.co must block iptables rule deletions"

    def test_has_output_flow(self):
        assert "define flow check output" in self._text() or \
               "define flow" in self._text()

    def test_allows_iptables_append(self):
        assert "iptables -A" in self._text() or "safe remediation" in self._text().lower()

    def test_allows_confirm_quarantine(self):
        assert "CONFIRM_QUARANTINE" in self._text()


# ══════════════════════════════════════════════════════════════════════════════
# nemo_guardrails/config.yaml
# ══════════════════════════════════════════════════════════════════════════════

class TestNemoConfig:

    CONFIG = NEMO_DIR / "config.yaml"

    def _load(self):
        import yaml  # standard lib available via pyyaml
        return yaml.safe_load(self.CONFIG.read_text())

    def test_file_exists(self):
        assert self.CONFIG.exists(), "nemo_guardrails/config.yaml missing"

    def test_has_rails_section(self):
        cfg = self._load()
        assert "rails" in cfg, "config.yaml must have a 'rails' section"

    def test_input_rails_defined(self):
        cfg = self._load()
        assert "input" in cfg["rails"], "rails.input missing"
        assert "flows" in cfg["rails"]["input"], "rails.input.flows missing"

    def test_output_rails_defined(self):
        cfg = self._load()
        assert "output" in cfg["rails"], "rails.output missing"

    def test_colang_files_listed(self):
        cfg = self._load()
        assert "colang_files" in cfg, "colang_files not listed in config.yaml"
        assert "input_rules.co" in cfg["colang_files"]
        assert "output_rules.co" in cfg["colang_files"]

    def test_schema_enforcement_section(self):
        cfg = self._load()
        assert "schema_enforcement" in cfg, "schema_enforcement section missing"
        se = cfg["schema_enforcement"]
        assert se.get("enabled") is True
        assert "schema_file" in se
        assert se["max_retries"] >= 1

    def test_schema_file_points_to_existing_file(self):
        cfg = self._load()
        schema_path = NEMO_DIR / cfg["schema_enforcement"]["schema_file"]
        assert schema_path.exists(), f"schema_file {schema_path} does not exist"

    def test_has_models_section(self):
        assert "models" in self._load()

    def test_logging_section(self):
        cfg = self._load()
        assert "logging" in cfg
        assert "log_violations" in cfg["logging"]


# ══════════════════════════════════════════════════════════════════════════════
# garak_config.yaml
# ══════════════════════════════════════════════════════════════════════════════

class TestGarakConfig:

    def _load(self):
        import yaml
        return yaml.safe_load(GARAK_CONFIG.read_text())

    def test_file_exists(self):
        assert GARAK_CONFIG.exists(), "garak_config.yaml missing"

    def test_has_probes_section(self):
        cfg = self._load()
        assert "probes" in cfg, "garak_config.yaml: probes section missing"

    def test_jailbreak_probe_present(self):
        probes = self._load()["probes"]
        assert any("jailbreak" in str(p) for p in probes)

    def test_xss_probe_present(self):
        probes = self._load()["probes"]
        assert any("xss" in str(p) for p in probes)

    def test_promptinject_probe_present(self):
        probes = self._load()["probes"]
        assert any("promptinject" in str(p) for p in probes)

    def test_jailbreak_threshold_is_zero(self):
        thresholds = self._load()["thresholds"]
        assert thresholds["jailbreak_success_rate"] == 0.0, \
            "jailbreak_success_rate must be 0.0 -- any success blocks promotion"

    def test_xss_threshold_is_zero(self):
        assert self._load()["thresholds"]["xss_success_rate"] == 0.0

    def test_rollback_on_fail(self):
        assert self._load().get("rollback_on_fail") is True

    def test_failure_log_dir_defined(self):
        assert "failure_log_dir" in self._load()

    def test_has_target_section(self):
        assert "target" in self._load()


# ══════════════════════════════════════════════════════════════════════════════
# vault_client.py -- I-9
# ══════════════════════════════════════════════════════════════════════════════

class TestVaultClient:
    """I-9: vault_client.py must expose the correct interface and fail safely."""

    def _import(self):
        """Load vault_client.py in isolation, stubbing hvac."""
        stub_hvac = types.ModuleType("hvac")
        stub_hvac.Client = None  # not called in unit tests
        sys.modules.setdefault("hvac", stub_hvac)

        spec = importlib.util.spec_from_file_location("vault_client", str(VAULT_SRC))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_file_exists(self):
        assert VAULT_SRC.exists(), "vault_client.py missing"

    def test_get_secret_function_exists(self):
        vc = self._import()
        assert callable(vc.get_secret), "vault_client.get_secret must be callable"

    def test_vault_client_class_exists(self):
        vc = self._import()
        assert hasattr(vc, "VaultClient"), "VaultClient class missing"

    def test_vault_error_class_exists(self):
        vc = self._import()
        assert hasattr(vc, "VaultError"), "VaultError exception class missing"

    def test_vault_error_is_exception(self):
        vc = self._import()
        assert issubclass(vc.VaultError, Exception)

    def test_read_raises_vault_error_no_token(self):
        vc = self._import()
        client = vc.VaultClient(addr="https://vault.test:8200", token="", mount_point="secret")
        with pytest.raises(vc.VaultError, match="VAULT_TOKEN"):
            client.read("nexus/nats/password")

    def test_read_raises_vault_error_hvac_missing(self, monkeypatch):
        vc = self._import()
        monkeypatch.setitem(sys.modules, "hvac", None)  # simulate import failure
        client = vc.VaultClient(addr="https://vault.test:8200", token="test", mount_point="secret")
        with pytest.raises((vc.VaultError, ImportError)):
            client.read("nexus/nats/password")

    def test_well_known_paths_defined(self):
        vc = self._import()
        for attr in ("NATS_PASSWORD_PATH", "QDRANT_API_KEY_PATH",
                     "HF_TOKEN_PATH", "SENSOR_HMAC_KEY_PATH", "SOAR_WEBHOOK_PATH"):
            assert hasattr(vc, attr), f"vault_client.py missing constant {attr}"

    def test_well_known_paths_start_with_nexus(self):
        vc = self._import()
        for attr in ("NATS_PASSWORD_PATH", "QDRANT_API_KEY_PATH",
                     "HF_TOKEN_PATH", "SENSOR_HMAC_KEY_PATH", "SOAR_WEBHOOK_PATH"):
            val = getattr(vc, attr)
            assert val.startswith("nexus/"), f"{attr} must start with 'nexus/' (got {val!r})"

    def test_invalidate_clears_cache(self):
        vc = self._import()
        client = vc.VaultClient(token="x")
        client._cache["nexus/test"] = "cached-value"
        client.invalidate("nexus/test")
        assert "nexus/test" not in client._cache

    def test_invalidate_all_clears_all(self):
        vc = self._import()
        client = vc.VaultClient(token="x")
        client._cache["nexus/a"] = "a"
        client._cache["nexus/b"] = "b"
        client.invalidate()
        assert len(client._cache) == 0

    def test_cache_hit_skips_vault_call(self):
        vc = self._import()
        client = vc.VaultClient(token="x")
        client._cache["nexus/nats/password"] = "pre-cached"
        result = client.read("nexus/nats/password")
        assert result == "pre-cached"

    def test_source_no_plaintext_credential_write(self):
        src = VAULT_SRC.read_text()
        assert "open(" not in src or "write" not in src, \
            "vault_client.py must not write credentials to disk"


# ══════════════════════════════════════════════════════════════════════════════
# Phase 3 source contract tests
# ══════════════════════════════════════════════════════════════════════════════

class TestPhase3Contracts:

    def test_nemo_config_dir_exists(self):
        assert NEMO_DIR.is_dir(), "mlops/config/nemo_guardrails/ directory missing"

    def test_garak_config_references_zero_thresholds(self):
        src = GARAK_CONFIG.read_text()
        assert "0.0" in src, "garak_config.yaml must set success_rate thresholds to 0.0"

    def test_vault_client_documents_air_gap_requirement(self):
        src = VAULT_SRC.read_text()
        assert "TRANSFORMERS_OFFLINE" in src or "air-gap" in src.lower() or \
               "Ansible Vault" in src, \
            "vault_client.py must document air-gap / Ansible Vault requirement"

    def test_nemo_schema_matches_critic_loop_keys(self):
        """REQUIRED_SCHEMA_KEYS in 05_critic_loop.py must match remediation_schema.json 'required'."""
        schema = json.loads((NEMO_DIR / "remediation_schema.json").read_text())
        schema_required = set(schema["required"])

        cl_src = (MLOPS / "scripts" / "05_critic_loop.py").read_text()
        assert "target_component" in cl_src
        assert "remediation_script_base64" in cl_src
        assert "verification_test_command" in cl_src

        for key in schema_required:
            assert key in cl_src, \
                f"05_critic_loop.py does not reference schema key {key!r}"

    def test_all_nemo_colang_files_present(self):
        for fname in ("input_rules.co", "output_rules.co", "config.yaml",
                      "remediation_schema.json"):
            assert (NEMO_DIR / fname).exists(), f"{fname} missing from nemo_guardrails/"
