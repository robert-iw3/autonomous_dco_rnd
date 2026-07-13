"""
Lab 10 (WS-G / G0) -- SIEM federation central configuration.

Vets `tools/nexus_config.get_siem_config()` (sovereign-by-default resolution,
double-gating on enabled_backends + token env) AND a real cross-config contract:
the swarm's queryable `nexus_indexes` must match the indexes the middleware
fanout actually writes (`middleware/config/middleware.toml`). A drift there means
the swarm would query an index the fanout never populates -- a real bug, caught
here rather than at 3am.
"""
import os
import sys
import tomllib
from pathlib import Path

import pytest

PE = Path(__file__).parent.parent.parent                    # project_empros/
HUNTER = PE / "analytics/llm_hunter"
sys.path.insert(0, str(HUNTER / "tools"))

import importlib
sys.modules.pop("nexus_config", None)
nexus_config = importlib.import_module("nexus_config")


# -- G0.1 resolution + sovereign default -------------------------------------
class TestSiemConfigResolution:
    def test_no_siem_table_is_sovereign_off(self):
        cfg = nexus_config.get_siem_config({})
        assert cfg["enabled_backends"] == []
        assert cfg["backends"] == {}
        assert cfg["any_active"] is False, "no [siem] config => swarm has no SIEM surface"

    def test_enabled_but_no_token_is_inactive(self, monkeypatch):
        monkeypatch.delenv("NEXUS_SPLUNK_TOKEN", raising=False)
        raw = {"siem": {"enabled_backends": ["splunk"],
                        "splunk": {"dialect": "spl", "search_url": "https://s:8089",
                                   "token_env_var": "NEXUS_SPLUNK_TOKEN",
                                   "nexus_indexes": ["nexus_endpoint"]}}}
        cfg = nexus_config.get_siem_config(raw)
        assert "splunk" in cfg["backends"]
        assert cfg["backends"]["splunk"]["active"] is False, "no token => not reachable"
        assert cfg["any_active"] is False

    def test_active_when_enabled_and_token_present(self, monkeypatch):
        monkeypatch.setenv("NEXUS_SPLUNK_TOKEN", "secret")
        raw = {"siem": {"enabled_backends": ["splunk"], "max_rows": 200, "default_window_hours": 6,
                        "splunk": {"dialect": "spl", "search_url": "https://s:8089",
                                   "token_env_var": "NEXUS_SPLUNK_TOKEN",
                                   "nexus_indexes": ["nexus_endpoint", "nexus_cloud"],
                                   "extra_indexes": ["fw_traffic"], "schema": "cim"}}}
        cfg = nexus_config.get_siem_config(raw)
        b = cfg["backends"]["splunk"]
        assert b["active"] is True and cfg["any_active"] is True
        assert b["token"] == "secret"
        # (B) cross-source: allowed = nexus telemetry + approved external sources
        assert b["allowed_indexes"] == ["nexus_endpoint", "nexus_cloud", "fw_traffic"]
        assert cfg["max_rows"] == 200 and cfg["default_window_hours"] == 6

    def test_a_backend_listed_but_undefined_is_skipped(self):
        cfg = nexus_config.get_siem_config({"siem": {"enabled_backends": ["ghost"]}})
        assert cfg["backends"] == {}

    def test_elastic_uses_apikey_env_var(self, monkeypatch):
        monkeypatch.setenv("NEXUS_ELASTIC_APIKEY", "k")
        raw = {"siem": {"enabled_backends": ["elastic"],
                        "elastic": {"dialect": "esql", "search_url": "https://e:9200",
                                    "apikey_env_var": "NEXUS_ELASTIC_APIKEY",
                                    "nexus_indexes": ["nexus-endpoint"], "schema": "ecs"}}}
        b = nexus_config.get_siem_config(raw)["backends"]["elastic"]
        assert b["active"] is True and b["token"] == "k" and b["dialect"] == "esql"


# -- G0.2 cross-config CONTRACT: query indexes ↔ fanout indexes ---------------
def _load_toml(path: Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


class TestFanoutIndexContract:
    """The swarm must only query indexes the middleware actually writes."""

    NEXUS_TOML = PE / "services/config/nexus.toml"
    MW_TOML = PE / "middleware/config/middleware.toml"

    def _siem(self):
        return _load_toml(self.NEXUS_TOML).get("siem", {})

    def _mw(self):
        return _load_toml(self.MW_TOML)

    def test_siem_table_exists_in_nexus_toml(self):
        assert self._siem(), "services/config/nexus.toml must define a [siem] table (G0)"

    def test_splunk_nexus_indexes_match_fanout(self):
        siem = self._siem().get("splunk", {})
        mw = self._mw().get("splunk", {})
        fanout = {mw[k] for k in ("index_endpoint", "index_cloud", "index_network", "index_alerts")
                  if k in mw}
        declared = set(siem.get("nexus_indexes", []))
        assert fanout, "middleware [splunk] index_* not found"
        assert declared == fanout, (
            f"swarm Splunk nexus_indexes {declared} != middleware fanout indexes {fanout} "
            f"-- the swarm would query an index the fanout never populates (or miss one)")

    def test_elastic_nexus_indexes_cover_fanout(self):
        siem = self._siem().get("elastic", {})
        mw = self._mw().get("elastic", {})
        fanout = {mw[k] for k in ("index_endpoint", "index_cloud", "index_network") if k in mw}
        declared = set(siem.get("nexus_indexes", []))
        assert fanout, "middleware [elastic] index_* not found"
        assert fanout <= declared, (
            f"swarm Elastic nexus_indexes {declared} must cover middleware fanout {fanout}")


# -- R-7 hardening: DuckDB SET s3_* values are structurally non-injectable -----
class TestS3SettingValidation:
    """DuckDB `SET` cannot bind parameters, so the S3 settings are interpolated.
    The values are operator/env-sourced, but a value carrying a quote or semicolon
    would break out of the statement. `_safe_s3_value` makes non-injectability
    structural rather than situational."""

    def test_clean_values_pass_through(self):
        assert nexus_config._safe_s3_value("minio:9000", "s3_endpoint") == "minio:9000"
        assert nexus_config._safe_s3_value("AKIAEXAMPLE", "s3_access_key_id") == "AKIAEXAMPLE"

    def test_quote_semicolon_newline_rejected(self):
        for bad in ["a'; ATTACH 'evil", 'a"b', "a;b", "a\nb", "a\x00b"]:
            with pytest.raises(ValueError):
                nexus_config._safe_s3_value(bad, "s3_endpoint")

    def test_url_style_is_allowlisted(self):
        assert nexus_config._safe_url_style("path") == "path"
        assert nexus_config._safe_url_style("vhost") == "vhost"
        with pytest.raises(ValueError):
            nexus_config._safe_url_style("path'; DROP")

    def test_apply_s3_settings_rejects_injected_secret(self, monkeypatch):
        nexus_config.get_s3_settings.cache_clear()
        monkeypatch.setenv("S3_SECRET_KEY", "x'; ATTACH 'http://evil/db")
        monkeypatch.setenv("S3_ACCESS_KEY", "ak")
        monkeypatch.setenv("S3_ENDPOINT", "minio:9000")

        class _Con:
            def __init__(self): self.stmts = []
            def execute(self, s): self.stmts.append(s)

        with pytest.raises(ValueError):
            nexus_config.apply_s3_settings(_Con())

    def test_apply_s3_settings_emits_expected_sets_for_clean_input(self, monkeypatch):
        nexus_config.get_s3_settings.cache_clear()
        for k in ("S3_SECRET_KEY", "AWS_SECRET_ACCESS_KEY", "MINIO_SECRET_KEY"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("S3_ENDPOINT", "minio:9000")
        monkeypatch.setenv("S3_ACCESS_KEY", "ak")
        monkeypatch.setenv("S3_SECRET_KEY", "sk")

        class _Con:
            def __init__(self): self.stmts = []
            def execute(self, s): self.stmts.append(s)

        con = _Con()
        nexus_config.apply_s3_settings(con)
        joined = "\n".join(con.stmts)
        assert "SET s3_endpoint='minio:9000';" in joined
        assert "SET s3_access_key_id='ak';" in joined
        assert "SET s3_url_style='path';" in joined
