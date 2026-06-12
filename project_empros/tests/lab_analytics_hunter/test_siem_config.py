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
