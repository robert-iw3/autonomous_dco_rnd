"""
Lab 10 (WS-G / G2a) -- SIEM query cookbook.

The point is to catch a cookbook pattern that references a CIM/ECS field the
middleware never emits (a future hallucination source). Every pattern's declared
`fields` must exist in SIEM_SCHEMA for its dialect's schema; the playbook must be
gated on the live [siem] config; and the counterpart disproof pivot must be present.
"""
import sys
import types
from pathlib import Path

import pytest

PE = Path(__file__).parent.parent.parent
HUNTER = PE / "analytics/llm_hunter"

# stub langchain_core.tools + tools package (siem_cookbook -> siem_query -> BaseTool)
_lc = types.ModuleType("langchain_core")
_lc_tools = types.ModuleType("langchain_core.tools")
_lc_tools.BaseTool = type("BaseTool", (), {"__init__": lambda self, **kw: None})
_lc.tools = _lc_tools
sys.modules.setdefault("langchain_core", _lc)
sys.modules.setdefault("langchain_core.tools", _lc_tools)
_tools_pkg = types.ModuleType("tools")
_tools_pkg.__path__ = [str(HUNTER / "tools")]
sys.modules["tools"] = _tools_pkg
sys.path.insert(0, str(HUNTER / "tools"))
sys.path.insert(0, str(HUNTER))

import importlib
sys.modules.pop("tools.siem_cookbook", None)
cb = importlib.import_module("tools.siem_cookbook")
sq = importlib.import_module("tools.siem_query")


def _active_cfg(dialect, allowed):
    return {"default_window_hours": 6, "max_rows": 200, "any_active": True,
            "backends": {"b": {"dialect": dialect, "allowed_indexes": list(allowed),
                               "active": True}}}


# -- field validity (the issue-finder) ---------------------------------------
class TestFieldValidity:
    def test_every_pattern_field_is_in_schema(self):
        for p in cb.all_patterns():
            schema = sq.SIEM_SCHEMA[sq.DIALECT_SCHEMA[p.dialect]]
            bad = [f for f in p.fields if f not in schema]
            assert not bad, f"pattern {p.id} references non-{p.dialect} fields {bad}"

    def test_template_references_its_declared_fields(self):
        # a declared field that never appears in the template is dead metadata
        for p in cb.all_patterns():
            missing = [f for f in p.fields if f not in p.template]
            assert not missing, f"pattern {p.id} declares fields not used in template: {missing}"

    def test_every_pattern_has_entity_and_index_placeholders(self):
        for p in cb.all_patterns():
            assert "{entity}" in p.template, f"{p.id} has no entity slot"
            assert "{idx}" in p.template, f"{p.id} has no index slot"


# -- gating ------------------------------------------------------------------
class TestGating:
    def test_no_active_backend_renders_empty(self):
        off = {"backends": {"b": {"dialect": "spl", "active": False, "allowed_indexes": []}}}
        assert cb.render_siem_playbook(off) == ""
        assert cb.render_siem_playbook({"backends": {}}) == ""

    def test_splunk_active_renders_spl_with_indexes(self):
        out = cb.render_siem_playbook(_active_cfg("spl", ["nexus_endpoint", "fw_traffic"]))
        assert "dialect=spl" in out
        assert "fw_traffic" in out, "cross-source allowed indexes must be advertised to the model"
        assert "search (" in out and "earliest=" in out

    def test_elastic_active_renders_esql(self):
        out = cb.render_siem_playbook(_active_cfg("esql", ["nexus-endpoint"]))
        assert "dialect=esql" in out and "FROM {idx}" in out


# -- disproof pivot for the review board -------------------------------------
class TestDisproofPivot:
    def test_each_dialect_has_a_disprove_pattern(self):
        for dialect in ("spl", "esql"):
            disprove = [p for p in cb.all_patterns() if p.dialect == dialect and p.phase == "disprove"]
            assert disprove, f"{dialect} needs a disprove pivot for counterparts"

    def test_prevalence_disproof_counts_distinct_sources(self):
        spl = next(p for p in cb._SPL if p.phase == "disprove")
        assert "dc(src)" in spl.template or "distinct_sources" in spl.template
        assert "benign" in spl.notes.lower()  # frames the disproof for the counterpart


# -- G2b expert SOP injection (source contract) ------------------------------
class TestExpertSopInjection:
    AGENTS = HUNTER / "agents"

    @pytest.mark.parametrize("f,var", [
        ("host_expert.py", "host_sop_prompt"),
        ("net_expert.py", "net_sop_prompt"),
        ("cloud_expert.py", "cloud_sop_prompt"),
        ("nettap_expert.py", "nettap_sop_prompt"),
    ])
    def test_expert_injects_gated_siem_playbook(self, f, var):
        src = (self.AGENTS / f).read_text()
        assert "from tools.siem_cookbook import render_siem_playbook" in src, f"{f} missing import"
        # gated: only appended when a backend is enabled (render returns "" otherwise)
        assert "_siem_play = render_siem_playbook()" in src
        assert f"{var} += " in src and "if _siem_play:" in src
