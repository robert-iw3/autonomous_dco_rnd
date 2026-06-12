"""
WS-G / G3 -- SIEM-pivot training corpus (`mlops/scripts/stage_siem_pivot.py`).

Vets that every generated SFT record teaches a VALID pivot: correct dialect, only
CIM/ECS fields the middleware fanout emits, read-only + bounded queries, and a
balanced TP/FP split whose disproof signal is cross-source prevalence. A query that
references a non-existent CIM/ECS field (a future hallucination source) fails here.
"""
import re
import sys
from pathlib import Path

import pytest

PE = Path(__file__).parent.parent
sys.path.insert(0, str(PE / "mlops/scripts"))

import importlib
sp = importlib.import_module("stage_siem_pivot")

RECORDS = sp.generate(records_per_scenario=4)

_DESTRUCTIVE = re.compile(
    r"\|\s*(delete|outputlookup|collect|sendalert|sendemail|script|rest|run)\b", re.IGNORECASE)


def _spl_fields(q):
    fields = {f for f in re.findall(r'(\w+)="', q) if f != "index"}
    fields |= set(re.findall(r"\bdc\((\w+)\)", q))
    for grp in re.findall(r"\bBY\s+([\w,\s]+)", q):
        fields |= {t for t in re.split(r"[,\s]+", grp) if t}
    return fields


def _esql_fields(q):
    return {f for f in re.findall(r'([\w.@]+)\s*==', q)} | \
           {m for m in re.findall(r"COUNT_DISTINCT\(([\w.]+)\)", q)} | \
           {m for m in re.findall(r"\bBY\s+([\w.]+)", q)}


def _query_of(rec):
    asst = rec["messages"][2]["content"]
    return asst.split("SIEM_PIVOT(dialect=", 1)[1].split("): ", 1)[1].split("\nVERDICT")[0]


class TestRecordShape:
    def test_messages_triplet(self):
        for r in RECORDS:
            roles = [m["role"] for m in r["messages"]]
            assert roles == ["system", "user", "assistant"]
            assert r["classification"] in ("true_positive", "false_positive")
            assert r["dialect"] in ("spl", "esql")

    def test_tp_fp_balanced(self):
        tp = sum(1 for r in RECORDS if r["classification"] == "true_positive")
        assert tp == len(RECORDS) - tp and tp > 0, "TP/FP must be balanced"

    def test_both_dialects_present(self):
        assert {r["dialect"] for r in RECORDS} == {"spl", "esql"}

    def test_assistant_emits_a_pivot_and_verdict(self):
        for r in RECORDS:
            asst = r["messages"][2]["content"]
            assert "SIEM_PIVOT(dialect=" in asst and "VERDICT:" in asst


class TestFieldValidity:
    """Every field a generated query uses must be a real CIM/ECS field."""
    def test_spl_queries_use_only_cim_fields(self):
        allowed = set(sp.CIM_FIELDS)
        for r in RECORDS:
            if r["dialect"] != "spl":
                continue
            bad = _spl_fields(_query_of(r)) - allowed - {"distinct_sources", "count"}
            assert not bad, f"SPL record uses non-CIM fields {bad}: {_query_of(r)}"

    def test_esql_queries_use_only_ecs_fields(self):
        allowed = set(sp.ECS_FIELDS)
        for r in RECORDS:
            if r["dialect"] != "esql":
                continue
            bad = _esql_fields(_query_of(r)) - allowed - {"distinct_sources", "count"}
            assert not bad, f"ES|QL record uses non-ECS fields {bad}: {_query_of(r)}"

    def test_corpus_fields_match_middleware_mappings_if_available(self):
        try:
            import yaml
        except ImportError:
            pytest.skip("pyyaml not installed")
        cim_yaml = PE / "middleware/config/cim_mappings.yaml"
        ecs_yaml = PE / "middleware/config/ecs_mappings.yaml"
        if not cim_yaml.exists():
            pytest.skip("middleware mapping not present in this image")

        def targets(p):
            d = yaml.safe_load(open(p))
            return {k for s in d["schemas"] for k in (s.get("fields") or {})}
        assert set(sp.CIM_FIELDS) <= targets(cim_yaml), "corpus CIM fields drifted from fanout mapping"
        assert set(sp.ECS_FIELDS) <= targets(ecs_yaml), "corpus ECS fields drifted from fanout mapping"


class TestReadOnlyAndBounded:
    def test_no_destructive_commands(self):
        for r in RECORDS:
            assert not _DESTRUCTIVE.search(_query_of(r)), f"destructive command in corpus: {_query_of(r)}"

    def test_spl_index_scoped_and_bounded(self):
        for r in RECORDS:
            if r["dialect"] != "spl":
                continue
            q = _query_of(r)
            assert "index=" in q, f"SPL not index-scoped: {q}"
            assert ("earliest=" in q), f"SPL not time-bounded: {q}"

    def test_esql_from_and_bounded(self):
        for r in RECORDS:
            if r["dialect"] != "esql":
                continue
            q = _query_of(r)
            assert q.strip().upper().startswith("FROM "), f"ES|QL must start FROM: {q}"
            assert ("LIMIT" in q or "STATS" in q), f"ES|QL not bounded/aggregated: {q}"


class TestDisproofSignal:
    def test_prevalence_scenario_teaches_distinct_source_disproof(self):
        fp = [r for r in RECORDS if r["scenario"] == "c2_beacon_prevalence"
              and r["classification"] == "false_positive"]
        assert fp, "missing the prevalence FP teaching records"
        cot = fp[0]["messages"][2]["content"].lower()
        assert "distinct" in cot and "benign" in cot


class TestEvalAxis:
    """SI-7: the deploy-gate eval (03_eval_model.py) carries a SIEM-pivot axis."""
    SRC = (PE / "mlops/scripts/03_eval_model.py").read_text()

    def test_siem_pivot_axis_present(self):
        # the eval matches model output with a (regex-escaped) SIEM_PIVOT pattern
        assert "SIEM_PIVOT" in self.SRC and "dialect=" in self.SRC, "eval gate missing the SIEM-pivot axis"
        assert "SIEM Pivot Validity" in self.SRC

    def test_axis_checks_readonly_dialect_and_bounds(self):
        s = self.SRC
        assert "generating/destructive command" in s             # read-only
        assert "index-scoped" in s and "bounded" in s            # SPL scope/bounds
        assert "must start FROM and be bounded" in s             # ES|QL
        assert "hallucinated dialect" in s                       # dialect validity
        # and a failure flips passed -> the production swap is blocked
        assert "passed = False" in s.split("SIEM Pivot Validity")[1][:900]
