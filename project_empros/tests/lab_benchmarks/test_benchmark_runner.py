"""
WS-A B0 / M-26 — benchmark runner + registry.

Verifies the logic the RSI loop has been waiting for (M-25): the runner loads a
typed registry, scores cases into BenchmarkResults, aggregates per-bench means,
and writes the flat {metric: float} score file the M-24 regression gate consumes.
The final test proves end-to-end that the produced file makes `_regression_gate`
non-vacuous (the whole point of M-26).

Offline; loads the numbered scripts via importlib (mlops convention).
"""
import importlib.util as ilu
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent.parent / "mlops" / "scripts"
REGISTRY = Path(__file__).parent.parent.parent / "mlops" / "benchmarks" / "registry.toml"


def _load(modname, filename):
    spec = ilu.spec_from_file_location(modname, str(SCRIPTS / filename))
    mod = ilu.module_from_spec(spec)
    sys.modules[modname] = mod   # dataclasses + `from __future__ annotations` need this
    spec.loader.exec_module(mod)
    return mod


br = _load("benchmark_runner", "09_benchmark_runner.py")


def _result(bench_id, case_id, score, passed=True):
    return br.BenchmarkResult(bench_id=bench_id, case_id=case_id, score=score, passed=passed)


# ── registry ─────────────────────────────────────────────────────────────────
class TestRegistry:
    def test_shipped_registry_loads_and_validates(self):
        reg = br.load_registry(REGISTRY)
        assert reg, "registry.toml must declare at least one benchmark"
        assert br.validate_registry(reg) == [], "shipped registry must be schema-valid"

    def test_shipped_registry_has_b0_benches(self):
        reg = br.load_registry(REGISTRY)
        # B0 ships the hard-negative held-out + governance benches (plan §7)
        assert "hard_negative_heldout" in reg and "governance_determinism" in reg

    def test_validation_catches_missing_and_bad_fields(self):
        bad = {
            "no_axis": {"version": "v1", "target": "model_c", "scorer": "accuracy",
                        "tier": "tier-1", "gates": True},               # missing axis
            "bad_tier": {"version": "v1", "axis": "x", "target": "model_c",
                         "scorer": "accuracy", "tier": "tier-9", "gates": True},
            "bad_target": {"version": "v1", "axis": "x", "target": "model_z",
                           "scorer": "accuracy", "tier": "tier-1", "gates": True},
        }
        errs = br.validate_registry(bad)
        assert any("no_axis" in e and "axis" in e for e in errs)
        assert any("bad_tier" in e for e in errs)
        assert any("bad_target" in e for e in errs)


# ── aggregation + score-file contract ───────────────────────────────────────
class TestAggregation:
    def test_per_bench_mean(self):
        results = [_result("hard_negative_heldout", "c1", 1.0),
                   _result("hard_negative_heldout", "c2", 0.0),
                   _result("governance_determinism", "g1", 1.0)]
        agg = br.aggregate_results(results)
        assert agg["hard_negative_heldout"] == 0.5
        assert agg["governance_determinism"] == 1.0

    def test_score_file_only_gate_marked_benches(self):
        reg = {
            "gated": {"version": "v1", "axis": "a", "target": "model_c",
                      "scorer": "accuracy", "tier": "tier-1", "gates": True},
            "trend_only": {"version": "v1", "axis": "a", "target": "model_c",
                           "scorer": "accuracy", "tier": "tier-1", "gates": False},
        }
        results = [_result("gated", "c1", 0.9), _result("trend_only", "t1", 0.5)]
        scores = br.score_file_payload(results, reg)
        assert "gated" in scores and "trend_only" not in scores
        assert all(isinstance(v, float) for v in scores.values())

    def test_write_score_file_roundtrip(self, tmp_path):
        p = tmp_path / "latest.json"
        br.write_score_file({"hard_negative_heldout": 0.97}, p)
        data = json.loads(p.read_text())
        assert data == {"hard_negative_heldout": 0.97}

    def test_runs_ledger_rows_one_per_case_plus_aggregate(self):
        results = [_result("b", "c1", 1.0), _result("b", "c2", 0.0)]
        rows = br.runs_ledger_rows(results, {"runner_git_sha": "abc", "run_id": "r1"})
        kinds = [r.get("kind") for r in rows]
        assert kinds.count("case") == 2 and kinds.count("aggregate") == 1
        assert all(r.get("run_id") == "r1" for r in rows)


# ── the point of M-26: activate the dormant M-24 regression gate ────────────
class TestRegressionGateActivation:
    def test_produced_scores_drive_rsi_regression_gate(self, tmp_path, monkeypatch):
        # runner writes the candidate score file…
        results = [_result("hard_negative_heldout", "c1", 0.96),
                   _result("governance_determinism", "g1", 1.0)]
        reg = br.load_registry(REGISTRY)
        scores = br.score_file_payload(results, reg)
        score_file = tmp_path / "latest.json"
        br.write_score_file(scores, score_file)

        # …and the RSI loop reads it as the candidate; a regressed metric is caught.
        monkeypatch.setenv("RSI_EVAL_SCORES_FILE", str(score_file))
        rsi = _load("rsi_loop", "08_rsi_loop.py")
        candidate = rsi._load_candidate_scores()
        assert candidate == scores and candidate, "gate is no longer vacuous"

        baseline = {"hard_negative_heldout": 0.99, "governance_determinism": 1.0}
        ok, regressions = rsi._regression_gate(candidate, baseline, epsilon=0.02)
        assert not ok and any("hard_negative_heldout" in r for r in regressions)
        # a candidate within epsilon passes
        ok2, _ = rsi._regression_gate({"hard_negative_heldout": 0.98}, baseline, epsilon=0.02)
        assert ok2
