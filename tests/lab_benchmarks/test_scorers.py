"""
Scorer units for the benchmark runner.

Every scorer name the registry may declare (accuracy, determinism,
replay_graded) has an implementation in the runner and is proven here on
fixture cases: label normalization across the record shapes in use,
binary correctness, consistency banding with the unstable flag, and the
graded replay composite. Registry validation must reject unknown scorer
names so a typo cannot silently register an unscorable bench.

Offline; loads the numbered scripts via importlib (mlops convention).
"""
import importlib.util as ilu
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent.parent / "mlops" / "scripts"
REGISTRY = Path(__file__).parent.parent.parent / "mlops" / "benchmarks" / "registry.toml"


def _load(modname, filename):
    spec = ilu.spec_from_file_location(modname, str(SCRIPTS / filename))
    mod = ilu.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


br = _load("benchmark_runner_scorers", "09_benchmark_runner.py")


# ── registry declares only implemented scorers ───────────────────────────────

class TestScorerRegistry:
    def test_every_shipped_scorer_is_implemented(self):
        reg = br.load_registry(REGISTRY)
        for bid, bench in reg.items():
            assert bench["scorer"] in br.SCORERS, \
                f"{bid} declares scorer {bench['scorer']!r} with no implementation"

    def test_unknown_scorer_rejected_by_validation(self):
        bad = {"typo": {"version": "v1", "axis": "a", "target": "model_c",
                        "scorer": "acuracy", "tier": "tier-1", "gates": True}}
        errs = br.validate_registry(bad)
        assert any("typo" in e and "scorer" in e for e in errs)

    def test_scorers_map_covers_valid_scorers(self):
        assert set(br.SCORERS) == br.VALID_SCORERS


# ── label normalization ──────────────────────────────────────────────────────

class TestLabelNormalization:
    def test_classification_string(self):
        assert br._tp_label({"classification": "true_positive"}) is True
        assert br._tp_label({"classification": "false_positive"}) is False

    def test_adjudicated_and_verdict_shapes(self):
        assert br._tp_label({"adjudicated": {"is_tp": True}}) is True
        assert br._tp_label({"verdict": {"is_tp": False}}) is False
        assert br._tp_label({"is_tp": True}) is True

    def test_unlabeled_is_none(self):
        assert br._tp_label({}) is None
        assert br._tp_label({"classification": "weird"}) is None


# ── accuracy ─────────────────────────────────────────────────────────────────

class TestAccuracyScorer:
    def test_match_and_mismatch(self):
        case = {"case_id": "c1", "classification": "true_positive"}
        assert br.score_accuracy(case, {"verdict": {"is_tp": True}}) == 1.0
        assert br.score_accuracy(case, {"verdict": {"is_tp": False}}) == 0.0

    def test_unparseable_output_scores_zero(self):
        case = {"classification": "false_positive"}
        assert br.score_accuracy(case, {}) == 0.0

    def test_unlabeled_case_is_an_error(self):
        with pytest.raises(ValueError):
            br.score_accuracy({"case_id": "nolabel"}, {"is_tp": True})


# ── determinism ──────────────────────────────────────────────────────────────

class TestDeterminismScorer:
    def _samples(self, labels):
        return [{"verdict": {"is_tp": lab}} for lab in labels]

    def test_fully_deterministic(self):
        case = {"classification": "true_positive"}
        res = br.score_determinism(case, self._samples([True] * 4))
        assert res["score"] == 1.0 and res["stable"] and res["correct"]

    def test_unstable_below_consistency_floor(self):
        case = {"classification": "true_positive"}
        res = br.score_determinism(case, self._samples([True, True, False, False]))
        assert res["score"] == 0.5
        assert not res["stable"], "50% agreement must be flagged unstable"

    def test_majority_scoring_when_unstable(self):
        case = {"classification": "false_positive"}
        res = br.score_determinism(case, self._samples([False, False, False, True]))
        assert res["score"] == 0.75 and not res["stable"]
        assert res["majority"] is False and res["correct"]

    def test_consistency_floor_matches_plan(self):
        assert br.CONSISTENCY_FLOOR == 0.8

    def test_empty_samples(self):
        res = br.score_determinism({"classification": "true_positive"}, [])
        assert res["score"] == 0.0 and not res["stable"] and not res["correct"]


# ── graded replay delegation ─────────────────────────────────────────────────

class TestReplayGradedScorer:
    def test_delegates_to_frozen_case_scorer(self):
        frozen = {
            "adjudicated": {"is_tp": True},
            "entity_graph": {"hostA": {"status": "malicious"}},
            "data_slice": [{"id": "ev1"}],
            "swarm": {"efficiency": {"turns": 5}},
        }
        candidate = {"verdict": {"is_tp": True}, "entities_malicious": ["hostA"],
                     "evidence_ids": ["ev1"], "efficiency": {"turns": 5, "tool_errors": 0}}
        res = br.score_replay_graded(frozen, candidate)
        assert res["score"] == 1.0
        assert set(res) >= {"verdict", "blast_radius", "grounding", "efficiency", "score"}

    def test_wrong_verdict_zeroes_verdict_component(self):
        frozen = {"adjudicated": {"is_tp": True}, "entity_graph": {},
                  "data_slice": [], "swarm": {}}
        res = br.score_replay_graded(frozen, {"verdict": {"is_tp": False}})
        assert res["verdict"] == 0.0
