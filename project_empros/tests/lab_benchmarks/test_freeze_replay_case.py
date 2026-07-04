"""Replay bench freezer: closed investigations become graded benchmark cases.

Validates mlops/scripts/10_freeze_replay_case.py offline: adjudication from
joined outcomes, the selection policy (overrides first, escalations, stratified
agreed sample), frozen-case packaging with integrity hashes, the graded scorer
(verdict + blast radius + evidence grounding + efficiency), the hardest-miss
tier-0 selection, and the write/manifest roundtrip.
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
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


fr = _load("freeze_replay_case", "10_freeze_replay_case.py")


def _metrics_record(event_id="e1", swarm_tp=True, confidence=0.9, action="",
                    operator_action="confirmed", reinfection=False,
                    source_type="sysmon", entities=None, efficiency=None):
    return {
        "event_id": event_id,
        "ts": 1000.0,
        "source_type": source_type,
        "vector_name": "vec",
        "anomaly_score": 0.8,
        "model_versions": {"model_c": "v3"},
        "verdict": {"is_tp": swarm_tp, "confidence": confidence,
                    "action": action or ("quarantine" if swarm_tp else "dismiss")},
        "analysis_complete": True,
        "gate_overrides_used": 0,
        "entities": entities or {"seeded": 3, "malicious": 1, "cleared": 2,
                                 "resolved": 3, "temporal_seeded": 0},
        "efficiency": efficiency or {"turns": 6, "llm_calls": 10,
                                     "provider_fallbacks": 0, "tool_errors": 0,
                                     "tokens_est": 9000, "wall_ms": 40000},
        "outcome": {"operator_action": operator_action, "soar_status": "done",
                    "reinfection_24h": reinfection, "label_latency_s": 60.0},
    }


def _artifact(event_id="e1", malicious=("host-1",), benign=("host-2",),
              slice_ids=("ev-1", "ev-2", "ev-3")):
    graph = {}
    for h in malicious:
        graph[h] = {"status": "malicious"}
    for h in benign:
        graph[h] = {"status": "cleared"}
    return {
        "event_id": event_id,
        "alert": {"event_id": event_id, "source_type": "sysmon",
                  "vector_name": "vec", "anomaly_score": 0.8},
        "entity_graph": graph,
        "data_slice": [{"id": i, "kind": "event"} for i in slice_ids],
    }


# -- adjudication ------------------------------------------------------------
class TestAdjudication:
    def test_confirm_labels_tp(self):
        adj = fr.adjudicate(_metrics_record(operator_action="confirmed"))
        assert adj["is_tp"] is True and adj["label_confidence"] == 1.0

    def test_dismiss_labels_fp(self):
        adj = fr.adjudicate(_metrics_record(operator_action="dismissed"))
        assert adj["is_tp"] is False

    def test_realized_tp_vocabulary(self):
        for word in ("true_positive", "tp", "confirmed", "malicious", "escalated"):
            assert fr.adjudicate(_metrics_record(operator_action=word))["is_tp"]

    def test_unlabeled_returns_none(self):
        assert fr.adjudicate(_metrics_record(operator_action="")) is None

    def test_dismiss_with_reinfection_is_disputed(self):
        adj = fr.adjudicate(_metrics_record(operator_action="dismissed",
                                            reinfection=True))
        assert adj["disputed"] is True and adj["label_confidence"] < 1.0

    def test_confirm_with_reinfection_not_disputed(self):
        adj = fr.adjudicate(_metrics_record(operator_action="confirmed",
                                            reinfection=True))
        assert adj["disputed"] is False


# -- selection policy --------------------------------------------------------
class TestSelection:
    def test_override_detected_swarm_fp_operator_tp(self):
        rec = _metrics_record(swarm_tp=False, operator_action="confirmed")
        assert fr.is_override(rec) is True

    def test_override_detected_swarm_tp_operator_fp(self):
        rec = _metrics_record(swarm_tp=True, operator_action="dismissed")
        assert fr.is_override(rec) is True

    def test_agreement_is_not_override(self):
        rec = _metrics_record(swarm_tp=True, operator_action="confirmed")
        assert fr.is_override(rec) is False

    def test_unlabeled_is_not_override(self):
        assert fr.is_override(_metrics_record(operator_action="")) is False

    def test_all_overrides_selected(self):
        recs = [_metrics_record(event_id=f"m{i}", swarm_tp=False,
                                operator_action="confirmed") for i in range(5)]
        selected = fr.select_cases(recs, agreed_rate=0.0)
        assert len(selected) == 5
        assert all(reason == "override" for _, reason in selected)

    def test_escalations_always_selected(self):
        rec = _metrics_record(swarm_tp=True, operator_action="confirmed",
                              action="manual_review_required")
        selected = fr.select_cases([rec], agreed_rate=0.0)
        assert len(selected) == 1 and selected[0][1] == "escalation"

    def test_agreed_sampled_at_rate(self):
        recs = [_metrics_record(event_id=f"a{i}", swarm_tp=True,
                                operator_action="confirmed") for i in range(20)]
        none_sel = fr.select_cases(recs, agreed_rate=0.0)
        all_sel = fr.select_cases(recs, agreed_rate=1.0)
        assert len(none_sel) == 0
        assert len(all_sel) == 20
        assert all(reason == "agreed_sample" for _, reason in all_sel)

    def test_agreed_sample_deterministic(self):
        recs = [_metrics_record(event_id=f"a{i}", operator_action="confirmed",
                                source_type=("sysmon" if i % 2 else "vpc"))
                for i in range(40)]
        s1 = [r["event_id"] for r, _ in fr.select_cases(recs, agreed_rate=0.5, seed=7)]
        s2 = [r["event_id"] for r, _ in fr.select_cases(recs, agreed_rate=0.5, seed=7)]
        assert s1 == s2 and 0 < len(s1) < 40

    def test_agreed_sample_stratified_by_source_type(self):
        recs = ([_metrics_record(event_id=f"s{i}", operator_action="confirmed",
                                 source_type="sysmon") for i in range(10)]
                + [_metrics_record(event_id=f"v{i}", operator_action="confirmed",
                                   source_type="vpc") for i in range(10)])
        selected = fr.select_cases(recs, agreed_rate=0.3, seed=1)
        types = {r["source_type"] for r, _ in selected}
        assert types == {"sysmon", "vpc"}, "each stratum contributes to the sample"

    def test_unlabeled_never_selected(self):
        recs = [_metrics_record(event_id="u1", operator_action="")]
        assert fr.select_cases(recs, agreed_rate=1.0) == []


# -- frozen case packaging ---------------------------------------------------
class TestBuildCase:
    def _case(self, **kw):
        rec = _metrics_record(swarm_tp=False, operator_action="confirmed", **kw)
        art = _artifact()
        return fr.build_case(rec, art["alert"], art["entity_graph"],
                             art["data_slice"], reason="override")

    def test_case_shape(self):
        case = self._case()
        assert case["schema"] == fr.CASE_SCHEMA
        assert case["case_id"] == "replay-e1"
        for key in ("alert", "entity_graph", "data_slice", "adjudicated",
                    "swarm", "selection_reason", "sha384"):
            assert key in case

    def test_adjudicated_block(self):
        case = self._case()
        assert case["adjudicated"]["is_tp"] is True
        assert case["adjudicated"]["label_confidence"] == 1.0

    def test_swarm_block_freezes_champion_behavior(self):
        case = self._case()
        assert case["swarm"]["verdict"]["is_tp"] is False
        assert case["swarm"]["efficiency"]["turns"] == 6

    def test_integrity_hash_stable_and_sensitive(self):
        c1, c2 = self._case(), self._case()
        assert c1["sha384"] == c2["sha384"]
        rec = _metrics_record(swarm_tp=False, operator_action="confirmed")
        art = _artifact(slice_ids=("ev-9",))
        c3 = fr.build_case(rec, art["alert"], art["entity_graph"],
                           art["data_slice"], reason="override")
        assert c3["sha384"] != c1["sha384"]

    def test_unlabeled_record_rejected(self):
        rec = _metrics_record(operator_action="")
        art = _artifact()
        with pytest.raises(ValueError):
            fr.build_case(rec, art["alert"], art["entity_graph"],
                          art["data_slice"], reason="override")


# -- graded scorer -----------------------------------------------------------
class TestScoring:
    def _frozen(self, adjudicated_tp=True, malicious=("host-1",)):
        rec = _metrics_record(
            swarm_tp=not adjudicated_tp,
            operator_action="confirmed" if adjudicated_tp else "dismissed")
        art = _artifact(malicious=malicious)
        return fr.build_case(rec, art["alert"], art["entity_graph"],
                             art["data_slice"], reason="override")

    def _candidate(self, is_tp=True, malicious=("host-1",),
                   evidence=("ev-1",), turns=6, tool_errors=0):
        return {
            "verdict": {"is_tp": is_tp, "confidence": 0.9},
            "entities_malicious": list(malicious),
            "evidence_ids": list(evidence),
            "efficiency": {"turns": turns, "tool_errors": tool_errors},
        }

    def test_wrong_verdict_scores_zero_on_verdict_axis(self):
        s = fr.score_case(self._frozen(True), self._candidate(is_tp=False))
        assert s["verdict"] == 0.0

    def test_correct_verdict_full_attribution_full_credit(self):
        s = fr.score_case(self._frozen(True), self._candidate(is_tp=True))
        assert s["verdict"] == 1.0

    def test_correct_verdict_wrong_attribution_partial_credit(self):
        cand = self._candidate(is_tp=True, malicious=("host-9",))
        s = fr.score_case(self._frozen(True), cand)
        assert 0.0 < s["verdict"] < 1.0

    def test_blast_radius_recall(self):
        frozen = self._frozen(True, malicious=("host-1", "host-3"))
        found_one = self._candidate(is_tp=True, malicious=("host-1",))
        assert fr.score_case(frozen, found_one)["blast_radius"] == 0.5
        found_both = self._candidate(is_tp=True, malicious=("host-1", "host-3"))
        assert fr.score_case(frozen, found_both)["blast_radius"] == 1.0

    def test_evidence_grounding_fraction_of_cited_ids_in_slice(self):
        frozen = self._frozen(True)
        grounded = self._candidate(evidence=("ev-1", "ev-2"))
        assert fr.score_case(frozen, grounded)["grounding"] == 1.0
        half = self._candidate(evidence=("ev-1", "fabricated"))
        assert fr.score_case(frozen, half)["grounding"] == 0.5

    def test_tp_verdict_with_no_citations_is_ungrounded(self):
        s = fr.score_case(self._frozen(True), self._candidate(evidence=()))
        assert s["grounding"] == 0.0

    def test_fp_verdict_with_no_citations_is_fine(self):
        frozen = self._frozen(adjudicated_tp=False)
        cand = self._candidate(is_tp=False, malicious=(), evidence=())
        assert fr.score_case(frozen, cand)["grounding"] == 1.0

    def test_efficiency_penalizes_tool_errors_and_turn_overrun(self):
        frozen = self._frozen(True)
        clean = fr.score_case(frozen, self._candidate())["efficiency"]
        messy = fr.score_case(
            frozen, self._candidate(turns=20, tool_errors=5))["efficiency"]
        assert clean == 1.0 and messy < clean

    def test_composite_in_unit_interval_and_weighted(self):
        frozen = self._frozen(True)
        perfect = fr.score_case(frozen, self._candidate())
        zero = fr.score_case(
            frozen, self._candidate(is_tp=False, malicious=(), evidence=(),
                                    turns=30, tool_errors=9))
        assert perfect["score"] == 1.0
        assert 0.0 <= zero["score"] < perfect["score"]


# -- tier-0 hardest-miss selection --------------------------------------------
class TestHardestMisses:
    def _miss(self, event_id, confidence, disputed=False):
        rec = _metrics_record(event_id=event_id, swarm_tp=False,
                              confidence=confidence,
                              operator_action="confirmed",
                              reinfection=False)
        art = _artifact(event_id=event_id)
        case = fr.build_case(rec, art["alert"], art["entity_graph"],
                             art["data_slice"], reason="override")
        if disputed:
            case["adjudicated"]["disputed"] = True
            case["adjudicated"]["label_confidence"] = 0.5
        return case

    def _agreed(self, event_id):
        rec = _metrics_record(event_id=event_id, swarm_tp=True,
                              operator_action="confirmed")
        art = _artifact(event_id=event_id)
        return fr.build_case(rec, art["alert"], art["entity_graph"],
                             art["data_slice"], reason="agreed_sample")

    def test_confident_wrong_verdicts_first(self):
        cases = [self._miss("low", 0.55), self._miss("high", 0.99),
                 self._miss("mid", 0.80)]
        picked = fr.hardest_misses(cases, n=2)
        assert [c["case_id"] for c in picked] == ["replay-high", "replay-mid"]

    def test_disputed_labels_excluded(self):
        cases = [self._miss("ok", 0.9), self._miss("disp", 0.99, disputed=True)]
        picked = fr.hardest_misses(cases, n=5)
        assert [c["case_id"] for c in picked] == ["replay-ok"]

    def test_only_overrides_qualify(self):
        cases = [self._agreed("agree"), self._miss("miss", 0.7)]
        picked = fr.hardest_misses(cases, n=5)
        assert [c["case_id"] for c in picked] == ["replay-miss"]


# -- write/manifest roundtrip -------------------------------------------------
class TestWriteCases:
    def _cases(self, n=3):
        out = []
        for i in range(n):
            rec = _metrics_record(event_id=f"w{i}", swarm_tp=False,
                                  operator_action="confirmed")
            art = _artifact(event_id=f"w{i}")
            out.append(fr.build_case(rec, art["alert"], art["entity_graph"],
                                     art["data_slice"], reason="override"))
        return out

    def test_writes_cases_jsonl_and_manifest(self, tmp_path):
        dest = tmp_path / "replay" / "v1"
        manifest = fr.write_cases(self._cases(), dest)
        lines = (dest / "cases.jsonl").read_text().strip().splitlines()
        assert len(lines) == 3
        on_disk = json.loads((dest / "manifest.json").read_text())
        assert on_disk == manifest
        assert manifest["count"] == 3 and manifest["schema"] == fr.CASE_SCHEMA
        assert len(manifest["dataset_sha384"]) == 96

    def test_manifest_hash_covers_case_content(self, tmp_path):
        m1 = fr.write_cases(self._cases(2), tmp_path / "a")
        m2 = fr.write_cases(self._cases(3), tmp_path / "b")
        assert m1["dataset_sha384"] != m2["dataset_sha384"]


# -- CLI ----------------------------------------------------------------------
class TestCLI:
    def test_end_to_end_freeze(self, tmp_path):
        recs = [_metrics_record(event_id="m1", swarm_tp=False,
                                operator_action="confirmed"),
                _metrics_record(event_id="a1", swarm_tp=True,
                                operator_action="confirmed")]
        arts = [_artifact(event_id="m1"), _artifact(event_id="a1")]
        metrics_f = tmp_path / "joined.jsonl"
        metrics_f.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        arts_f = tmp_path / "artifacts.jsonl"
        arts_f.write_text("\n".join(json.dumps(a) for a in arts) + "\n")
        dest = tmp_path / "replay" / "v1"

        rc = fr.main(["--metrics", str(metrics_f), "--artifacts", str(arts_f),
                      "--out", str(dest), "--agreed-rate", "0.0"])
        assert rc == 0
        lines = (dest / "cases.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["case_id"] == "replay-m1"

    def test_missing_artifact_skipped_not_fatal(self, tmp_path):
        recs = [_metrics_record(event_id="m1", swarm_tp=False,
                                operator_action="confirmed")]
        metrics_f = tmp_path / "joined.jsonl"
        metrics_f.write_text(json.dumps(recs[0]) + "\n")
        arts_f = tmp_path / "artifacts.jsonl"
        arts_f.write_text("")
        rc = fr.main(["--metrics", str(metrics_f), "--artifacts", str(arts_f),
                      "--out", str(tmp_path / "out")])
        assert rc == 0
        assert not (tmp_path / "out" / "cases.jsonl").exists()


# -- registry wiring ----------------------------------------------------------
class TestRegistryBenches:
    def test_replay_and_tier0_benches_registered(self):
        br = _load("benchmark_runner_reg", "09_benchmark_runner.py")
        reg = br.load_registry(REGISTRY)
        assert "replay_investigations" in reg
        assert "tier0_canary" in reg
        assert reg["tier0_canary"]["tier"] == "tier-0"
        assert reg["tier0_canary"]["gates"] is True
        assert br.validate_registry(reg) == []
