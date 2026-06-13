"""
Lab 11 -- NIST AI 600-1 control implementations (llm_hunter/agents/controls.py).

These prove the engineering fixes tracked in nist_ai_600_1_control_tracker.md:

  P3  Confabulated-evidence grounding   (Confabulation / MS-2.5-003)
  P3  Confidence-calibration logging    (Confabulation / MS-2.13-001)
  P1  Immunity-memory TTL / expiry      (Harmful Bias & Homogenization / GV-1.3-005)
  P5  AI-origin provenance disclosure   (Human-AI Configuration / MP-5.1-003)
  P2  Frontier model version pinning    (Value Chain / MP-4.1-007)

controls.py is dependency-free (stdlib only) so it imports standalone without the
heavy agents package __init__.
"""
import sys
import time
from pathlib import Path

import pytest

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"
sys.path.insert(0, str(HUNTER / "agents"))

import importlib
sys.modules.pop("controls", None)
controls = importlib.import_module("controls")


# ----------------------- P3: evidence grounding ----------------------------
class TestArtifactExtraction:
    def test_extracts_ipv4_pid_hashes_arn(self):
        text = ("beacon to 203.0.113.7 from pid=4821; dropped "
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
                "(md5 d41d8cd98f00b204e9800998ecf8427e) via "
                "arn:aws:iam::123456789012:role/Deployer")
        a = controls.extract_artifacts(text)
        assert "203.0.113.7" in a
        assert "4821" in a
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in a
        assert "d41d8cd98f00b204e9800998ecf8427e" in a
        assert any(x.startswith("arn:aws:iam") for x in a)

    def test_does_not_extract_confidence_decimals_or_durations(self):
        # 0.92 / 60s must NOT be mistaken for an IP or PID artifact
        a = controls.extract_artifacts("confidence 0.92, 60s beacon cadence, 4MB egress")
        assert a == set(), f"prose numerics must not be treated as artifacts: {a}"

    def test_empty_text_is_empty_set(self):
        assert controls.extract_artifacts("") == set()
        assert controls.extract_artifacts(None) == set()


class TestEvidenceCorpus:
    def _msg(self, content):
        import types
        return types.SimpleNamespace(content=content, id=None)

    def test_corpus_unions_entities_notes_messages_and_alert(self):
        state = {
            "alert": {"sensor_id": "dc-prod-01", "raw_event": {"src": "198.51.100.4"}},
            "entities_of_interest": {"10.0.0.5": {"type": "ip", "notes": "spawned pid=991"}},
            "messages": [self._msg("egress to 203.0.113.7 observed")],
        }
        corpus = controls.build_evidence_corpus(state)
        assert "10.0.0.5" in corpus          # entity key
        assert "991" in corpus               # pid from entity notes
        assert "203.0.113.7" in corpus       # from a message
        assert "198.51.100.4" in corpus      # from raw alert
        assert "dc-prod-01" in corpus        # sensor id


class TestGroundingEnforcement:
    def _state(self, justification, corpus_msg=""):
        import types
        return {
            "alert": {"sensor_id": "host-1", "raw_event": {}},
            "entities_of_interest": {},
            "messages": [types.SimpleNamespace(content=corpus_msg, id=None)],
            "verdict": {"is_true_positive": True, "confidence": 0.9,
                        "recommended_action": "contain", "justification": justification},
        }

    def _board(self, is_tp=True):
        return {"verdict": {"is_true_positive": is_tp, "confidence": 0.9,
                            "recommended_action": "contain" if is_tp else "monitor",
                            "justification": "Review board CONFIRMED true positive"},
                "next_agent": "response_agent"}

    def test_confirmed_tp_citing_phantom_ip_is_demoted(self):
        # supervisor's finding cites an IP that appears NOWHERE in the evidence
        state = self._state("malicious C2 to 203.0.113.250 confirmed", corpus_msg="benign noise")
        result, violations = controls.enforce_grounding(self._board(True), state)
        assert "203.0.113.250" in violations
        v = result["verdict"]
        assert v["is_true_positive"] is False, "ungrounded TP must be demoted"
        assert v["recommended_action"] == "monitor"
        assert "GROUNDING OVERRIDE" in v["justification"]

    def test_confirmed_tp_with_grounded_artifacts_passes(self):
        # the cited IP IS present in the evidence corpus -> no override
        state = self._state("malicious C2 to 203.0.113.7 confirmed",
                            corpus_msg="netflow shows 203.0.113.7 beaconing")
        result, violations = controls.enforce_grounding(self._board(True), state)
        assert violations == []
        assert result["verdict"]["is_true_positive"] is True

    def test_non_tp_board_result_is_never_touched(self):
        state = self._state("cites 8.8.8.8 nowhere", corpus_msg="")
        board = self._board(is_tp=False)
        result, violations = controls.enforce_grounding(board, state)
        assert violations == []
        assert result is board, "a non-TP verdict must pass through untouched"

    def test_tp_with_no_cited_artifacts_passes(self):
        # purely prose justification (no IP/hash/PID) cannot be ungrounded
        state = self._state("lsass dump + scheduled-task persistence; no benign cause")
        result, violations = controls.enforce_grounding(self._board(True), state)
        assert violations == []
        assert result["verdict"]["is_true_positive"] is True


# ----------------------- P3: confidence calibration ------------------------
class TestCalibration:
    def test_record_pairs_prediction_with_outcome(self):
        rec = controls.calibration_record(
            {"is_true_positive": True, "confidence": 0.91}, operator_disposition="true_positive")
        assert rec["predicted_tp"] is True
        assert rec["predicted_confidence"] == 0.91
        assert rec["realized_tp"] is True
        assert rec["correct"] is True

    def test_record_flags_miscalibration(self):
        rec = controls.calibration_record(
            {"is_true_positive": True, "confidence": 0.97}, operator_disposition="false_positive")
        assert rec["correct"] is False
        assert rec["brier"] == pytest.approx((0.97 - 0.0) ** 2)


# ----------------------- P1: immunity-memory TTL ---------------------------
class TestMemoryTTL:
    def test_fresh_eligible_fp_is_actionable(self):
        now = 1_000_000.0
        p = {"is_true_positive": False, "immunity_eligible": True, "created_at": now - 10}
        assert controls.memory_is_actionable(p, now, ttl_seconds=3600) is True

    def test_expired_fp_is_not_actionable(self):
        now = 1_000_000.0
        p = {"is_true_positive": False, "immunity_eligible": True, "created_at": now - 7200}
        assert controls.memory_is_actionable(p, now, ttl_seconds=3600) is False, \
            "an FP older than the TTL must not auto-dismiss future alerts"

    def test_true_positive_never_grants_immunity(self):
        now = 1_000_000.0
        p = {"is_true_positive": True, "immunity_eligible": True, "created_at": now}
        assert controls.memory_is_actionable(p, now, ttl_seconds=3600) is False

    def test_ineligible_fp_never_grants_immunity(self):
        now = 1_000_000.0
        p = {"is_true_positive": False, "immunity_eligible": False, "created_at": now}
        assert controls.memory_is_actionable(p, now, ttl_seconds=3600) is False

    def test_legacy_point_without_timestamp_preserves_prior_behavior(self):
        # backward-compat: pre-TTL points have no created_at -> still actionable
        now = 1_000_000.0
        p = {"is_true_positive": False, "immunity_eligible": True}
        assert controls.memory_is_actionable(p, now, ttl_seconds=3600) is True


# ----------------------- P5: AI provenance disclosure ----------------------
class TestProvenanceDisclosure:
    def test_banner_prepended_once(self):
        out = controls.stamp_ai_provenance("## Incident Report\nbody")
        assert out.startswith(controls.AI_PROVENANCE_BANNER)
        assert "## Incident Report" in out

    def test_idempotent_no_double_stamp(self):
        once = controls.stamp_ai_provenance("body")
        twice = controls.stamp_ai_provenance(once)
        assert twice.count(controls.AI_PROVENANCE_BANNER) == 1


# ----------------------- P2: frontier model version pinning ----------------
class TestFrontierPinning:
    def test_floating_alias_detected(self):
        assert controls.is_floating_model("claude-3-5-sonnet-latest") is True
        assert controls.is_floating_model("") is True
        assert controls.is_floating_model("gpt-4o") is False
        assert controls.is_floating_model("claude-opus-4-8") is False

    def test_unpinned_frontier_providers_are_reported(self):
        llm_cfg = {
            "anthropic_primary": {"api_type": "anthropic", "model": "claude-3-5-sonnet-latest"},
            "azure_corp": {"api_type": "openai", "model": "gpt-4o"},
            "internal_sovereign": {"api_type": "rest_openai_compatible", "model": "latest"},
        }
        unpinned = controls.unpinned_frontier_models(llm_cfg)
        assert "anthropic_primary" in unpinned, "floating frontier alias must be flagged"
        assert "azure_corp" not in unpinned, "a pinned frontier model is fine"
        assert "internal_sovereign" not in unpinned, "internal sovereign providers are out of scope"

    def test_all_pinned_is_empty(self):
        llm_cfg = {"anthropic_primary": {"api_type": "anthropic", "model": "claude-opus-4-8"}}
        assert controls.unpinned_frontier_models(llm_cfg) == []


# ----------- P1: disaggregated fairness / disparity over verdict history ----
class TestFairnessReport:
    def _recs(self, source, n, contained):
        """n records for `source`, `contained` of them resulting in containment."""
        out = []
        for i in range(n):
            out.append({"source_type": source,
                        "is_true_positive": i < contained,
                        "action": "contain" if i < contained else "monitor"})
        return out

    def test_balanced_subgroups_raise_no_flag(self):
        recs = self._recs("linux_sentinel", 10, 5) + self._recs("windows_c2", 10, 5)
        rep = controls.fairness_report(recs, dimension="source_type",
                                       min_support=5, max_disparity=0.2)
        assert rep["baseline_contain_rate"] == pytest.approx(0.5)
        assert rep["flagged"] == [], "evenly-distributed containment must not flag"

    def test_disparate_subgroup_is_flagged(self):
        # windows_c2 contains 90% vs linux_sentinel 10% -> both deviate >0.2 from 0.5
        recs = self._recs("linux_sentinel", 10, 1) + self._recs("windows_c2", 10, 9)
        rep = controls.fairness_report(recs, dimension="source_type",
                                       min_support=5, max_disparity=0.2)
        assert "windows_c2" in rep["flagged"]
        assert "linux_sentinel" in rep["flagged"]
        assert rep["groups"]["windows_c2"]["contain_rate"] == pytest.approx(0.9)

    def test_subgroup_below_min_support_is_not_flagged(self):
        # the 2-sample group is extreme (100%) but lacks the support to flag
        recs = self._recs("linux_sentinel", 10, 5) + self._recs("aws_guardduty", 2, 2)
        rep = controls.fairness_report(recs, dimension="source_type",
                                       min_support=5, max_disparity=0.2)
        assert "aws_guardduty" not in rep["flagged"]
        assert rep["groups"]["aws_guardduty"]["n"] == 2

    def test_empty_history_is_safe(self):
        rep = controls.fairness_report([], dimension="source_type")
        assert rep["total"] == 0 and rep["flagged"] == [] and rep["groups"] == {}


# ----------- P1: immunity-memory homogenization / model-collapse monitor ----
class TestMemoryHomogenization:
    def test_uniform_distribution_is_healthy(self):
        sigs = {"sigA": 4, "sigB": 4, "sigC": 4, "sigD": 4, "sigE": 4}
        h = controls.memory_homogenization(sigs)
        assert h["homogenized"] is False
        assert h["top_share"] == pytest.approx(0.2)
        assert h["normalized_entropy"] > 0.9

    def test_single_dominant_signature_is_flagged(self):
        sigs = {"sigA": 90, "sigB": 5, "sigC": 5}
        h = controls.memory_homogenization(sigs)
        assert h["homogenized"] is True, "an over-concentrated memory is a collapse risk"
        assert h["top_share"] == pytest.approx(0.9)

    def test_accepts_a_list_of_signatures(self):
        h = controls.memory_homogenization(["s1", "s1", "s1", "s2"])
        assert h["total"] == 4 and h["distinct"] == 2
        assert h["top_share"] == pytest.approx(0.75)

    def test_empty_memory_is_not_homogenized(self):
        h = controls.memory_homogenization([])
        assert h["homogenized"] is False and h["total"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# Wave 4 — remaining code-implementable AI 600-1 gaps
#   NC-7  Automation-bias / over-reliance measurement (2.7 / MG-1.3-002, MP-3.4-005)
#   NC-8  Active-learning failure capture            (2.2 / MG-4.1-004)
#   NC-9  Tamper-evident verdict lineage             (2.8 Information Integrity)
#   NC-10 Per-run inference energy accounting        (2.5 / MS-2.12-003)
# ═══════════════════════════════════════════════════════════════════════════

# ----------- NC-7: automation-bias / over-reliance --------------------------
class TestOverReliance:
    def _rec(self, ai_tp, conf, action, truth):
        return controls.reliance_record(
            {"is_true_positive": ai_tp, "confidence": conf}, action, truth)

    def test_record_marks_accept_vs_override_and_ai_correctness(self):
        r = self._rec(True, 0.9, "accept", "true_positive")
        assert r["accepted"] is True and r["ai_tp"] is True
        assert r["ground_truth_tp"] is True and r["ai_correct"] is True
        o = self._rec(True, 0.9, "override", "false_positive")
        assert o["accepted"] is False and o["ai_correct"] is False

    def test_override_without_ground_truth_has_no_correctness(self):
        r = self._rec(False, 0.3, "override", None)
        assert r["accepted"] is False
        assert "ai_correct" not in r and "ground_truth_tp" not in r

    def test_automation_bias_flagged_when_humans_rubber_stamp_wrong_calls(self):
        # AI wrong 6 times; operator accepted 5 of them -> high automation bias
        recs = [self._rec(True, 0.95, "accept", "false_positive") for _ in range(5)]
        recs += [self._rec(True, 0.95, "override", "false_positive")]      # caught 1
        recs += [self._rec(True, 0.9, "accept", "true_positive") for _ in range(4)]  # correct accepts
        rep = controls.over_reliance_report(recs, min_support=3)
        assert rep["n_ai_wrong"] == 6
        assert rep["automation_bias"] == pytest.approx(5 / 6, abs=1e-3)
        assert rep["caught_rate"] == pytest.approx(1 / 6, abs=1e-3)
        assert rep["flagged"] is True
        assert any("automation" in r for r in rep["reasons"])

    def test_healthy_oversight_is_not_flagged(self):
        # operator catches most AI errors
        recs = [self._rec(True, 0.9, "override", "false_positive") for _ in range(5)]
        recs += [self._rec(True, 0.9, "accept", "true_positive") for _ in range(5)]
        rep = controls.over_reliance_report(recs, min_support=3)
        assert rep["automation_bias"] == pytest.approx(0.0, abs=1e-6)
        assert rep["flagged"] is False

    def test_acceptance_rises_with_confidence_band(self):
        recs = [self._rec(True, 0.95, "accept", "true_positive") for _ in range(4)]
        recs += [self._rec(True, 0.2, "override", "false_positive") for _ in range(4)]
        rep = controls.over_reliance_report(recs)
        assert rep["accept_rate_high_conf"] == pytest.approx(1.0)
        assert rep["accept_rate_low_conf"] == pytest.approx(0.0)

    def test_empty_is_safe(self):
        rep = controls.over_reliance_report([])
        assert rep["n"] == 0 and rep["flagged"] is False
        assert rep["automation_bias"] is None


# ----------- NC-8: active-learning failure capture --------------------------
class TestActiveLearningFailure:
    def test_misclassification_is_a_failure(self):
        v = {"is_true_positive": True, "confidence": 0.9}
        assert controls.is_model_failure(v, "false_positive") is True
        rec = controls.failure_record(v, "false_positive", event_id="e1",
                                      artifacts=["203.0.113.7"])
        assert rec["reason"] == "misclassification"
        assert rec["predicted_tp"] is True and rec["realized_tp"] is False
        assert rec["artifacts"] == ["203.0.113.7"]

    def test_grounding_violation_is_a_failure_even_if_class_matches(self):
        v = {"is_true_positive": True, "confidence": 0.9}
        assert controls.is_model_failure(v, "true_positive", grounding_violation=True) is True
        rec = controls.failure_record(v, "true_positive", grounding_violation=True)
        assert rec["reason"] == "ungrounded_evidence"

    def test_correct_grounded_verdict_is_not_captured(self):
        v = {"is_true_positive": True, "confidence": 0.9}
        assert controls.is_model_failure(v, "true_positive") is False
        assert controls.failure_record(v, "true_positive") is None

    def test_no_ground_truth_and_no_grounding_issue_is_not_a_failure(self):
        assert controls.is_model_failure({"is_true_positive": True}, None) is False


# ----------- NC-9: tamper-evident verdict lineage ---------------------------
class TestVerdictLineage:
    def test_chain_links_and_verifies(self):
        e1 = controls.lineage_entry(None, {"event_id": "a", "verdict": "tp"})
        e2 = controls.lineage_entry(e1["entry_hash"], {"event_id": "b", "verdict": "fp"})
        assert e1["prev_hash"] == controls.GENESIS_HASH
        assert e2["prev_hash"] == e1["entry_hash"]
        res = controls.verify_lineage([e1, e2])
        assert res["valid"] is True and res["broken_at"] is None

    def test_tampered_record_breaks_the_chain(self):
        e1 = controls.lineage_entry(None, {"event_id": "a", "verdict": "tp"})
        e2 = controls.lineage_entry(e1["entry_hash"], {"event_id": "b", "verdict": "fp"})
        e2_tampered = dict(e2, record={"event_id": "b", "verdict": "tp"})  # flip verdict
        res = controls.verify_lineage([e1, e2_tampered])
        assert res["valid"] is False and res["broken_at"] == 1

    def test_reordered_entries_break_the_chain(self):
        e1 = controls.lineage_entry(None, {"i": 1})
        e2 = controls.lineage_entry(e1["entry_hash"], {"i": 2})
        res = controls.verify_lineage([e2, e1])
        assert res["valid"] is False and res["broken_at"] == 0

    def test_canonicalization_is_key_order_independent(self):
        a = controls.lineage_entry(None, {"x": 1, "y": 2})
        b = controls.lineage_entry(None, {"y": 2, "x": 1})
        assert a["entry_hash"] == b["entry_hash"]

    def test_empty_chain_is_valid(self):
        assert controls.verify_lineage([])["valid"] is True


# ----------- NC-10: per-run inference energy accounting ----------------------
class TestInferenceEnergy:
    def test_energy_and_carbon_math(self):
        # 300 W for 1 h at PUE 1.5 -> 450 Wh; at 400 gCO2/kWh -> 180 g
        r = controls.estimate_inference_energy(3600, 300, pue=1.5, grid_gco2_per_kwh=400.0)
        assert r["energy_wh"] == pytest.approx(450.0, abs=1e-6)
        assert r["co2e_g"] == pytest.approx(180.0, abs=1e-6)

    def test_zero_and_negative_inputs_are_clamped(self):
        r = controls.estimate_inference_energy(-5, -10)
        assert r["energy_wh"] == 0.0 and r["co2e_g"] == 0.0

    def test_pue_scales_overhead(self):
        base = controls.estimate_inference_energy(3600, 100, pue=1.0)["energy_wh"]
        pue2 = controls.estimate_inference_energy(3600, 100, pue=2.0)["energy_wh"]
        assert pue2 == pytest.approx(2 * base)
