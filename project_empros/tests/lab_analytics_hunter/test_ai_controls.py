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
