"""
GRC continuous-assessment — Phase H5: posture ledger + trend + SARIF (GA-11).

The ledger is the append-only record that turns a point-in-time gate into
*continuous monitoring* (mirrors the NC-2 calibration Brier-trend pattern): each
scheduled re-assessment appends a posture snapshot, and `--trend` reports the
delta and flags a regression. `--sarif` exports the open findings for a
code-scanning UI.
"""
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("yaml")

PE = Path(__file__).resolve().parent.parent.parent
GOV = PE / "docs/governance"
if not (GOV / "controls_manifest.yaml").exists():
    pytest.skip("governance layer not present in this image", allow_module_level=True)
sys.path.insert(0, str(GOV))
import grc_lib as L          # noqa: E402
import grc_assess as A       # noqa: E402


def _snap_line(ts, owasp, findings=()):
    return json.dumps({
        "timestamp": ts,
        "posture": {fw: (owasp if fw == "owasp_llm" else 100.0) for fw in A.FRAMEWORKS},
        "counts": {A.SATISFIED: 1, A.FAILED: 0, A.NOT_RUN: 0, A.DOCUMENTATION: 0},
        "findings": list(findings), "incomplete": [],
    })


class TestLedger:
    def test_append_then_read_roundtrips(self, tmp_path):
        led = tmp_path / "posture_ledger.jsonl"
        a = [{"id": "C1", "assessed": A.SATISFIED, "finding": False, "incomplete": False}]
        post = {fw: {"pct": 100.0} for fw in A.FRAMEWORKS}
        A.append_ledger(a, post, "2026-01-01T00:00:00+00:00", path=led)
        rows = A.read_ledger(led)
        assert len(rows) == 1 and rows[0]["timestamp"] == "2026-01-01T00:00:00+00:00"

    def test_append_is_idempotent_on_unchanged_run(self, tmp_path):
        led = tmp_path / "posture_ledger.jsonl"
        a = [{"id": "C1", "assessed": A.SATISFIED, "finding": False, "incomplete": False}]
        post = {fw: {"pct": 100.0} for fw in A.FRAMEWORKS}
        A.append_ledger(a, post, "2026-01-01T00:00:00+00:00", path=led)
        A.append_ledger(a, post, "2026-01-01T00:00:00+00:00", path=led)   # same snapshot
        assert len(A.read_ledger(led)) == 1


class TestTrend:
    def test_regression_delta_and_flag(self, tmp_path):
        led = tmp_path / "l.jsonl"
        led.write_text(_snap_line("2026-01-01T00:00:00+00:00", 90.0) + "\n"
                       + _snap_line("2026-01-02T00:00:00+00:00", 80.0,
                                    findings=["SEC-X"]) + "\n")
        tr = A.compute_trend(A.read_ledger(led))
        assert tr["available"]
        assert tr["deltas"]["owasp_llm"] == pytest.approx(-10.0)
        assert "owasp_llm" in tr["regressed"]
        assert tr["new_findings"] == ["SEC-X"]

    def test_improvement_has_no_regression(self, tmp_path):
        led = tmp_path / "l.jsonl"
        led.write_text(_snap_line("2026-01-01T00:00:00+00:00", 80.0, findings=["SEC-X"]) + "\n"
                       + _snap_line("2026-01-02T00:00:00+00:00", 90.0) + "\n")
        tr = A.compute_trend(A.read_ledger(led))
        assert tr["regressed"] == []
        assert tr["resolved_findings"] == ["SEC-X"]

    def test_single_snapshot_is_not_a_trend(self, tmp_path):
        led = tmp_path / "l.jsonl"
        led.write_text(_snap_line("2026-01-01T00:00:00+00:00", 90.0) + "\n")
        assert A.compute_trend(A.read_ledger(led))["available"] is False


class TestSarif:
    ASSESSMENT = A.assess(L.load_junit())

    def test_sarif_structural_validity(self):
        s = A.build_sarif(self.ASSESSMENT)
        assert s["version"] == "2.1.0"
        assert s["$schema"].endswith("sarif-2.1.0.json")
        run = s["runs"][0]
        assert run["tool"]["driver"]["name"] == "grc_assess"
        assert run["tool"]["driver"]["rules"], "expected ≥1 rule"

    def test_one_result_per_finding_with_required_fields(self):
        s = A.build_sarif(self.ASSESSMENT)
        n_findings = sum(1 for a in self.ASSESSMENT if a["finding"])
        results = s["runs"][0]["results"]
        assert len(results) == n_findings
        rule_ids = {r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]}
        for r in results:
            assert r["ruleId"] in rule_ids
            assert r["level"] in ("error", "warning")
            assert r["message"]["text"]
            assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    def test_failed_is_error_incomplete_is_warning(self):
        s = A.build_sarif(self.ASSESSMENT)
        by_rule = {}
        for r in s["runs"][0]["results"]:
            by_rule.setdefault(r["ruleId"], set()).add(r["level"])
        # incomplete findings (e.g. SEC-ENDPOINT-ID) are warnings
        if "grc/incomplete" in by_rule:
            assert by_rule["grc/incomplete"] == {"warning"}
        if "grc/failed" in by_rule:
            assert by_rule["grc/failed"] == {"error"}
