"""
GRC continuous-assessment — Phase H1/H2: classification, posture, gate
(GA-3/GA-4/GA-5/GA-6).

The synthetic half of the mock E2E (§6 of the plan): a hand-built fixture
manifest — one control with a passing bound test, one with a failing bound test,
one `implemented` whose test result is *missing*, and one documentation control
— plus synthesised JUnit XML matching those bindings. It asserts the classifier
maps each to the right status, posture math is exact, and `--gate` fails on a
regression / contradicted claim and passes when the floor is met.
"""
import sys
import xml.etree.ElementTree as ET
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


# --------------------------------------------------------------------------- #
# fixtures: a synthetic manifest + a matching JUnit reports dir
# --------------------------------------------------------------------------- #
FIX_CONTROLS = [
    {"id": "FIX-PASS", "title": "passing", "category": "Fixture", "status": "implemented",
     "implementation": "analytics/x.py",
     "tests": ["tests/lab_fixture/test_pass.py::TestPass"],
     "frameworks": {"owasp_llm": ["LLMX1"], "sp_800_53": ["AC-1"]}},
    {"id": "FIX-FAIL", "title": "failing", "category": "Fixture", "status": "implemented",
     "implementation": "analytics/y.py",
     "tests": ["tests/lab_fixture/test_fail.py::TestFail"],
     "frameworks": {"owasp_llm": ["LLMX2"], "sp_800_53": ["AC-2"]}},
    {"id": "FIX-MISS", "title": "missing", "category": "Fixture", "status": "implemented",
     "implementation": "analytics/z.py",
     "tests": ["tests/lab_fixture/test_absent.py::TestAbsent"],
     "frameworks": {"owasp_llm": ["LLMX3"], "sp_800_53": ["AC-3"]}},
    {"id": "FIX-DOC", "title": "policy", "category": "Fixture", "status": "documented",
     "implementation": "docs/governance/policy.md", "tests": [],
     "frameworks": {"sp_800_53": ["PL-1"]}},
]

FIX_REFERENCE = {
    "owasp_llm": {"title": "fixture owasp", "items": [
        {"id": "LLMX1", "applicable": True},
        {"id": "LLMX2", "applicable": True},
        {"id": "LLMX3", "applicable": True},
        {"id": "LLMX4", "applicable": False, "reason": "n/a"},
    ]},
    "atlas": {"title": "fixture atlas", "items": []},
}


def _write_junit(tmp):
    """Synthesize the reports: FIX-PASS passes, FIX-FAIL fails, FIX-MISS absent."""
    suite = ET.Element("testsuite", name="fixture", tests="2", failures="1")
    ok = ET.SubElement(suite, "testcase",
                       classname="lab_fixture.test_pass.TestPass", name="test_ok")
    ok.text = ""
    bad = ET.SubElement(suite, "testcase",
                        classname="lab_fixture.test_fail.TestFail", name="test_bad")
    ET.SubElement(bad, "failure", message="boom").text = "AssertionError"
    p = Path(tmp) / "fixture.xml"
    ET.ElementTree(suite).write(p, encoding="unicode")
    return p


@pytest.fixture()
def junit(tmp_path):
    _write_junit(tmp_path)
    # tests_dir=None → the fixture modules aren't on disk; use the case heuristic
    return L.load_junit(tmp_path, tests_dir=None)


# give the code fixtures a full evidence chain so completeness (H4) doesn't add
# findings here — these tests isolate classification / posture / gate.
FIX_EVIDENCE = {c["id"]: [{"step": "Invocation"}, {"step": "Execution"}]
                for c in FIX_CONTROLS if c["status"] == "implemented"}


@pytest.fixture()
def assessment(junit):
    return A.assess(junit, controls=FIX_CONTROLS, evidence_map=FIX_EVIDENCE)


class TestClassification:
    def test_status_map(self, assessment):
        got = {a["id"]: a["assessed"] for a in assessment}
        assert got == {
            "FIX-PASS": A.SATISFIED,
            "FIX-FAIL": A.FAILED,
            "FIX-MISS": A.NOT_RUN,
            "FIX-DOC": A.DOCUMENTATION,
        }

    def test_documentation_never_not_run(self, assessment):
        doc = next(a for a in assessment if a["id"] == "FIX-DOC")
        assert doc["assessed"] == A.DOCUMENTATION
        assert doc["assessed"] != A.NOT_RUN

    def test_findings_flagged_for_implemented_gaps(self, assessment):
        findings = {a["id"] for a in assessment if a["finding"]}
        assert findings == {"FIX-FAIL", "FIX-MISS"}   # not the doc control

    def test_evidence_cases_recorded_for_pass(self, assessment):
        p = next(a for a in assessment if a["id"] == "FIX-PASS")
        assert p["evidence_cases"] == [
            "tests/lab_fixture/test_pass.py::TestPass::test_ok"]


class TestPosture:
    def test_owasp_covered_only_by_satisfied(self, assessment):
        post = A.posture(assessment, controls=FIX_CONTROLS, reference=FIX_REFERENCE)
        # 3 applicable owasp items (LLMX1-3); only FIX-PASS is Satisfied → covers LLMX1
        assert post["owasp_llm"]["applicable"] == 3
        assert post["owasp_llm"]["covered"] == 1
        assert post["owasp_llm"]["pct"] == pytest.approx(33.3, abs=0.1)
        assert post["owasp_llm"]["uncovered"] == ["LLMX2", "LLMX3"]

    def test_sp80053_from_satisfied_controls(self, assessment):
        post = A.posture(assessment, controls=FIX_CONTROLS, reference=FIX_REFERENCE)
        # AC-1..AC-3 + PL-1 claimed; only AC-1 (FIX-PASS) proven
        assert post["sp_800_53"]["covered"] == 1
        assert post["sp_800_53"]["applicable"] == 4


class TestGate:
    def _post(self, assessment):
        return A.posture(assessment, controls=FIX_CONTROLS, reference=FIX_REFERENCE)

    def test_failed_control_fails_gate(self, assessment):
        post = self._post(assessment)
        ok, reasons = A.gate(assessment, post, baseline=None)
        assert not ok
        assert any("FIX-FAIL" in r and "FAILED" in r for r in reasons)

    def test_regression_below_baseline_named(self, assessment):
        post = self._post(assessment)
        baseline = {"posture": {"owasp_llm": {"pct": 90.0}}}
        ok, reasons = A.gate(assessment, post, baseline)
        assert not ok
        assert any("REGRESSED" in r and "OWASP" in r for r in reasons)

    def test_meeting_floor_has_no_regression_reason(self, assessment):
        # remove the failing control so only the posture floor is exercised
        clean = [a for a in assessment if a["id"] != "FIX-FAIL"]
        post = A.posture(clean, controls=FIX_CONTROLS, reference=FIX_REFERENCE)
        baseline = {"posture": {fw: {"pct": post[fw]["pct"]} for fw in A.FRAMEWORKS}}
        ok, reasons = A.gate(clean, post, baseline)
        assert ok, reasons

    def test_strict_flags_not_run_implemented(self, assessment):
        clean = [a for a in assessment if a["id"] != "FIX-FAIL"]   # drop the hard failure
        post = A.posture(clean, controls=FIX_CONTROLS, reference=FIX_REFERENCE)
        ok, reasons = A.gate(clean, post, baseline=None, strict=True)
        assert not ok
        assert any("FIX-MISS" in r and "NOT-RUN" in r for r in reasons)


class TestOscalAr:
    def test_ar_structure(self, assessment):
        post = self._post(assessment) if hasattr(self, "_post") else \
            A.posture(assessment, controls=FIX_CONTROLS, reference=FIX_REFERENCE)
        ar = A.build_oscal_ar(assessment, post, "2026-01-01T00:00:00+00:00")
        root = ar["assessment-results"]
        assert root["metadata"]["oscal-version"] == "1.1.2"
        res = root["results"][0]
        assert len(res["observations"]) == len(FIX_CONTROLS)
        # a finding per implemented gap (FIX-FAIL, FIX-MISS)
        targets = {f["target"]["target-id"] for f in res["findings"]}
        assert targets == {"FIX-FAIL", "FIX-MISS"}

    def test_ar_is_deterministic(self, assessment):
        post = A.posture(assessment, controls=FIX_CONTROLS, reference=FIX_REFERENCE)
        a1 = A.build_oscal_ar(assessment, post, "2026-01-01T00:00:00+00:00")
        a2 = A.build_oscal_ar(assessment, post, "2026-01-01T00:00:00+00:00")
        import json
        assert json.dumps(a1, sort_keys=True) == json.dumps(a2, sort_keys=True)
