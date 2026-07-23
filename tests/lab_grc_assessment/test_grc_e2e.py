"""
GRC continuous-assessment — mock end-to-end lab (plan §6).

This is the lab the **grc pipeline section** runs. It has two halves:

* **Synthetic** (hermetic, deterministic): a hand-built fixture manifest + JUnit
  drives the full pipeline — classification, exact posture math, the regression
  gate, the OSCAL Assessment Results shape, and the report render. It must catch
  a *real* binding/posture defect, not merely pass.

* **Real** (earns its keep): runs the engine against the **real** controls
  manifest and the latest `tests/reports/*.xml` (the other sections' output,
  mounted at `$GRC_REPORTS` in the container). It asserts every control's
  binding resolves without a *broken* (stale) ref, and that the committed
  posture baseline still holds — i.e. this is the build-blocking gate expressed
  as a test. `grc.xml` is this lab's JUnit report.
"""
import os
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


# =========================================================================== #
# Synthetic half
# =========================================================================== #
SYNTH_CONTROLS = [
    {"id": "S-OK", "title": "proven", "category": "Fx", "status": "implemented",
     "implementation": "a/x.py", "tests": ["tests/lab_fx/test_ok.py::TestOk"],
     "frameworks": {"owasp_llm": ["LLMX1"], "sp_800_53": ["AC-1"]}},
    {"id": "S-BAD", "title": "regressed", "category": "Fx", "status": "implemented",
     "implementation": "a/y.py", "tests": ["tests/lab_fx/test_bad.py::TestBad"],
     "frameworks": {"owasp_llm": ["LLMX2"], "sp_800_53": ["AC-2"]}},
    {"id": "S-MISS", "title": "not run", "category": "Fx", "status": "implemented",
     "implementation": "a/z.py", "tests": ["tests/lab_fx/test_gone.py::TestGone"],
     "frameworks": {"owasp_llm": ["LLMX3"]}},
    {"id": "S-DOC", "title": "policy", "category": "Fx", "status": "documented",
     "implementation": "docs/p.md", "tests": [], "frameworks": {"sp_800_53": ["PL-1"]}},
]
SYNTH_REF = {"owasp_llm": {"items": [{"id": f"LLMX{i}", "applicable": True}
                                     for i in (1, 2, 3)]},
             "atlas": {"items": []}}


@pytest.fixture()
def synth(tmp_path):
    suite = ET.Element("testsuite", name="fx")
    ET.SubElement(suite, "testcase", classname="lab_fx.test_ok.TestOk", name="t")
    bad = ET.SubElement(suite, "testcase", classname="lab_fx.test_bad.TestBad", name="t")
    ET.SubElement(bad, "failure", message="x")
    ET.ElementTree(suite).write(tmp_path / "fx.xml", encoding="unicode")
    junit = L.load_junit(tmp_path, tests_dir=None)
    # full evidence chain for the code fixtures so completeness (H4) doesn't add
    # findings — the synthetic half isolates classification / posture / gate.
    em = {c["id"]: [{"step": "Invocation"}, {"step": "Execution"}]
          for c in SYNTH_CONTROLS if c["status"] == "implemented"}
    return A.assess(junit, controls=SYNTH_CONTROLS, evidence_map=em)


class TestSyntheticPipeline:
    def test_classification_is_exact(self, synth):
        got = {a["id"]: a["assessed"] for a in synth}
        assert got == {"S-OK": A.SATISFIED, "S-BAD": A.FAILED,
                       "S-MISS": A.NOT_RUN, "S-DOC": A.DOCUMENTATION}

    def test_posture_math_is_exact(self, synth):
        post = A.posture(synth, controls=SYNTH_CONTROLS, reference=SYNTH_REF)
        assert post["owasp_llm"] == {"applicable": 3, "covered": 1, "pct": 33.3,
                                     "uncovered": ["LLMX2", "LLMX3"]}

    def test_gate_fails_and_names_the_regression(self, synth):
        post = A.posture(synth, controls=SYNTH_CONTROLS, reference=SYNTH_REF)
        baseline = {"posture": {"owasp_llm": {"pct": 100.0}}}
        ok, reasons = A.gate(synth, post, baseline)
        assert not ok
        assert any("S-BAD" in r for r in reasons)         # contradicted claim named
        assert any("REGRESSED" in r for r in reasons)     # posture drop named

    def test_oscal_ar_shape_and_report_render(self, synth):
        post = A.posture(synth, controls=SYNTH_CONTROLS, reference=SYNTH_REF)
        ar = A.build_oscal_ar(synth, post, "2026-01-01T00:00:00+00:00")
        root = ar["assessment-results"]
        assert root["metadata"]["oscal-version"] == "1.1.2"
        assert len(root["results"][0]["observations"]) == 4
        assert {f["target"]["target-id"] for f in root["results"][0]["findings"]} \
            == {"S-BAD", "S-MISS"}
        md = A.render_report(synth, post, "2026-01-01T00:00:00+00:00")
        assert "Continuous Control Assessment" in md and "S-BAD" in md

    def test_grc_junit_is_wellformed(self, synth):
        post = A.posture(synth, controls=SYNTH_CONTROLS, reference=SYNTH_REF)
        xml = A.build_grc_junit(synth, post, baseline=None,
                                timestamp="2026-01-01T00:00:00+00:00")
        suite = ET.fromstring(xml)                        # parses → well-formed
        assert suite.get("name") == "grc"
        assert int(suite.get("tests")) == len(SYNTH_CONTROLS) + 1  # + posture_gate


# =========================================================================== #
# Real half — against the actual manifest + latest reports
# =========================================================================== #
REPORTS = Path(os.environ.get("GRC_REPORTS", str(L.DEFAULT_REPORTS)))
REAL_JUNIT = L.load_junit(REPORTS)
REAL = A.assess(REAL_JUNIT)


@pytest.mark.skipif(not REAL_JUNIT,
                    reason="no JUnit reports available to assess against")
class TestRealAssessment:
    def test_no_broken_bindings_anywhere(self):
        """Every control's chain-of-custody resolves; no stale class/method ref."""
        broken = [(a["id"], b["ref"]) for a in REAL
                  for b in a["bindings"] if b["state"] == "broken"]
        assert not broken, f"stale bindings (fix the ref or the code): {broken}"

    def test_no_implemented_control_is_actively_contradicted(self):
        """`implemented` + a *failing* bound test = a real regression to fix."""
        failed = [a["id"] for a in REAL
                  if a["assessed"] == A.FAILED and a["intent"] == "implemented"]
        assert not failed, f"implemented controls whose bound tests FAILED: {failed}"

    def test_posture_baseline_holds(self):
        """The committed floor must not have regressed (the build-blocking gate)."""
        post = A.posture(REAL)
        baseline = A.load_baseline()
        assert baseline, "posture_baseline.json must be committed for the gate"
        ok, reasons = A.gate(REAL, post, baseline)
        assert ok, "posture regressed / a claim is contradicted:\n  " + "\n  ".join(reasons)

    def test_artifacts_render_from_real_data(self):
        post = A.posture(REAL)
        ar = A.build_oscal_ar(REAL, post, "2026-01-01T00:00:00+00:00")
        assert ar["assessment-results"]["results"][0]["observations"]
        assert "Per-Control Proven Status" in A.render_report(
            REAL, post, "2026-01-01T00:00:00+00:00")

    def test_documentation_controls_never_counted_not_run(self):
        for a in REAL:
            if a["intent"] == "documented":
                assert a["assessed"] == A.DOCUMENTATION
