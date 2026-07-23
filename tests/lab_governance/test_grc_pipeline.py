"""
GRC continuous-assessment — Phase H3: pipeline integration (GA-7/GA-8).

Proves the section entrypoint and the runner wiring without needing Docker:

  * invoking `grc_assess` against a fixture reports dir writes a well-formed
    `grc.xml` and returns the documented exit code (0 = gate holds,
    1 = gate fails);
  * `run_tests.sh` registers the `grc` section, forces it to run **last** (it
    consumes the other sections' JUnit), and its change-detection triggers fire
    for governance / manifest / lab_grc_assessment edits;
  * `Dockerfile.grc` writes `grc.xml` into the mounted reports dir.

The entrypoint's file outputs are redirected to a tmp dir so the suite never
mutates the committed artifacts (host-mutation-free, like the other labs).
"""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

pytest.importorskip("yaml")

PE = Path(__file__).resolve().parent.parent.parent
GOV = PE / "docs/governance"
TESTS = PE / "tests"
if not (GOV / "controls_manifest.yaml").exists():
    pytest.skip("governance layer not present in this image", allow_module_level=True)
sys.path.insert(0, str(GOV))
import grc_assess as A       # noqa: E402


def _fixture_reports(tmp, with_failure=False):
    suite = ET.Element("testsuite", name="fx")
    ok = ET.SubElement(suite, "testcase",
                       classname="lab_governance.test_ai_controls.TestGroundingEnforcement",
                       name="test_tp_with_no_cited_artifacts_passes")
    if with_failure:
        ET.SubElement(ok, "failure", message="synthetic")
    ET.ElementTree(suite).write(tmp / "analytics.xml", encoding="unicode")
    return tmp


@pytest.fixture()
def redirect_outputs(tmp_path, monkeypatch):
    """Point the engine's file writes at a tmp dir (no host mutation)."""
    monkeypatch.setattr(A, "AR_JSON", tmp_path / "assessment_results.json")
    monkeypatch.setattr(A, "REPORT_MD", tmp_path / "assessment_report.md")
    monkeypatch.setattr(A, "BASELINE", tmp_path / "no_baseline.json")  # → gate w/o floor
    return tmp_path


class TestSectionEntrypoint:
    def test_writes_valid_grc_xml_and_exits_zero(self, tmp_path, redirect_outputs):
        reports = _fixture_reports(tmp_path)
        grc_xml = tmp_path / "grc.xml"
        rc = A.main(["--reports", str(reports), "--gate", "--junit", str(grc_xml)])
        assert rc == 0                                   # no baseline, no Failed → gate holds
        assert grc_xml.exists()
        suite = ET.parse(grc_xml).getroot()              # parses → well-formed
        assert suite.get("name") == "grc"
        # one case per control + the posture_gate case
        assert int(suite.get("tests")) >= 2
        assert (redirect_outputs / "assessment_results.json").exists()

    def test_failed_implemented_control_exits_one(self, tmp_path, redirect_outputs):
        reports = _fixture_reports(tmp_path, with_failure=True)
        grc_xml = tmp_path / "grc.xml"
        rc = A.main(["--reports", str(reports), "--gate", "--junit", str(grc_xml)])
        assert rc == 1                                   # AI-GROUNDING bound test failed
        suite = ET.parse(grc_xml).getroot()
        assert int(suite.get("failures")) >= 1

    def test_out_dir_preserves_artifacts(self, tmp_path, redirect_outputs):
        reports = _fixture_reports(tmp_path)
        out = tmp_path / "host_reports"
        A.main(["--reports", str(reports), "--out-dir", str(out)])
        assert (out / "assessment_results.json").exists()
        assert (out / "assessment_report.md").exists()


class TestRunnerWiring:
    RUNNER = (TESTS / "run_tests.sh").read_text()

    def test_grc_section_registered(self):
        assert "grc|Dockerfile.grc|" in self.RUNNER
        assert 'GRC_SECTION="grc"' in self.RUNNER

    def test_grc_forced_last_and_deferred_in_parallel(self):
        assert "_has_grc" in self.RUNNER and "RUN_GRC_AFTER" in self.RUNNER

    def test_dockerfile_grc_present_and_writes_report(self):
        df = (TESTS / "Dockerfile.grc").read_text()
        assert "grc_assess.py" in df
        assert "--junit-xml=/reports/grc.xml" in df

    def test_triggers_map_to_grc(self):
        # extract the TRIGGERS array lines and confirm governance/manifest → grc
        trig_block = self.RUNNER
        # a change under docs/governance/ must queue the grc section
        gov_line = next(l for l in trig_block.splitlines()
                        if "docs/governance/:" in l)
        assert gov_line.rstrip().endswith("grc") or " grc" in gov_line
        assert ":grc\"" in trig_block   # a dedicated grc trigger exists


class TestChangeDetection:
    """Replicate the runner's regex trigger match for representative edits."""

    RUNNER = (TESTS / "run_tests.sh").read_text()

    def _triggers(self):
        # parse the TRIGGERS=( "pattern:sections" ... ) block
        out = []
        for m in re.finditer(r'"([^"]+):([^"]*)"', self.RUNNER):
            pattern, sections = m.group(1), m.group(2)
            if "/" in pattern or "tests/" in pattern or "|" in pattern:
                out.append((pattern, sections.split()))
        return out

    @pytest.mark.parametrize("changed", [
        "docs/governance/controls_manifest.yaml",
        "docs/governance/grc_assess.py",
        "tests/lab_grc_assessment/test_grc_e2e.py",
    ])
    def test_edit_triggers_grc(self, changed):
        triggered = set()
        for pattern, sections in self._triggers():
            try:
                if re.search(pattern, changed):
                    triggered.update(sections)
            except re.error:
                continue
        assert "grc" in triggered, f"{changed} did not trigger the grc section"
