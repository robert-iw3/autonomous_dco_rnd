"""
GRC continuous-assessment — Phase H0: control ↔ real-testcase binding (GA-1/GA-2).

Where `test_governance_manifest.py::TestReferencedPathsExist` only proves a
control's `tests:` *files* exist on disk, this proves the **dynamic** contract:
each `tests:` ref can be normalised against, and resolved to, the *real* JUnit
testcase ids the pipeline emits — so a binding cannot silently rot into a
class/method that no longer exists.

Two distinct failure modes are separated (see `grc_lib.binding_report`):

  * **broken**  - the ref's test file ran (its cases are in the reports) but the
                  ref's `::Class::method` qualifier matches none of them. This is
                  a stale binding and is a hard failure here.
  * **not-run** - the ref's whole file is absent from this report set because its
                  pipeline section didn't execute. That is a *coverage* question
                  for the `--gate` (Phase H2), not a binding defect, so it is
                  surfaced but does not fail this suite (which must stay green on
                  a partial / change-detect report set).
"""
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

PE = Path(__file__).resolve().parent.parent.parent
GOV = PE / "docs/governance"
if not (GOV / "controls_manifest.yaml").exists():
    pytest.skip("governance manifest not present in this image", allow_module_level=True)
sys.path.insert(0, str(GOV))
import grc_lib as L  # noqa: E402

CONTROLS = L.controls()
JUNIT = L.load_junit()


class TestJunitNormalization:
    """`classname`/`name` → pytest node-id round-trips (the binding contract)."""

    def test_nested_module_with_class(self):
        node = L.normalize_junit_id(
            "lab_governance.test_ai_controls.TestGroundingEnforcement",
            "test_confirmed_tp_citing_phantom_ip_is_demoted")
        assert node == ("tests/lab_governance/test_ai_controls.py"
                        "::TestGroundingEnforcement"
                        "::test_confirmed_tp_citing_phantom_ip_is_demoted")

    def test_top_level_test_file(self):
        node = L.normalize_junit_id(
            "test_worker_contracts.TestEvidenceIngress", "test_verified_before_archive")
        assert node == ("tests/test_worker_contracts.py"
                        "::TestEvidenceIngress::test_verified_before_archive")

    def test_module_level_function_no_class(self):
        # a real module-level test function (no class) — resolved via the tree
        node = L.normalize_junit_id(
            "lab_det_chamber.test_acquire_agents", "test_linux_agent_hashes_zips_manifests")
        assert node == ("tests/lab_det_chamber/test_acquire_agents.py"
                        "::test_linux_agent_hashes_zips_manifests")

    def test_fallback_case_split_without_tree(self):
        # with no tree to consult, the upper-case segment starts the class
        node = L.normalize_junit_id("pkg.mod.TestThing", "test_x", tests_dir=None)
        assert node == "tests/pkg/mod.py::TestThing::test_x"


class TestFreshnessOrdering:
    """Latest *execution* wins, keyed on the JUnit timestamp — not file mtime.

    Regression guard for a defect the containerised E2E surfaced: when every
    report shares one mtime (a fresh checkout / `cp` / CI artifact restore), an
    mtime tiebreak is non-deterministic and a stale *failing* report could
    override a newer *passing* one. Ordering on the embedded `testsuite`
    timestamp is stable regardless of filesystem mtimes.
    """

    def _write(self, path, ts, result):
        import xml.etree.ElementTree as ET
        suite = ET.Element("testsuite", name="s", timestamp=ts)
        tc = ET.SubElement(suite, "testcase",
                           classname="lab_fx.test_x.TestX", name="test_y")
        if result != "pass":
            ET.SubElement(tc, "failure", message="x")
        ET.ElementTree(suite).write(path, encoding="unicode")

    def test_newer_timestamp_wins_despite_equal_mtime(self, tmp_path):
        import os
        stale, fresh = tmp_path / "a.xml", tmp_path / "b.xml"
        # stale run FAILED later-by-filename but earlier-by-execution;
        # fresh run PASSED and is the most recent execution.
        self._write(stale, "2026-07-03T22:42:00+00:00", "fail")
        self._write(fresh, "2026-07-03T23:23:00+00:00", "pass")
        fixed = 1_700_000_000                       # identical mtime on both
        os.utime(stale, (fixed, fixed))
        os.utime(fresh, (fixed, fixed))
        junit = L.load_junit(tmp_path, tests_dir=None)
        assert junit["tests/lab_fx/test_x.py::TestX::test_y"] == L.PASS


class TestReportsLoaded:
    def test_reports_dir_yielded_testcases(self):
        # the check below is only meaningful if *some* reports were parsed
        assert JUNIT, "no JUnit testcases parsed from tests/reports/*.xml"

    def test_results_are_from_the_vocabulary(self):
        assert set(JUNIT.values()) <= {L.PASS, L.FAIL, L.ERROR, L.SKIP}


class TestManifestBindingResolves:
    """No `implemented` control may carry a *broken* (stale) binding."""

    def test_no_broken_bindings(self):
        broken = []
        for c in CONTROLS:
            for b in L.binding_report(c, JUNIT):
                if b["state"] == "broken":
                    broken.append((c["id"], b["ref"]))
        assert not broken, (
            "manifest tests: refs whose file ran but whose class/method matched no "
            f"collected testcase (stale binding — fix the ref or the code): {broken}")

    def test_resolved_refs_carry_a_result(self):
        for c in CONTROLS:
            for b in L.binding_report(c, JUNIT):
                if b["state"] == "resolved":
                    assert b["result"] in {L.PASS, L.FAIL, L.ERROR, L.SKIP}
                    assert b["cases"], f"{c['id']} resolved ref has no cases"

    def test_tightened_worker_contract_bindings_resolve(self):
        # regression guard for the H0 remediation: these were file-level refs to
        # the whole test_worker_contracts.py (which swept in an unrelated failing
        # meta-test); they are now bound to their specific proving class.
        want = {
            "ING-ZERO-TRUST": "TestEvidenceIngress",
            "SEC-FAILOVER": "TestLLMCircuitBreaker",
            "SEC-ENDPOINT-ID": "TestEndpointIdInjectionDefense",
        }
        by_id = {c["id"]: c for c in CONTROLS}
        for cid, cls in want.items():
            refs = by_id[cid].get("tests", []) or []
            assert any(cls in r for r in refs), f"{cid} not bound to {cls}"
            report = L.binding_report(by_id[cid], JUNIT)
            assert all(b["state"] != "broken" for b in report), \
                f"{cid} binding broke: {report}"
