"""
Lab 10 -- Governance manifest integrity + doc-sync guard.

This is the mechanism that keeps the governance documentation up to date as the
code changes:

  * the manifest (`docs/governance/controls_manifest.yaml`) is the single source of
    truth for every control + its OWASP / ATLAS / NIST-AI / 800-53 / CSF mappings;
  * every `implementation` and `tests` path it references MUST exist (so a control
    can't claim code/tests that were deleted);
  * the generated `controls_catalog.md` MUST match a fresh render of the manifest
    (so editing a control without regenerating fails CI).

A drift here means: update the manifest, run `docs/governance/gen_governance.py`,
and commit.
"""
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

PE = Path(__file__).parent.parent.parent          # project_empros/
GOV = PE / "docs/governance"
if not (GOV / "controls_manifest.yaml").exists():
    pytest.skip("governance manifest not present in this image", allow_module_level=True)
sys.path.insert(0, str(GOV))
import gen_governance as gg  # noqa: E402

MANIFEST = gg.load_manifest()
CONTROLS = MANIFEST["controls"]

_VALID_STATUS = {"implemented", "partial", "documented", "planned"}
_VALID_CSF = {"GV", "ID", "PR", "DE", "RS", "RC"}
_REQUIRED = {"id", "title", "category", "status", "implementation", "frameworks"}


class TestManifestSchema:
    def test_required_fields_present(self):
        for c in CONTROLS:
            missing = _REQUIRED - set(c)
            assert not missing, f"control {c.get('id', '?')} missing fields {missing}"

    def test_status_values_valid(self):
        bad = [(c["id"], c["status"]) for c in CONTROLS if c["status"] not in _VALID_STATUS]
        assert not bad, f"invalid status values: {bad}"

    def test_ids_unique(self):
        ids = [c["id"] for c in CONTROLS]
        dupes = {i for i in ids if ids.count(i) > 1}
        assert not dupes, f"duplicate control ids: {dupes}"

    def test_every_control_maps_to_a_framework(self):
        for c in CONTROLS:
            fw = c.get("frameworks", {}) or {}
            assert any(fw.get(k) for k in
                       ("owasp_llm", "atlas", "nist_ai_600_1", "sp_800_53", "csf_2_0")), \
                f"{c['id']} maps to no framework"

    def test_csf_values_valid(self):
        for c in CONTROLS:
            for f in (c.get("frameworks", {}) or {}).get("csf_2_0", []) or []:
                assert f in _VALID_CSF, f"{c['id']} has invalid CSF function '{f}'"


class TestReferencedPathsExist:
    """The manifest cannot claim implementation/tests that don't exist."""

    def test_implementation_paths_exist(self):
        missing = []
        for c in CONTROLS:
            impls = c["implementation"]
            for p in ([impls] if isinstance(impls, str) else impls):
                if not (PE / p).exists():
                    missing.append((c["id"], p))
        assert not missing, f"manifest references missing implementation files: {missing}"

    def test_test_paths_exist(self):
        missing = []
        for c in CONTROLS:
            for t in (c.get("tests", []) or []):
                f = t.split("::")[0]               # strip ::Class::method
                if not (PE / f).exists():
                    missing.append((c["id"], f))
        assert not missing, f"manifest references missing test files: {missing}"

    def test_implemented_controls_have_tests(self):
        # an 'implemented' control should be backed by a proving test
        untested = [c["id"] for c in CONTROLS
                    if c["status"] == "implemented" and not (c.get("tests") or [])]
        assert not untested, f"implemented controls with no proving test: {untested}"


OSCAL = gg.load_oscal()
REF = gg.load_reference()


class TestCatalogInSync:
    def test_generated_docs_match_sources(self):
        oscal, ref = OSCAL, REF
        cat = gg.render_catalog(MANIFEST, oscal)
        mat = gg.render_matrix(MANIFEST, oscal, ref)
        for name, expected in [("controls_catalog.md", cat), ("applicability_matrix.md", mat)]:
            f = GOV / name
            assert f.exists(), f"{name} not generated -- run gen_governance.py"
            assert f.read_text() == expected, (
                f"{name} is STALE -- a control/reference changed without regenerating. "
                f"Run `docs/governance/gen_governance.py` and commit.")

    def test_all_five_frameworks_cross_referenced(self):
        out = gg.render_catalog(MANIFEST, OSCAL)
        for section in ("OWASP Top 10 for LLM", "MITRE ATLAS",
                        "NIST AI 600-1 (GenAI Profile)", "NIST CSF 2.0 Function",
                        "NIST SP 800-53 Rev. 5"):
            assert f"### {section}" in out, f"missing cross-reference section: {section}"


class TestOscalAlignment:
    """SP 800-53 references must be real NIST OSCAL rev5 controls."""

    def test_oscal_cache_present(self):
        assert OSCAL.get("controls"), "OSCAL rev5 title cache missing/empty"

    def test_every_sp80053_ref_is_a_real_control(self):
        oscal = OSCAL["controls"]
        bad = []
        for c in CONTROLS:
            for ctl in (c.get("frameworks", {}) or {}).get("sp_800_53", []) or []:
                if ctl not in oscal:
                    bad.append((c["id"], ctl))
        assert not bad, f"manifest references SP 800-53 controls absent from OSCAL rev5: {bad}"


class TestApplicabilityMatrix:
    def test_reference_items_have_required_fields(self):
        for fw in ("owasp_llm", "atlas"):
            for it in REF[fw]["items"]:
                assert "id" in it and "name" in it, f"{fw} item missing id/name: {it}"
                if it.get("applicable", True) is False:
                    assert it.get("reason"), f"{it['id']} N-A needs a reason"

    def test_covered_items_actually_have_a_control(self):
        # if the reference marks coverage by id, the manifest must contain it
        for fw in ("owasp_llm", "atlas"):
            for it in REF[fw]["items"]:
                if not it.get("applicable", True):
                    continue
                covering = gg._covering_controls(CONTROLS, fw, it["id"])
                if not covering:                       # it's a gap -> must give remediation
                    assert it.get("remediation"), \
                        f"{fw} {it['id']} is an applicable GAP but has no remediation guidance"

    def test_matrix_surfaces_gaps_with_remediation(self):
        mat = gg.render_matrix(MANIFEST, OSCAL, REF)
        assert "## Outstanding Gaps (addressable)" in mat
        # the known residual (inference-endpoint abuse) must be surfaced
        assert "LLM10" in mat and "AML.T0024" in mat
        assert "**GAP**" in mat
