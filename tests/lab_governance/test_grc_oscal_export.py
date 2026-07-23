"""
GRC continuous-assessment — Phase H6 (stretch): OSCAL SSP + POA&M export (GA-12).

Emits an OSCAL SSP `implemented-requirements` block and an OSCAL POA&M from the
open findings, cross-referenced to the cached OSCAL rev5 catalog — making the
whole assessment portable to any OSCAL-aware GRC tool. This proves the generated
OSCAL validates structurally and that its control ids round-trip against the
catalog.
"""
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
import gen_governance as gg  # noqa: E402

TS = "2026-01-01T00:00:00+00:00"
ASSESSMENT = A.assess(L.load_junit())
OSCAL_CONTROLS = gg.load_oscal().get("controls", {})


class TestOscalSsp:
    SSP = A.build_oscal_ssp(ASSESSMENT, TS)

    def test_top_level_shape(self):
        ssp = self.SSP["system-security-plan"]
        assert ssp["metadata"]["oscal-version"] == "1.1.2"
        assert ssp["import-profile"]["href"]
        assert ssp["control-implementation"]["implemented-requirements"]

    def test_every_implemented_requirement_wellformed(self):
        for r in self.SSP["system-security-plan"]["control-implementation"]["implemented-requirements"]:
            assert r["uuid"] and r["control-id"]
            assert r["statements"] and r["statements"][0]["uuid"]

    def test_control_ids_round_trip_against_catalog(self):
        """Every implemented-requirement control-id is a real OSCAL rev5 control."""
        assert OSCAL_CONTROLS, "OSCAL rev5 catalog cache must be present"
        bad = []
        for r in self.SSP["system-security-plan"]["control-implementation"]["implemented-requirements"]:
            if r["control-id"].upper() not in OSCAL_CONTROLS:
                bad.append(r["control-id"])
        assert not bad, f"implemented-requirements cite non-catalog controls: {bad}"

    def test_uuids_are_deterministic(self):
        again = A.build_oscal_ssp(ASSESSMENT, TS)
        import json
        assert json.dumps(self.SSP, sort_keys=True) == json.dumps(again, sort_keys=True)

    def test_proven_status_reflects_assessment(self):
        # a requirement satisfied by a Satisfied control is 'implemented'/proven
        reqs = {r["control-id"]: r for r in
                self.SSP["system-security-plan"]["control-implementation"]["implemented-requirements"]}
        # SI-4 is mapped by several controls, at least one Satisfied
        si4 = reqs.get("si-4")
        if si4:
            status = next(p["value"] for p in si4["props"]
                          if p["name"] == "implementation-status")
            assert status == "implemented"


class TestOscalPoam:
    POAM = A.build_oscal_poam(ASSESSMENT, TS)

    def test_top_level_shape(self):
        poam = self.POAM["plan-of-action-and-milestones"]
        assert poam["uuid"] and poam["metadata"]["oscal-version"] == "1.1.2"
        assert poam["import-ssp"]["href"]

    def test_one_item_per_open_finding(self):
        items = self.POAM["plan-of-action-and-milestones"]["poam-items"]
        assert len(items) == sum(1 for a in ASSESSMENT if a["finding"])
        for it in items:
            assert it["uuid"] and it["title"] and it["description"]
            assert it["related-observations"][0]["observation-uuid"]

    def test_poam_control_refs_are_catalog_controls(self):
        for it in self.POAM["plan-of-action-and-milestones"]["poam-items"]:
            val = next(p["value"] for p in it["props"] if p["name"] == "sp800-53-controls")
            for ctl in [c.strip() for c in val.split(",") if c.strip() and c != "—"]:
                assert ctl in OSCAL_CONTROLS, f"POA&M cites non-catalog control {ctl}"

    def test_poam_item_uuid_matches_ar_observation(self):
        # a POA&M item's related observation ties back to the AR observation uuid
        a = next(x for x in ASSESSMENT if x["finding"])
        item = next(it for it in self.POAM["plan-of-action-and-milestones"]["poam-items"]
                    if it["title"].startswith(a["id"]))
        assert item["related-observations"][0]["observation-uuid"] == A._uuid("obs", a["id"])
