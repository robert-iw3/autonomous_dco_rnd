"""
GRC continuous-assessment — Phase H4: assessment completeness (GA-9) + the
evidence-anchor authoring assist (GA-10).

The completeness rule is the teeth of design decision #8: an `implemented` code
control must present its evidence as an **execution chain** — reaching in
(Invocation/Boot/Node) and acting out (Execution/Persistence) — not a lone logic
snippet. A chain that is all Logic is the defined-but-unwired failure mode and is
flagged `logic-only`.

Real-half note: running this against the live manifest surfaced two genuine,
tracked evidence gaps (see `KNOWN_INCOMPLETE`). Most notably `SEC-ENDPOINT-ID`:
its `endpoint_id` regex lives on `DynamicUebaVector` in `lib_siem_core`, but that
struct is never constructed and `.validate()` is never called anywhere in the
Rust tree — the validation is *declared but not wired*. The source-contract test
proves the declaration exists (so the control is `Satisfied`); the completeness
rule proves the chain is not wired (so it is also `Incomplete`). That pair is the
whole point of the two-layer design, and the gap is left surfaced for the owner
rather than papered over.
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

# Genuine, tracked evidence-chain gaps in the live manifest. This is the
# "names exactly which controls to finish" ledger the plan calls for: a NEW
# logic-only control fails the real-half below, while these two known gaps are
# consciously tracked until their runtime wiring / evidence is authored.
#   SEC-ENDPOINT-ID      — endpoint_id validator (DynamicUebaVector) is declared
#                          but never invoked in the Rust ingestion path.
#   SEC-TRAINING-HYGIENE — evidence is a lone Vault-credential snippet; the
#                          payload-scrub → corpus-persist chain is not yet wired.
KNOWN_INCOMPLETE = {"SEC-ENDPOINT-ID", "SEC-TRAINING-HYGIENE"}


# --------------------------------------------------------------------------- #
# Synthetic fixtures
# --------------------------------------------------------------------------- #
def _ctl(cid, status="implemented", impl="analytics/x.py",
         tests=("tests/lab_fx/test_x.py::TestX",), fw=("owasp_llm",)):
    return {"id": cid, "title": cid, "category": "Fx", "status": status,
            "implementation": impl, "tests": list(tests),
            "frameworks": {k: ["X1"] for k in fw}}


class TestCompletenessRule:
    def test_full_chain_is_complete(self):
        ctl = _ctl("C-FULL")
        em = {"C-FULL": [{"step": "Invocation"}, {"step": "Logic"}, {"step": "Execution"}]}
        assert A.completeness(ctl, em) == []

    def test_logic_only_is_flagged(self):
        ctl = _ctl("C-LOGIC")
        em = {"C-LOGIC": [{"step": "Logic"}, {"step": "Logic"}]}
        issues = A.completeness(ctl, em)
        assert any("logic-only" in i for i in issues)

    def test_execution_only_is_complete(self):
        # a chain with an Execution endpoint is wired enough (acts out)
        ctl = _ctl("C-EXE")
        em = {"C-EXE": [{"step": "Logic"}, {"step": "Execution"}]}
        assert A.completeness(ctl, em) == []

    def test_invocation_only_is_complete(self):
        ctl = _ctl("C-INV")
        em = {"C-INV": [{"step": "Boot"}, {"step": "Logic"}]}
        assert A.completeness(ctl, em) == []

    def test_no_evidence_is_flagged(self):
        assert "no code-evidence chain" in A.completeness(_ctl("C-NONE"), {})

    def test_missing_tests_and_framework_flagged(self):
        ctl = _ctl("C-BARE", tests=(), fw=())
        em = {"C-BARE": [{"step": "Invocation"}, {"step": "Execution"}]}
        issues = A.completeness(ctl, em)
        assert "no bound test" in issues and "no framework mapping" in issues

    def test_documentation_control_is_exempt(self):
        ctl = _ctl("C-DOC", status="documented", impl="docs/p.md", tests=())
        assert A.completeness(ctl, {}) == []

    def test_test_implemented_control_is_exempt(self):
        # a control whose implementation *is* a test file (Proof) needs no chain
        ctl = _ctl("C-PROOF", impl="tests/lab_x/test_e2e.py")
        assert A.completeness(ctl, {}) == []

    def test_proof_only_chain_is_exempt(self):
        ctl = _ctl("C-PROOFCHAIN")
        em = {"C-PROOFCHAIN": [{"step": "Proof"}, {"step": "Proof"}]}
        assert A.completeness(ctl, em) == []


class TestGateOnIncomplete:
    def test_incomplete_blocks_only_under_strict(self):
        ctl = _ctl("C-LOGIC")
        a = A.assess({}, controls=[ctl], evidence_map={"C-LOGIC": [{"step": "Logic"}]})
        post = A.posture(a, controls=[ctl], reference={"owasp_llm": {"items": []},
                                                       "atlas": {"items": []}})
        ok_default, _ = A.gate(a, post, baseline=None, strict=False)
        ok_strict, reasons = A.gate(a, post, baseline=None, strict=True)
        # C-LOGIC is Not-Run here (no junit) AND incomplete; both surface under strict
        assert not ok_strict
        assert any("INCOMPLETE" in r and "C-LOGIC" in r for r in reasons)


class TestSuggestAnchors:
    def test_suggests_real_symbols_for_logic_only_control(self):
        sug = A.suggest_anchors("SEC-ENDPOINT-ID")
        names = {s["anchor"] for s in sug}
        assert "RE_ENDPOINT" in names               # the validator symbol
        assert all("step" in s and "file" in s for s in sug)

    def test_unknown_control_yields_nothing(self):
        assert A.suggest_anchors("NOPE-404") == []


class TestRealManifestCompleteness:
    ASSESSMENT = A.assess(L.load_junit())

    def test_incomplete_set_is_the_tracked_ledger(self):
        incomplete = {a["id"] for a in self.ASSESSMENT
                      if a["intent"] == "implemented" and a["incomplete"]}
        new = incomplete - KNOWN_INCOMPLETE
        assert not new, (
            f"NEW logic-only / incomplete controls (author the execution chain, "
            f"or run grc_assess.py --suggest-anchors <id>): {sorted(new)}")

    def test_tracked_gaps_are_logic_only(self):
        by_id = {a["id"]: a for a in self.ASSESSMENT}
        for cid in KNOWN_INCOMPLETE:
            issues = by_id[cid]["completeness_issues"]
            assert any("logic-only" in i for i in issues), (cid, issues)

    def test_remediated_control_is_now_complete(self):
        # SIEM-CONFIG-CONTRACT was logic-only; an Invocation step was added
        siem = next(a for a in self.ASSESSMENT if a["id"] == "SIEM-CONFIG-CONTRACT")
        assert not siem["incomplete"], siem["completeness_issues"]
