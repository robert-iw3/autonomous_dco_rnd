#!/usr/bin/env python3
"""
GRC continuous-assessment engine — the *dynamic* half of the governance layer.

Where `gen_governance.py` renders what the register **claims** and
`test_governance_manifest.py` proves the register is well-formed, this engine
answers, every pipeline run, what is **proven right now**: it binds each control
to the real JUnit results (`grc_lib`), classifies it, scores framework posture,
and gates the build against a committed baseline.

Per-control assessed status
---------------------------
  * Satisfied     - every bound test ref resolved to a real testcase, none
                    failed, and at least one passed.
  * Failed        - a bound test failed or errored (an `implemented` claim the
                    tests actively contradict).
  * Not-Run       - no result for one or more bound refs in this report set
                    (the proving section didn't run, or a partial/change-detect
                    run). Distinct from Failed.
  * Documentation - a policy control with no code by design; Satisfied when its
                    governance artifact exists (guarded statically).

Outputs
-------
  * assessment_results.json  - OSCAL Assessment Results (canonical, machine)
  * assessment_report.md     - human report (per-control proven status + posture
                               + open findings), rendered *from* the AR
  * posture_baseline.json    - committed posture floor (via --write-baseline)

CLI
---
  grc_assess.py                       # write assessment_results.json + report
  grc_assess.py --reports DIR         # read a specific reports dir (default tests/reports)
  grc_assess.py --gate                # exit 1 on posture regression or any Failed control
  grc_assess.py --gate --strict       # also fail on Not-Run implemented controls (--full runs)
  grc_assess.py --write-baseline      # (re)write posture_baseline.json from the current run
  grc_assess.py --summary             # print the posture + status table, no file writes
"""
import argparse
import datetime as _dt
import json
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import grc_lib as L  # noqa: E402
import gen_governance as gg  # noqa: E402

AR_JSON = HERE / "assessment_results.json"
REPORT_MD = HERE / "assessment_report.md"
BASELINE = HERE / "posture_baseline.json"
SSP_JSON = HERE / "oscal_ssp.json"
POAM_JSON = HERE / "oscal_poam.json"

# assessed-status vocabulary
SATISFIED, FAILED, NOT_RUN, DOCUMENTATION = \
    "Satisfied", "Failed", "Not-Run", "Documentation"

# a stable namespace so every derived uuid is reproducible across runs
_NS = uuid.UUID("6f1b0d2a-9c3e-5a7b-8d21-000000000001")
# framework keys scored for posture
FRAMEWORKS = ["owasp_llm", "atlas", "nist_ai_600_1", "sp_800_53", "csf_2_0"]
_FW_LABEL = {"owasp_llm": "OWASP Top 10 LLM", "atlas": "MITRE ATLAS",
             "nist_ai_600_1": "NIST AI 600-1", "sp_800_53": "NIST SP 800-53",
             "csf_2_0": "NIST CSF 2.0"}


def _uuid(*parts):
    return str(uuid.uuid5(_NS, "|".join(parts)))


def _is_doc_control(control):
    impls = control["implementation"]
    impls = [impls] if isinstance(impls, str) else impls
    return all(str(p).endswith(".md") for p in impls)


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
def classify(control, junit):
    """Return (assessed_status, binding_report) for one control."""
    report = L.binding_report(control, junit)
    if control["status"] == "documented" or (_is_doc_control(control)
                                              and not L._test_refs(control)):
        return DOCUMENTATION, report
    results = [b["result"] for b in report]
    if L.FAIL in results or L.ERROR in results:
        return FAILED, report
    if report and all(b["state"] == "resolved" for b in report) \
            and any(r == L.PASS for r in results):
        return SATISFIED, report
    return NOT_RUN, report


def assess(junit, controls=None, evidence_map=None):
    """Full assessment → list of per-control dicts (source of truth for AR/report)."""
    controls = controls if controls is not None else L.controls()
    evidence_map = evidence_map if evidence_map is not None else gg.load_evidence_map()
    out = []
    for c in sorted(controls, key=lambda c: c["id"]):
        status, report = classify(c, junit)
        cases = sorted({n for b in report for n in b["cases"]})
        issues = completeness(c, evidence_map)
        out.append({
            "id": c["id"], "title": c["title"], "category": c["category"],
            "intent": c["status"], "assessed": status,
            "frameworks": c.get("frameworks", {}) or {},
            "implementation": c["implementation"],
            "bindings": [{"ref": b["ref"], "state": b["state"],
                          "result": b["result"], "cases": b["cases"]} for b in report],
            "evidence_cases": cases,
            "completeness_issues": issues,
            "incomplete": bool(issues),
            # an implemented (code) control whose proof failed / didn't run, or whose
            # evidence chain is incomplete, is a finding
            "finding": (c["status"] == "implemented"
                        and (status in (FAILED, NOT_RUN) or bool(issues))),
        })
    return out


# --------------------------------------------------------------------------- #
# Posture scoring (Phase H2)
# --------------------------------------------------------------------------- #
def _applicable_items(fw, controls, reference):
    """The set of item ids that count toward a framework's posture."""
    if fw in ("owasp_llm", "atlas"):
        return {it["id"] for it in reference[fw]["items"]
                if it.get("applicable", True)}
    # frameworks without an external applicability list: everything the register claims
    items = set()
    for c in controls:
        items.update((c.get("frameworks", {}) or {}).get(fw, []) or [])
    return items


def posture(assessment, controls=None, reference=None):
    """Per-framework coverage = applicable items covered by ≥1 Satisfied control."""
    controls = controls if controls is not None else L.controls()
    reference = reference if reference is not None else gg.load_reference()
    satisfied_ids = {a["id"] for a in assessment if a["assessed"] == SATISFIED}
    out = {}
    for fw in FRAMEWORKS:
        applicable = _applicable_items(fw, controls, reference)
        covered = set()
        for c in controls:
            if c["id"] not in satisfied_ids:
                continue
            for item in (c.get("frameworks", {}) or {}).get(fw, []) or []:
                if item in applicable:
                    covered.add(item)
        n = len(applicable)
        out[fw] = {"applicable": n, "covered": len(covered),
                   "pct": round(100.0 * len(covered) / n, 1) if n else 100.0,
                   "uncovered": sorted(applicable - covered)}
    return out


# --------------------------------------------------------------------------- #
# Completeness — evidence chain-of-custody (Phase H4, GA-9)
# --------------------------------------------------------------------------- #
# A control's evidence is its *execution chain*, not a single snippet. The chain
# must reach in (an Invocation/Boot/Node step) and act out (an Execution/
# Persistence step); a lone Logic snippet proves only *what* a control computes,
# not that it is reached and acted on — exactly the defined-but-unwired failure
# mode. These vocabularies classify the `step` labels in evidence_map.yaml.
STEP_INVOCATION = {"Invocation", "Boot", "Node"}
STEP_EXECUTION = {"Execution", "Persistence"}
STEP_LOGIC = {"Logic", "Routing", "Effect"}
STEP_PROOF = {"Proof"}


def _control_impls(control):
    impls = control["implementation"]
    return [impls] if isinstance(impls, str) else impls


def completeness(control, evidence_map):
    """Issues that make an `implemented` code control not *fully evidenced*.

    Every implemented code control needs (a) ≥1 test ref, (b) ≥1 framework
    mapping, and (c) a code-evidence **chain** with an endpoint — not a lone
    logic snippet. Documentation, pure-doc, and test-implemented (`Proof`)
    controls are exempt from the chain requirement.
    """
    if control["status"] != "implemented":
        return []
    impls = _control_impls(control)
    if all(p.endswith(".md") for p in impls):          # documentation control
        return []
    issues = []
    if not L._test_refs(control):
        issues.append("no bound test")
    fw = control.get("frameworks", {}) or {}
    if not any(fw.get(k) for k in
               ("owasp_llm", "atlas", "nist_ai_600_1", "sp_800_53", "csf_2_0")):
        issues.append("no framework mapping")
    # evidence chain
    if all(p.startswith("tests/") for p in impls):     # test-implemented → Proof by nature
        return issues
    entries = evidence_map.get(control["id"]) or []
    if not entries:
        issues.append("no code-evidence chain")
        return issues
    steps = [e.get("step") for e in entries]
    if not any(steps):
        issues.append("evidence chain has no step labels")
        return issues
    if all(s in STEP_PROOF for s in steps if s):       # test-only control, exempt
        return issues
    has_inv = any(s in STEP_INVOCATION for s in steps)
    has_exe = any(s in STEP_EXECUTION for s in steps)
    if not has_inv and not has_exe:
        # every step is Logic/Routing/Effect — the lone-logic-snippet state
        issues.append("logic-only (no wired invocation→execution)")
    return issues


# --------------------------------------------------------------------------- #
# Evidence-anchor authoring assist (Phase H4, GA-10)
# --------------------------------------------------------------------------- #
import re as _re  # noqa: E402

# where the live graph / workers call in — used to guess an Invocation role
_LIVE_GRAPH = ["analytics/llm_hunter/orchestrator.py",
               "analytics/llm_hunter/agents/response.py",
               "analytics/llm_hunter/agents/review_board.py"]
_DEF_PATTERNS = {
    ".py": _re.compile(r"^\s*(?:async\s+)?def\s+(\w+)|^\s*class\s+(\w+)"),
    ".rs": _re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)|^\s*(?:pub\s+)?"
                       r"(?:struct|enum)\s+(\w+)|^\s*(?:pub\s+)?static\s+(\w+)"),
    ".sh": _re.compile(r"^\s*(\w+)\s*\(\)\s*\{"),
}


def _symbols(path):
    p = L.PE / path
    if not p.exists():
        return []
    pat = _DEF_PATTERNS.get(Path(path).suffix)
    if not pat:
        return []
    out = []
    for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
        m = pat.match(line)
        if m:
            name = next(g for g in m.groups() if g)
            out.append((name, i, line.strip()))
    return out


def _role_for(name):
    lname = name.lower()
    if any(k in lname for k in ("run", "dispatch", "handle", "_node", "invoke",
                                "main", "boot", "start", "verify_integrity")):
        return "Invocation"
    if any(k in lname for k in ("write", "persist", "store", "publish", "append",
                                "put", "save", "execute", "commit", "emit", "verify")):
        return "Execution"
    return "Logic"


def suggest_anchors(control_id):
    """Propose candidate evidence_map anchors + likely step role for a control.

    Intersects the control's implementation symbols with the identifiers its
    proving test references (so the anchor is one the test actually exercises)
    and the call sites in the live graph/worker (to guess the Invocation role).
    Reduces hand-authoring of evidence_map.yaml (GA-10).
    """
    controls = {c["id"]: c for c in L.controls()}
    c = controls.get(control_id)
    if not c:
        return []
    test_tokens = set()
    for t in L._test_refs(c):
        tp = L.PE / t.split("::")[0]
        if tp.exists():
            test_tokens |= set(_re.findall(r"\w+", tp.read_text(errors="replace")))
    live = "\n".join((L.PE / p).read_text(errors="replace")
                     for p in _LIVE_GRAPH if (L.PE / p).exists())
    out = []
    for impl in _control_impls(c):
        for name, line, text in _symbols(impl):
            if name.startswith("_") and name not in test_tokens:
                continue
            exercised = name in test_tokens
            called_live = bool(_re.search(rf"\b{_re.escape(name)}\b", live))
            role = "Invocation" if called_live else _role_for(name)
            score = (2 if exercised else 0) + (1 if called_live else 0)
            if score == 0:
                continue
            out.append({"file": impl, "anchor": name, "line": line,
                        "step": role, "exercised_by_test": exercised,
                        "called_in_live_graph": called_live, "score": score,
                        "source": text})
    out.sort(key=lambda x: (-x["score"], x["file"], x["line"]))
    return out


def load_baseline():
    if BASELINE.exists():
        return json.loads(BASELINE.read_text())
    return None


def gate(assessment, post, baseline, strict=False):
    """Return (ok, [reasons]). Fails on posture regression or contradicted claims."""
    reasons = []
    # 1) any implemented control the tests actively contradict is always a failure
    for a in assessment:
        if a["assessed"] == FAILED and a["intent"] == "implemented":
            reasons.append(f"FAILED: {a['id']} is 'implemented' but a bound test failed")
    # 2) surfaced findings that block only in strict/full runs (a warning otherwise,
    #    like a coverage gap): an implemented control that didn't run, or whose
    #    evidence chain is incomplete (decision #8 — logic-only, no wired
    #    invocation→execution). Always surfaced in the report/AR; blocks under --strict.
    if strict:
        for a in assessment:
            if a["intent"] != "implemented":
                continue
            if a["assessed"] == NOT_RUN:
                reasons.append(f"NOT-RUN: {a['id']} is 'implemented' but no bound test executed")
            if a.get("incomplete"):
                reasons.append(f"INCOMPLETE: {a['id']} — " + "; ".join(a["completeness_issues"]))
    # 3) posture must not regress below the committed floor
    if baseline:
        base_p = baseline.get("posture", {})
        for fw in FRAMEWORKS:
            floor = base_p.get(fw, {}).get("pct")
            cur = post[fw]["pct"]
            if floor is not None and cur + 1e-9 < floor:
                reasons.append(
                    f"REGRESSED: {_FW_LABEL[fw]} posture {cur}% < baseline {floor}%")
    return (not reasons), reasons


def build_baseline(assessment, post):
    return {
        "note": "Committed posture floor for the GRC gate. Raising it is a "
                "deliberate, reviewed commit; the build fails if posture drops below.",
        "generated_from_controls": len(assessment),
        "posture": {fw: {"pct": post[fw]["pct"],
                         "covered": post[fw]["covered"],
                         "applicable": post[fw]["applicable"]} for fw in FRAMEWORKS},
    }


# --------------------------------------------------------------------------- #
# Posture ledger + trend (Phase H5, GA-11) — the continuous-monitoring record
# --------------------------------------------------------------------------- #
LEDGER = HERE / "posture_ledger.jsonl"


def ledger_snapshot(assessment, post, timestamp):
    counts = {s: sum(1 for a in assessment if a["assessed"] == s)
              for s in (SATISFIED, FAILED, NOT_RUN, DOCUMENTATION)}
    return {
        "timestamp": timestamp,
        "posture": {fw: post[fw]["pct"] for fw in FRAMEWORKS},
        "counts": counts,
        "findings": sorted(a["id"] for a in assessment if a["finding"]),
        "incomplete": sorted(a["id"] for a in assessment if a.get("incomplete")),
    }


def append_ledger(assessment, post, timestamp, path=LEDGER):
    """Append one posture snapshot (append-only, like the NC-2 Brier trend).

    Idempotent per timestamp: re-running the same assessment does not duplicate
    the last row, so a re-run on unchanged reports is a no-op.
    """
    path = Path(path)
    snap = ledger_snapshot(assessment, post, timestamp)
    rows = read_ledger(path)
    if rows and rows[-1].get("timestamp") == snap["timestamp"] \
            and rows[-1].get("posture") == snap["posture"]:
        return snap
    with path.open("a") as f:
        f.write(json.dumps(snap) + "\n")
    return snap


def read_ledger(path=LEDGER):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def compute_trend(ledger):
    """Delta between the last two ledger snapshots + a regression flag."""
    if len(ledger) < 2:
        return {"available": False, "n_snapshots": len(ledger)}
    prev, cur = ledger[-2], ledger[-1]
    deltas = {fw: round(cur["posture"].get(fw, 0) - prev["posture"].get(fw, 0), 1)
              for fw in set(cur["posture"]) | set(prev["posture"])}
    regressed = sorted(fw for fw, d in deltas.items() if d < 0)
    new_findings = sorted(set(cur.get("findings", [])) - set(prev.get("findings", [])))
    resolved = sorted(set(prev.get("findings", [])) - set(cur.get("findings", [])))
    return {
        "available": True, "from": prev["timestamp"], "to": cur["timestamp"],
        "deltas": deltas, "regressed": regressed,
        "new_findings": new_findings, "resolved_findings": resolved,
    }


# --------------------------------------------------------------------------- #
# SARIF export (Phase H5, GA-11) — findings for code-scanning UIs
# --------------------------------------------------------------------------- #
_SARIF_LEVEL = {FAILED: "error", NOT_RUN: "warning"}


def build_sarif(assessment):
    """SARIF 2.1.0 log of the open findings (Failed / Not-Run / Incomplete)."""
    rules, results, seen_rules = [], [], set()
    for a in assessment:
        if not a["finding"]:
            continue
        # classify the finding kind for the SARIF rule id
        if a["assessed"] == FAILED:
            rule_id, level = "grc/failed", "error"
        elif a.get("incomplete"):
            rule_id, level = "grc/incomplete", "warning"
        else:
            rule_id, level = "grc/not-run", "warning"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({"id": rule_id, "name": rule_id.replace("/", "_"),
                          "shortDescription": {"text": {
                              "grc/failed": "Implemented control's bound test failed",
                              "grc/not-run": "Implemented control's bound test did not run",
                              "grc/incomplete": "Implemented control's evidence chain is incomplete",
                          }[rule_id]}})
        impls = _control_impls({"implementation": a["implementation"]})
        msg = (f"{a['id']} ({a['title']}): claimed '{a['intent']}', assessed "
               f"'{a['assessed']}'" + (f"; {'; '.join(a['completeness_issues'])}"
                                       if a.get("incomplete") else ""))
        results.append({
            "ruleId": rule_id, "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": impls[0]}}}],
            "properties": {"control": a["id"], "assessed": a["assessed"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "grc_assess", "informationUri":
                                "https://nexus/governance", "rules": rules}},
            "results": results,
        }],
    }


# --------------------------------------------------------------------------- #
# OSCAL Assessment Results
# --------------------------------------------------------------------------- #
def _timestamp(reports_dir):
    """Deterministic ISO-8601 UTC from the newest report (reproducible AR)."""
    files = list(Path(reports_dir).glob("*.xml"))
    if files:
        newest = max(f.stat().st_mtime for f in files)
        return _dt.datetime.fromtimestamp(newest, _dt.timezone.utc)\
            .replace(microsecond=0).isoformat()
    return "1970-01-01T00:00:00+00:00"


_METHOD = {SATISFIED: "TEST", FAILED: "TEST", NOT_RUN: "TEST", DOCUMENTATION: "EXAMINE"}
_OSCAL_STATE = {SATISFIED: "satisfied", FAILED: "not-satisfied",
                NOT_RUN: "not-satisfied", DOCUMENTATION: "satisfied"}


def build_oscal_ar(assessment, post, timestamp):
    observations, findings = [], []
    for a in assessment:
        obs_uuid = _uuid("obs", a["id"])
        observations.append({
            "uuid": obs_uuid,
            "title": f"{a['id']} — {a['title']}",
            "description": f"Assessed status: {a['assessed']} "
                           f"(claimed intent: {a['intent']}).",
            "methods": [_METHOD[a["assessed"]]],
            "props": [
                {"name": "assessed-status", "value": a["assessed"]},
                {"name": "control-intent", "value": a["intent"]},
            ],
            "relevant-evidence": [
                {"description": f"testcase {n}"} for n in a["evidence_cases"]
            ] or [{"description": "no bound testcase executed in this run"}],
        })
        if a["finding"]:
            findings.append({
                "uuid": _uuid("finding", a["id"]),
                "title": f"{a['id']} — proof gap ({a['assessed']})",
                "description": (
                    f"Control {a['id']} is claimed '{a['intent']}' but assessed "
                    f"'{a['assessed']}' from the bound tests: "
                    + "; ".join(f"{b['ref']} [{b['state']}]" for b in a["bindings"])),
                "target": {
                    "type": "objective-id",
                    "target-id": a["id"],
                    "status": {"state": "not-satisfied"},
                },
                "related-observations": [{"observation-uuid": obs_uuid}],
            })
    control_ids = [{"control-id": a["id"]} for a in assessment]
    result = {
        "uuid": _uuid("result", timestamp),
        "title": "Sentinel Nexus continuous control assessment",
        "description": "Per-control proven status derived from the pipeline's "
                       "JUnit results, with framework posture.",
        "start": timestamp,
        "reviewed-controls": {
            "control-selections": [{"include-controls": control_ids}]
        },
        "props": [
            {"name": f"posture:{fw}", "value": f"{post[fw]['pct']}",
             "class": "coverage-percent"} for fw in FRAMEWORKS
        ] + [
            {"name": "status-count",
             "value": str(sum(1 for a in assessment if a["assessed"] == s)),
             "class": s} for s in (SATISFIED, FAILED, NOT_RUN, DOCUMENTATION)
        ],
        "observations": observations,
        "findings": findings,
    }
    return {
        "assessment-results": {
            "uuid": _uuid("assessment-results"),
            "metadata": {
                "title": "Sentinel Nexus — Continuous Control Assessment Results",
                "last-modified": timestamp,
                "version": gg.load_manifest().get("meta", {}).get("version", "1.0"),
                "oscal-version": "1.1.2",
            },
            "import-ap": {"href": "./controls_manifest.yaml"},
            "results": [result],
        }
    }


# --------------------------------------------------------------------------- #
# OSCAL SSP implemented-requirements + POA&M export (Phase H6, GA-12 — stretch)
# --------------------------------------------------------------------------- #
def _metadata(title, timestamp):
    return {"title": title, "last-modified": timestamp,
            "version": gg.load_manifest().get("meta", {}).get("version", "1.0"),
            "oscal-version": "1.1.2"}


def build_oscal_ssp(assessment, timestamp):
    """OSCAL SSP with `implemented-requirements`, one per SP 800-53 control the
    register claims, cross-referenced to the cached OSCAL rev5 catalog.

    Each requirement lists the Nexus controls that implement it and whether at
    least one is **Satisfied** (proven), turning the SSP into a proof-backed
    statement of implementation rather than an assertion.
    """
    oscal = gg.load_oscal().get("controls", {})
    by_control = {a["id"]: a for a in assessment}
    # SP 800-53 control-id → [nexus control ids]
    reqs = {}
    for a in assessment:
        for ctl in a["frameworks"].get("sp_800_53", []) or []:
            reqs.setdefault(ctl, []).append(a["id"])
    implemented = []
    for ctl in sorted(reqs):
        nexus_ids = sorted(reqs[ctl])
        satisfied = [n for n in nexus_ids if by_control[n]["assessed"] == SATISFIED]
        implemented.append({
            "uuid": _uuid("impl-req", ctl),
            "control-id": ctl.lower(),                    # OSCAL uses lower-case ids
            "props": [
                {"name": "control-title", "value": oscal.get(ctl, "")},
                {"name": "implementing-controls", "value": ", ".join(nexus_ids)},
                {"name": "implementation-status",
                 "value": "implemented" if satisfied else "planned",
                 "class": "proven" if satisfied else "unproven"},
                {"name": "satisfied-by", "value": ", ".join(satisfied) or "—"},
            ],
            "statements": [{
                "statement-id": f"{ctl.lower()}_stmt",
                "uuid": _uuid("stmt", ctl),
                "description": (f"Addressed by {', '.join(nexus_ids)}; "
                               f"proven by {len(satisfied)} Satisfied control(s)."),
            }],
        })
    return {
        "system-security-plan": {
            "uuid": _uuid("ssp"),
            "metadata": _metadata("Sentinel Nexus — System Security Plan (generated)", timestamp),
            "import-profile": {"href": "./_oscal_sp800-53_rev5.json"},
            "system-characteristics": {
                "system-name": "Sentinel Nexus",
                "description": "Sovereign autonomous SOC platform (generated SSP excerpt).",
                "status": {"state": "operational"},
            },
            "control-implementation": {
                "description": "Implemented requirements derived from the controls "
                               "manifest and proven by the continuous assessment.",
                "implemented-requirements": implemented,
            },
        }
    }


def build_oscal_poam(assessment, timestamp):
    """OSCAL POA&M whose `poam-items` are the open findings (Failed / Not-Run /
    Incomplete implemented controls), each cross-referenced to its 800-53 controls."""
    items = []
    for a in assessment:
        if not a["finding"]:
            continue
        sp = a["frameworks"].get("sp_800_53", []) or []
        detail = "; ".join(a["completeness_issues"]) if a.get("incomplete") else ""
        items.append({
            "uuid": _uuid("poam", a["id"]),
            "title": f"{a['id']} — {a['title']}",
            "description": (f"Control claimed '{a['intent']}' but assessed "
                            f"'{a['assessed']}'." + (f" Evidence: {detail}." if detail else "")),
            "props": [
                {"name": "assessed-status", "value": a["assessed"]},
                {"name": "sp800-53-controls", "value": ", ".join(sp) or "—"},
            ],
            "related-observations": [{"observation-uuid": _uuid("obs", a["id"])}],
        })
    return {
        "plan-of-action-and-milestones": {
            "uuid": _uuid("poam"),
            "metadata": _metadata("Sentinel Nexus — POA&M (generated from open findings)",
                                  timestamp),
            "import-ssp": {"href": "./oscal_ssp.json"},
            "poam-items": items,
        }
    }


# --------------------------------------------------------------------------- #
# Human report (rendered from the assessment)
# --------------------------------------------------------------------------- #
# plain-text labels (no emoji) so the rendered PDF is glyph-clean under DejaVu
_STATUS_BADGE = {SATISFIED: "Satisfied", FAILED: "Failed",
                 NOT_RUN: "Not-Run", DOCUMENTATION: "Documentation"}


def _evidence_pointer(control_id, evidence_map):
    """First `file:line` code-evidence anchor for a control, if any."""
    entries = evidence_map.get(control_id) or []
    try:
        import gen_evidence as ge
        for e in entries:
            _lang, citation, _snip = ge.extract_snippet(e)
            return citation
    except Exception:
        pass
    return None


def render_report(assessment, post, timestamp):
    evidence_map = gg.load_evidence_map()
    counts = {s: sum(1 for a in assessment if a["assessed"] == s)
              for s in (SATISFIED, FAILED, NOT_RUN, DOCUMENTATION)}
    L_ = gg._frontmatter("Continuous Control Assessment",
                         "Sentinel Nexus — proven control posture (generated from the test run)")
    # the shared frontmatter helper credits gen_governance.py; this doc is emitted
    # by grc_assess.py from the live JUnit results, so correct the attribution.
    L_ = [ln.replace("Source: controls_manifest.yaml + frameworks_reference.yaml. "
                     "Regenerate: ./gen_governance.py",
                     "Source: controls_manifest.yaml + tests/reports/*.xml. "
                     "Regenerate: ./grc_assess.py") for ln in L_]
    L_ += [f"<!-- Assessment start: {timestamp}. Generated by grc_assess.py from "
           "controls_manifest.yaml + tests/reports/*.xml. Do not edit by hand. -->", "",
           "\\newpage", "", "## Assessment Summary", "",
           "Unlike the *claims* in the control catalog, every status below is **derived "
           "from the pipeline's JUnit results in this run** — a control is Satisfied only "
           "when its bound tests actually executed and passed.", "",
           f"*Assessed **{len(assessment)}** controls — "
           f"{counts[SATISFIED]} Satisfied · {counts[FAILED]} Failed · "
           f"{counts[NOT_RUN]} Not-Run · {counts[DOCUMENTATION]} Documentation.*", "",
           "| Status | Count |", "|---|---|"]
    for s in (SATISFIED, FAILED, NOT_RUN, DOCUMENTATION):
        L_.append(f"| {_STATUS_BADGE[s]} | {counts[s]} |")

    # posture
    L_ += ["", "## Framework Posture", "",
           "Coverage = the share of **applicable** framework items addressed by at least "
           "one **Satisfied** control (claimed *and* proven).", "",
           "| Framework | Covered | Applicable | Posture |", "|---|---|---|---|"]
    for fw in FRAMEWORKS:
        p = post[fw]
        L_.append(f"| {_FW_LABEL[fw]} | {p['covered']} | {p['applicable']} | {p['pct']}% |")

    # per-control proven status
    L_ += ["", "\\newpage", "", "## Per-Control Proven Status", "",
           "| ID | Title | Intent | Assessed | Evidence | Bound tests | Code evidence |",
           "|---|---|---|---|---|---|---|"]
    for a in assessment:
        refs = ", ".join(f"`{b['ref'].split('::')[-1] if '::' in b['ref'] else b['ref'].split('/')[-1]}`"
                         + (f"·{b['state']}" if b["state"] != "resolved" else "")
                         for b in a["bindings"]) or "_(none)_"
        ptr = _evidence_pointer(a["id"], evidence_map)
        chain = "INCOMPLETE — " + "; ".join(a["completeness_issues"]) if a["incomplete"] else "complete"
        L_.append(f"| {a['id']} | {a['title']} | {a['intent']} | "
                  f"{_STATUS_BADGE[a['assessed']]} | {chain} | {refs} | "
                  f"{('`' + ptr + '`') if ptr else '—'} |")

    # open findings (POA&M seed)
    findings = [a for a in assessment if a["finding"]]
    L_ += ["", "\\newpage", "", "## Open Findings (Plan-of-Action seed)", "",
           "Controls claimed **implemented** with a proof gap: bound tests that **failed / did "
           "not run**, or an **incomplete evidence chain** (e.g. a lone logic snippet with no "
           "wired invocation→execution). A Failed or Incomplete finding turns the build red; a "
           "Not-Run finding is a coverage gap (blocking only in `--gate --strict` / `--full`).", ""]
    if findings:
        for a in findings:
            detail = "; ".join(f"{b['ref']} [{b['state']}"
                               + (f"={b['result']}" if b['result'] else "") + "]"
                               for b in a["bindings"])
            chain = (" · **evidence:** " + "; ".join(a["completeness_issues"])
                     if a["incomplete"] else "")
            L_ += [f"- **{a['id']} — {a['title']}** → *{a['assessed']}*. Bound: {detail}{chain}"]
    else:
        L_ += ["- _None: every implemented control's bound tests executed, passed, and is "
               "fully evidenced._"]
    return "\n".join(L_).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Gate result as JUnit (so the pipeline dashboard shows GRC like any section)
# --------------------------------------------------------------------------- #
import xml.etree.ElementTree as _ET   # noqa: E402


def build_grc_junit(assessment, post, baseline, timestamp, strict=False):
    """Express the assessment as a JUnit testsuite → `tests/reports/grc.xml`.

    One `<testcase>` per control (Satisfied→pass, Documentation→pass,
    Failed→failure, Not-Run→skipped unless --strict makes it a failure) plus a
    synthetic `posture_gate` case that fails on any baseline regression. The
    section's exit code still comes from `gate()`; this file is what lets the
    XML summary and CI dashboard render GRC alongside the functional sections.
    """
    ok, reasons = gate(assessment, post, baseline, strict=strict)
    suite = _ET.Element("testsuite", name="grc")
    n_fail = n_skip = 0
    for a in assessment:
        tc = _ET.SubElement(suite, "testcase", classname="grc.assessment",
                            name=f"{a['id']} ({a['assessed']})", time="0")
        blocking = (a["assessed"] == FAILED and a["intent"] == "implemented") or \
                   (strict and a["assessed"] == NOT_RUN and a["intent"] == "implemented")
        if blocking:
            _ET.SubElement(tc, "failure", message=f"{a['id']}: {a['assessed']}").text = \
                "; ".join(f"{b['ref']} [{b['state']}]" for b in a["bindings"])
            n_fail += 1
        elif a["assessed"] == NOT_RUN:
            _ET.SubElement(tc, "skipped",
                           message=f"{a['id']}: bound test not run in this report set")
            n_skip += 1
    # the posture-regression gate as its own case
    pg = _ET.SubElement(suite, "testcase", classname="grc.gate",
                        name="posture_gate", time="0")
    regressions = [r for r in reasons if r.startswith("REGRESSED")]
    if regressions:
        _ET.SubElement(pg, "failure",
                       message="posture regressed below committed baseline").text = \
            "\n".join(regressions)
        n_fail += 1
    total = len(assessment) + 1
    suite.set("tests", str(total))
    suite.set("failures", str(n_fail))
    suite.set("skipped", str(n_skip))
    suite.set("errors", "0")
    suite.set("timestamp", timestamp)
    return _ET.tostring(suite, encoding="unicode")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _print_summary(assessment, post):
    print(f"{'CONTROL':22} {'INTENT':12} ASSESSED")
    print("-" * 52)
    for a in assessment:
        print(f"{a['id']:22} {a['intent']:12} {a['assessed']}"
              + ("  *finding*" if a["finding"] else ""))
    print("\nPosture:")
    for fw in FRAMEWORKS:
        p = post[fw]
        print(f"  {_FW_LABEL[fw]:20} {p['pct']:5}%  ({p['covered']}/{p['applicable']})")


def main(argv):
    ap = argparse.ArgumentParser(description="GRC continuous-assessment engine")
    ap.add_argument("--reports", default=str(L.DEFAULT_REPORTS))
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="with --gate, also fail on Not-Run implemented controls")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--summary", action="store_true", help="print status; no file writes")
    ap.add_argument("--suggest-anchors", metavar="CONTROL_ID",
                    help="propose evidence_map anchors + step roles for a control; no file writes")
    ap.add_argument("--junit", metavar="PATH",
                    help="write the gate result as a JUnit file (e.g. /reports/grc.xml)")
    ap.add_argument("--out-dir", metavar="DIR",
                    help="also copy assessment_results.json + assessment_report.md here "
                         "(for host preservation from the grc container)")
    ap.add_argument("--append-ledger", action="store_true",
                    help="append this run's posture to posture_ledger.jsonl (scheduled re-assessment)")
    ap.add_argument("--trend", action="store_true",
                    help="report posture deltas from the ledger; no file writes")
    ap.add_argument("--sarif", metavar="PATH",
                    help="write findings as a SARIF 2.1.0 log to PATH")
    ap.add_argument("--oscal-export", action="store_true",
                    help="also emit oscal_ssp.json (implemented-requirements) + "
                         "oscal_poam.json (open findings), cross-referenced to the catalogs")
    args = ap.parse_args(argv)

    junit = L.load_junit(args.reports)
    assessment = assess(junit)
    post = posture(assessment)
    timestamp = _timestamp(args.reports)
    baseline = load_baseline()

    if args.trend:
        tr = compute_trend(read_ledger())
        if not tr.get("available"):
            print(f"posture trend: need ≥2 ledger snapshots (have {tr.get('n_snapshots', 0)})")
            return 0
        print(f"posture trend {tr['from']} → {tr['to']}:")
        for fw in FRAMEWORKS:
            d = tr["deltas"].get(fw, 0.0)
            arrow = "▲" if d > 0 else ("▼" if d < 0 else "•")
            print(f"  {_FW_LABEL[fw]:20} {arrow} {d:+.1f} pts")
        if tr["regressed"]:
            print(f"  REGRESSED: {', '.join(_FW_LABEL[f] for f in tr['regressed'])}")
        if tr["new_findings"]:
            print(f"  new findings: {', '.join(tr['new_findings'])}")
        if tr["resolved_findings"]:
            print(f"  resolved: {', '.join(tr['resolved_findings'])}")
        return 0

    if args.suggest_anchors:
        sug = suggest_anchors(args.suggest_anchors)
        if not sug:
            print(f"no anchor candidates found for {args.suggest_anchors}")
            return 0
        print(f"# candidate evidence_map anchors for {args.suggest_anchors} "
              f"(step role is a guess — verify + caption):")
        for s in sug:
            tags = []
            if s["exercised_by_test"]:
                tags.append("exercised-by-test")
            if s["called_in_live_graph"]:
                tags.append("called-in-live-graph")
            print(f'    - {{file: {s["file"]}, step: {s["step"]}, '
                  f'anchor: "{s["anchor"]}"}}   # {", ".join(tags)} (L{s["line"]})')
        return 0

    if args.summary:
        _print_summary(assessment, post)
        return 0

    if args.write_baseline:
        BASELINE.write_text(json.dumps(build_baseline(assessment, post), indent=2) + "\n")
        print(f"wrote {BASELINE.name} (posture floor from {len(assessment)} controls)")

    AR_JSON.write_text(json.dumps(build_oscal_ar(assessment, post, timestamp), indent=2) + "\n")
    REPORT_MD.write_text(render_report(assessment, post, timestamp))
    print(f"wrote {AR_JSON.name} + {REPORT_MD.name}")

    if args.sarif:
        Path(args.sarif).parent.mkdir(parents=True, exist_ok=True)
        Path(args.sarif).write_text(json.dumps(build_sarif(assessment), indent=2) + "\n")
        print(f"wrote {args.sarif}")

    if args.oscal_export:
        SSP_JSON.write_text(json.dumps(build_oscal_ssp(assessment, timestamp), indent=2) + "\n")
        POAM_JSON.write_text(json.dumps(build_oscal_poam(assessment, timestamp), indent=2) + "\n")
        print(f"wrote {SSP_JSON.name} + {POAM_JSON.name}")

    if args.append_ledger:
        snap = append_ledger(assessment, post, timestamp)
        pcts = ", ".join(f"{fw}={snap['posture'][fw]}" for fw in FRAMEWORKS)
        print(f"ledger ← {snap['timestamp']} (posture {pcts})")

    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        for src in (AR_JSON, REPORT_MD, LEDGER, SSP_JSON, POAM_JSON):
            if src.exists():
                (out / src.name).write_text(src.read_text())

    # the gate JUnit is written whether or not the gate passes (so the dashboard
    # always shows GRC, red or green).
    if args.junit:
        Path(args.junit).parent.mkdir(parents=True, exist_ok=True)
        Path(args.junit).write_text(
            build_grc_junit(assessment, post, baseline, timestamp, strict=args.strict))
        print(f"wrote {args.junit}")

    if args.gate:
        ok, reasons = gate(assessment, post, baseline, strict=args.strict)
        if ok:
            print("GRC gate: PASS — posture holds; no contradicted implemented control.")
            return 0
        print("GRC gate: FAIL", file=sys.stderr)
        for r in reasons:
            print(f"  - {r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
