#!/usr/bin/env python3
"""
Governance doc generator (manifest-driven — keeps docs in sync with the code).

Source of truth:
  * controls_manifest.yaml      — every control + its OWASP/ATLAS/AI-600-1/800-53/CSF mappings
  * frameworks_reference.yaml   — OWASP/ATLAS enumerations + applicability + remediation
  * _oscal_sp800-53_rev5.json   — authoritative SP 800-53 rev5 control titles (NIST OSCAL v1.4.0)

Generates (both checked for drift by test_governance_manifest.py):
  * controls_catalog.md         — consolidated, cross-correlated control catalog
  * applicability_matrix.md     — what is applicable / covered / a GAP, per framework

Usage:
  gen_governance.py            # (re)write both generated docs
  gen_governance.py --check    # exit 1 if either is out of sync (CI)
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

HERE = Path(__file__).parent
MANIFEST = HERE / "controls_manifest.yaml"
REFERENCE = HERE / "frameworks_reference.yaml"
OSCAL = HERE / "_oscal_sp800-53_rev5.json"
OSCAL_CSF = HERE / "_oscal_csf_v2.0.json"
CSF_MAP = HERE / "csf_category_map.yaml"
CATALOG = HERE / "controls_catalog.md"
MATRIX = HERE / "applicability_matrix.md"

_STATUS_ORDER = ["implemented", "partial", "documented", "planned"]
_CSF_NAMES = {"GV": "Govern", "ID": "Identify", "PR": "Protect",
              "DE": "Detect", "RS": "Respond", "RC": "Recover"}
_CSF_ORDER = ["GV", "ID", "PR", "DE", "RS", "RC"]


def load_manifest():
    return yaml.safe_load(MANIFEST.read_text())


def load_reference():
    return yaml.safe_load(REFERENCE.read_text())


def load_oscal():
    if OSCAL.exists():
        return json.loads(OSCAL.read_text())
    return {"families": {}, "controls": {}}


def load_csf():
    """Authoritative NIST CSF 2.0 catalog (functions/categories/subcategories)."""
    if OSCAL_CSF.exists():
        return json.loads(OSCAL_CSF.read_text())
    return {"functions": {}, "category_titles": {}, "v2_categories": [], "subcategories": {}}


def load_csf_map():
    """control id -> [CSF 2.0 category ids]."""
    if CSF_MAP.exists():
        return (yaml.safe_load(CSF_MAP.read_text()) or {}).get("map", {}) or {}
    return {}


def load_evidence_map():
    """control id -> [code-evidence entries] (see gen_evidence.py / evidence_map.yaml)."""
    p = HERE / "evidence_map.yaml"
    if p.exists():
        return (yaml.safe_load(p.read_text()) or {}).get("evidence", {}) or {}
    return {}


def _csf_function_names():
    return load_csf().get("functions") or _CSF_NAMES


def _csf_categories_by_control():
    """category id -> set(control ids), from the CSF category map."""
    m = defaultdict(set)
    for cid, cats in load_csf_map().items():
        for cat in (cats or []):
            m[cat].add(cid)
    return m


def _fw(c, key):
    return list((c.get("frameworks", {}) or {}).get(key, []) or [])


def _covering_controls(controls, fw_key, item_id):
    return sorted(c["id"] for c in controls if item_id in _fw(c, fw_key))


def _frontmatter(title, subtitle):
    return ["---", f'title: "{title}"', f'subtitle: "{subtitle}"',
            'author: "Information Security & AI Governance"', 'date: "June 2026"',
            'version: "1.0"', "---", "",
            "<!-- GENERATED FILE — DO NOT EDIT BY HAND. Source: controls_manifest.yaml + "
            "frameworks_reference.yaml. Regenerate: ./gen_governance.py -->", ""]


# -- Catalog -----------------------------------------------------------------
def render_catalog(manifest, oscal):
    controls = sorted(manifest.get("controls", []), key=lambda c: c["id"])
    fam_titles = oscal.get("families", {})
    ctl_titles = oscal.get("controls", {})
    L = _frontmatter("Security & AI Control Catalog",
                     "Sentinel Nexus — generated from controls_manifest.yaml")
    L += ["\\newpage", "", "## Summary", "",
          f"Generated from the master controls manifest: **{len(controls)} controls**, each "
          f"mapped to its implementing module, proving tests, and its references across OWASP "
          f"Top 10 for LLM, MITRE ATLAS, NIST AI 600-1, NIST SP 800-53 Rev. 5, and NIST CSF 2.0.",
          ""]
    by_status = Counter(c["status"] for c in controls)
    by_cat = Counter(c["category"] for c in controls)
    L += ["| Status | Count |", "|---|---|"]
    L += [f"| {s} | {by_status[s]} |" for s in _STATUS_ORDER if by_status.get(s)]
    L += ["", "| Category | Count |", "|---|---|"]
    L += [f"| {cat} | {by_cat[cat]} |" for cat in sorted(by_cat)]

    # full matrix (rendered small; the build uses landscape for this doc)
    L += ["", "\\newpage", "", "## Control Catalog", "", "\\footnotesize", "",
          "| ID | Title | Status | OWASP | ATLAS | NIST AI 600-1 | SP 800-53 | CSF | Tests |",
          "|---|---|---|---|---|---|---|---|---|"]
    for c in controls:
        L.append("| {id} | {title} | {st} | {ow} | {at} | {ai} | {sp} | {csf} | {nt} |".format(
            id=c["id"], title=c["title"], st=c["status"],
            ow=", ".join(_fw(c, "owasp_llm")) or "—",
            at=", ".join(_fw(c, "atlas")) or "—",
            ai=", ".join(_fw(c, "nist_ai_600_1")) or "—",
            sp=", ".join(_fw(c, "sp_800_53")) or "—",
            csf=", ".join(_fw(c, "csf_2_0")) or "—",
            nt=len(c.get("tests", []) or [])))
    L += ["", "\\normalsize", ""]

    # framework cross-correlation
    L += ["\\newpage", "", "## Framework Cross-Correlation", "",
          "Five lenses on one register — locating a control via any framework surfaces its "
          "coverage under the others.", ""]

    def _xref(items_for, title, col, sort_key=None, decorate=None):
        m = defaultdict(set)
        for c in controls:
            for item in items_for(c):
                m[item].add(c["id"])
        if not m:
            return
        L.extend(["", f"### {title}", "", f"| {col} | Controls |", "|---|---|"])
        for k in (sorted(m, key=sort_key) if sort_key else sorted(m)):
            label = decorate(k) if decorate else k
            L.append(f"| {label} | {', '.join(sorted(m[k]))} |")

    fn_names = _csf_function_names()
    _xref(lambda c: _fw(c, "owasp_llm"), "OWASP Top 10 for LLM", "Risk")
    _xref(lambda c: _fw(c, "atlas"), "MITRE ATLAS", "Technique")
    _xref(lambda c: _fw(c, "nist_ai_600_1"), "NIST AI 600-1 (GenAI Profile)", "Action")
    _xref(lambda c: [f"{f} {fn_names.get(f, '')}".strip() for f in _fw(c, "csf_2_0")],
          "NIST CSF 2.0 Function", "Function",
          sort_key=lambda s: (_CSF_ORDER.index(s.split()[0])
                              if s.split()[0] in _CSF_ORDER else 99))

    # CSF 2.0 *category* cross-reference (category-granularity, from csf_category_map.yaml,
    # titled from the authoritative NIST OSCAL CSF 2.0 catalog).
    csf = load_csf()
    cat_titles = csf.get("category_titles", {})
    catm = _csf_categories_by_control()
    if catm:
        L.extend(["", "### NIST CSF 2.0 Category", "",
                  "| Category · title | Controls |", "|---|---|"])
        for cat in sorted(catm, key=lambda x: (_CSF_ORDER.index(x[:2]) if x[:2] in _CSF_ORDER else 99, x)):
            L.append(f"| {cat} · {cat_titles.get(cat, '?')} | {', '.join(sorted(catm[cat]))} |")

    _xref(lambda c: _fw(c, "sp_800_53"), "NIST SP 800-53 Rev. 5", "Control · OSCAL title",
          sort_key=lambda s: (s.split("-")[0], s),
          decorate=lambda c: f"{c} · {ctl_titles.get(c, '?')}")

    # per-control detail
    evidence_ids = set(load_evidence_map())
    L += ["", "\\newpage", "", "## Control Detail", "",
          "Each implemented control's *proving code* is extracted verbatim (cited by "
          "`file:line`) into the **Control Evidence Dossier** (`control_evidence.pdf`) and, "
          "per control, under `artifacts/`.", ""]
    cats = defaultdict(list)
    for c in controls:
        cats[c["category"]].append(c)
    for cat in sorted(cats):
        L += ["", f"### {cat}", ""]
        for c in sorted(cats[cat], key=lambda c: c["id"]):
            tests = c.get("tests", []) or []
            L += [f"**{c['id']} — {c['title']}** *(status: {c['status']}; owner: {c.get('owner', '—')})*",
                  "", c.get("description", "").strip(), "",
                  f"- Implementation: `{c['implementation']}`",
                  "- Tests: " + (", ".join(f"`{t}`" for t in tests) if tests else "_(documentation control)_")]
            if c["id"] in evidence_ids:
                L += [f"- Code evidence: `artifacts/{c['id']}.md` (extracted snippets)"]
            L += [""]
    return "\n".join(L).rstrip() + "\n"


# -- Applicability & Gap matrix ----------------------------------------------
def _matrix_section(L, controls, fw_key, ref_block):
    items = ref_block.get("items", [])
    covered_n = gap_n = na_n = 0
    rows = []
    gaps = []
    for it in items:
        iid, name = it["id"], it.get("name", "")
        if not it.get("applicable", True):
            status = "N-A"
            na_n += 1
            note = it.get("reason", "")
            ctls = "—"
        else:
            covering = _covering_controls(controls, fw_key, iid)
            if covering:
                status = "Covered"
                covered_n += 1
                ctls = ", ".join(covering)
                note = ""
            else:
                status = "**GAP**"
                gap_n += 1
                ctls = "—"
                note = " ".join((it.get("remediation", "") or "").split())
                gaps.append((iid, name, note))
        rows.append((iid, name, status, ctls, note))
    L += ["", f"### {ref_block.get('title', fw_key)}", "",
          f"*Covered {covered_n} · Gaps {gap_n} · N-A {na_n}*", "",
          "| ID | Item | Status | Controls | Remediation (if gap) |", "|---|---|---|---|---|"]
    for iid, name, status, ctls, note in rows:
        L.append(f"| {iid} | {name} | {status} | {ctls} | {note or '—'} |")
    return gaps


def render_matrix(manifest, oscal, reference):
    controls = manifest.get("controls", [])
    fam_titles = oscal.get("families", {})
    L = _frontmatter("Applicability & Gap Matrix",
                     "Sentinel Nexus — framework coverage, gaps, and remediation")
    L += ["\\newpage", "", "## Overview", "",
          "For each framework taxonomy, every item is classified **Covered** (a Sentinel Nexus "
          "control addresses it), **GAP** (applicable but not yet addressed — with a remediation "
          "that *can* address it), or **N-A** (not applicable to a defensive SOC platform; see the "
          "Applicability Determinations). OWASP/ATLAS coverage is computed from the controls "
          "manifest; SP 800-53 titles are the authoritative NIST OSCAL rev5 catalog.", ""]

    L += ["\\newpage", "", "## Framework Applicability", ""]
    gaps = []
    gaps += _matrix_section(L, controls, "owasp_llm", reference["owasp_llm"])
    gaps += _matrix_section(L, controls, "atlas", reference["atlas"])

    # SP 800-53 family coverage with OSCAL titles
    fam_map = defaultdict(set)
    for c in controls:
        for ctl in _fw(c, "sp_800_53"):
            fam_map[ctl.split("-")[0]].add(ctl)
    L += ["", "\\newpage", "", "## NIST SP 800-53 Rev. 5 — Family Coverage",
          "", "*Authoritative control titles from NIST OSCAL v1.4.0.*", "",
          "| Family | Title | Controls referenced |", "|---|---|---|"]
    for fam in sorted(fam_map):
        L.append(f"| {fam} | {fam_titles.get(fam, '?')} | {', '.join(sorted(fam_map[fam]))} |")

    # NIST CSF 2.0 — function & category self-assessment (category granularity).
    csf = load_csf()
    cat_titles = csf.get("category_titles", {})
    fn_names = csf.get("functions") or _CSF_NAMES
    cats = csf.get("v2_categories", [])
    catm = _csf_categories_by_control()
    covered = [c for c in cats if catm.get(c)]
    process = [c for c in cats if not catm.get(c)]
    if cats:
        L += ["", "\\newpage", "", "## NIST CSF 2.0 — Function & Category Coverage", "",
              "*Authoritative function/category titles from NIST OSCAL v1.4.0 (CSF 2.0). "
              "Controls are mapped at **category** granularity in `csf_category_map.yaml`.*", "",
              f"*Of the **{len(cats)}** CSF 2.0 categories, **{len(covered)}** are realised by a "
              f"technical control; the remaining **{len(process)}** are organizational / process "
              "categories carried by the policy layer (System Security Plan, AI Incident Response "
              "Plan, Applicability Determinations) rather than by software.*", "",
              "| Fn | Category | Title | Realised by | Coverage |", "|---|---|---|---|---|"]
        for cat in sorted(cats, key=lambda x: (_CSF_ORDER.index(x[:2]) if x[:2] in _CSF_ORDER else 99, x)):
            fn = cat[:2]
            ctls = sorted(catm.get(cat, []))
            if ctls:
                realised, cov = ", ".join(ctls), "Technical"
            else:
                realised, cov = "_policy / process — see SSP_", "Process"
            L.append(f"| {fn} {fn_names.get(fn, '')} | {cat} | {cat_titles.get(cat, '?')} | {realised} | {cov} |")
        L += ["",
              "**Process-layer categories** (no code control by design): "
              + ", ".join(f"{c} {cat_titles.get(c, '')}" for c in process)
              + ". These are addressed as policy/governance obligations in the System Security "
              "Plan and supporting governance documents, consistent with a defensive SOC "
              "platform whose mission, risk-tolerance, workforce-training, and incident-management "
              "*processes* are organizational rather than implemented in the codebase.", ""]

    # NIST AI 600-1 pointer
    L += ["", "## NIST AI 600-1 (GenAI Profile)", "",
          "The 12 GAI risk families and their coverage/gaps are maintained in "
          "`../nist_ai_600_1_control_tracker.md` §1 (e.g. Confabulation, Bias/Homogenization, "
          "and Value-Chain are the active high-exposure areas; CBRN/CSAM/violent/IP are N-A per "
          "the Applicability Determinations).", ""]

    # outstanding addressable gaps summary
    L += ["\\newpage", "", "## Outstanding Gaps (addressable)", "",
          "These are **applicable** items not yet covered by a control, each with a remediation "
          "that can close it. They are candidate backlog items.", ""]
    if gaps:
        for iid, name, note in gaps:
            L += [f"- **{iid} — {name}.** {note}"]
    else:
        L += ["- _None: every applicable OWASP/ATLAS item maps to a control._"]
    L += ["",
          "**Theme.** The principal residual exposure is **inference-endpoint abuse / model "
          "extraction** (OWASP LLM10, ATLAS AML.T0024 / AML.T0040, NIST MS-2.10-001): the "
          "sovereign vLLM endpoints are network-isolated but not rate-/anomaly-monitored for "
          "extraction or membership-inference query patterns. Remediation is a bounded, testable "
          "control (per-caller quotas + query-volume anomaly alerting + a membership-inference "
          "review) — tracked as a backlog item and SSP POA&M-4.", ""]
    return "\n".join(L).rstrip() + "\n"


def main(argv):
    manifest, oscal, reference = load_manifest(), load_oscal(), load_reference()
    outputs = {CATALOG: render_catalog(manifest, oscal),
               MATRIX: render_matrix(manifest, oscal, reference)}
    if "--check" in argv:
        stale = [p.name for p, exp in outputs.items()
                 if (p.read_text() if p.exists() else "") != exp]
        if stale:
            print(f"DRIFT: {stale} out of sync with the manifest/reference. "
                  f"Run `gen_governance.py` and commit.", file=sys.stderr)
            return 1
        print("generated governance docs are in sync.")
        return 0
    for p, exp in outputs.items():
        p.write_text(exp)
        print(f"wrote {p.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
