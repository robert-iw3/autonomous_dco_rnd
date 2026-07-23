#!/usr/bin/env python3
"""
GRC continuous-assessment library — the binding layer between the controls
manifest and the *real* JUnit results emitted by the test pipeline.

The static drift-guard (`test_governance_manifest.py`) proves the control
register is well-formed and that every referenced file exists. This module adds
the **dynamic** half: it reads the JUnit XML the containerised test sections
write into `tests/reports/`, normalises each `<testcase>` back to the pytest
node-id form the manifest uses (`path::Class::method`), and resolves every
control's `tests:` bindings to a concrete pass/fail/skip/not-run result.

Nothing here classifies a control or scores posture — that is `grc_assess.py`.
This module is deliberately thin, stdlib-only (`xml.etree` + `pyyaml` via
`gen_governance`), and shared by the assessment engine, the binding test
(`test_grc_binding.py`) and the pipeline lab.

Key normalisation fact (empirically true of every section's report): pytest
writes `classname` as the test file's path **relative to `tests/`**, dots for
slashes, `.py` dropped, with the class appended —
`tests/lab_governance/test_ai_controls.py::TestGroundingEnforcement::test_x`
serialises as `classname="lab_governance.test_ai_controls.TestGroundingEnforcement"
name="test_x"`. `load_junit` reverses that back to the node-id.
"""
import datetime as _dt
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
PE = HERE.parent.parent                       # autonomous_dco_rnd/
TESTS_DIR = PE / "tests"
DEFAULT_REPORTS = TESTS_DIR / "reports"

# Result vocabulary for a single resolved testcase.
PASS, FAIL, ERROR, SKIP = "pass", "fail", "error", "skip"
_WORST_FIRST = (ERROR, FAIL, SKIP, PASS)      # precedence when aggregating a ref

# gen_governance is the single source of truth for loading the manifest / OSCAL
# caches; re-export the pieces the assessment engine needs so callers depend on
# one loader.
sys.path.insert(0, str(HERE))
import gen_governance as gg  # noqa: E402


def load_manifest():
    return gg.load_manifest()


def controls():
    return load_manifest().get("controls", []) or []


# --------------------------------------------------------------------------- #
# JUnit → node-id normalisation
# --------------------------------------------------------------------------- #
def _module_and_class(classname, tests_dir):
    """Split a JUnit `classname` into (module_relpath, class_parts).

    `module_relpath` is the file path relative to `tests/` (dots→slashes, no
    `.py`); `class_parts` are the remaining dotted segments (the test class,
    possibly nested). We resolve the split against the real tree when available
    (the grc container copies the source in), which is exact; otherwise we fall
    back to the convention that module/file segments are lower-case and the
    class begins at the first upper-case segment.
    """
    parts = classname.split(".")
    # Exact: longest leading prefix that is a real test file under tests/.
    if tests_dir is not None:
        for cut in range(len(parts), 0, -1):
            candidate = tests_dir.joinpath(*parts[:cut]).with_suffix(".py")
            if candidate.exists():
                return "/".join(parts[:cut]), parts[cut:]
    # Fallback: first segment whose first char is upper-case starts the class.
    for i, seg in enumerate(parts):
        if seg[:1].isupper():
            return "/".join(parts[:i]) or parts[0], parts[i:]
    return "/".join(parts), []


def normalize_junit_id(classname, name, tests_dir=TESTS_DIR):
    """Reconstruct the pytest node-id (`tests/…py[::Class]::name`) for a case."""
    if not classname:
        return f"tests/{name}"
    mod, cls = _module_and_class(classname, tests_dir)
    node = f"tests/{mod}.py"
    for c in cls:
        node += f"::{c}"
    node += f"::{name}"
    return node


def _case_result(case):
    for child in case:
        tag = child.tag.split("}")[-1]           # tolerate namespaces
        if tag == "failure":
            return FAIL
        if tag == "error":
            return ERROR
        if tag == "skipped":
            return SKIP
    return PASS


def _suite_time(root, fallback):
    """Freshness of a report = the newest `<testsuite timestamp=...>` (when the
    tests actually *ran*), falling back to the file mtime.

    Using the embedded execution timestamp — not the filesystem mtime — makes
    ordering deterministic even when every report shares one mtime (a fresh git
    checkout, a `cp`, or a CI artifact restore all reset mtimes to a single
    instant, which would otherwise make "newest wins" pick a stale result).
    """
    best = None
    for s in root.iter("testsuite"):
        t = s.get("timestamp")
        if not t:
            continue
        try:
            e = _dt.datetime.fromisoformat(t).timestamp()
        except ValueError:
            continue
        if best is None or e > best:
            best = e
    return best if best is not None else fallback


def load_junit(reports_dir=DEFAULT_REPORTS, tests_dir=TESTS_DIR):
    """Parse every `*.xml` under `reports_dir` → {node_id: result}.

    The reports directory legitimately accumulates many files (one per pipeline
    section, plus ad-hoc combined runs). When a testcase appears in more than
    one file the report from the **most recent test execution** wins (keyed on
    the JUnit `testsuite` timestamp, mtime as tiebreak), so the map reflects the
    latest known result rather than a stale one. Within a single file the worse
    result wins (defensive; pytest emits each case once).
    """
    reports_dir = Path(reports_dir)
    # skip our own outputs so a prior grc run in the same reports dir can't feed
    # back into the next assessment (self-inclusion).
    parsed = []
    for p in reports_dir.glob("*.xml"):
        if p.name in ("grc.xml", "grc_lab.xml"):
            continue
        try:
            root = ET.parse(p).getroot()
        except ET.ParseError:
            continue
        mtime = p.stat().st_mtime
        parsed.append((_suite_time(root, mtime), mtime, root))
    junit = {}
    for _fresh, _mtime, root in sorted(parsed, key=lambda r: (r[0], r[1])):
        seen_here = {}
        for case in root.iter("testcase"):
            cid = case.get("classname", "")
            name = case.get("name", "")
            if not name:
                continue
            node = normalize_junit_id(cid, name, tests_dir)
            res = _case_result(case)
            prev = seen_here.get(node)
            if prev is None or _WORST_FIRST.index(res) < _WORST_FIRST.index(prev):
                seen_here[node] = res
        junit.update(seen_here)      # more-recent execution overrides older per node-id
    return junit


# --------------------------------------------------------------------------- #
# Control ↔ testcase binding
# --------------------------------------------------------------------------- #
def _test_refs(control):
    return list(control.get("tests", []) or [])


def _matches(ref, node_id):
    """True if a JUnit node-id is covered by a manifest `tests:` ref.

    A ref may be file-level (`…py`), class-level (`…py::Class`) or a fully
    qualified case (`…py::Class::method`). A file/class-level ref covers every
    node-id beneath it; an exact ref matches itself.
    """
    return node_id == ref or node_id.startswith(ref + "::")


def resolve_binding(control, junit):
    """Resolve a control's `tests:` refs against the loaded JUnit map.

    Returns a list of one entry per ref:
        {"ref": str, "result": pass|fail|error|skip|None, "cases": [node_ids]}
    `result` is `None` when the ref matched no collected testcase (not run in
    the reports we have); otherwise it is the aggregate over every matching
    case, worst result winning (a class-level ref is Failed if any of its
    methods failed).
    """
    out = []
    for ref in _test_refs(control):
        matched = {n: r for n, r in junit.items() if _matches(ref, n)}
        if not matched:
            out.append({"ref": ref, "result": None, "cases": []})
            continue
        agg = min(matched.values(), key=_WORST_FIRST.index)
        out.append({"ref": ref, "result": agg, "cases": sorted(matched)})
    return out


def _ref_file(ref):
    return ref.split("::", 1)[0]


def ref_file_present(ref, junit):
    """True if the ref's test *file* contributed any case to the reports.

    Lets us separate a genuinely **broken** ref (its file ran, but the
    class/method qualifier matches nothing — a stale binding) from one that is
    merely **not run** (the whole file is absent from this report set because
    its pipeline section didn't execute).
    """
    prefix = _ref_file(ref) + ".py::" if not _ref_file(ref).endswith(".py") \
        else _ref_file(ref) + "::"
    return any(n.startswith(prefix) for n in junit)


def binding_report(control, junit):
    """Per-ref binding health: resolved | not-run | broken.

    * resolved - matched ≥1 real testcase
    * broken   - the ref's file ran but the ref matched nothing (stale ref)
    * not-run  - the ref's file is absent from the report set (section not run)
    """
    out = []
    for b in resolve_binding(control, junit):
        if b["cases"]:
            state = "resolved"
        elif ref_file_present(b["ref"], junit):
            state = "broken"
        else:
            state = "not-run"
        out.append({**b, "state": state})
    return out


def binding_is_complete(control, junit):
    """All of a control's test refs resolve to at least one real testcase."""
    return all(b["cases"] for b in resolve_binding(control, junit))
