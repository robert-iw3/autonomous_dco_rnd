#!/usr/bin/env python3
"""
Track the platform's contract surface, so its changes reach this stack deliberately.

The DFIR platform is developed on its own track and changes constantly. Almost none of
that matters here — but a handful of things do, because the projection contract is
expressed in the platform's own terms: its verdict ladder, and the model fields the
projection mirrors. If either moves and this stack does not notice, the failure is silent
in the worst way. Findings still arrive, still validate, and mean something slightly
different than they did.

So the contract surface is **pinned**. This tool reads a platform checkout, extracts that
surface, and diffs it against `platform_baseline.json`. Drift is classified, because most
of it is noise:

  **contract-affecting**  the verdict ladder changed, or a field the projection maps was
                          renamed or removed, or the platform's ladder and the toolkit's
                          ladder have diverged from each other. `--check` exits nonzero.

  **incidental**          new fields, new routes, new models the projection does not touch.
                          Reported so the next contract revision has somewhere to start.

The platform tree is opened **read-only and never written**. It is a source to copy from,
not a place this repo edits — and it is parsed with `ast`, never imported, so reading it
requires none of its dependencies and executes none of its code.

Usage:
    python platform_drift.py                 # report drift against the pinned baseline
    python platform_drift.py --check         # CI: exit 1 on contract-affecting drift
    python platform_drift.py --update        # re-pin after a reviewed contract change
    python platform_drift.py --platform PATH # a checkout somewhere other than the default
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASELINE = HERE / "platform_baseline.json"

DEFAULT_PLATFORM = os.environ.get(
    "DFIR_PLATFORM_PATH", str(Path.home() / "Documents" / "DFIR_PLATFORM_DEV"))

# The files that carry the contract surface, relative to the platform checkout root.
TOOLKIT_SCHEMA = "toolkit/playbooks/reporting/finding_schema.py"
BACKEND_MODELS = "platform/backend/cases/models.py"
BACKEND_URLS = "platform/backend/cases/urls.py"

# The models the projection reads from, and the fields of each it actually maps. A field
# listed here disappearing or being renamed breaks the projection; anything else on these
# models is incidental.
MAPPED_FIELDS = {
    "Investigation": {"incident_id", "name", "status"},
    "Host": {"hostname", "machine_id", "platform"},
    "CollectionRun": {"stamp", "toolkit_version", "overall_status", "tp_count",
                      "custody_verified", "collected_at", "run_kind", "compromised"},
    "Finding": {"finding_type", "target", "verdict", "confidence", "mitre", "tier", "source"},
    "MemoryFinding": {"finding_type", "severity"},
}


class PlatformNotFound(FileNotFoundError):
    pass


# ── extraction (ast only — the platform is never imported) ───────────────────
def _parse(root: Path, rel: str) -> ast.Module:
    path = root / rel
    if not path.is_file():
        raise PlatformNotFound(f"{rel} not found under {root}")
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _string_tuple(tree: ast.Module, name: str) -> list:
    """A module-level `NAME = ("a", "b", ...)` as a list of strings ([] if absent)."""
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            continue
        if isinstance(node.value, (ast.Tuple, ast.List)):
            return [e.value for e in node.value.elts if isinstance(e, ast.Constant)
                    and isinstance(e.value, str)]
    return []


def _model_fields(tree: ast.Module) -> dict:
    """Django model classes -> the field names they declare. A field is an assignment whose
    value is a call on the `models` module, which is what a Django field always is."""
    out = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        fields = set()
        for stmt in node.body:
            if not isinstance(stmt, ast.Assign) or not isinstance(stmt.value, ast.Call):
                continue
            func = stmt.value.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                    and func.value.id == "models":
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        fields.add(target.id)
        if fields:
            out[node.name] = sorted(fields)
    return out


def _routes(tree: ast.Module) -> list:
    """Route strings from `path("...", ...)` and `router.register("...", ...)`."""
    routes = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name not in ("path", "register"):
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            routes.add(first.value)
    return sorted(routes)


def fingerprint(platform_root) -> dict:
    """The contract surface of a platform checkout."""
    root = Path(platform_root).expanduser()
    if not root.is_dir():
        raise PlatformNotFound(f"platform checkout not found: {root}")
    toolkit = _parse(root, TOOLKIT_SCHEMA)
    models = _parse(root, BACKEND_MODELS)
    urls = _parse(root, BACKEND_URLS)
    all_fields = _model_fields(models)
    return {
        "toolkit_verdicts": _string_tuple(toolkit, "VERDICTS"),
        "backend_verdicts": _string_tuple(models, "VERDICTS"),
        "models": {name: all_fields.get(name, []) for name in sorted(MAPPED_FIELDS)},
        "routes": _routes(urls),
    }


# ── diff + classification ────────────────────────────────────────────────────
def compare(baseline: dict, current: dict) -> dict:
    """Classify the difference. `affecting` is what breaks the projection; `incidental` is
    everything else that moved, reported so it is visible rather than discovered later."""
    affecting, incidental = [], []

    # The two ladders must match each other before either is compared to the baseline: a
    # divergence between the toolkit and the backend is a defect in the platform, and the
    # projection would inherit it as inconsistent verdicts.
    if current["toolkit_verdicts"] != current["backend_verdicts"]:
        affecting.append(
            "the platform's two verdict ladders have diverged: "
            f"toolkit={current['toolkit_verdicts']} backend={current['backend_verdicts']}")

    for key in ("toolkit_verdicts", "backend_verdicts"):
        if baseline.get(key) != current.get(key):
            affecting.append(
                f"{key} changed: {baseline.get(key)} -> {current.get(key)}")

    for model, mapped in sorted(MAPPED_FIELDS.items()):
        was = set(baseline.get("models", {}).get(model, []))
        now = set(current.get("models", {}).get(model, []))
        if not now:
            affecting.append(f"model {model} no longer found in the platform's models")
            continue
        missing = sorted(mapped - now)
        if missing:
            affecting.append(
                f"{model}: field(s) the projection maps are gone: {', '.join(missing)}")
        removed = sorted((was - now) - set(missing))
        if removed:
            incidental.append(f"{model}: field(s) removed (unmapped): {', '.join(removed)}")
        added = sorted(now - was)
        if added:
            incidental.append(f"{model}: field(s) added: {', '.join(added)}")

    was_routes, now_routes = set(baseline.get("routes", [])), set(current.get("routes", []))
    if was_routes - now_routes:
        incidental.append(f"routes removed: {', '.join(sorted(was_routes - now_routes))}")
    if now_routes - was_routes:
        incidental.append(f"routes added: {', '.join(sorted(now_routes - was_routes))}")

    return {"affecting": affecting, "incidental": incidental}


def load_baseline() -> dict:
    if not BASELINE.is_file():
        return {}
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def write_baseline(current: dict) -> None:
    BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--platform", default=DEFAULT_PLATFORM,
                    help=f"platform checkout to read (default: {DEFAULT_PLATFORM})")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 on contract-affecting drift (CI)")
    ap.add_argument("--update", action="store_true",
                    help="re-pin the baseline after a reviewed contract change")
    args = ap.parse_args(argv)

    try:
        current = fingerprint(args.platform)
    except PlatformNotFound as e:
        # Not a failure in CI: most runners have no platform checkout, and the pinned
        # baseline is what the contract tests assert against.
        print(f"platform drift: {e}", file=sys.stderr)
        return 0 if not args.update else 2

    if args.update:
        write_baseline(current)
        print(f"platform baseline re-pinned from {args.platform}")
        return 0

    baseline = load_baseline()
    if not baseline:
        write_baseline(current)
        print(f"platform baseline created from {args.platform}")
        return 0

    result = compare(baseline, current)
    for line in result["affecting"]:
        print(f"CONTRACT-AFFECTING: {line}")
    for line in result["incidental"]:
        print(f"incidental: {line}")
    if not result["affecting"] and not result["incidental"]:
        print(f"platform contract surface unchanged ({args.platform})")

    if result["affecting"]:
        print("\nThe projection contract no longer matches the platform. Review "
              "integrations/dfir_platform/PROJECTION-CONTRACT.md, update contract.py, then "
              "re-pin with --update.", file=sys.stderr)
        return 1 if args.check else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
