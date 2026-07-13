"""
Containment capability contract loader.

Reads operations/infra/capability_matrix.toml, the single source of truth for
which containment actions are executable for a given (target_class, environment).
The containment planner consults this so it never plans an action no executor can
run, and the per-entity assurance gate reads each action's certainty_floor.
Pure / stdlib-only (tomllib).
"""
from __future__ import annotations

import tomllib
from pathlib import Path

DEFAULT_MATRIX = (Path(__file__).resolve().parents[3]
                  / "operations" / "infra" / "capability_matrix.toml")

# Ordered assurance levels: an action fires autonomously only if the entity's
# certainty is at or above the action's certainty_floor.
CERTAINTY_ORDER = {"malicious": 0, "corroborated": 1, "confirmed": 2}
_REQUIRED_FIELDS = ("target_class", "environment", "action", "executor",
                    "wave", "certainty_floor")


def load_capabilities(path=None) -> dict:
    """Return {(target_class, environment, action): entry} from the matrix toml."""
    raw = tomllib.loads(Path(path or DEFAULT_MATRIX).read_text())
    caps = {}
    for e in raw.get("capability", []):
        caps[(e["target_class"], e["environment"], e["action"])] = e
    return caps


def capability(caps: dict, target_class: str, environment: str, action: str):
    return caps.get((target_class, environment, action))


def actions_for(caps: dict, target_class: str, environment: str) -> list:
    """Executable actions for a (target_class, environment), wave then name ordered."""
    hits = [(k[2], e) for k, e in caps.items()
            if k[0] == target_class and k[1] == environment]
    return [a for a, _ in sorted(hits, key=lambda x: (x[1].get("wave", 1), x[0]))]


def is_executable(caps: dict, target_class: str, environment: str, action: str) -> bool:
    return (target_class, environment, action) in caps


def meets_floor(entity_certainty: str, floor: str) -> bool:
    """True if the entity's certainty is at or above the action's certainty floor."""
    return CERTAINTY_ORDER.get(entity_certainty, -1) >= CERTAINTY_ORDER.get(floor, 99)


def validate_capabilities(caps: dict) -> list:
    """Structural errors in the matrix: missing fields, bad certainty, bad reversible_by."""
    errs = []
    actions_by_te = {}
    for (tc, env, act), e in caps.items():
        actions_by_te.setdefault((tc, env), set()).add(act)
        for f in _REQUIRED_FIELDS:
            if f not in e:
                errs.append(f"{tc}/{env}/{act}: missing field {f}")
        if e.get("certainty_floor") not in CERTAINTY_ORDER:
            errs.append(f"{tc}/{env}/{act}: bad certainty_floor {e.get('certainty_floor')!r}")
        if e.get("wave") not in (1, 2):
            errs.append(f"{tc}/{env}/{act}: wave must be 1 or 2")
    for (tc, env, act), e in caps.items():
        rb = e.get("reversible_by")
        if rb and rb not in actions_by_te.get((tc, env), set()):
            errs.append(f"{tc}/{env}/{act}: reversible_by {rb!r} not executable for {tc}/{env}")
    return errs
