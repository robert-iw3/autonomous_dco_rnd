"""
Project-wide pytest configuration for the Nexus test suite.

Guarantee: **every** pytest session under tests/ writes a JUnit XML report into
tests/reports/. The docker section runners pass an explicit
`--junit-xml=/reports/<section>.xml`, which is respected as-is; any other
invocation (host pytest, ad-hoc single-file runs, CI one-offs) gets a report
auto-assigned here, named from the selected test path(s). No test can run
without producing a report artifact.
"""
import os
import re
from pathlib import Path

import pytest

REPORTS_DIR = Path(__file__).parent / "reports"


def _slug_from_args(args) -> str:
    """Build a filesystem-safe report name from the selected test path(s).

    Only real test selectors count — a path that exists, ends in `.py`, or
    contains a path separator. Option values (e.g. the `no:cacheprovider` after
    `-p`) are ignored so they never leak into the report name.
    """
    parts = []
    for a in args:
        if a.startswith("-"):
            continue
        target = a.split("::")[0]                 # drop ::TestClass::test_x
        if not (target.endswith(".py") or "/" in target or os.path.exists(target)):
            continue
        name = Path(target).name or Path(target).parts[-1]
        name = re.sub(r"\.py$", "", name)
        if name and name not in parts:
            parts.append(name)
    slug = "+".join(parts) if parts else "session"
    slug = re.sub(r"[^A-Za-z0-9_.+-]", "_", slug)
    return slug[:80] or "session"


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    # tryfirst so this runs before the builtin junitxml plugin's pytest_configure,
    # which instantiates LogXML from config.option.xmlpath.
    if getattr(config.option, "xmlpath", None):
        return  # explicit --junit-xml already requested (docker sections / CI)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    slug = _slug_from_args(config.invocation_params.args)
    config.option.xmlpath = str(REPORTS_DIR / f"{slug}.xml")
