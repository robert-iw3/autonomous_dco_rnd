"""
Report-coverage governance test (host-only).

Enforces the invariant: **every test file under tests/ produces a report in
tests/reports/** — i.e. it is either executed by a report-emitting section
runner (a `Dockerfile.*` CMD or the Det Chamber compose, each of which passes
`--junit-xml=/reports/<section>.xml`), or it is explicitly listed as a
live-infra / host-only test that the offline CI sections intentionally skip.

This makes orphaned tests (run by nobody → no report) a hard failure instead of
a silent gap. It reads the section definitions from disk, so it only runs on the
host (the Dockerfiles are not copied into the section images); inside a container
it skips cleanly.
"""
import re
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent
DOCKERFILES = sorted(TESTS_DIR.glob("Dockerfile.*"))
DETCHAMBER_COMPOSE = TESTS_DIR / "lab_det_chamber" / "docker-compose.yml"

# Tests intentionally NOT in any offline CI section. Each runs only against live
# infrastructure (or is a host-only meta-test) and still emits a report via
# conftest.py / its own runner when executed. Keep this list tight and justified.
LIVE_OR_HOST = {
    "lab_nats_ingress/test_ingress_pipeline.py",      # live NATS
    "lab_qdrant_pipeline/test_qdrant_pipeline.py",    # live NATS + Qdrant
    "lab_middleware/test_middleware_etl.py",          # live ingress + NATS (compose lab)
    "test_model_regression.py",                       # live vLLM endpoint
    "test_report_coverage.py",                        # this host-only meta-test
}

def _covered_tokens() -> set:
    """Every `tests/...` path token a section *runs* — parsed only from the
    pytest invocation arrays (Dockerfile `CMD [...]` / compose `command: [...]`),
    never from COPY lines or build comments."""
    tokens = set()
    for df in DOCKERFILES:
        for block in re.findall(r'CMD\s*\[(.*?)\]', df.read_text(), re.DOTALL):
            for t in re.findall(r'"(tests/[^"]+)"', block):
                tokens.add(t.rstrip("/"))
    if DETCHAMBER_COMPOSE.exists():
        for block in re.findall(r'command:\s*\[(.*?)\]', DETCHAMBER_COMPOSE.read_text(), re.DOTALL):
            for t in re.findall(r'"(tests/[^"]+)"', block):
                tokens.add(t.rstrip("/"))
    return tokens


def _all_test_files() -> list:
    files = []
    for p in TESTS_DIR.rglob("test_*.py"):
        if "__pycache__" in p.parts:
            continue
        files.append(p.relative_to(TESTS_DIR).as_posix())
    return sorted(files)


def _is_covered(rel: str, tokens: set) -> bool:
    full = f"tests/{rel}"
    if full in tokens:                      # exact file reference
        return True
    # directory-prefix reference, e.g. token "tests/sensors" covers
    # "sensors/test_x.py"
    for tok in tokens:
        if not tok.endswith(".py") and (full == tok or full.startswith(tok + "/")):
            return True
    return False


@pytest.fixture(scope="module")
def section_tokens():
    if not DOCKERFILES:
        pytest.skip("section Dockerfiles not present (running inside a container image)")
    return _covered_tokens()


def test_every_test_file_lands_in_a_section(section_tokens):
    orphans = []
    for rel in _all_test_files():
        if rel in LIVE_OR_HOST:
            continue
        if not _is_covered(rel, section_tokens):
            orphans.append(rel)
    assert not orphans, (
        "These test files are run by no report-emitting section (so they produce "
        "no report in tests/reports/). Add them to a Dockerfile.* CMD, or to "
        "LIVE_OR_HOST with justification:\n  " + "\n  ".join(orphans)
    )


def test_live_exclusions_actually_exist(section_tokens):
    # guard against the exclusion list rotting (referencing a deleted test)
    missing = [rel for rel in LIVE_OR_HOST if not (TESTS_DIR / rel).exists()]
    assert not missing, f"LIVE_OR_HOST references nonexistent tests: {missing}"


def test_live_exclusions_are_not_silently_covered(section_tokens):
    # if a "live" test is in fact wired into a section, it should leave the list
    wrongly = [rel for rel in LIVE_OR_HOST
               if rel != "test_report_coverage.py" and _is_covered(rel, section_tokens)]
    assert not wrongly, (
        f"these are listed LIVE_OR_HOST but ARE wired into a section -- remove "
        f"them from LIVE_OR_HOST: {wrongly}")


def test_each_section_emits_a_junit_report():
    if not DOCKERFILES:
        pytest.skip("section Dockerfiles not present")
    missing = []
    for df in DOCKERFILES:
        text = df.read_text()
        if "pytest" not in text:
            continue
        if "--junit-xml=/reports/" not in text:
            missing.append(df.name)
    # Det Chamber runs via compose, assert separately
    if DETCHAMBER_COMPOSE.exists() and "--junit" not in DETCHAMBER_COMPOSE.read_text():
        missing.append(DETCHAMBER_COMPOSE.name)
    assert not missing, f"section runners with no --junit-xml=/reports/ output: {missing}"
