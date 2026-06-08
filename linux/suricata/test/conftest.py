"""Shared pytest fixtures for the suricata test workbench."""
import os
import sys
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
NEXUS_TOML = os.path.normpath(
    os.path.join(REPO_ROOT, "..", "..", "project_empros", "services", "config", "nexus.toml")
)

sys.path.insert(0, TEST_DIR)
sys.path.insert(0, os.path.join(TEST_DIR, "tier0"))

@pytest.fixture(scope="session")
def repo_root():
    return REPO_ROOT

@pytest.fixture(scope="session")
def nexus_toml_path():
    assert os.path.isfile(NEXUS_TOML), f"central contract not found at {NEXUS_TOML}"
    return NEXUS_TOML

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "tier0: pure-Python transmission-layer & schema-contract tests (no containers)"
    )