"""Shared pytest fixtures for the Azure connector (nsg/activity/entraid) test workbench."""
import os
import sys
import pytest

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
AZURE_DIR = os.path.dirname(TEST_DIR)
NEXUS_TOML = os.path.join(REPO_ROOT, "project_empros", "services", "config", "nexus.toml")

sys.path.insert(0, TEST_DIR)
sys.path.insert(0, os.path.join(TEST_DIR, "tier0"))

@pytest.fixture(scope="session")
def repo_root():
    return REPO_ROOT

@pytest.fixture(scope="session")
def azure_dir():
    return AZURE_DIR

@pytest.fixture(scope="session", params=["nsg", "activity", "entraid"])
def connector_dir(request, azure_dir):
    """Each of the three connector crates -- transmitter.rs is byte-identical
    across all three (confirmed via diff) and config.rs/cache.rs differ only
    in per-connector fields/literals; transformer.rs differs per event
    source. Parametrizing lets the shared wire-contract tests run once per
    crate without duplication."""
    return os.path.join(azure_dir, request.param)

@pytest.fixture(scope="session")
def nexus_toml_path():
    assert os.path.isfile(NEXUS_TOML), f"central contract not found at {NEXUS_TOML}"
    return NEXUS_TOML

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "tier0: pure-Python schema-contract & transmission-layer tests (no containers)"
    )