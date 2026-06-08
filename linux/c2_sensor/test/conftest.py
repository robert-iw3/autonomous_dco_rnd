"""Shared pytest fixtures for the c2_sensor test workbench."""
import os
import sys
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_ENGINE = os.path.join(REPO_ROOT, "python_engine")

sys.path.insert(0, PYTHON_ENGINE)
sys.path.insert(0, os.path.dirname(__file__))

@pytest.fixture(scope="session")
def repo_root():
    return REPO_ROOT

@pytest.fixture(scope="session")
def python_engine_dir():
    return PYTHON_ENGINE

def pytest_configure(config):
    config.addinivalue_line("markers", "tier0: pure-Python algorithm & transmission-layer tests (no containers)")