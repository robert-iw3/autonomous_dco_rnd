"""Shared pytest fixtures for the sysmon_sensor test workbench."""

import os
import sys
import pytest

SENSOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT  = os.path.dirname(os.path.dirname(SENSOR_DIR))

sys.path.insert(0, SENSOR_DIR)
sys.path.insert(0, os.path.dirname(__file__))

@pytest.fixture(scope="session")
def sensor_dir():
    return SENSOR_DIR

@pytest.fixture(scope="session")
def repo_root():
    return REPO_ROOT

@pytest.fixture(scope="session")
def nexus_toml_path():
    return os.path.join(REPO_ROOT, "project_empros", "services", "config", "nexus.toml")

def pytest_configure(config):
    config.addinivalue_line("markers", "tier0: pure-Python algorithm & transmission-layer tests (no containers)")