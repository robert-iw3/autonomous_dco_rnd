"""Shared pytest fixtures for the DeepXDR test workbench."""

import os
import sys
import pytest

# Make tier0 importable from any test file
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tier0"))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_INI = os.path.join(REPO_ROOT, "agent", "DeepXDR_Config.ini")


@pytest.fixture(scope="session")
def config_ini_path():
    """Absolute path to DeepXDR_Config.ini."""
    assert os.path.exists(CONFIG_INI), f"DeepXDR_Config.ini not found at {CONFIG_INI}"
    return CONFIG_INI


@pytest.fixture(scope="session")
def parsed_config(config_ini_path):
    """Pre-parsed configparser instance of DeepXDR_Config.ini."""
    import configparser
    cfg = configparser.ConfigParser(strict=False)
    cfg.read(config_ini_path)
    return cfg


def pytest_configure(config):
    config.addinivalue_line("markers", "tier0: pure-Python logic tests (no containers)")
    config.addinivalue_line("markers", "tier4: driver IPC contract tests")
