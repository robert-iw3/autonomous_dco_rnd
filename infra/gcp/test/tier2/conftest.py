"""Tier-2 fixtures: locate each connector's deploy/ IaC.
Inherits the session-scoped `connector_dir` param (audit/scc/vpc)
from the workbench root conftest.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "tier2: deploy/ IaC validation -- runtime-contract, posture, and "
        "convergence tests (containerized; terraform + scanners)",
    )

def _find_tf_dir(deploy_dir):
    for cand in (os.path.join(deploy_dir, "terraform"), deploy_dir):
        if os.path.isdir(cand) and any(f.endswith(".tf") for f in os.listdir(cand)):
            return cand
    return None

@pytest.fixture
def connector_name(connector_dir):
    return os.path.basename(connector_dir)

@pytest.fixture
def deploy_dir(connector_dir):
    d = os.path.join(connector_dir, "deploy")
    if not os.path.isdir(d):
        pytest.skip(f"{os.path.basename(connector_dir)}: no deploy/ directory")
    return d

@pytest.fixture
def tf_dir(deploy_dir, connector_name):
    d = _find_tf_dir(deploy_dir)
    if not d:
        pytest.skip(f"{connector_name}: no Terraform (*.tf) under deploy/")
    return d

@pytest.fixture
def tf_src(tf_dir):
    import _iac_parse as P
    return P.read_tf(tf_dir)

@pytest.fixture(scope="session")
def _plugin_cache(tmp_path_factory):
    # Share provider downloads across audit/scc/vpc to avoid re-pulling
    # the google provider on every init.
    d = tmp_path_factory.mktemp("tf_plugin_cache")
    return str(d)