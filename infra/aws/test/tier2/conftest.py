"""Tier-2 fixtures: locate each connector's deploy/ IaC and (for the
convergence layer) a moto endpoint. Inherits the session-scoped `connector_dir`
param (vpc/cloudtrail/guardduty) from the workbench root conftest.
"""
import os
import socket
import subprocess
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "tier2: deploy/ IaC validation -- runtime-contract, posture, and "
        "emulated-convergence tests (containerized; terraform + moto + scanners)",
    )

# --- deploy-path discovery -------------------------------------------------

def _find_tf_dir(deploy_dir):
    """A dir containing *.tf -- either deploy/terraform or deploy/ itself."""
    for cand in (os.path.join(deploy_dir, "terraform"), deploy_dir):
        if os.path.isdir(cand) and any(f.endswith(".tf") for f in os.listdir(cand)):
            return cand
    return None

def _find_cfn_file(deploy_dir):
    cfn_dir = os.path.join(deploy_dir, "cloudformation")
    search = cfn_dir if os.path.isdir(cfn_dir) else deploy_dir
    if os.path.isdir(search):
        for f in sorted(os.listdir(search)):
            if f.endswith((".yaml", ".yml")):
                return os.path.join(search, f)
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

@pytest.fixture
def cfn_file(deploy_dir, connector_name):
    f = _find_cfn_file(deploy_dir)
    if not f:
        pytest.skip(f"{connector_name}: no CloudFormation template under deploy/")
    return f

@pytest.fixture
def cfn_doc(cfn_file):
    import _iac_parse as P
    return P.load_cfn(cfn_file)

# --- moto server (convergence layer) ---------------------------------------

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture(scope="session")
def moto_endpoint():
    """Start a moto standalone server for the session and yield its URL."""
    import shutil
    if not shutil.which("moto_server") and not _module_exists("moto"):
        pytest.skip("moto not installed (present in the tier2 container)")

    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "moto.server", "-p", str(port), "-H", "127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail("moto server did not come up")
    try:
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

def _module_exists(name):
    import importlib.util
    return importlib.util.find_spec(name) is not None