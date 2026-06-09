"""
Tier2 conftest: terraform fixtures for VMware IaC tests.
"""
import os
import subprocess
import sys
import pytest

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "tier0")))

VMWARE_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
TF_DIR     = os.path.join(VMWARE_DIR, "deploy", "terraform")

@pytest.fixture(scope="session")
def vmware_dir():
    return VMWARE_DIR

@pytest.fixture(scope="session")
def src_dir():
    return os.path.join(VMWARE_DIR, "src")

@pytest.fixture(scope="session")
def tf_dir():
    return TF_DIR

@pytest.fixture(scope="session")
def tf_src(tf_dir):
    """Concatenate all .tf files in the terraform directory."""
    parts = []
    for name in sorted(os.listdir(tf_dir)):
        if name.endswith(".tf"):
            with open(os.path.join(tf_dir, name)) as f:
                parts.append(f.read())
    return "\n".join(parts)

@pytest.fixture(scope="session")
def _plugin_cache(tf_dir, tmp_path_factory):
    """
    Run `terraform init -backend=false` once per session into a shared plugin
    cache directory so individual test functions do not need network access.
    """
    cache = str(tmp_path_factory.mktemp("tf_plugin_cache"))
    env = {**os.environ, "TF_PLUGIN_CACHE_DIR": cache}
    result = subprocess.run(
        ["terraform", "init", "-backend=false", "-no-color"],
        cwd=tf_dir,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        pytest.fail(f"terraform init failed:\n{result.stdout}\n{result.stderr}")
    return cache