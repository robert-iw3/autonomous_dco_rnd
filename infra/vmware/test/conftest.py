"""
Root conftest: shared path fixtures for all VMware test tiers.
"""
import os
import sys
import pytest

REPO_ROOT  = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
TEST_DIR   = os.path.dirname(os.path.abspath(__file__))
VMWARE_DIR = os.path.dirname(TEST_DIR)

# Make the tier0 logic mirror importable from all tiers.
sys.path.insert(0, TEST_DIR)
sys.path.insert(0, os.path.join(TEST_DIR, "tier0"))

@pytest.fixture(scope="session")
def vmware_dir():
    return VMWARE_DIR

@pytest.fixture(scope="session")
def src_dir(vmware_dir):
    return os.path.join(vmware_dir, "src")

@pytest.fixture(scope="session")
def deploy_dir(vmware_dir):
    return os.path.join(vmware_dir, "deploy")