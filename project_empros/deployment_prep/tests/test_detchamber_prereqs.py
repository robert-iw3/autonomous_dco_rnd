"""
deployment_prep -- Det Chamber air-gap prerequisites.

The Det Chamber pulls in software the offline bundle must stage: engine + intake
Python wheels, the WinRM/libvirt ansible collections, the engine/intake container
base + custom images, and -- the real air-gap blocker -- the external Windows
analysis tools (Procmon/CAPA/YARA/Volatility/INetSim) and YARA rule repos that the
engine Dockerfile otherwise fetches from the internet at build time.

These assert the canonical prep manifests cover the Det Chamber so an air-gapped
install has everything it needs.
"""

import json
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

PREP = Path(__file__).resolve().parent.parent
PYREQ = (PREP / "python_requirements.txt").read_text().lower()
ANSIBLE = yaml.safe_load((PREP / "ansible_requirements.yml").read_text())
MANIFEST = json.loads((PREP / "image_manifest.json").read_text())
ASSETS = PREP / "detchamber_assets.json"


# --- Python wheels -----------------------------------------------------------
@pytest.mark.parametrize("pkg", [
    "pefile", "yara-python", "pywin32",         # engine static analysis (Windows)
    "prometheus-client",                        # intake /metrics (PyPI dist name)
    "volatility3",                              # memory analysis
])
def test_python_requirements_has_detchamber_deps(pkg):
    assert pkg in PYREQ, f"python_requirements.txt must stage Det Chamber dep: {pkg}"


def test_python_requirements_has_intake_runtime():
    # intake service runtime (these may be shared with other components)
    for pkg in ("nats-py", "boto3"):
        assert pkg in PYREQ


# --- Ansible collections -----------------------------------------------------
def test_ansible_has_windows_and_libvirt_collections():
    names = {c["name"] for c in ANSIBLE.get("collections", [])}
    assert "ansible.windows" in names, "det_chamber_sandbox role uses ansible.windows (WinRM)"
    assert "community.libvirt" in names, "det_chamber_linux KVM sandbox uses community.libvirt"


# --- Container images --------------------------------------------------------
def test_manifest_has_engine_base_image():
    bases = " ".join(i.get("repo", "") for i in MANIFEST.get("build_base_images", []))
    assert "servercore" in bases, "Windows engine base image (servercore) must be staged"


def test_manifest_has_detchamber_custom_images():
    names = {i.get("name") for i in MANIFEST.get("custom_images", [])}
    assert "detchamber-engine" in names and "detchamber-intake" in names, \
        "both det_chamber images must be in custom_images"


# --- External analysis assets (the air-gap blocker) --------------------------
def test_detchamber_assets_manifest_exists_and_valid():
    assert ASSETS.exists(), "deployment_prep/detchamber_assets.json must list the external assets"
    json.loads(ASSETS.read_text())


def test_detchamber_assets_cover_yara_rules_and_tools():
    blob = ASSETS.read_text().lower()
    # YARA rule repos the engine Dockerfile clones online
    assert "reversinglabs" in blob and "protections-artifacts" in blob
    # Windows analysis toolset download_tools.ps1 fetches online
    for tool in ("procmon", "capa", "yara", "volatility", "inetsim"):
        assert tool in blob, f"asset manifest must stage the {tool} tooling for air-gap"
