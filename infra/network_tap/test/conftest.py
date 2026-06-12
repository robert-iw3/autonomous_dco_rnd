"""Shared fixtures for the network_tap infrastructure + deployment workbench.

Validates the *stack* (Arkime sensor → Redpanda → ML gateway → OpenSearch +
Nexus), not just the gateway crate (that is `gateway/test/`). Pure Python: it
parses the real compose / config / scripts and asserts the security, performance,
interoperability, and PCAP-retention contracts.
"""

import os
import sys
from pathlib import Path

import pytest

NETWORK_TAP = Path(__file__).resolve().parents[1]        # infra/network_tap
INFRA = NETWORK_TAP / "infrastructure"
DEPLOY = NETWORK_TAP / "deployment"
GATEWAY = NETWORK_TAP / "gateway"

# Make the gateway logic mirror importable for interop cross-checks.
sys.path.insert(0, str(GATEWAY / "test" / "tier0"))


def read(p: Path) -> str:
    return p.read_text()


@pytest.fixture(scope="session")
def paths():
    return {
        "compose": INFRA / "core_services" / "docker-compose.yml",
        "opensearch_yml": INFRA / "core_services" / "opensearch.yml",
        "ism": INFRA / "core_services" / "opensearch_index.json",
        "bootstrap": INFRA / "core_services" / "bootstrap_os.sh",
        "env_example": INFRA / "core_services" / ".env.example",
        "arkime_ini": INFRA / "sensor_node" / "config.ini",
        "startarkime": INFRA / "sensor_node" / "startarkime.sh",
        "pcap_retention": INFRA / "sensor_node" / "pcap_retention.sh",
        "sensor_dockerfile": INFRA / "sensor_node" / "Dockerfile",
        "host_tuning": DEPLOY / "01_host_tuning.sh",
        "firewall": DEPLOY / "multi_vm" / "firewall_rules.sh",
        "gateway_toml": GATEWAY / "config.toml",
    }


def pytest_configure(config):
    config.addinivalue_line("markers", "tier0: pure-Python infra/deploy posture & interop tests")
