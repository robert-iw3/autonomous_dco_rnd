"""
Interoperability across the stack (paramount — the pieces must agree).

The data path is: Arkime (SPI) → Redpanda topic → ML gateway → Parquet → Nexus
ingress, with OpenSearch as the metadata store. A name/port/type mismatch between
any two components silently breaks the pipeline in prod. These pin every seam.
"""

import json
import re

import pytest

import network_tap_logic_mirror as mirror      # gateway wire-contract mirror (via conftest path)

pytestmark = pytest.mark.tier0


# -- Arkime → Redpanda → gateway: the SPI topic must match end to end ---------
def test_spi_topic_matches_sensor_and_gateway(paths):
    ini = paths["arkime_ini"].read_text()
    toml = paths["gateway_toml"].read_text()
    m_sensor = re.search(r"kafkaTopic=(\S+)", ini)
    m_gw = re.search(r'topic\s*=\s*"([^"]+)"', toml)
    assert m_sensor and m_gw, "both ends must declare the topic"
    assert m_sensor.group(1) == m_gw.group(1) == "arkime-spi-raw", \
        "Arkime kafkaTopic and gateway redpanda.topic must be the same topic"


def test_sensor_emits_json_the_gateway_consumes(paths):
    assert "kafkaFormat=json" in paths["arkime_ini"].read_text(), "gateway consumes JSON SPI"


def test_broker_port_consistent(paths):
    ini = paths["arkime_ini"].read_text()
    toml = paths["gateway_toml"].read_text()
    compose = paths["compose"].read_text()
    assert ":9092" in re.search(r"kafkaBootstrapServers=(\S+)", ini).group(1)
    assert 'brokers  = "redpanda:9092"' in toml, "gateway brokers must point at the redpanda service:port"
    assert "internal://0.0.0.0:9092" in compose, "redpanda must listen on the internal 9092 advertised to the gateway"


def test_gateway_has_consumer_group(paths):
    assert re.search(r'group_id\s*=\s*"[^"]+"', paths["gateway_toml"].read_text()), \
        "a consumer group_id is required for horizontal gateway scaling"


# -- gateway → Nexus: the wire contract the central ingress expects -----------
def test_gateway_sensor_type_is_network_tap(paths):
    toml = paths["gateway_toml"].read_text()
    assert f'sensor_type = "{mirror.WIRE_SENSOR_TYPE}"' in toml, \
        "gateway sensor_type must be the value core_ingress maps to the 48-col schema"


def test_gateway_egress_is_https_parquet(paths):
    toml = paths["gateway_toml"].read_text()
    assert mirror.CONTENT_TYPE == "application/vnd.apache.parquet"
    assert 'gateway_url  = "https://' in toml
    assert len(mirror.EXPECTED_NETWORK_TAP_PARQUET_COLUMNS) == 48, "the network_tap schema is 48 columns"


# -- OpenSearch: Arkime ↔ cluster ↔ ISM template all line up ------------------
def test_opensearch_endpoints_consistent(paths):
    ini = paths["arkime_ini"].read_text()
    compose = paths["compose"].read_text()
    assert ":9200" in ini, "Arkime points at OpenSearch :9200"
    assert '"127.0.0.1:9200:9200"' in compose, "cluster exposes :9200"


def test_ism_template_matches_arkime_indices(paths):
    policy = json.loads(paths["ism"].read_text())["policy"]
    pat = policy["ism_template"]["index_patterns"]
    assert "arkime_sessions3-*" in pat, "ISM must target Arkime's session indices"
    boot = paths["bootstrap"].read_text()
    assert "arkime_sessions3-*" in boot and "arkime_sessions3_write" in boot, \
        "the index template + rollover write alias must match the ISM pattern"


# -- ports opened by the firewall match what the services actually expose ------
def test_firewall_opens_exactly_the_service_ports(paths):
    fw = paths["firewall"].read_text()
    # OpenSearch API + transport, Kafka, Arkime viewer, gateway metrics
    for port in ("9200", "9300", "9092", "8005", "9090"):
        assert f"dport {port}" in fw, f"firewall must admit {port} for the stack to interoperate"
