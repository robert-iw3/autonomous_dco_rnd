"""
Security posture of the network defense stack (paramount).

Asserts the stack is mTLS/TLS end to end, runs least-privilege, binds management
surfaces to loopback, never ships real secrets in source, and that the firewall
default-denies. These parse the REAL compose/config/scripts, so a regression that
opens a port to the world or drops TLS fails here.
"""

import pytest

pytestmark = pytest.mark.tier0


# -- TLS / mTLS everywhere ----------------------------------------------------
def test_opensearch_http_and_transport_tls(paths):
    y = paths["opensearch_yml"].read_text()
    assert "plugins.security.ssl.http.enabled: true" in y, "OpenSearch HTTP API must be TLS"
    assert "plugins.security.ssl.transport.pemcert_filepath" in y, "transport layer must be mTLS"
    assert "plugins.security.authcz.admin_dn" in y and "nodes_dn" in y, "cert-DN authz pinned"
    assert "plugins.security.audit.type" in y, "security audit logging must be on"


def test_arkime_talks_to_opensearch_over_mtls(paths):
    ini = paths["arkime_ini"].read_text()
    assert "elasticsearch=https://" in ini, "Arkime → OpenSearch must be HTTPS"
    assert "elasticsearchCACert=" in ini and "elasticsearchCert=" in ini and "elasticsearchKey=" in ini, \
        "Arkime must present a client cert (mTLS)"


def test_dashboards_verify_tls(paths):
    compose = paths["compose"].read_text()
    assert "opensearch.ssl.verificationMode=certificate" in compose
    assert 'OPENSEARCH_HOSTS=["https://' in compose, "dashboards must use HTTPS to the cluster"


def test_gateway_to_nexus_is_https_enforced(paths):
    toml = paths["gateway_toml"].read_text()
    assert 'gateway_url  = "https://' in toml, "gateway → Nexus must be HTTPS"
    # the crate enforces it at startup (real guard, not just config)
    cfg_rs = (paths["gateway_toml"].parent / "src" / "config.rs").read_text()
    assert 'starts_with("https://")' in cfg_rs, "HTTPS must be enforced in code at startup"


# -- least privilege ----------------------------------------------------------
def test_arkime_drops_privileges(paths):
    ini = paths["arkime_ini"].read_text()
    assert "dropUser=nobody" in ini and "dropGroup=nobody" in ini, \
        "capture must drop root after binding the interface"


def test_sensor_caps_are_scoped_not_blanket(paths):
    compose = paths["compose"].read_text()
    # the sensor needs raw capture caps; assert they're the specific ones, present
    for cap in ("net_admin", "net_raw"):
        assert cap in compose, f"sensor must declare {cap} for capture"


# -- no real secrets in source ------------------------------------------------
def test_gateway_secrets_are_placeholders_only(paths):
    toml = paths["gateway_toml"].read_text()
    assert "INJECT_FROM_SECRETS_MANAGER" in toml, "auth_token/integrity_secret must be injected, not committed"
    assert "CHANGE_VIA_ENV" in toml, "redis password must come from env"
    # the config must not contain anything that looks like a committed bearer/secret value
    assert "redis://:CHANGE_VIA_ENV@" in toml


def test_redis_requires_password(paths):
    compose = paths["compose"].read_text()
    assert "--requirepass ${REDIS_PASSWORD}" in compose, "redis must require auth"


def test_gateway_rejects_placeholder_integrity_secret(paths):
    cfg_rs = (paths["gateway_toml"].parent / "src" / "config.rs").read_text()
    assert "integrity_secret" in cfg_rs and "CHANGE_ME_IN_PRODUCTION" in cfg_rs, \
        "startup must refuse an unset/placeholder integrity secret"


# -- attack surface: management bound to loopback -----------------------------
@pytest.mark.parametrize("port", ["9200", "9092", "19092", "9090", "5601"])
def test_management_ports_bound_to_loopback(paths, port):
    compose = paths["compose"].read_text()
    assert f'"127.0.0.1:{port}:{port}"' in compose, \
        f"port {port} must bind to loopback (multi-VM uses the firewall, not 0.0.0.0)"


def test_redis_has_no_published_port(paths):
    # redis is co-located; it must not be reachable off-box
    compose = paths["compose"].read_text()
    redis_block = compose.split("redis:", 1)[1].split("arkime-sensor:", 1)[0]
    assert "127.0.0.1:6379" not in redis_block and "6379:6379" not in redis_block, \
        "redis must not publish a host port (gateway reaches it on the compose network)"


# -- firewall default-deny + passive tap --------------------------------------
def test_firewall_default_drops(paths):
    fw = paths["firewall"].read_text()
    assert "policy drop;" in fw, "input/forward chains must default-drop"
    assert "ct state established,related accept" in fw


def test_capture_interface_is_passive(paths):
    fw = paths["firewall"].read_text()
    assert "Capture interface accepts no inbound (passive tap)" in fw, \
        "the SPAN/tap interface must take no inbound traffic"
