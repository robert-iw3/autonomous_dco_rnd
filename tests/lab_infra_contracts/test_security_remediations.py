"""
Threat-model remediation contracts (config layer).

  F-13  NATS account passwords have no weak inline fallback (fail closed on unset vault).
  F-14  Qdrant requires an api_key; the swarm clients send one.
  F-15  Redis requires a password (defense in depth atop port 0 + socket perm 700).
  F-17  the misleading static NATS sample is banner-marked NOT DEPLOYED.
"""
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
NATS_TPL = ROOT / "infrastructure/ansible/roles/nats_node/templates/nats-server.conf.j2"
NATS_SAMPLE = ROOT / "infrastructure/nats/nats-server.conf"
QDRANT_TPL = ROOT / "infrastructure/ansible/roles/qdrant_node/templates/qdrant-bare-metal-config.yaml.j2"
REDIS_TPL = ROOT / "infrastructure/redis/redis.conf.j2"
AGENTS = ROOT / "analytics/llm_hunter/agents"


def test_f13_nats_passwords_have_no_weak_default():
    t = NATS_TPL.read_text()
    assert "vault_nats_ingress_pass" in t, "template must still template the vault vars"
    assert "_replace_me" not in t, "weak inline password defaults must be removed"
    # no password line falls back via `| default(...)`
    for line in t.splitlines():
        if "password:" in line and "vault_nats_" in line:
            assert "default(" not in line, f"password must fail closed, not default: {line.strip()}"


def test_f14_qdrant_requires_api_key():
    t = QDRANT_TPL.read_text()
    assert "api_key:" in t and "vault_qdrant_api_key" in t


def test_f14_swarm_qdrant_clients_send_api_key():
    for f in ("response.py", "supervisor.py"):
        src = (AGENTS / f).read_text()
        assert "AsyncQdrantClient(" in src
        assert 'api_key=os.getenv("QDRANT_API_KEY")' in src, f"{f} must pass the Qdrant api_key"


def test_f15_redis_requires_password():
    t = REDIS_TPL.read_text()
    assert "requirepass" in t and "vault_redis_password" in t


def test_f17_static_nats_sample_marked_not_deployed():
    t = NATS_SAMPLE.read_text()
    assert "NOT DEPLOYED" in t and "nats_node/templates/nats-server.conf.j2" in t
