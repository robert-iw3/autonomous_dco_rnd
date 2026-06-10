"""
Lab 12b: NATS Cross-Component Contracts (QA C1-C6)
"""
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
SERVICES = PROJECT_ROOT / "services"
ANALYTICS = PROJECT_ROOT / "analytics"
MIDDLEWARE = PROJECT_ROOT / "middleware"
NATS_CONF = (PROJECT_ROOT / "infrastructure/ansible/roles/nats_node"
             / "templates/nats-server.conf.j2")
STREAMS_INIT = PROJECT_ROOT / "infrastructure/nats/streams_init.sh"
WORKER_ENV = (PROJECT_ROOT / "infrastructure/ansible/roles/rust_podman_worker"
              / "templates/worker.env.j2")
HUNTER_ENV = (PROJECT_ROOT / "infrastructure/ansible/roles/nexus_hunter"
              / "templates/hunter.env.j2")
INGRESS_ENV = (PROJECT_ROOT / "infrastructure/ansible/roles/rust_ingress"
               / "templates/ingress.env.j2")


def _conf():
    return NATS_CONF.read_text()


def _user_section(conf: str, user: str) -> str:
    idx = conf.find(f'user: "{user}"')
    assert idx >= 0, f"user {user} missing from nats-server.conf.j2"
    nxt = conf.find("user:", idx + 10)
    return conf[idx: nxt if nxt > 0 else len(conf)]


# ── C1: authorization allowlists cover the code's subjects ───────────────────

class TestNatsAuthorizationCoversCode:
    def test_worker_publish_subjects(self):
        sect = _user_section(_conf(), "worker_node")
        for subj in ("nexus.alerts.math", "nexus.alerts.baseline",
                     "nexus.soar.callback", "nexus.training.rlhf.records",
                     "nexus.dlq.>"):
            assert subj in sect, f"worker_node publish allow missing {subj}"

    def test_worker_subscribe_subjects(self):
        sect = _user_section(_conf(), "worker_node")
        for subj in ("nexus.*.telemetry", "nexus.soar.execute", "nexus.training.rlhf"):
            assert subj in sect, f"worker_node subscribe allow missing {subj}"

    def test_swarm_subjects(self):
        sect = _user_section(_conf(), "swarm_node")
        for subj in ("nexus.soar.execute", "nexus.hud.telemetry", "nexus.alerts.>"):
            assert subj in sect, f"swarm_node allow missing {subj}"

    def test_middleware_user_exists(self):
        sect = _user_section(_conf(), "middleware_node")
        assert "middleware.telemetry.>" in sect
        assert "middleware.dlq.>" in sect

    def test_jetstream_api_permissions(self):
        # JetStream consumers publish to $JS.API.* and subscribe to _INBOX.>;
        # without these the default-deny policy blocks every fetch and ack.
        conf = _conf()
        for user in ("worker_node", "swarm_node", "middleware_node"):
            sect = _user_section(conf, user)
            assert "$JS.API." in sect, f"{user}: no JetStream API publish access"
            assert "_INBOX.>" in sect, f"{user}: no _INBOX.> reply subscription"

    def test_no_legacy_vocabulary(self):
        conf = _conf()
        assert "nexus.qdrant.alerts" not in conf, "legacy subject — nothing publishes it"
        assert "nexus.soar.actions" not in conf, "legacy subject — hunter uses nexus.soar.execute"

    def test_subjects_actually_in_code(self):
        # Vocabulary anti-drift: if these move in code, the contract must move too.
        assert "nexus.alerts.math" in (SERVICES / "worker_qdrant/src/main.rs").read_text()
        assert "nexus.soar.execute" in (SERVICES / "worker_soar/src/main.rs").read_text()
        assert "nexus.training.rlhf.records" in (SERVICES / "worker_rlhf/src/main.rs").read_text()
        hunter = (ANALYTICS / "llm_hunter").rglob("*.py")
        joined = "\n".join(p.read_text() for p in hunter)
        assert "nexus.soar.execute" in joined


# ── C2: every client authenticates ───────────────────────────────────────────

class TestNatsClientAuthentication:
    def test_rust_lib_helper(self):
        src = (PROJECT_ROOT / "libs/lib_siem_core/src/lib.rs").read_text()
        assert "nats_connect" in src and "with_user_and_password" in src

    def test_no_bare_connect_in_workers(self):
        for svc in ("worker_qdrant", "worker_rlhf", "worker_soar",
                    "worker_rules", "worker_s3_archive"):
            main = SERVICES / svc / "src/main.rs"
            if main.exists():
                assert "async_nats::connect(" not in main.read_text(), \
                    f"{svc}: bare connect against a default-deny broker"

    def test_python_clients_read_credentials(self):
        assert "NATS_USER" in (ANALYTICS / "llm_hunter/orchestrator.py").read_text()
        assert "NATS_USER" in (PROJECT_ROOT / "mlops/scripts/serve_baseline.py").read_text()
        assert "NATS_USER" in (SERVICES / "worker_ti_ingest/main.py").read_text()

    def test_env_templates_provision_credentials(self):
        assert "NATS_USER=worker_node" in WORKER_ENV.read_text()
        assert "NATS_USER=swarm_node" in HUNTER_ENV.read_text()
        assert "NATS_USER=ingress_node" in INGRESS_ENV.read_text()

    def test_middleware_quadlets_provision_credentials(self):
        tpl_dir = MIDDLEWARE / "deploy/ansible/templates"
        for tpl in ("middleware-worker.container.j2", "middleware-ingress.container.j2"):
            assert "NATS_USER=middleware_node" in (tpl_dir / tpl).read_text(), tpl

    def test_dead_nkey_seed_removed(self):
        # NATS_NKEY_SEED was provisioned everywhere but read by nothing
        assert "NATS_NKEY_SEED" not in WORKER_ENV.read_text()
        assert "NATS_NKEY_SEED" not in (PROJECT_ROOT / "nexus.env.example").read_text()


# ── C4/C5/C6: stream names agree with streams_init.sh ───────────────────────

class TestStreamNameAgreement:
    def test_streams_init_defines_canonical_streams(self):
        init = STREAMS_INIT.read_text()
        for stream in ("Tier5_Telemetry", "Nexus_SOAR_Execute", "Nexus_RLHF_Training"):
            assert stream in init

    def test_s3_archive_binds_tier5(self):
        src = (SERVICES / "worker_s3_archive/src/main.rs").read_text()
        assert '"Tier5_Telemetry"' in src
        assert "Telemetry_Stream" not in src, \
            "C5: duplicate stream over nexus.*.telemetry is rejected by JetStream"

    def test_soar_binds_soar_stream(self):
        src = (SERVICES / "worker_soar/src/main.rs").read_text()
        assert '"Nexus_SOAR_Execute"' in src, \
            "C4: binding the telemetry stream makes SOAR consumer creation fail"

    def test_rlhf_binds_training_stream(self):
        src = (SERVICES / "worker_rlhf/src/main.rs").read_text()
        assert '"Nexus_RLHF_Training"' in src
        assert "Nexus_RLHF_Records" not in src, \
            "C6: second stream over nexus.training.rlhf.records is rejected"


# ── C7/C8: middleware -> gateway auth chain ──────────────────────────────────

class TestMiddlewareGatewayChain:
    TOML = MIDDLEWARE / "deploy/ansible/templates/middleware.toml.j2"
    MAIN = MIDDLEWARE / "deploy/ansible/main.yml"
    MINT = PROJECT_ROOT / "operations/scripts/mint-ingress-jwt.py"

    def test_mint_tool_exists(self):
        assert self.MINT.exists(), "C7: no production JWT mint path"

    def test_mint_audience_matches_ingress(self):
        src = self.MINT.read_text()
        assert "nexus-ingress" in src
        ingress = (SERVICES / "core_ingress/src/main.rs").read_text()
        assert "nexus-ingress" in ingress, "audience must match on both sides"

    def test_deploy_mints_token(self):
        raw = self.MAIN.read_text()
        assert "mint-ingress-jwt.py" in raw and "vault_jwt_secret" in raw

    def test_transmitter_signs_with_gateway_hmac_key(self):
        raw = self.TOML.read_text()
        nexus_sect = raw[raw.find("[nexus]"): raw.find("[splunk]")]
        assert "vault_integrity_hmac_secret" in nexus_sect, \
            "C8: signing with a different key gets the middleware sensor banned"

    def test_gateway_url_from_inventory(self):
        raw = self.TOML.read_text()
        nexus_sect = raw[raw.find("[nexus]"): raw.find("[splunk]")]
        assert "groups['ingress']" in nexus_sect
