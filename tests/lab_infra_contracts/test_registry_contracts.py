"""
Registry/promotion seam - cross-layer source contracts.

The training/serving plane split introduces one new cross-layer contract:
the model registry bucket + the nexus.models.* subjects. Cross-layer
vocabulary drift is this project's dominant failure mode, so the seam's
vocabulary is asserted in every layer that speaks it: the training-plane
publisher, the serving-plane steward, the NATS authorization template, the
MinIO provisioning, and the deployment wiring. Pure source reads - no
imports, no network.
"""
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
PUBLISHER = PROJECT_ROOT / "mlops" / "scripts" / "13_publish_model.py"
RSI_LOOP = PROJECT_ROOT / "mlops" / "scripts" / "08_rsi_loop.py"
MAKEFILE = PROJECT_ROOT / "mlops" / "Makefile"
STEWARD_DIR = PROJECT_ROOT / "services" / "model_steward"
NATS_CONF = (PROJECT_ROOT / "infrastructure/ansible/roles/nats_node"
             / "templates/nats-server.conf.j2")
MINIO_ROLE = (PROJECT_ROOT / "infrastructure/ansible/roles/minio_node"
              / "tasks/main.yml")
STEWARD_ROLE = (PROJECT_ROOT / "infrastructure/ansible/roles/model_steward"
                / "tasks/main.yml")
SITE_YML = PROJECT_ROOT / "infrastructure/ansible/site.yml"
VAULT_STUB = PROJECT_ROOT / "infrastructure/ansible/group_vars/all/vault.yml"

SUBJECTS = ("nexus.models.promote", "nexus.models.promoted", "nexus.models.rejected")
REQUIRED_GATES = ("tier0", "garak", "pyrit", "regression", "alignment")


def _user_section(conf: str, user: str) -> str:
    idx = conf.find(f'user: "{user}"')
    assert idx >= 0, f"user {user} missing from nats-server.conf.j2"
    nxt = conf.find("user:", idx + 10)
    section = conf[idx: nxt if nxt > 0 else len(conf)]
    return "\n".join(ln for ln in section.splitlines()
                     if not ln.strip().startswith("#"))


# ── subject vocabulary asserted in both planes ───────────────────────────────

class TestSubjectVocabulary:
    def test_publisher_speaks_all_three_subjects(self):
        src = PUBLISHER.read_text()
        for subj in SUBJECTS:
            assert f'"{subj}"' in src, f"publisher missing {subj}"

    def test_steward_speaks_all_three_subjects(self):
        src = (STEWARD_DIR / "steward.py").read_text()
        for subj in SUBJECTS:
            assert f'"{subj}"' in src, f"steward missing {subj}"

    def test_both_planes_pin_the_same_required_gates(self):
        pub_src = PUBLISHER.read_text()
        mf_src = (STEWARD_DIR / "manifest.py").read_text()
        for gate in REQUIRED_GATES:
            assert f'"{gate}"' in pub_src, f"publisher REQUIRED_GATES missing {gate}"
            assert f'"{gate}"' in mf_src, f"steward REQUIRED_GATES missing {gate}"

    def test_both_planes_share_the_manifest_schema_name(self):
        assert 'MANIFEST_SCHEMA = "model_manifest_v1"' in PUBLISHER.read_text()
        assert 'MANIFEST_SCHEMA = "model_manifest_v1"' in (STEWARD_DIR / "manifest.py").read_text()


# ── NATS per-plane authorization ─────────────────────────────────────────────

class TestNatsPerPlaneAuthorization:
    def test_training_user_publishes_promote_only(self):
        sect = _user_section(NATS_CONF.read_text(), "training_node")
        publish = sect[sect.find("publish:"): sect.find("subscribe:")]
        assert "nexus.models.promote" in publish
        assert "nexus.models.promoted" not in publish, \
            "training must not be able to forge steward acks"
        assert "nexus.soar" not in sect and "telemetry" not in sect

    def test_training_user_reads_the_acks(self):
        sect = _user_section(NATS_CONF.read_text(), "training_node")
        subscribe = sect[sect.find("subscribe:"):]
        assert "nexus.models.promoted" in subscribe
        assert "nexus.models.rejected" in subscribe

    def test_steward_user_consumes_promote_and_answers(self):
        sect = _user_section(NATS_CONF.read_text(), "steward_node")
        publish = sect[sect.find("publish:"): sect.find("subscribe:")]
        subscribe = sect[sect.find("subscribe:"):]
        assert "nexus.models.promoted" in publish and "nexus.models.rejected" in publish
        assert '"nexus.models.promote"' in subscribe
        assert '"nexus.models.promote"' not in publish, \
            "steward must not be able to forge promote offers"

    def test_steward_user_is_least_privilege(self):
        sect = _user_section(NATS_CONF.read_text(), "steward_node")
        for forbidden in ("nexus.soar", "telemetry", "nexus.alerts", "nexus.ti"):
            assert forbidden not in sect, f"steward_node must not touch {forbidden}"

    def test_vault_stub_declares_the_new_secrets(self):
        stub = VAULT_STUB.read_text()
        for var in ("vault_nats_training_pass", "vault_nats_steward_pass",
                    "vault_registry_training_secret", "vault_registry_steward_secret"):
            assert var in stub, f"vault stub missing {var}"


# ── the training plane cannot deploy ─────────────────────────────────────────

class TestTrainingPlaneCannotDeploy:
    def test_rsi_loop_never_invokes_make_deploy(self):
        src = RSI_LOOP.read_text()
        assert '_run_make_target("deploy")' not in src
        assert "make deploy" not in src, \
            "no deploy invocation or reference may remain in the RSI loop"

    def test_rsi_loop_ends_at_publish(self):
        src = RSI_LOOP.read_text()
        assert '_run_make_target("publish"' in src

    def test_makefile_deploy_target_has_no_swap_or_restart_power(self):
        content = MAKEFILE.read_text()
        deploy_idx = content.find("\ndeploy:")
        assert deploy_idx > 0
        nxt = content.find("\n\n", deploy_idx)
        deploy_body = content[deploy_idx: nxt if nxt > 0 else len(content)]
        assert "systemctl" not in deploy_body
        assert "ln -sfn" not in deploy_body
        assert "exit 1" in deploy_body

    def test_makefile_publish_runs_the_publisher_with_ack(self):
        content = MAKEFILE.read_text()
        pub_idx = content.find("\npublish:")
        assert pub_idx > 0
        body = content[pub_idx: content.find("\n\n", pub_idx)]
        assert "13_publish_model.py" in body
        assert "--wait-ack" in body

    def test_publish_keeps_the_alignment_gates(self):
        content = MAKEFILE.read_text()
        pub_idx = content.find("\npublish:")
        body = content[pub_idx: content.find("\n\n# Serving-side", pub_idx)]
        assert "Execute-CognitiveBypass.sh" in body
        assert "Invoke-CrossPollinationStress.py" in body


# ── provisioning: bucket, credentials, deployment wiring ─────────────────────

class TestRegistryProvisioning:
    def test_minio_role_creates_the_registry_bucket(self):
        role = MINIO_ROLE.read_text()
        assert "nexus-model-registry" in role
        assert "mc version enable local/nexus-model-registry" in role

    def test_minio_role_splits_credentials_per_plane(self):
        role = MINIO_ROLE.read_text()
        assert "nexus-registry-training" in role
        assert "nexus-registry-steward" in role
        assert "s3:PutObject" in role and "s3:GetObject" in role

    def test_steward_policy_is_read_only(self):
        import yaml
        docs = yaml.safe_load(MINIO_ROLE.read_text())
        policy_task = next(t for t in docs
                           if t.get("name", "").startswith("Write per-plane registry"))
        by_name = {item["name"]: item["policy"] for item in policy_task["loop"]}
        steward_actions = {a for stmt in by_name["steward"]["Statement"]
                           for a in stmt["Action"]}
        assert "s3:PutObject" not in steward_actions
        assert "s3:DeleteObject" not in steward_actions
        training_actions = {a for stmt in by_name["training"]["Statement"]
                            for a in stmt["Action"]}
        assert "s3:GetObject" not in training_actions, \
            "training is write-only: it must not read serving artifacts back"

    def test_steward_role_deploys_source_and_unit(self):
        role = STEWARD_ROLE.read_text()
        for needle in ("main.py", "steward.py", "manifest.py",
                       "model-steward.service", "steward_node",
                       "nexus-model-registry", "MODEL_STORE_DIR"):
            assert needle in role, f"model_steward role missing {needle}"

    def test_site_yml_wires_the_steward_onto_the_serving_plane(self):
        assert "- model_steward" in SITE_YML.read_text()

    def test_steward_env_uses_readonly_registry_account(self):
        role = STEWARD_ROLE.read_text()
        assert "vault_registry_steward_secret" in role
        assert "vault_registry_training_secret" not in role, \
            "the serving plane must never hold the training write credential"


# ── serving quadlets stay pull-side consumers of the store ───────────────────

class TestServingPlaneShape:
    def test_steward_service_source_exists(self):
        for f in ("main.py", "steward.py", "manifest.py", "requirements.txt"):
            assert (STEWARD_DIR / f).exists(), f"services/model_steward/{f} missing"

    def test_steward_main_defaults_match_the_quadlet_units(self):
        src = (STEWARD_DIR / "main.py").read_text()
        for unit in ("vllm-inference.service", "vllm-network.service",
                     "vllm-critic.service"):
            assert unit in src, f"steward default unit map missing {unit}"
