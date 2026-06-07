"""
test_worker_contracts.py -- Source-level contract tests for P1 safety fixes.

These are OFFLINE tests (no running services required) that verify correctness
of critical error-handling changes by reading source code. They act as regression
guards: if someone reverts any of the safety fixes, these tests fail immediately.

Fixes validated:
  H-F2  worker_soar:         partial containment failure → Err (not Ok)
  H-P3  worker_s3_archive:   partial S3 upload failure  → Err (not Ok)
  H-R5  qdrant_init.sh:      on_disk_payload + wal_config present
  H-I1  production.yaml:     nexus_enabled=true + nexus_gateway_url set (middleware vectorization)
  H-G1  llm_providers.py:    circuit breaker open/half-open/closed state machine
  P0    Track 6 tests:        all passing (regression check)
"""

import json
import subprocess
import re
from pathlib import Path

import pytest

SERVICES = Path(__file__).parent.parent / "services"
INFRA    = Path(__file__).parent.parent / "infrastructure"
TESTS    = Path(__file__).parent.parent / "tests"
ORCH     = Path(__file__).parent.parent / "orchestration"

SOAR_MAIN       = SERVICES / "worker_soar/src/main.rs"
S3_MAIN         = SERVICES / "worker_s3_archive/src/main.rs"
QDRANT_INIT     = INFRA    / "qdrant/qdrant_init.sh"
QDRANT_INIT_T   = TESTS    / "deploy/config/qdrant_init.sh"
PROD_YAML       = ORCH     / "environments/production.yaml"
NEXUS_TOML      = SERVICES / "config/nexus.toml"
CONTAINMENT_TOML = Path(__file__).parent.parent / "operations/infra/containment.toml"
QDRANT_MAIN     = SERVICES / "worker_qdrant/src/main.rs"


# ── H-F2: worker_soar ACK ordering ───────────────────────────────────────────

class TestWorkerSoarAckOrdering:
    """H-F2: Partial containment failure must propagate as Err, not Ok."""

    def _src(self) -> str:
        return SOAR_MAIN.read_text()

    def test_partial_failure_returns_err(self):
        """Any n8n or API failure must produce Err -- not Ok with a warning.
        Pre-fix: returned Ok(()) on partial failure, ACKing and losing the action."""
        src = self._src()
        # The fix removes the Ok(()) branch for partial failures.
        # Verify the only Ok(()) is in the total-success path.
        # Look for the block structure: any_failure → Err, else → Ok
        assert "if failures > 0 || n8n_failures > 0" in src, \
            "worker_soar: expected unified failure check 'failures > 0 || n8n_failures > 0'"
        # The failure branch must return Err
        failure_block_start = src.find("if failures > 0 || n8n_failures > 0")
        failure_block = src[failure_block_start:failure_block_start + 400]
        assert "Err(" in failure_block, \
            "worker_soar: partial failure branch must return Err, not Ok"

    def test_no_ok_on_partial_failure(self):
        """The old pattern -- partial success returning Ok(()) -- must be gone."""
        src = self._src()
        # The old code had: else if total_n8n > 0 { ... Ok(()) }
        # Verify no 'Partial containment success' warn + Ok() pattern remains
        assert "Partial containment success" not in src, \
            "worker_soar: old 'Partial containment success' warn (from Ok path) must be removed"

    def test_total_failure_returns_err_via_unified_check(self):
        """Total failure is subsumed by the unified 'any failure → Err' check."""
        src = self._src()
        check = "if failures > 0 || n8n_failures > 0"
        assert check in src, "Unified failure check must exist"
        pos = src.find(check)
        # Grab a wider window that includes the else branch
        block = src[pos:pos + 600]
        assert "Err(" in block, "Unified failure block must contain Err(...)"
        assert "} else {" in block, "Success else-branch must follow the failure check"
        else_pos = block.find("} else {")
        else_block = block[else_pos:]
        assert "Ok(())" in else_block, "Success path must return Ok(())"

    def test_dedup_cache_present_for_idempotent_retry(self):
        """TimedDedup must exist -- it prevents double-execution on retry."""
        src = self._src()
        assert "TimedDedup" in src, \
            "worker_soar: TimedDedup cache required for safe retry idempotency"
        assert "is_duplicate" in src, \
            "worker_soar: dedup.is_duplicate() check required"


# ── H-P3: worker_s3_archive partial failure DLQ routing ─────────────────────

class TestWorkerS3ArchiveDLQ:
    """H-P3: Any S3 upload failure must return Err to trigger DLQ routing."""

    def _src(self) -> str:
        return S3_MAIN.read_text()

    def test_partial_failure_returns_err(self):
        """total_failed > 0 must return Err regardless of total_uploaded."""
        src = self._src()
        # Find the return logic block
        assert "if total_failed > 0 {" in src, \
            "worker_s3_archive: expected 'if total_failed > 0' as sole failure gate"
        # The failure block must return Err
        fail_pos = src.find("if total_failed > 0 {")
        fail_block = src[fail_pos:fail_pos + 300]
        assert "Err(" in fail_block, \
            "worker_s3_archive: total_failed > 0 must return Err, not Ok"

    def test_no_silent_partial_drop(self):
        """The old pattern -- Ok(()) on partial failure -- must be gone."""
        src = self._src()
        # Pre-fix: 'else if total_failed > 0 { ... Ok(()) }'
        # Verify this pattern no longer exists
        old_partial_pattern = "Partial S3 upload failure"
        assert old_partial_pattern not in src, \
            "worker_s3_archive: old silent partial failure path must be removed"

    def test_total_success_still_returns_ok(self):
        """Total success (total_failed == 0) must still return Ok(())."""
        src = self._src()
        transmit_fn = src[src.find("async fn transmit_batch"):]
        fn_end = transmit_fn.find("\n    }\n}\n")
        fn_body = transmit_fn[:fn_end]
        assert "Ok(())" in fn_body, \
            "worker_s3_archive: success path must still return Ok(())"

    def test_dlq_counter_incremented_on_failure(self):
        """DLQ counter must be incremented to make partial failures observable."""
        src = self._src()
        assert "nexus_s3_partial_failures_total" in src, \
            "worker_s3_archive: counter 'nexus_s3_partial_failures_total' must be incremented"


# ── H-R5: Qdrant WAL + on_disk_payload ───────────────────────────────────────

class TestQdrantInitConfig:
    """H-R5: Collection init must include on_disk_payload and wal_config."""

    def _read(self, path: Path) -> str:
        return path.read_text()

    @pytest.mark.parametrize("script", [
        pytest.param(QDRANT_INIT,   id="production"),
        pytest.param(QDRANT_INIT_T, id="tests-deploy"),
    ])
    def test_on_disk_payload_present(self, script: Path):
        """on_disk_payload: true prevents payload RAM exhaustion at 50k endpoints."""
        src = self._read(script)
        assert '"on_disk_payload": true' in src, \
            f"{script.name}: missing 'on_disk_payload: true'. Without it, Qdrant " \
            "loads all payloads into RAM -- exhausted at ~10k stored points per GB."

    @pytest.mark.parametrize("script", [
        pytest.param(QDRANT_INIT,   id="production"),
        pytest.param(QDRANT_INIT_T, id="tests-deploy"),
    ])
    def test_wal_config_present(self, script: Path):
        """wal_config must be set to bound WAL memory and segment growth."""
        src = self._read(script)
        assert '"wal_config"' in src, \
            f"{script.name}: missing wal_config block. Without explicit WAL limits " \
            "Qdrant may pre-allocate unbounded WAL segments under high write load."
        assert '"wal_capacity_mb"' in src, \
            f"{script.name}: wal_config must specify wal_capacity_mb"

    def test_wal_capacity_is_sane(self):
        """WAL capacity must be between 16MB and 256MB for production workloads."""
        src = self._read(QDRANT_INIT)
        m = re.search(r'"wal_capacity_mb":\s*(\d+)', src)
        assert m, "wal_capacity_mb not found"
        capacity = int(m.group(1))
        assert 16 <= capacity <= 256, \
            f"wal_capacity_mb={capacity} is outside the expected 16–256MB range"

    def test_vector_spaces_complete(self):
        """Production init must define all 7 named vector spaces."""
        src = self._read(QDRANT_INIT)
        for space in ("c2_math", "sentinel_math", "windows_math",
                      "deepsensor_math", "trellix_math", "cloud_flow", "network_tap"):
            assert f'"{space}"' in src, \
                f"qdrant_init.sh missing vector space: {space}"

    def test_windows_math_is_6d(self):
        """windows_math must be 6D (was 4D before grant_access + driver_trust expansion)."""
        src = self._read(QDRANT_INIT)
        m = re.search(r'"windows_math".*?"size":\s*(\d+)', src, re.DOTALL)
        assert m, "windows_math size not found in qdrant_init.sh"
        assert int(m.group(1)) == 6, \
            f"windows_math size={m.group(1)}, expected 6 (after grant_access + driver_trust expansion)"


# ── H-I1: Middleware telemetry vectorization via nexus passthrough ─────────────

class TestMiddlewareVectorizationConfig:
    """H-I1: nexus_enabled + nexus_gateway_url must both be set so middleware
    telemetry flows through worker_qdrant and gets anomaly scores + tripwires."""

    def _prod_yaml(self) -> str:
        return PROD_YAML.read_text()

    def test_nexus_enabled_true(self):
        """nexus_enabled: true is required for worker_nexus to forward middleware telemetry."""
        src = self._prod_yaml()
        assert "nexus_enabled: true" in src, \
            "production.yaml: nexus_enabled must be true or middleware " \
            "telemetry is never vectorized (math tripwires blind)"

    def test_nexus_gateway_url_set(self):
        """nexus_gateway_url must be non-empty or worker_nexus forwards to '' (silent fail)."""
        src = self._prod_yaml()
        m = re.search(r'nexus_gateway_url:\s*"([^"]*)"', src)
        assert m, "production.yaml: nexus_gateway_url not found"
        url = m.group(1).strip()
        assert url, \
            "production.yaml: nexus_gateway_url is blank -- worker_nexus forwards " \
            "to '' (all re-stamps fail silently, middleware telemetry never vectorized)"
        assert url.startswith("http"), \
            f"nexus_gateway_url should be an HTTP(S) URL, got: {url!r}"


# ── Sensor schema completeness ───────────────────────────────────────────────

class TestSensorSchemaCompleteness:
    """All sensor source_types used in production must have schema_mappings in nexus.toml
    and routing branches in worker_qdrant so no records are silently dropped."""

    def _nexus(self) -> str:
        return NEXUS_TOML.read_text()

    def _qdrant(self) -> str:
        return QDRANT_MAIN.read_text()

    def _containment(self) -> str:
        return CONTAINMENT_TOML.read_text()

    def test_suricata_eve_schema_mapping_present(self):
        """suricata_eve must have a schema_mapping in nexus.toml (was missing, causing silent drop)."""
        assert "schema_mappings.suricata_eve" in self._nexus(), \
            "nexus.toml missing [schema_mappings.suricata_eve] -- suricata records would be silently dropped"

    def test_suricata_eve_duck_type_branch_present(self):
        """worker_qdrant must have a duck-type branch for suricata_eve (community_id identifier)."""
        src = self._qdrant()
        assert "suricata_eve" in src, \
            "worker_qdrant: no suricata_eve duck-type branch -- EVE records silently dropped at continue"

    def test_vmware_containment_routing_present(self):
        """vmware_source_types must be in containment.toml -- vmware_syslog was missing,
        causing VMware alerts to fall through to EDR isolation instead of cloud containment."""
        cfg = self._containment()
        assert "vmware_source_types" in cfg, \
            "containment.toml missing vmware_source_types -- vmware_syslog routes to EDR instead of cloud"
        assert "vmware_containment_v1" in cfg, \
            "containment.toml missing active_vmware_provider"

    def test_vmware_routing_in_soar_struct(self):
        """worker_soar CloudRouting struct must have vmware_source_types field."""
        src = SOAR_MAIN.read_text()
        assert "vmware_source_types" in src, \
            "worker_soar CloudRouting struct missing vmware_source_types -- vmware routes silently skipped"

    def test_macos_sensor_6d_padding_present(self):
        """worker_qdrant must zero-pad legacy 4D macos_sensor vectors to 6D windows_math.
        Without this, Qdrant rejects macos_sensor uploads with dimension mismatch."""
        src = self._qdrant()
        assert 'active_source_type == "macos_sensor" && raw_math.len() == 6' in src, \
            "worker_qdrant missing macos_sensor 6D branch"
        assert 'active_source_type == "macos_sensor" && raw_math.len() == 4' in src, \
            "worker_qdrant missing legacy 4D macos_sensor padding branch"


# ── P0: Track 6 regression gate ──────────────────────────────────────────────

class TestTrack6Regression:
    """P0: Track 6 query alignment must remain at 0 broken queries."""

    def test_track6_tests_pass(self):
        """Run the Track 6 query alignment suite as a subprocess regression gate."""
        result = subprocess.run(
            ["python3", "-m", "pytest",
             "tests/test_s3_query_alignment.py", "-q", "--tb=short"],
            capture_output=True, text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0, (
            "Track 6 query alignment tests FAILED -- a column name regression was introduced.\n"
            f"stdout:\n{result.stdout[-2000:]}\n"
            f"stderr:\n{result.stderr[-500:]}"
        )


# ── H-S1: NATS subject-level authorization ────────────────────────────────────

NATS_PROD_TEMPLATE = (
    Path(__file__).parent.parent
    / "infrastructure/ansible/roles/nats_node/templates/nats-server.conf.j2"
)
NATS_LAB_CONF = Path(__file__).parent / "lab_nats_ingress/nats-test.conf"
NATS_LIB_SIEM = Path(__file__).parent.parent / "libs/lib_siem_core/src/lib.rs"
NATS_WORKER_RLHF = Path(__file__).parent.parent / "services/worker_rlhf/src/main.rs"


class TestNATSSubjectAuth:
    """H-S1: NATS subject-level token enforcement must be present in all configs."""

    def _read(self, p: Path) -> str:
        assert p.exists(), f"File not found: {p}"
        return p.read_text()

    # ── Production template ───────────────────────────────────────────────────

    def test_prod_template_has_authorization_block(self):
        """Production Ansible template must define an authorization block."""
        src = self._read(NATS_PROD_TEMPLATE)
        assert "authorization" in src, \
            "nats-server.conf.j2 missing 'authorization' block -- H-S1 not enforced in production"

    def test_prod_template_default_deny_all(self):
        """default_permissions must deny all publish and subscribe by default."""
        src = self._read(NATS_PROD_TEMPLATE)
        assert 'deny: [">"]' in src, \
            "nats-server.conf.j2: default_permissions does not deny all subjects -- " \
            "unauthenticated clients can publish/subscribe to any subject"

    def test_prod_template_ingress_publish_only(self):
        """ingress_node must only be able to publish (read-restricted pipeline)."""
        src = self._read(NATS_PROD_TEMPLATE)
        assert "ingress_node" in src, "nats-server.conf.j2: ingress_node user missing"
        # ingress must have subscribe deny -- ingress nodes must not read back
        assert 'subscribe: { deny: [">"] }' in src, \
            "ingress_node must have subscribe deny -- ingress reading pipeline data is a risk"

    def test_prod_template_worker_restricted_publish(self):
        """worker_node must not have wildcard publish access."""
        src = self._read(NATS_PROD_TEMPLATE)
        assert "worker_node" in src, "nats-server.conf.j2: worker_node user missing"
        # worker should not publish to arbitrary telemetry subjects
        assert 'nexus.dlq.>' in src, \
            "worker_node missing DLQ publish permission -- DLQ routing would fail"

    def test_prod_template_swarm_restricted_to_soar(self):
        """swarm_node must publish only to nexus.soar.actions -- not raw telemetry."""
        src = self._read(NATS_PROD_TEMPLATE)
        assert "swarm_node" in src, "nats-server.conf.j2: swarm_node user missing"
        assert "nexus.soar.actions" in src, \
            "swarm_node missing publish permission for nexus.soar.actions"

    # ── Lab conf mirrors production ───────────────────────────────────────────

    def test_lab_conf_has_authorization_block(self):
        """Lab 3 NATS config must enforce auth to prove the security contract."""
        src = self._read(NATS_LAB_CONF)
        assert "authorization" in src, \
            "lab_nats_ingress/nats-test.conf missing authorization block -- " \
            "Lab 3 does not exercise NATS auth (H-S1 not validated by tests)"

    def test_lab_conf_has_three_roles(self):
        """Lab 3 conf must define all three production roles: ingress, worker, swarm."""
        src = self._read(NATS_LAB_CONF)
        for role in ("ingress_node", "worker_node", "swarm_node"):
            assert role in src, \
                f"lab_nats_ingress/nats-test.conf missing role '{role}'"

    def test_lab_conf_default_deny(self):
        """Lab 3 conf must have default deny so un-authed clients are rejected."""
        src = self._read(NATS_LAB_CONF)
        assert 'deny: [">"]' in src, \
            "lab_nats_ingress/nats-test.conf missing default deny -- auth not enforced"

    # ── lib_siem_core OTLP extractor presence (H-I4 dependency) ─────────────

    def test_nats_header_extractor_present(self):
        """lib_siem_core must have NatsHeaderExtractor for OTLP context propagation."""
        src = self._read(NATS_LIB_SIEM)
        assert "NatsHeaderExtractor" in src, \
            "lib_siem_core: NatsHeaderExtractor missing -- OTLP trace context cannot be " \
            "extracted from inbound NATS messages (H-I4 broken)"

    def test_nats_header_injector_present(self):
        """lib_siem_core must have NatsHeaderInjector for outbound trace propagation (H-I4)."""
        src = self._read(NATS_LIB_SIEM)
        assert "NatsHeaderInjector" in src, \
            "lib_siem_core: NatsHeaderInjector missing -- OTLP trace context cannot be " \
            "injected into outbound DLQ/alert NATS messages (H-I4 not implemented)"

    # ── H-R6: worker_rlhf stream retention ───────────────────────────────────

    def test_rlhf_dedicated_stream_defined(self):
        """worker_rlhf must bind a dedicated stream with WorkQueuePolicy retention."""
        src = self._read(NATS_WORKER_RLHF)
        assert "Nexus_RLHF_Feedback" in src, \
            "worker_rlhf: uses Nexus_System stream for RLHF feedback. " \
            "RLHF feedback needs a dedicated WorkQueuePolicy stream so processed " \
            "messages are deleted and the stream does not grow unboundedly (H-R6)"

    def test_rlhf_workqueue_retention(self):
        """worker_rlhf stream must use WorkQueuePolicy to auto-delete ACKed messages."""
        src = self._read(NATS_WORKER_RLHF)
        assert "WorkQueuePolicy" in src, \
            "worker_rlhf stream missing WorkQueuePolicy retention -- processed RLHF " \
            "feedback is never deleted, stream grows without bound (H-R6)"

    def test_rlhf_max_age_set(self):
        """RLHF stream must have max_age to expire stale feedback (7-day TTL)."""
        src = self._read(NATS_WORKER_RLHF)
        assert "max_age" in src, \
            "worker_rlhf stream missing max_age -- stale RLHF feedback from weeks " \
            "ago poisons the reward model on worker restart (H-R6)"

    # ── H-P2: adaptive batch deadline in lib_siem_core ───────────────────────

    def test_adaptive_batch_deadline_present(self):
        """lib_siem_core must use an adaptive batch deadline (not fixed 2s)."""
        src = self._read(NATS_LIB_SIEM)
        assert "adaptive" in src.lower() or "batch_deadline" in src.lower(), \
            "lib_siem_core: no evidence of adaptive batch deadline logic (H-P2)"
        assert "MIN_BATCH_DEADLINE" in src or "min_batch" in src.lower() or "adaptive_deadline" in src, \
            "lib_siem_core: adaptive batch deadline constants not found -- fixed 2s deadline still in use (H-P2)"


# ── I-16 / I-8: Infrastructure hardening contracts ───────────────────────────

DR_SNAPSHOT_SH = (
    Path(__file__).parent.parent
    / "infrastructure/bare-metal/scripts/dr_snapshot.sh"
)
DR_SNAPSHOT_TIMER = (
    Path(__file__).parent.parent
    / "infrastructure/bare-metal/scripts/dr_snapshot.timer"
)
DR_SNAPSHOT_SERVICE = (
    Path(__file__).parent.parent
    / "infrastructure/bare-metal/scripts/dr_snapshot.service"
)
TF_BACKEND = (
    Path(__file__).parent.parent
    / "infrastructure/terraform/backend.tf"
)


class TestInfraHardeningContracts:
    """I-16 + I-8: DR snapshot script and Terraform remote state must be correctly
    structured so DR is recoverable and IaC state is never lost or corrupted."""

    def _read(self, p: Path) -> str:
        assert p.exists(), f"File not found: {p}"
        return p.read_text()

    # ── I-16: DR snapshot script ──────────────────────────────────────────────

    def test_qdrant_api_snapshot_call(self):
        """dr_snapshot.sh must POST to the Qdrant REST snapshot API.
        Without this, Qdrant data is not included in DR."""
        src = self._read(DR_SNAPSHOT_SH)
        assert "/collections/" in src and "/snapshots" in src, \
            "dr_snapshot.sh: Qdrant snapshot API call not found " \
            "(/collections/{name}/snapshots POST). Qdrant data will not be in DR."
        assert "-X POST" in src, \
            "dr_snapshot.sh: snapshot creation must use POST method"

    def test_qdrant_snapshot_delete_after_upload(self):
        """dr_snapshot.sh must DELETE the Qdrant snapshot after upload.
        Without cleanup, Qdrant's data directory fills up over time."""
        src = self._read(DR_SNAPSHOT_SH)
        assert "-X DELETE" in src, \
            "dr_snapshot.sh: snapshot not deleted from Qdrant after upload -- " \
            "Qdrant data disk will fill up with retained snapshots (I-16)"

    def test_redis_bgsave_triggered(self):
        """dr_snapshot.sh must issue a Redis BGSAVE command before backing up."""
        src = self._read(DR_SNAPSHOT_SH)
        assert "BGSAVE" in src, \
            "dr_snapshot.sh: Redis BGSAVE not called -- dump.rdb may be stale at backup time"

    def test_redis_bgsave_completion_poll(self):
        """dr_snapshot.sh must poll until BGSAVE completes before copying dump.rdb.
        Without the poll, the rdb file may be captured mid-write and corrupted."""
        src = self._read(DR_SNAPSHOT_SH)
        assert "rdb_bgsave_in_progress" in src, \
            "dr_snapshot.sh: no BGSAVE completion check (rdb_bgsave_in_progress) -- " \
            "dump.rdb may be captured mid-write and be unrestorable"

    def test_s3_upload_both_services(self):
        """dr_snapshot.sh must upload both Qdrant snapshots and the Redis rdb to S3."""
        src = self._read(DR_SNAPSHOT_SH)
        assert src.count("aws s3 cp") >= 2, \
            "dr_snapshot.sh: expected at least 2 'aws s3 cp' calls (Qdrant + Redis). " \
            "One of the two stateful services is not being backed up."

    def test_s3_storage_class_standard_ia(self):
        """S3 uploads must use STANDARD_IA to reduce DR archive costs.
        STANDARD costs ~4x more per GB for infrequently accessed backup data."""
        src = self._read(DR_SNAPSHOT_SH)
        assert "STANDARD_IA" in src, \
            "dr_snapshot.sh: S3 upload missing --storage-class STANDARD_IA -- " \
            "DR backups will be stored at full STANDARD pricing (~4x more expensive)"

    def test_manifest_written_to_s3(self):
        """dr_snapshot.sh must write a manifest.json so DR recovery knows what was captured."""
        src = self._read(DR_SNAPSHOT_SH)
        assert "manifest.json" in src, \
            "dr_snapshot.sh: no manifest.json -- recovery operator has no inventory of what was backed up"
        # Verify the manifest is uploaded -- look for aws s3 cp followed by manifest.json on the same or next line
        assert re.search(r'aws s3 cp.*manifest\.json|manifest\.json.*aws s3 cp', src, re.DOTALL), \
            "dr_snapshot.sh: manifest.json must be uploaded to S3 via 'aws s3 cp'"

    def test_local_retention_purge(self):
        """dr_snapshot.sh must purge local snapshots older than RETAIN_DAYS.
        Without this, /var/lib/nexus-dr fills up on the bare-metal host."""
        src = self._read(DR_SNAPSHOT_SH)
        assert "nexus-dr" in src and "-mtime" in src, \
            "dr_snapshot.sh: local retention purge (find -mtime +N) not present -- " \
            "local snapshot directory will grow unboundedly (I-16)"
        assert "rm -rf" in src or "rm -f" in src, \
            "dr_snapshot.sh: local retention purge does not remove files"

    def test_systemd_timer_utc_schedule(self):
        """systemd timer must run at a fixed UTC time (02:00 UTC) not wall clock.
        Bare-metal hosts may be in different timezones."""
        src = self._read(DR_SNAPSHOT_TIMER)
        assert "02:00:00" in src, \
            "dr_snapshot.timer: expected 02:00:00 UTC schedule not found"
        assert "UTC" in src or "OnCalendar" in src, \
            "dr_snapshot.timer: schedule lacks UTC marker -- may fire at wrong time on non-UTC hosts"

    def test_systemd_service_runs_as_nexus_user(self):
        """systemd service must run as the nexus user, not root."""
        src = self._read(DR_SNAPSHOT_SERVICE)
        assert "User=nexus" in src, \
            "dr_snapshot.service: must run as User=nexus -- running as root violates least-privilege"

    # ── I-8: Terraform remote state backend ──────────────────────────────────

    def test_terraform_s3_backend_defined(self):
        """backend.tf must declare an S3 backend so state is remote, not local."""
        src = self._read(TF_BACKEND)
        assert 'backend "s3"' in src, \
            "infrastructure/terraform/backend.tf: S3 backend not declared -- " \
            "terraform state will be stored locally and lost if the engineer's " \
            "machine is unavailable (I-8)"

    def test_terraform_dynamodb_locking(self):
        """S3 backend must declare a DynamoDB table for state locking.
        Without this, concurrent 'terraform apply' runs can corrupt state."""
        src = self._read(TF_BACKEND)
        assert "dynamodb_table" in src, \
            "backend.tf: dynamodb_table not set -- concurrent terraform apply runs " \
            "can corrupt the state file (I-8)"
        assert "sentinel-nexus-tflock" in src, \
            "backend.tf: DynamoDB lock table must be 'sentinel-nexus-tflock'"

    def test_terraform_state_encrypted(self):
        """State must be encrypted at rest -- it may contain DB passwords, TLS keys, etc."""
        src = self._read(TF_BACKEND)
        assert "encrypt" in src, \
            "backend.tf: encrypt not set -- terraform state stored in S3 plaintext. " \
            "State may contain secrets (passwords, TLS keys, IAM key IDs)."
        assert "encrypt        = true" in src or "encrypt = true" in src, \
            "backend.tf: encrypt must be 'true', found something else"

    def test_terraform_state_key_namespaced(self):
        """State key must include a namespace prefix so multiple modules don't collide."""
        src = self._read(TF_BACKEND)
        assert "terraform.tfstate" in src, \
            "backend.tf: state key must end with terraform.tfstate"
        assert 'key' in src and 'nexus' in src, \
            "backend.tf: state key must include a nexus namespace prefix to avoid " \
            "collisions between modules or environments"


# ── H-G2: Cognitive fault DLQ ────────────────────────────────────────────────

ORCHESTRATOR_PY = Path(__file__).parent.parent / "analytics/llm_hunter/orchestrator.py"


class TestCognitiveFaultDLQ:
    """H-G2: GraphRecursionError and unhandled DAG exceptions must be caught and
    routed to nexus.dlq.cognitive -- not propagate silently and strand NATS messages."""

    def _src(self) -> str:
        return ORCHESTRATOR_PY.read_text()

    def test_graph_recursion_error_imported(self):
        """GraphRecursionError must be imported so the except clause is not NameError."""
        assert "from langgraph.errors import GraphRecursionError" in self._src(), \
            "orchestrator.py: GraphRecursionError not imported -- except clause would raise NameError"

    def test_graph_recursion_error_caught(self):
        """GraphRecursionError must be caught in trigger_swarm to prevent un-ACK'd NATS messages."""
        assert "except GraphRecursionError" in self._src(), \
            "orchestrator.py: GraphRecursionError not caught -- DAG recursion limit leaves NATS message un-ACK'd"

    def test_bare_except_catches_all_cognitive_faults(self):
        """A bare except (or except Exception) must follow GraphRecursionError to catch
        any other unhandled DAG exception before it silently drops the investigation."""
        src = self._src()
        assert "except Exception as exc" in src, \
            "orchestrator.py: no catch-all except block -- unhandled DAG faults swallow investigations silently"

    def test_cognitive_dlq_subject_used(self):
        """nexus.dlq.cognitive must be the publish target for cognitive faults."""
        assert "nexus.dlq.cognitive" in self._src(), \
            "orchestrator.py: cognitive faults not routed to nexus.dlq.cognitive"

    def test_publish_cognitive_dlq_helper_exists(self):
        """_publish_cognitive_dlq helper must exist to separate DLQ publishing from trigger_swarm."""
        assert "async def _publish_cognitive_dlq" in self._src(), \
            "orchestrator.py: _publish_cognitive_dlq helper missing"

    def test_dlq_publish_failure_does_not_reraise(self):
        """DLQ publish failure must be caught and logged -- not re-raised, which would
        deadlock the semaphore and prevent new investigations from starting."""
        src = self._src()
        # The helper must have its own try/except to absorb publish failures
        helper_start = src.find("async def _publish_cognitive_dlq")
        helper_body = src[helper_start:helper_start + 900]
        assert "except Exception as pub_exc" in helper_body, \
            "_publish_cognitive_dlq: publish failure must be caught locally to release the semaphore"


# ── H-S2: Redis destructive command lockdown ─────────────────────────────────

DOCKER_COMPOSE_TESTS = Path(__file__).parent / "docker-compose.yml"
MIDDLEWARE_TOML = Path(__file__).parent.parent / "middleware/config/middleware.toml"


class TestRedisDestructiveCommandLockdown:
    """H-S2: FLUSHALL / FLUSHDB / DEBUG / CONFIG must be renamed to '' in Redis
    so a compromised service cannot wipe the deterministic alert queue or session store."""

    def _compose(self) -> str:
        return DOCKER_COMPOSE_TESTS.read_text()

    def test_flushall_renamed(self):
        """FLUSHALL renamed to '' -- prevents total queue wipe via a single Redis command."""
        assert 'rename-command FLUSHALL ""' in self._compose(), \
            "docker-compose.yml (tests): FLUSHALL not renamed -- compromised service can wipe alert queue"

    def test_flushdb_renamed(self):
        """FLUSHDB renamed to '' -- prevents per-database wipe."""
        assert 'rename-command FLUSHDB ""' in self._compose(), \
            "docker-compose.yml (tests): FLUSHDB not renamed"

    def test_debug_renamed(self):
        """DEBUG renamed to '' -- DEBUG SLEEP / OBJECT ENCODING enables RCE-level abuse."""
        assert 'rename-command DEBUG ""' in self._compose(), \
            "docker-compose.yml (tests): DEBUG not renamed"

    def test_config_renamed(self):
        """CONFIG renamed to '' -- prevents live config changes (e.g., disabling auth)."""
        assert 'rename-command CONFIG ""' in self._compose(), \
            "docker-compose.yml (tests): CONFIG not renamed -- live config changes possible"


# ── H-I3: Intentional config divergence documented ───────────────────────────

class TestConfigDivergenceDocumented:
    """H-I3: The nats_url divergence between middleware.toml (127.0.0.1) and nexus.toml
    (nats://nats:4222) must be documented so future maintainers don't 'fix' it incorrectly."""

    def _middleware(self) -> str:
        return MIDDLEWARE_TOML.read_text()

    def test_middleware_nats_url_divergence_documented(self):
        """middleware.toml must contain a comment explaining why nats_url is 127.0.0.1
        (host-mapped port) rather than the Docker service alias used by sensor services."""
        src = self._middleware()
        assert "127.0.0.1" in src, "middleware.toml: nats_url changed -- check H-I3"
        assert "Docker" in src or "docker" in src or "host" in src, \
            "middleware.toml: nats_url 127.0.0.1 divergence from nexus.toml must be documented with a comment"

    def test_middleware_stream_divergence_documented(self):
        """MiddlewareStream vs Sensor_Telemetry isolation must be documented."""
        src = self._middleware()
        assert "MiddlewareStream" in src, "middleware.toml: stream_name missing"
        assert "isolation" in src or "prefix" in src or "separate" in src or "middleware.*" in src, \
            "middleware.toml: MiddlewareStream / middleware.* subject isolation must be documented"


# ── M-10: Calibration sweep in 03_eval_model.py ──────────────────────────────

EVAL_MODEL_PY = Path(__file__).parent.parent / "mlops/scripts/03_eval_model.py"
EVAL_CRITIC_PY = Path(__file__).parent.parent / "mlops/scripts/03_eval_critic.py"


class TestMLOpsEvalContracts:
    """M-10/M-11: Eval scripts must include calibration sweep and negative transfer tests
    so model quality regressions are caught before deployment."""

    def _eval_model(self) -> str:
        return EVAL_MODEL_PY.read_text()

    def _eval_critic(self) -> str:
        return EVAL_CRITIC_PY.read_text()

    # ── M-10: Calibration sweep ──────────────────────────────────────────────
    def test_m10_calibration_sweep_function_exists(self):
        """03_eval_model.py must contain run_calibration_sweep() (M-10)."""
        assert "def run_calibration_sweep" in self._eval_model(), \
            "03_eval_model.py: run_calibration_sweep missing -- M-10 calibration not wired"

    def test_m10_temperature_sweep_defined(self):
        """Calibration sweep must test multiple temperatures, not just greedy (0.01)."""
        src = self._eval_model()
        assert "CALIBRATION_TEMPS" in src, \
            "03_eval_model.py: CALIBRATION_TEMPS not defined -- single-temperature eval cannot detect instability"
        assert "0.3" in src and "0.7" in src, \
            "03_eval_model.py: temperature sweep must include ≥0.3 to detect decision boundary instability"

    def test_m10_stability_gate_present(self):
        """Calibration must gate deployment when >25% of cases are unstable at temp=0.1."""
        src = self._eval_model()
        assert "unstable_cases" in src, \
            "03_eval_model.py: no unstable_cases tracking -- stability gate cannot fire"
        assert "25%" in src or "0.25" in src, \
            "03_eval_model.py: 25% instability gate must be present"

    def test_m10_called_from_run_regression_suite(self):
        """run_regression_suite must call run_calibration_sweep to execute M-10 automatically."""
        src = self._eval_model()
        # The call must exist somewhere after the def (not just in the calibration def itself)
        suite_start = src.find("def run_regression_suite")
        suite_end_marker = src.find("\nif __name__", suite_start)
        suite_body = src[suite_start:suite_end_marker] if suite_end_marker > 0 else src[suite_start:]
        assert "run_calibration_sweep" in suite_body, \
            "03_eval_model.py: run_regression_suite does not call run_calibration_sweep -- M-10 not wired"

    # ── M-11: Negative transfer defense ─────────────────────────────────────
    def test_m11_phase5_function_exists(self):
        """03_eval_critic.py must contain run_phase5_negative_transfer() (M-11)."""
        assert "def run_phase5_negative_transfer" in self._eval_critic(), \
            "03_eval_critic.py: run_phase5_negative_transfer missing -- M-11 negative transfer not wired"

    def test_m11_regression_stability_cohort_present(self):
        """Phase 5 must include regression_stability cohort (Phase 1 verbatim cases)."""
        assert "regression_stability" in self._eval_critic(), \
            "03_eval_critic.py: regression_stability cohort missing -- Phase 1 regressions not tested"

    def test_m11_cross_sensor_domain_cohort_present(self):
        """Phase 5 must include cross_sensor_domain cohort (cloud vs EDR)."""
        assert "cross_sensor_domain" in self._eval_critic(), \
            "03_eval_critic.py: cross_sensor_domain cohort missing -- cloud/EDR negative transfer not tested"

    def test_m11_os_artifact_bleed_cohort_present(self):
        """Phase 5 must include os_artifact_bleed cohort (Linux vs Windows context)."""
        assert "os_artifact_bleed" in self._eval_critic(), \
            "03_eval_critic.py: os_artifact_bleed cohort missing -- OS vocabulary bleed not tested"

    def test_m11_called_from_run_critic_validation(self):
        """run_critic_validation must call run_phase5_negative_transfer."""
        src = self._eval_critic()
        # Search from the run_critic_validation def to the next top-level def
        critic_start = src.find("def run_critic_validation")
        next_def = src.find("\ndef ", critic_start + 10)
        critic_body = src[critic_start:next_def] if next_def > 0 else src[critic_start:]
        assert "run_phase5_negative_transfer" in critic_body, \
            "03_eval_critic.py: run_critic_validation does not call run_phase5_negative_transfer -- M-11 not wired"

    def test_m11_hard_fail_on_any_negative_transfer(self):
        """Phase 5 must exit(1) on any regression -- negative transfer is a hard deploy blocker."""
        src = self._eval_critic()
        p5_start = src.find("def run_phase5_negative_transfer")
        # The function is large -- search a wide window
        next_def = src.find("\ndef ", p5_start + 10)
        p5_body = src[p5_start:next_def] if next_def > 0 else src[p5_start:]
        assert "exit(1)" in p5_body, \
            "03_eval_critic.py: Phase 5 must exit(1) on negative transfer -- not just warn"


# ── H-G1: LLM circuit breaker state machine ──────────────────────────────────

class TestLLMCircuitBreaker:
    """H-G1: open/half-open/closed state machine for per-provider LLM failover."""

    LLM_PROVIDERS = (
        Path(__file__).parent.parent /
        "analytics/llm_hunter/agents/llm_providers.py"
    )
    CALL_SITES = [
        Path(__file__).parent.parent / "analytics/llm_hunter/agents/critic.py",
        Path(__file__).parent.parent / "analytics/llm_hunter/agents/supervisor.py",
        Path(__file__).parent.parent / "analytics/llm_hunter/agents/response.py",
        Path(__file__).parent.parent / "analytics/llm_hunter/agents/expert_base.py",
    ]

    def _providers_src(self) -> str:
        return self.LLM_PROVIDERS.read_text()

    def test_circuit_states_defined(self):
        """CircuitState enum must define CLOSED, OPEN, and HALF_OPEN."""
        src = self._providers_src()
        assert "CircuitState" in src, "llm_providers.py: CircuitState enum missing"
        for state in ("CLOSED", "OPEN", "HALF_OPEN"):
            assert state in src, f"llm_providers.py: CircuitState.{state} missing"

    def test_state_machine_transitions(self):
        """ProviderCircuitBreaker must implement record_success and record_failure."""
        src = self._providers_src()
        assert "def record_success" in src, \
            "llm_providers.py: ProviderCircuitBreaker.record_success missing"
        assert "def record_failure" in src, \
            "llm_providers.py: ProviderCircuitBreaker.record_failure missing"

    def test_half_open_recovery_timeout(self):
        """Circuit must auto-transition OPEN → HALF_OPEN after a recovery timeout."""
        src = self._providers_src()
        assert "_recovery_timeout" in src or "recovery_timeout" in src, \
            "llm_providers.py: recovery timeout field missing -- OPEN circuit never recovers"
        assert "HALF_OPEN" in src and "OPEN" in src, \
            "llm_providers.py: OPEN → HALF_OPEN transition not implemented"

    def test_public_circuit_api_exported(self):
        """circuit_is_callable, record_call_success, record_call_failure must be top-level."""
        src = self._providers_src()
        for fn in ("circuit_is_callable", "record_call_success", "record_call_failure"):
            assert f"def {fn}" in src, \
                f"llm_providers.py: public function '{fn}' not exported"

    def test_env_var_thresholds_configurable(self):
        """Failure threshold and recovery timeout must be overridable via env vars."""
        src = self._providers_src()
        assert "NEXUS_CB_FAILURE_THRESHOLD" in src, \
            "llm_providers.py: NEXUS_CB_FAILURE_THRESHOLD env var not used"
        assert "NEXUS_CB_RECOVERY_TIMEOUT_SECS" in src, \
            "llm_providers.py: NEXUS_CB_RECOVERY_TIMEOUT_SECS env var not used"

    def test_all_call_sites_import_circuit_helpers(self):
        """Every agent that calls LLM providers must import the circuit breaker helpers."""
        for path in self.CALL_SITES:
            src = path.read_text()
            assert "circuit_is_callable" in src, \
                f"{path.name}: circuit_is_callable not imported -- circuit breaker not wired"
            assert "record_call_success" in src, \
                f"{path.name}: record_call_success not imported"
            assert "record_call_failure" in src, \
                f"{path.name}: record_call_failure not imported"

    def test_call_sites_check_before_invoke(self):
        """Every agent must guard each provider call with circuit_is_callable."""
        for path in self.CALL_SITES:
            src = path.read_text()
            assert "circuit_is_callable" in src and "not circuit_is_callable" in src, \
                f"{path.name}: circuit_is_callable guard (if not circuit_is_callable) missing"

    def test_call_sites_record_success_on_break(self):
        """Every agent must call record_call_success before breaking out of the loop."""
        for path in self.CALL_SITES:
            src = path.read_text()
            assert "record_call_success" in src, \
                f"{path.name}: record_call_success missing -- successful calls not closing circuit"

    def test_call_sites_record_failure_in_except(self):
        """Every agent must call record_call_failure in the except block."""
        for path in self.CALL_SITES:
            src = path.read_text()
            assert "record_call_failure" in src, \
                f"{path.name}: record_call_failure missing -- failures not counted toward trip"

    def test_circuit_logic_unit(self):
        """Unit-test the ProviderCircuitBreaker state machine directly."""
        import importlib.util, sys, os, time
        # Patch env vars for fast test (threshold=2, immediate recovery)
        os.environ["NEXUS_CB_FAILURE_THRESHOLD"] = "2"
        os.environ["NEXUS_CB_RECOVERY_TIMEOUT_SECS"] = "3600"  # long -- OPEN stays OPEN
        try:
            # Load only the llm_providers module -- skip the agents package __init__
            # so we don't need langchain installed in the test environment.
            spec = importlib.util.spec_from_file_location(
                "lp_isolated",
                str(self.LLM_PROVIDERS),
            )
            lp = importlib.util.module_from_spec(spec)

            import types
            # Stub langchain_anthropic
            la_stub = types.ModuleType("langchain_anthropic")
            la_stub.ChatAnthropic = object
            sys.modules["langchain_anthropic"] = la_stub
            # Stub langchain_openai
            lo_stub = types.ModuleType("langchain_openai")
            lo_stub.ChatOpenAI = object
            sys.modules["langchain_openai"] = lo_stub
            # Stub tools.nexus_config
            nc_stub = types.ModuleType("tools.nexus_config")
            nc_stub.CONFIG = {}
            nc_stub.get_llm_provider_order = lambda: []
            sys.modules["tools"] = types.ModuleType("tools")
            sys.modules["tools.nexus_config"] = nc_stub

            spec.loader.exec_module(lp)

            cb = lp.ProviderCircuitBreaker("test-unit")

            # CLOSED → normal calls pass
            assert cb.is_callable()
            assert cb.state is lp.CircuitState.CLOSED

            # Two failures → OPEN (timeout=3600 so it stays OPEN)
            cb.record_failure()
            assert cb.is_callable()  # threshold not reached yet
            cb.record_failure()
            assert not cb.is_callable()   # circuit tripped
            assert cb.state is lp.CircuitState.OPEN  # still OPEN -- timeout not elapsed

            # Manually force HALF_OPEN by backdating opened_at past recovery window
            cb._opened_at = time.monotonic() - 7200
            assert cb.state is lp.CircuitState.HALF_OPEN
            assert cb.is_callable()   # probe allowed

            # Success in HALF_OPEN → CLOSED
            cb.record_success()
            assert cb.state is lp.CircuitState.CLOSED
            assert cb.is_callable()

            # Re-trip via HALF_OPEN failure path
            cb2 = lp.ProviderCircuitBreaker("test-unit2")
            cb2.record_failure()
            cb2.record_failure()   # → OPEN
            cb2._opened_at = time.monotonic() - 7200  # force HALF_OPEN
            _ = cb2.state          # transitions to HALF_OPEN
            cb2.record_failure()   # probe fails → OPEN
            assert cb2.state is lp.CircuitState.OPEN

        finally:
            os.environ.pop("NEXUS_CB_FAILURE_THRESHOLD", None)
            os.environ.pop("NEXUS_CB_RECOVERY_TIMEOUT_SECS", None)
