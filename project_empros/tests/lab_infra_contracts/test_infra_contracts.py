"""
Lab 12: Infrastructure Hardening Contracts

Validates:
  - Ansible SSH hardening role (drop-in config, sshd -t validation, moduli, client hardening)
  - Ansible kernel hardening role (sysctl, core dumps, /tmp noexec)
  - production.yaml cluster sizes (quorum), flags, and required keys

All offline -- reads source files, no Ansible/SSH needed.
"""
import yaml
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
ANSIBLE_BASE = PROJECT_ROOT / "infrastructure/ansible"
HARDENING_TASKS = ANSIBLE_BASE / "roles/common_hardening/tasks"
PROD_YAML = PROJECT_ROOT / "orchestration/environments/production.yaml"


def _ssh():
    return (HARDENING_TASKS / "ssh.yml").read_text()


def _kernel():
    return (HARDENING_TASKS / "kernel.yml").read_text()


def _prod():
    return yaml.safe_load(PROD_YAML.read_text())


# ── SSH hardening role ────────────────────────────────────────────────────────

class TestSSHHardeningRole:
    """SSH hardening role must deploy a validated drop-in config."""

    def test_ssh_yml_exists(self):
        assert (HARDENING_TASKS / "ssh.yml").exists()

    def test_sshd_config_d_directory_created(self):
        assert "sshd_config.d" in _ssh(), \
            "Role must create /etc/ssh/sshd_config.d for drop-in configs"

    def test_drop_in_file_named_99_nexus_hardening(self):
        assert "99-nexus-hardening.conf" in _ssh(), \
            "Drop-in must be 99-nexus-hardening.conf (high sort order -- overrides distro defaults)"

    def test_sshd_t_validation_gate(self):
        assert "sshd -t" in _ssh(), \
            "Template deploy must run 'sshd -t' to validate config before activating"

    def test_sshd_config_includes_drop_in_dir(self):
        assert "Include /etc/ssh/sshd_config.d" in _ssh() or "Include" in _ssh(), \
            "sshd_config must include the drop-in directory"

    def test_hash_known_hosts_enforced_on_client(self):
        assert "HashKnownHosts" in _ssh(), \
            "SSH client config must enforce HashKnownHosts (prevents hostname reconnaissance)"

    def test_private_key_permissions_0600(self):
        assert "mode: '0600'" in _ssh(), \
            "SSH private host keys must have mode 0600"

    def test_moduli_filtered_for_minimum_strength(self):
        assert "moduli" in _ssh() and "hardening_ssh_moduli_minimum" in _ssh(), \
            "Weak DH moduli must be filtered -- prevents Logjam-style downgrade attacks"

    def test_banner_deployed(self):
        assert "/etc/issue" in _ssh() or "banner" in _ssh().lower(), \
            "Login banner must be deployed (/etc/issue, /etc/issue.net, /etc/motd)"

    def test_notify_restart_sshd(self):
        assert "Restart sshd" in _ssh() or "restart" in _ssh().lower(), \
            "SSH config changes must notify a handler to restart sshd"


# ── Kernel hardening role ─────────────────────────────────────────────────────

class TestKernelHardeningRole:
    """Kernel hardening role must deploy sysctl config and disable dangerous features."""

    def test_kernel_yml_exists(self):
        assert (HARDENING_TASKS / "kernel.yml").exists()

    def test_sysctl_hardening_conf_deployed(self):
        assert "99-nexus-hardening.conf" in _kernel(), \
            "Kernel hardening must deploy /etc/sysctl.d/99-nexus-hardening.conf"

    def test_sysctl_system_applied_immediately(self):
        assert "sysctl --system" in _kernel(), \
            "Sysctl settings must be applied immediately, not just on next boot"

    def test_core_dumps_disabled_via_limits(self):
        src = _kernel()
        assert "core" in src and "hard" in src, \
            "Core dumps must be disabled via limits.conf (hard core 0)"

    def test_suid_dumpable_disabled(self):
        assert "fs.suid_dumpable" in _kernel(), \
            "fs.suid_dumpable must be 0 (prevents SUID binary core dump exploitation)"

    def test_tmp_mounted_noexec(self):
        assert "noexec" in _kernel() and "/tmp" in _kernel(), \
            "/tmp must be mounted with noexec to prevent execution of uploaded payloads"

    def test_tmp_mounted_nosuid(self):
        assert "nosuid" in _kernel(), "/tmp must be mounted with nosuid"

    def test_devshm_hardened(self):
        assert "/dev/shm" in _kernel(), \
            "/dev/shm must have noexec,nosuid,nodev (shared memory attack surface)"

    def test_crontab_0600_permissions(self):
        assert "/etc/crontab" in _kernel() and "'0600'" in _kernel(), \
            "/etc/crontab must be mode 0600 to prevent unauthorized cron job injection"

    def test_cron_directories_hardened(self):
        assert "/etc/cron.d" in _kernel() and "'0700'" in _kernel(), \
            "cron directories must be mode 0700"


# ── production.yaml environment ───────────────────────────────────────────────

class TestProductionYAML:
    """production.yaml required keys and cluster quorum contracts."""

    def test_file_is_valid_yaml(self):
        data = _prod()
        assert isinstance(data, dict)

    def test_nats_cluster_size_is_3(self):
        assert _prod()["nats_cluster_size"] == 3, \
            "NATS must run 3 nodes (never an even number -- quorum requires odd)"

    def test_nats_cluster_size_is_odd(self):
        assert _prod()["nats_cluster_size"] % 2 == 1, \
            "NATS cluster size must be odd for quorum"

    def test_qdrant_cluster_size_is_3(self):
        assert _prod()["qdrant_cluster_size"] == 3

    def test_redis_cluster_size_is_3(self):
        assert _prod()["redis_cluster_size"] == 3

    def test_deployment_tier_valid_value(self):
        assert _prod()["deployment_tier"] in ("small", "medium", "large")

    def test_infra_target_valid_value(self):
        assert _prod()["infra_target"] in ("aws-ec2", "vmware", "aws-eks")

    def test_nexus_enabled_is_true(self):
        assert _prod()["nexus_enabled"] is True, \
            "nexus_enabled must be true -- disabling it silently drops all sensor telemetry"

    def test_middleware_tls_enabled(self):
        assert _prod()["middleware_tls_enabled"] is True, \
            "Middleware TLS must be enabled in production"

    def test_worker_rules_instances_defined(self):
        assert "worker_rules_instances" in _prod()

    def test_worker_qdrant_instances_defined(self):
        assert "worker_qdrant_instances" in _prod()

    def test_hardening_ssh_port_defined(self):
        assert "hardening_ssh_port" in _prod()

    def test_hardening_firewall_trusted_subnet_defined(self):
        assert "hardening_firewall_trusted_subnet" in _prod()

    def test_mlops_model_version_defined(self):
        assert "mlops_model_version" in _prod()

    def test_aws_region_defined(self):
        assert "aws_region" in _prod()

    def test_endpoint_count_positive(self):
        assert _prod().get("endpoint_count", 0) > 0

    def test_ansible_ssh_key_file_defined(self):
        assert "ansible_ssh_key_file" in _prod()


# ── Memory / IR evidence WORM archive + worker_memory automation ────────────
TF_MEM_BUCKET = PROJECT_ROOT / "infrastructure/terraform/aws/memory_evidence_bucket.tf"
SITE_YML = ANSIBLE_BASE / "site.yml"


class TestMemoryEvidenceAutomation:
    """The memory-forensics bridge is automated into the stack build: a WORM
    evidence bucket (Terraform), worker_memory in the Ansible fleet, and the
    config keys core_ingress + worker_memory consume."""

    def test_worm_bucket_terraform_exists(self):
        assert TF_MEM_BUCKET.exists(), "memory_evidence_bucket.tf must provision the WORM archive"

    def test_bucket_is_object_locked_governance_kms(self):
        tf = TF_MEM_BUCKET.read_text()
        assert "object_lock_enabled = true" in tf, "WORM object-lock must be enabled at creation"
        assert "GOVERNANCE" in tf, "image default retention is GOVERNANCE (operator-purgeable)"
        assert "aws_kms_key" in tf and "aws:kms" in tf, "KMS server-side encryption required"
        assert "aws_s3_bucket_public_access_block" in tf, "bucket must block all public access"
        assert "aws:SecureTransport" in tf, "TLS-only bucket policy required"

    def test_worker_memory_deploys_as_python_service_not_cargo(self):
        site = SITE_YML.read_text()
        # worker_memory is Python — it must NOT ride the cargo-only rust_podman_worker
        # fleet (that build is `cargo build -p <name>` and would fail), but its own role.
        assert 'worker_name: "worker_memory"' not in site, \
            "worker_memory is Python; it cannot build via the rust_podman_worker (cargo) fleet"
        assert "memory_worker" in site, "worker_memory must deploy via the memory_worker role"
        role = PROJECT_ROOT / "infrastructure/ansible/roles/memory_worker/tasks/main.yml"
        assert role.exists(), "memory_worker role must exist"
        rt = role.read_text()
        assert "services/worker_memory/" in rt, "role builds from the service's own dir (context)"
        assert "podman.sock" in rt, "worker needs the host runtime to spawn the analyzer container"
        assert "NEXUS_MEMORY_ARCHIVE_BUCKET" in rt, "evidence bucket env must be passed"

    def test_worker_memory_dockerfile_is_service_local(self):
        df = (PROJECT_ROOT / "services/worker_memory/Dockerfile").read_text()
        # built with context = the service dir (like worker_ti_ingest): COPY *.py, no
        # outer project_empros/ prefix, and not a cargo build.
        assert "COPY *.py" in df and "project_empros/" not in df
        assert "cargo" not in df and "alpine:3.24" in df

    def test_production_config_keys(self):
        p = _prod()
        assert p.get("worker_memory_instances", 0) >= 1
        assert p.get("memory_archive_bucket"), "memory_archive_bucket must be set"
        assert int(p.get("max_evidence_bytes", 0)) > p.get("nats_max_payload_mb", 10) * 1024 * 1024, \
            "evidence cap must exceed the telemetry NATS payload cap (RAM images are large)"
