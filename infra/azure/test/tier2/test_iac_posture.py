"""
Tier-2 -- security-posture regression guards for the Azure deploy/ IaC.
"""
import shutil
import subprocess
import pytest
import iac_deploy_mirror as M
import _iac_parse as P

pytestmark = pytest.mark.tier2

class TestStoragePosture:
    """Only nsg ships an azurerm_storage_account; skip for activity/entraid."""

    def test_storage_account_uses_minimum_tls(self, tf_src, connector_name):
        accounts = list(P.iter_resources(tf_src, "azurerm_storage_account"))
        if not accounts:
            pytest.skip(f"{connector_name}: no storage account in this stack")
        for name, body in accounts:
            assert P.scalar(body, "min_tls_version") == M.POSTURE["storage_min_tls"], (
                f"{connector_name}: storage account {name} min_tls_version "
                f"!= {M.POSTURE['storage_min_tls']}"
            )

    def test_storage_account_uses_grs_replication(self, tf_src, connector_name):
        accounts = list(P.iter_resources(tf_src, "azurerm_storage_account"))
        if not accounts:
            pytest.skip(f"{connector_name}: no storage account in this stack")
        for name, body in accounts:
            assert P.scalar(body, "account_replication_type") == M.POSTURE["storage_replication"], (
                f"{connector_name}: storage account {name} account_replication_type "
                f"!= {M.POSTURE['storage_replication']} (cross-region redundancy required)"
            )

    def test_storage_container_is_private(self, tf_src, connector_name):
        containers = list(P.iter_resources(tf_src, "azurerm_storage_container"))
        if not containers:
            pytest.skip(f"{connector_name}: no storage container in this stack")
        for name, body in containers:
            assert P.scalar(body, "container_access_type") == M.POSTURE["container_access"], (
                f"{connector_name}: container {name} container_access_type "
                f"!= {M.POSTURE['container_access']}"
            )

    def test_storage_has_blob_versioning_enabled(self, tf_src, connector_name):
        accounts = list(P.iter_resources(tf_src, "azurerm_storage_account"))
        if not accounts:
            pytest.skip(f"{connector_name}: no storage account in this stack")
        for name, body in accounts:
            assert P.scalar(body, "versioning_enabled") == "true", (
                f"{connector_name}: storage account {name} missing "
                f"blob_properties.versioning_enabled = true"
            )

    def test_storage_has_delete_retention_policy(self, tf_src, connector_name):
        accounts = list(P.iter_resources(tf_src, "azurerm_storage_account"))
        if not accounts:
            pytest.skip(f"{connector_name}: no storage account in this stack")
        for name, body in accounts:
            assert "delete_retention_policy" in body, (
                f"{connector_name}: storage account {name} has no "
                f"blob_properties.delete_retention_policy block"
            )

    def test_storage_requires_https_traffic_only(self, tf_src, connector_name):
        """https_traffic_only_enabled defaults to true in azurerm 3.x but must be
        declared explicitly -- implicit defaults silently change across provider
        upgrades and are not visible in plan diffs."""
        accounts = list(P.iter_resources(tf_src, "azurerm_storage_account"))
        if not accounts:
            pytest.skip(f"{connector_name}: no storage account in this stack")
        for name, body in accounts:
            assert P.scalar(body, "https_traffic_only_enabled") == "true", (
                f"{connector_name}: storage account {name} does not explicitly set "
                f"https_traffic_only_enabled = true (required for IaC auditability "
                f"and checkov CKV_AZURE_3)"
            )

    def test_storage_disallows_public_blob_access(self, tf_src, connector_name):
        """In azurerm 3.x the default for allow_nested_items_to_be_public is true,
        meaning any blob can be exposed publicly. This must be explicitly false."""
        accounts = list(P.iter_resources(tf_src, "azurerm_storage_account"))
        if not accounts:
            pytest.skip(f"{connector_name}: no storage account in this stack")
        for name, body in accounts:
            assert P.scalar(body, "allow_nested_items_to_be_public") == "false", (
                f"{connector_name}: storage account {name} is missing "
                f"allow_nested_items_to_be_public = false (default is true -- "
                f"blobs can be made public without this explicit guard)"
            )

class TestEventHubPosture:
    def test_eventhub_namespace_uses_standard_sku(self, tf_src, connector_name):
        namespaces = list(P.iter_resources(tf_src, "azurerm_eventhub_namespace"))
        assert namespaces, f"{connector_name}: no azurerm_eventhub_namespace found"
        for name, body in namespaces:
            assert P.scalar(body, "sku") == M.POSTURE["eventhub_sku"], (
                f"{connector_name}: namespace {name} sku != {M.POSTURE['eventhub_sku']} "
                f"(Basic SKU has no consumer groups -- required for independent offset tracking)"
            )

    def test_eventhub_has_message_retention(self, tf_src, connector_name):
        hubs = list(P.iter_resources(tf_src, "azurerm_eventhub"))
        assert hubs, f"{connector_name}: no azurerm_eventhub found"
        for name, body in hubs:
            retention = P.scalar(body, "message_retention")
            assert retention is not None, (
                f"{connector_name}: hub {name} has no message_retention set"
            )
            assert int(retention) >= 1, (
                f"{connector_name}: hub {name} message_retention={retention} "
                f"(must be >= 1 day)"
            )

    def test_eventhub_partition_count_meets_minimum(self, tf_src, connector_name):
        """Below MIN_PARTITION_COUNT all partitions are consumed by a single
        goroutine-equivalent; the connector cannot scale parallel reads."""
        hubs = list(P.iter_resources(tf_src, "azurerm_eventhub"))
        assert hubs, f"{connector_name}: no azurerm_eventhub found"
        for name, body in hubs:
            count = P.scalar(body, "partition_count")
            assert count is not None, f"{connector_name}: hub {name} has no partition_count"
            assert int(count) >= M.MIN_PARTITION_COUNT, (
                f"{connector_name}: hub {name} partition_count={count} "
                f"(minimum {M.MIN_PARTITION_COUNT} required for parallel consumption)"
            )

    def test_send_only_rule_is_properly_scoped(self, tf_src, connector_name):
        """activity/entraid: the diagnostic-send rule must have send=true,
        listen=false, manage=false. If it also has listen=true the Diagnostic
        Setting service account gains read access -- an over-grant."""
        send_rules = [
            (name, body)
            for name, body in P.iter_resources(tf_src, "azurerm_eventhub_authorization_rule")
            if P.scalar(body, "send") == "true"
        ]
        if not send_rules:
            pytest.skip(f"{connector_name}: no send=true auth rule (nsg does not need one)")
        for name, body in send_rules:
            assert P.scalar(body, "listen") == "false", (
                f"{connector_name}: send rule {name} also grants listen -- over-grant; "
                f"the Diagnostic Setting service account should not be able to read the hub"
            )
            assert P.scalar(body, "manage") == "false", (
                f"{connector_name}: send rule {name} also grants manage -- over-grant"
            )

    def test_listen_only_rule_cannot_send_or_manage(self, tf_src, connector_name):
        """The Nexus consumer's authorization rule must be strictly read-only --
        listen=true, send=false, manage=false. This is the Azure analogue of the
        least-privilege IAM policy check on the AWS side."""
        listen_rules = [
            (name, body)
            for name, body in P.iter_resources(tf_src, "azurerm_eventhub_authorization_rule")
            if P.scalar(body, "listen") == "true"
        ]
        assert listen_rules, (
            f"{connector_name}: no azurerm_eventhub_authorization_rule with listen=true"
        )
        for name, body in listen_rules:
            assert P.scalar(body, "send") == "false", (
                f"{connector_name}: auth rule {name} has listen=true but also send=true "
                f"(over-grant -- listen-only rules must not send)"
            )
            assert P.scalar(body, "manage") == "false", (
                f"{connector_name}: auth rule {name} has listen=true but also manage=true "
                f"(over-grant -- listen-only rules must not manage)"
            )

class TestManagedIdentityPosture:
    def test_user_assigned_identity_exists(self, tf_src, connector_name):
        identities = list(P.iter_resources(tf_src, "azurerm_user_assigned_identity"))
        assert identities, (
            f"{connector_name}: no azurerm_user_assigned_identity found -- "
            f"connector runtime must authenticate via managed identity, not shared credentials"
        )

class TestKeyVaultPosture:
    def test_key_vault_exists(self, tf_src, connector_name):
        vaults = list(P.iter_resources(tf_src, "azurerm_key_vault"))
        assert vaults, (
            f"{connector_name}: no azurerm_key_vault found -- "
            f"connector secrets must be stored in Key Vault"
        )

    def test_key_vault_has_purge_protection(self, tf_src, connector_name):
        for name, body in P.iter_resources(tf_src, "azurerm_key_vault"):
            assert P.scalar(body, "purge_protection_enabled") == "true", (
                f"{connector_name}: key vault {name} purge_protection_enabled != true -- "
                f"secrets cannot be permanently deleted without this guard"
            )

    def test_key_vault_uses_rbac_authorization(self, tf_src, connector_name):
        for name, body in P.iter_resources(tf_src, "azurerm_key_vault"):
            assert P.scalar(body, "enable_rbac_authorization") == "true", (
                f"{connector_name}: key vault {name} must enable RBAC authorization "
                f"(CKV_AZURE_188 -- access policies are legacy and harder to audit)"
            )

    def test_auth_token_secret_exists(self, tf_src, connector_name):
        secrets = list(P.iter_resources(tf_src, "azurerm_key_vault_secret"))
        assert secrets, (
            f"{connector_name}: no azurerm_key_vault_secret found -- "
            f"connector bearer token must be stored in Key Vault"
        )
        names = {P.scalar(body, "name") for _, body in secrets}
        assert "auth-token" in names, (
            f"{connector_name}: no secret named 'auth-token' found in Key Vault; "
            f"provisioned secrets: {sorted(n for n in names if n)}"
        )

class TestMonitorAlertPosture:
    def test_eventhub_throttle_alert_exists(self, tf_src, connector_name):
        alerts = list(P.iter_resources(tf_src, "azurerm_monitor_metric_alert"))
        assert alerts, (
            f"{connector_name}: no azurerm_monitor_metric_alert found -- "
            f"Event Hub throttling must be monitored to detect back-pressure events"
        )

    def test_eventhub_alert_watches_throttled_requests(self, tf_src, connector_name):
        for name, body in P.iter_resources(tf_src, "azurerm_monitor_metric_alert"):
            assert "ThrottledRequests" in body or "Microsoft.EventHub" in body, (
                f"{connector_name}: alert {name} does not appear to watch "
                f"Event Hub ThrottledRequests"
            )

class TestPolicyScanners:
    def test_checkov_enforces_all_but_documented_na(self, tf_dir, connector_name):
        if not shutil.which("checkov"):
            pytest.skip("checkov not installed (present in the tier2 container)")
        cmd = [
            "checkov", "-d", tf_dir, "--quiet", "--compact",
            "--framework", "terraform", "-o", "cli",
            "--skip-check", ",".join(sorted(M.CHECKOV_SKIP)),
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        assert r.returncode == 0, (
            f"{connector_name}: checkov found real (non-N/A) findings on {tf_dir}.\n"
            f"Documented N/A skips: {sorted(M.CHECKOV_SKIP)}\n{r.stdout[-3000:]}"
        )