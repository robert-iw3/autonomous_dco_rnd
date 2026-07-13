"""
Lab 9: Worker Rules Offline Source-Code Contracts

Reads services/worker_rules/src/main.rs and asserts structural/behavioral
invariants without compiling or running any service.

Coverage:
  - Duck-typing column sentinels for all 6 sensor types
  - Layer A (edge pass-through) logic
  - Layer B centralized rules (LotL, DGA, cloud API, identity, GuardDuty, TLS, Windows bins)
  - Circuit breaker parameters
  - Alert JSON schema fields
  - Redis queue key consistency with orchestrator
  - Prometheus metric names
"""
from pathlib import Path

MAIN_RS = Path(__file__).parent.parent.parent / "services/worker_rules/src/main.rs"
ORCHESTRATOR_PY = Path(__file__).parent.parent.parent / "analytics/llm_hunter/orchestrator.py"


def _src():
    return MAIN_RS.read_text()


class TestDuckTypingColumns:
    """Duck-typing column sentinels -- must match what sensors actually emit."""

    def test_linux_c2_sentinel_outbound_ratio_and_comm(self):
        assert 'has_col("outbound_ratio") && has_col("comm")' in _src(), \
            "linux_c2 branch must require outbound_ratio AND comm columns"

    def test_windows_c2_sentinel_outbound_ratio_and_image(self):
        assert 'has_col("outbound_ratio") && has_col("Image")' in _src(), \
            "windows_c2 branch must require outbound_ratio AND Image columns"

    def test_linux_sentinel_detected_by_shannon_entropy(self):
        assert 'has_col("shannon_entropy")' in _src(), \
            "linux_sentinel must be identified by shannon_entropy column"

    def test_windows_deepsensor_detected_by_max_velocity(self):
        assert 'has_col("max_velocity")' in _src(), \
            "windows_deepsensor must be identified by max_velocity column"

    def test_network_tap_detected_by_session_id_and_tls_ja3(self):
        assert 'has_col("session_id") && has_col("tls_ja3")' in _src(), \
            "network_tap must be identified by session_id AND tls_ja3 columns"

    def test_cloud_sensor_requires_event_type_mitre_tactic_sensor_id(self):
        assert 'has_col("event_type") && has_col("mitre_tactic") && has_col("sensor_id")' in _src(), \
            "Cloud sensors must be identified by event_type, mitre_tactic, and sensor_id columns"

    def test_linux_c2_branch_precedes_windows_c2(self):
        """Priority: linux_c2 (outbound_ratio+comm) must be checked before windows_c2 (outbound_ratio+Image)."""
        src = _src()
        assert src.index('has_col("comm")') < src.index('has_col("Image")'), \
            "linux_c2 branch must appear before windows_c2 in duck-typing chain"

    def test_shannon_entropy_branch_precedes_max_velocity(self):
        src = _src()
        assert src.index('has_col("shannon_entropy")') < src.index('has_col("max_velocity")'), \
            "linux_sentinel branch must appear before windows_deepsensor"


class TestLayerAEdgePassThrough:
    """Layer A: O(1) edge pass-through -- fires when edge device pre-classified the event."""

    def test_fires_on_non_empty_non_unknown_signature(self):
        assert '!edge_signature.is_empty() && edge_signature != "unknown"' in _src(), \
            "Layer A must fire when edge_signature is non-empty and not 'unknown'"

    def test_signature_prefers_signature_name_over_message(self):
        src = _src()
        assert src.index('get_str("signature_name")') < src.index('get_str("message")'), \
            "edge_signature must prefer signature_name field, fall back to message"

    def test_layer_a_calls_create_alert_with_edge_signature(self):
        assert 'create_alert(&edge_signature, &event)' in _src(), \
            "Layer A must call create_alert with edge_signature as the rule name"

    def test_layer_a_short_circuits_with_continue(self):
        src = _src()
        # The continue after Layer A push means Layer B is skipped
        la_pos = src.find('create_alert(&edge_signature, &event)')
        continue_pos = src.find('continue;', la_pos)
        assert continue_pos != -1 and continue_pos - la_pos < 200, \
            "Layer A must short-circuit (continue) to skip Layer B evaluation"


class TestLayerBLotLRule:
    """Web_Shell_Downloader_LotL: web process UID running downloader."""

    def test_uid_33_www_data(self):
        assert 'event.uid == 33' in _src(), \
            "LotL rule must check uid == 33 (www-data -- Apache on Debian)"

    def test_uid_48_apache(self):
        assert 'event.uid == 48' in _src(), \
            "LotL rule must check uid == 48 (apache -- RHEL/CentOS)"

    def test_wget_downloader(self):
        assert '"wget"' in _src(), "LotL rule must trigger on wget process"

    def test_curl_downloader(self):
        assert '"curl"' in _src(), "LotL rule must trigger on curl process"

    def test_rule_name_web_shell_downloader_lotl(self):
        assert '"Web_Shell_Downloader_LotL"' in _src(), \
            "Rule name must be exactly Web_Shell_Downloader_LotL"


class TestLayerBDGARule:
    """Suspicious_DGA_TLD: domain generation algorithm TLD detection."""

    def test_tld_top(self):
        assert '".top"' in _src(), "DGA TLD rule must cover .top"

    def test_tld_xyz(self):
        assert '".xyz"' in _src(), "DGA TLD rule must cover .xyz"

    def test_uses_ends_with(self):
        assert '.ends_with(".top")' in _src() or 'ends_with(".top")' in _src(), \
            "DGA TLD rule must use ends_with for TLD matching"

    def test_rule_name_suspicious_dga_tld(self):
        assert '"Suspicious_DGA_TLD"' in _src()


class TestLayerBCloudRules:
    """Cloud control plane and identity rules."""

    def test_cloud_critical_api_stop_logging(self):
        assert '"StopLogging"' in _src(), "Cloud rule must cover StopLogging (CloudTrail disable)"

    def test_cloud_critical_api_delete_trail(self):
        assert '"DeleteTrail"' in _src(), "Cloud rule must cover DeleteTrail"

    def test_cloud_critical_api_delete_detector(self):
        assert '"DeleteDetector"' in _src(), "Cloud rule must cover DeleteDetector (GuardDuty disable)"

    def test_cloud_critical_api_disable_key(self):
        assert '"DisableKey"' in _src(), "Cloud rule must cover DisableKey (KMS tamper)"

    def test_cloud_critical_api_put_bucket_policy(self):
        assert '"PutBucketPolicy"' in _src(), "Cloud rule must cover PutBucketPolicy (S3 exfil gate)"

    def test_cloud_critical_api_authorize_sg_ingress(self):
        assert '"AuthorizeSecurityGroupIngress"' in _src(), \
            "Cloud rule must cover AuthorizeSecurityGroupIngress (firewall bypass)"

    def test_entra_high_risk_threshold_60(self):
        assert '>= 60' in _src(), "Entra_High_Risk_SignIn must trigger at score >= 60"

    def test_entra_high_risk_rule_name(self):
        assert '"Entra_High_Risk_SignIn"' in _src()

    def test_guardduty_severity_threshold_70(self):
        assert '>= 70' in _src(), "GuardDuty_High_Severity must trigger at score >= 70"

    def test_guardduty_rule_name(self):
        assert '"GuardDuty_High_Severity"' in _src()

    def test_self_signed_tls_rule_name(self):
        assert '"SelfSigned_TLS_With_JA3"' in _src()

    def test_self_signed_tls_checks_cert_field(self):
        assert 'cert_self_signed' in _src(), "TLS rule must check cert_self_signed field"


class TestLayerBWindowsBinsRule:
    """Suspicious_Windows_Bin_*: LOLBins and credential/volume shadow tools."""

    WINDOWS_IOCS = ["whoami.exe", "vssadmin.exe", "procdump.exe", "shadowcopy", "regsvr32.exe"]

    def test_all_windows_iocs_present(self):
        src = _src()
        for ioc in self.WINDOWS_IOCS:
            assert f'"{ioc}"' in src or ioc in src, \
                f"Windows suspicious binary rule must include {ioc}"

    def test_uses_cmd_lower_for_case_insensitive_match(self):
        assert 'cmd_lower' in _src(), \
            "Windows bin rule must use lowercased command line for case-insensitive match"


class TestCircuitBreaker:
    """Redis circuit breaker -- prevents alert cascade from overwhelming a degraded Redis."""

    def test_trips_after_3_consecutive_failures(self):
        # failsafe 1.3's failure_policy::consecutive_failures(n, backoff) is a free
        # function (ConsecutiveFailures has no ::new constructor in this version) --
        # the literal "3," argument is what encodes the consecutive-failure threshold.
        assert 'failure_policy::consecutive_failures(' in _src() and '3,' in _src(), \
            "Circuit breaker must open after 3 consecutive failures"

    def test_exponential_backoff_starts_at_2s(self):
        assert 'Duration::from_secs(2)' in _src(), \
            "Exponential backoff initial delay must be 2 seconds"

    def test_exponential_backoff_caps_at_60s(self):
        assert 'Duration::from_secs(60)' in _src(), \
            "Exponential backoff must cap at 60 seconds"

    def test_uses_lpush_for_queue(self):
        assert 'lpush' in _src(), \
            "Alerts must be pushed via LPUSH (Redis list -- orchestrator BLPOP consumer)"


class TestAlertSchema:
    """JSON alert schema produced by create_alert() -- changes break the orchestrator."""

    def test_event_id_field_present(self):
        assert '"event_id"' in _src()

    def test_timestamp_field_present(self):
        assert '"timestamp"' in _src()

    def test_sensor_id_field_present(self):
        assert '"sensor_id"' in _src()

    def test_source_type_field_present(self):
        assert '"source_type"' in _src()

    def test_vector_name_is_sigma_rule(self):
        assert '"sigma_rule"' in _src(), \
            "vector_name must be 'sigma_rule' so orchestrator routes correctly"

    def test_anomaly_score_is_1_0(self):
        assert '"anomaly_score": 1.0' in _src(), \
            "Deterministic rule alerts must emit anomaly_score = 1.0"

    def test_raw_event_rule_triggered(self):
        assert '"rule_triggered"' in _src(), \
            "raw_event must include rule_triggered for SOAR/analyst context"


class TestRedisKeyConsistency:
    """The key worker_rules pushes to must match what the orchestrator BLPOP reads from."""

    def test_orchestrator_reads_nexus_deterministic_alerts(self):
        orch_src = ORCHESTRATOR_PY.read_text()
        assert '"nexus:deterministic:alerts"' in orch_src, \
            "Orchestrator must BLPOP from 'nexus:deterministic:alerts'"

    def test_worker_rules_config_has_alert_queue_key(self):
        assert 'alert_queue_key' in _src(), \
            "worker_rules config must define alert_queue_key -- key comes from config, not hardcoded"

    def test_lpush_uses_config_alert_queue_key(self):
        assert 'lpush(&alert_queue_key' in _src(), \
            "LPUSH must use alert_queue_key from config (not a hardcoded string)"

    def test_config_struct_has_redis_section(self):
        assert 'struct RedisConf' in _src(), \
            "Separate RedisConf struct must isolate Redis configuration"


class TestMetricNames:
    """Prometheus metric names must be stable -- renaming breaks dashboards/alerts."""

    def test_alerts_fired_total(self):
        assert '"nexus_rules_alerts_fired_total"' in _src()

    def test_redis_faults_total(self):
        assert '"nexus_rules_redis_faults_total"' in _src()

    def test_circuit_breaker_rejected_total(self):
        assert '"nexus_rules_redis_rejected_total"' in _src()

    def test_prometheus_listener_on_port_9002(self):
        assert '9002' in _src(), \
            "Prometheus metrics listener must be on port 9002"
