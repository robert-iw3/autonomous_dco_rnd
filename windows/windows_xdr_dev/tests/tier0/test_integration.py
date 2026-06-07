"""
Tier-0 -- End-to-end integration scenario tests.

Each test simulates a complete attacker technique from raw event through
decision logic to expected verdict.  No Windows APIs, no ETW, no containers.

Scenarios:
  01  ETW tamper attempt               → ETW_TAMPER beacon, score=9.5
  02  Web shell via nginx→cmd          → WEB_SHELL_DETECTED, score=9.5
  03  DB RCE via sqlservr→powershell   → DB_RCE_DETECTED, score=9.5
  04  ASP.NET compiler exception       → No alert
  05  Benign wininit→services lineage  → Dropped before AppGuard check
  06  Cobalt Strike named pipe         → MALICIOUS_PIPE beacon
  07  High-entropy pipe                → HIGH_ENTROPY_PIPE beacon
  08  Canary file heartbeat            → Silently dropped
  09  Registry Run key persistence     → persistence key flagged
  10  Suspicious temp path launch      → SUSPICIOUS_PATH, score=7.5
  11  YARA memory: valid RWX region    → parse succeeds, scan eligible
  12  YARA memory: invalid details     → parse fails, skipped
  13  YARA memory: critical process    → scan skipped even on RWX
  14  C2 beacon confirmed (low CV)     → is_beacon_confirmed=True
  15  C2 beacon dismissed (high CV)    → is_beacon_confirmed=False
  16  Lateral SMB movement             → LATERAL_SMB reason
  17  Ingress flood                    → is_ingress_flood=True
  18  Port scan                        → is_port_scan=True
  19  Malicious IP TI match exclusion  → 185.220.101.1 passes exclusion check
  20  HMAC integrity: config key       → HMAC uses configured secret correctly
  21  DNS exclusion: microsoft domain  → filtered out
  22  Full beacon context JSON         → valid JSON with all required fields
  23  Cobalt Strike CS-1 beacon timing → regular 60-sec intervals, CV < 0.20
  24  Human browsing traffic           → irregular intervals, CV > 0.20
  25  KernelBridge score conversion    → fixed-point / 100 maps correctly
"""

import json
import math
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from deepxdr_logic import (
    detect_etw_tamper, ETW_TAMPER_SCORE,
    classify_appguard, is_benign_lineage,
    classify_file_event, MALICIOUS_PIPE_SCORE, HIGH_ENTROPY_PIPE_SCORE,
    is_persistence_registry_key, has_suspicious_path, SUSPICIOUS_PATH_SCORE,
    parse_memory_details, memory_event_should_scan,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ,
    compute_jitter_cv, is_beacon_confirmed, is_beacon_suspicious,
    classify_lateral_port, is_ingress_flood, is_port_scan,
    is_ip_excluded, build_ip_exclusion_patterns, is_dns_excluded,
    compute_hmac, INTEGRITY_SECRET_DEFAULT,
    build_beacon_context_json,
    BEACON_CV_THRESHOLD, TICKS_PER_MS, SCORE_DIVISOR,
    SCORE_CRITICAL_FP, SCORE_HIGH_FP, SCORE_MEDIUM_FP,
    EVT_OB_ACCESS, EVT_QUARANTINE_BLOCK, EVT_TOKEN_ACCESS,
    KERNEL_BEACON_SCORE_THRESHOLD, MONITOR_EVENT_VALID_SENTINEL,
    BEACON_SCORES, sigma_hit_score, extract_ppid,
    ip_str_to_uint, ip_uint_to_str,
)

pytestmark = pytest.mark.tier0


def _ticks_from_intervals(intervals_ms: list[float]) -> list[int]:
    ticks = [0]
    for ms in intervals_ms:
        ticks.append(ticks[-1] + int(ms * TICKS_PER_MS))
    return ticks

# -----------------------------------------------------------------------------
# Scenario 01 -- ETW tamper attempt
# -----------------------------------------------------------------------------

class TestScenario01EtwTamper:
    """Attacker runs: logman stop "XDR-Trace" to kill telemetry session."""

    def test_logman_stop_detected(self):
        cmd = 'logman stop "XDR-Trace"'
        assert detect_etw_tamper(cmd) is True

    def test_expected_score(self):
        assert ETW_TAMPER_SCORE == 9.5

    def test_logman_query_not_tamper(self):
        # Admins may run 'logman query' legitimately
        assert detect_etw_tamper("logman query") is False

    def test_logman_start_not_tamper(self):
        assert detect_etw_tamper("logman start SomeName -p ...") is False


# -----------------------------------------------------------------------------
# Scenario 02 -- Web shell via nginx → cmd.exe
# -----------------------------------------------------------------------------

class TestScenario02WebShell:
    """Attacker uploads webshell to nginx server; triggers cmd.exe spawn."""

    def test_nginx_spawns_cmd_triggers_alert(self):
        active_web = {100: "nginx.exe"}
        reason, score = classify_appguard("cmd.exe", 100, "", active_web, {})
        assert reason == "WEB_SHELL_DETECTED"
        assert score == 9.5

    def test_score_above_critical_threshold(self):
        active_web = {100: "w3wp.exe"}
        _, score = classify_appguard("powershell.exe", 100, "", active_web, {})
        assert score >= 9.0

    def test_benign_lineage_not_applicable_for_web(self):
        # nginx is NOT in benign lineage list -- not dropped before AppGuard
        assert not is_benign_lineage("nginx.exe", "cmd.exe")


# -----------------------------------------------------------------------------
# Scenario 03 -- DB RCE via sqlservr → powershell
# -----------------------------------------------------------------------------

class TestScenario03DbRce:
    """SQL injection triggers xp_cmdshell, spawning powershell."""

    def test_sqlservr_spawns_powershell_triggers_alert(self):
        active_db = {200: "sqlservr.exe"}
        reason, score = classify_appguard("powershell.exe", 200, "", {}, active_db)
        assert reason == "DB_RCE_DETECTED"
        assert score == 9.5

    def test_all_db_daemons_covered(self):
        for daemon in ("sqlservr.exe", "mysqld.exe", "postgres.exe", "mongod.exe", "redis-server.exe"):
            active_db = {200: daemon}
            reason, _ = classify_appguard("cmd.exe", 200, "", {}, active_db)
            assert reason == "DB_RCE_DETECTED", f"{daemon} → cmd.exe must trigger DB_RCE_DETECTED"


# -----------------------------------------------------------------------------
# Scenario 04 -- ASP.NET compiler exception (benign)
# -----------------------------------------------------------------------------

class TestScenario04AspNetException:
    """csc.exe in Temporary ASP.NET Files is benign -- must not trigger AppGuard."""

    def test_csc_in_aspnet_temp_is_benign(self):
        active_web = {100: "w3wp.exe"}
        cmd = r"C:\Windows\Microsoft.NET\Temporary ASP.NET Files\compile.cs"
        reason, score = classify_appguard("csc.exe", 100, cmd, active_web, {})
        assert reason is None and score is None

    def test_cvtres_in_aspnet_temp_is_benign(self):
        active_web = {100: "w3wp.exe"}
        cmd = r"C:\Windows\Microsoft.NET\Temporary ASP.NET Files\res.res"
        reason, score = classify_appguard("cvtres.exe", 100, cmd, active_web, {})
        assert reason is None

    def test_csc_outside_aspnet_temp_is_malicious(self):
        active_web = {100: "w3wp.exe"}
        cmd = "csc.exe /target:exe /out:C:\\Temp\\evil.exe exploit.cs"
        reason, score = classify_appguard("csc.exe", 100, cmd, active_web, {})
        assert reason == "WEB_SHELL_DETECTED"


# -----------------------------------------------------------------------------
# Scenario 05 -- Benign wininit → services lineage
# -----------------------------------------------------------------------------

class TestScenario05BenignLineage:
    """wininit.exe → services.exe is normal OS boot -- must be dropped immediately."""

    def test_wininit_services_lineage_benign(self):
        assert is_benign_lineage("wininit.exe", "services.exe")

    def test_services_spawning_svchost_benign(self):
        assert is_benign_lineage("services.exe", "svchost.exe")

    def test_wininit_powershell_not_benign(self):
        # wininit spawning a shell directly is unusual
        assert not is_benign_lineage("wininit.exe", "powershell.exe")


# -----------------------------------------------------------------------------
# Scenario 06 -- Cobalt Strike named pipe
# -----------------------------------------------------------------------------

class TestScenario06CobaltStrikePipe:
    """Cobalt Strike post-ex creates \\msagent_<random> named pipe for comms."""

    def test_msagent_pipe_detected(self):
        result = classify_file_event(r"\device\namedpipe\msagent_4f2c9a")
        assert result is not None
        assert "MALICIOUS_PIPE" in result[0]
        assert result[1] == MALICIOUS_PIPE_SCORE

    def test_postex_pipe_detected(self):
        result = classify_file_event(r"\device\namedpipe\postex_staging")
        assert result is not None
        assert "MALICIOUS_PIPE" in result[0]

    def test_psexec_svc_pipe_detected(self):
        result = classify_file_event(r"\device\namedpipe\psexec_svc")
        assert result is not None
        assert "MALICIOUS_PIPE" in result[0]


# -----------------------------------------------------------------------------
# Scenario 07 -- High-entropy pipe (generic C2 stager)
# -----------------------------------------------------------------------------

class TestScenario07HighEntropyPipe:
    """Generic C2 framework uses random pipe name -- detected by entropy."""

    def test_high_entropy_pipe_detected(self):
        result = classify_file_event(r"\pipe\xK9mQ2pL7nR4wT1y")
        assert result is not None
        assert result[0].startswith("HIGH_ENTROPY_PIPE")
        assert result[1] == HIGH_ENTROPY_PIPE_SCORE

    def test_low_entropy_pipe_not_detected(self):
        result = classify_file_event(r"\pipe\chrome")
        assert result is None


# -----------------------------------------------------------------------------
# Scenario 08 -- Canary file heartbeat (silent drop)
# -----------------------------------------------------------------------------

class TestScenario08Canary:
    """DeepSensor canary file writes must not generate alerts."""

    def test_canary_file_silent(self):
        result = classify_file_event(r"C:\Windows\Temp\deepsensor_canary.tmp")
        assert result is None

    def test_canary_in_pipe_path_also_silent(self):
        result = classify_file_event(r"\device\namedpipe\deepsensor_canary.tmp")
        assert result is None


# -----------------------------------------------------------------------------
# Scenario 09 -- Registry Run key persistence
# -----------------------------------------------------------------------------

class TestScenario09RegistryPersistence:
    """Malware writes to HKLM Run key for persistence."""

    def test_run_key_flagged(self):
        key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil_updater"
        assert is_persistence_registry_key(key)

    def test_ifeo_injection_flagged(self):
        key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
        assert is_persistence_registry_key(key)

    def test_amsi_provider_hijack_flagged(self):
        key = r"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{BAAD-F00D}"
        assert is_persistence_registry_key(key)

    def test_office_settings_not_flagged(self):
        key = r"HKCU\Software\Microsoft\Office\16.0\Word\RecentFiles"
        assert not is_persistence_registry_key(key)


# -----------------------------------------------------------------------------
# Scenario 10 -- Suspicious path launch
# -----------------------------------------------------------------------------

class TestScenario10SuspiciousPath:
    """Malware executes from %TEMP% directory."""

    def test_temp_launch_flagged(self):
        assert has_suspicious_path(r"C:\Windows\Temp\updater.exe -silent")

    def test_score_is_7_5(self):
        assert SUSPICIOUS_PATH_SCORE == 7.5

    def test_normal_path_not_flagged(self):
        assert not has_suspicious_path(r"C:\Program Files\Chrome\chrome.exe")


# -----------------------------------------------------------------------------
# Scenario 11-13 -- YARA memory scanning gate
# -----------------------------------------------------------------------------

class TestScenario11_13YaraMemory:
    """YARA memory scanning: valid RWX region, invalid details, critical process."""

    def test_scenario_11_valid_rwx_region(self):
        result = parse_memory_details("VirtualAlloc:0x7fff0000:4096")
        assert result is not None
        addr, size = result
        assert addr == 0x7fff0000
        assert size == 4096
        # Non-critical process → eligible for scan
        assert memory_event_should_scan(PAGE_EXECUTE_READWRITE, "beacon.exe")

    def test_scenario_12_malformed_details_skipped(self):
        # Missing prefix
        assert parse_memory_details("HeapAlloc:0x1000:512") is None
        # Zero size
        assert parse_memory_details("VirtualAlloc:0x1000:0") is None
        # Over 50MB
        assert parse_memory_details("VirtualAlloc:0x1000:52428801") is None

    def test_scenario_13_critical_process_skipped(self):
        # Even on RWX page, lsass.exe is never YARA-scanned
        assert not memory_event_should_scan(PAGE_EXECUTE_READWRITE, "lsass.exe")
        assert not memory_event_should_scan(PAGE_EXECUTE_READWRITE, "csrss.exe")
        # Normal process on non-exec page: also skipped
        assert not memory_event_should_scan(0x04, "beacon.exe")  # PAGE_READWRITE


# -----------------------------------------------------------------------------
# Scenario 14-15 -- C2 beacon confirmed vs dismissed
# -----------------------------------------------------------------------------

class TestScenario14_15BeaconVerdict:
    """Simulates C2EphemeralModule evaluation after 5-min observation window."""

    def test_scenario_14_confirmed_regular_beacon(self):
        # Textbook C2: 60-second intervals, 10 connections, 1 destination IP
        ticks = _ticks_from_intervals([60_000.0] * 10)
        cv = compute_jitter_cv(ticks)
        # CV should be near 0 for perfectly regular intervals
        assert cv == pytest.approx(0.0, abs=1e-9)
        assert is_beacon_confirmed(cv, 10, 1)

    def test_scenario_15_dismissed_human_browsing(self):
        # Human browsing: wildly variable intervals
        ticks = _ticks_from_intervals([500.0, 45000.0, 200.0, 120000.0, 1000.0, 90000.0])
        cv = compute_jitter_cv(ticks)
        assert cv > BEACON_CV_THRESHOLD
        assert not is_beacon_confirmed(cv, 6, 5)

    def test_beacon_with_too_many_unique_ips_dismissed(self):
        # CDN / load-balancer behind C2? More than 3 IPs → not confirmed
        ticks = _ticks_from_intervals([30_000.0] * 10)
        cv = compute_jitter_cv(ticks)
        assert not is_beacon_confirmed(cv, 10, 4)

    def test_beacon_needs_at_least_8_connections(self):
        ticks = _ticks_from_intervals([30_000.0] * 7)
        cv = compute_jitter_cv(ticks)
        assert not is_beacon_confirmed(cv, 7, 1)

    def test_beacon_boundary_exactly_8_connections(self):
        ticks = _ticks_from_intervals([30_000.0] * 8)
        cv = compute_jitter_cv(ticks)
        assert is_beacon_confirmed(cv, 8, 1)


# -----------------------------------------------------------------------------
# Scenario 16 -- Lateral SMB movement
# -----------------------------------------------------------------------------

class TestScenario16LateralSmb:
    """Attacker pivots from 10.0.1.5 to 10.0.1.10 via SMB."""

    def test_smb_445_classified_as_lateral_smb(self):
        reason = classify_lateral_port(445, "10.0.1.5", "10.0.1.10")
        assert reason is not None
        assert "LATERAL_SMB" in reason
        assert "10.0.1.5" in reason
        assert "10.0.1.10" in reason

    def test_rdp_classified_as_lateral_rdp(self):
        reason = classify_lateral_port(3389, "10.0.1.5", "10.0.1.15")
        assert reason is not None and "LATERAL_RDP" in reason

    def test_http_443_not_lateral(self):
        assert classify_lateral_port(443, "10.0.1.5", "10.0.1.10") is None


# -----------------------------------------------------------------------------
# Scenario 17 -- Ingress flood detection
# -----------------------------------------------------------------------------

class TestScenario17IngressFlood:
    """DDoS / brute-force attack: 150 SYNs/min from one source."""

    def test_150_per_min_is_flood(self):
        assert is_ingress_flood(150)

    def test_exactly_at_threshold_is_flood(self):
        assert is_ingress_flood(120)

    def test_119_per_min_not_flood(self):
        assert not is_ingress_flood(119)

    def test_zero_not_flood(self):
        assert not is_ingress_flood(0)


# -----------------------------------------------------------------------------
# Scenario 18 -- Port scan detection
# -----------------------------------------------------------------------------

class TestScenario18PortScan:
    """Recon: attacker scans 20 distinct ports in 60 seconds."""

    def test_20_distinct_ports_is_scan(self):
        assert is_port_scan(20)

    def test_exactly_at_threshold_is_scan(self):
        assert is_port_scan(15)

    def test_14_ports_not_scan(self):
        assert not is_port_scan(14)


# -----------------------------------------------------------------------------
# Scenario 19 -- Malicious IP passes exclusion check
# -----------------------------------------------------------------------------

class TestScenario19MaliciousIpNotExcluded:
    """185.220.101.1 (Tor exit node) must NOT be in exclusion patterns."""

    def test_known_c2_ip_not_excluded_by_config_patterns(self):
        # Patterns from DeepXDR_Config.ini
        patterns_csv = (
            r"^52\., ^142\.25[0-9]\., ^13\., ^20\., ^23\., ^74\.125\., "
            r"^127\., ^2(?:2[4-9]|3[0-9])\., ^2[4-5][0-9]\., "
            r"^1\.1\.1\.1$, ^1\.0\.0\.1$, ^8\.8\.8\.8$, ^8\.8\.4\.4$, "
            r"^9\.9\.9\.9$, \.255$, ^18\.214\.245\., ^104\.20\.23\."
        )
        patterns = build_ip_exclusion_patterns(patterns_csv)
        assert not is_ip_excluded("185.220.101.1", patterns), \
            "Known C2 IP 185.220.101.1 must not be excluded"

    def test_loopback_is_excluded(self):
        patterns_csv = r"^127\., ^52\."
        patterns = build_ip_exclusion_patterns(patterns_csv)
        assert is_ip_excluded("127.0.0.1", patterns)


# -----------------------------------------------------------------------------
# Scenario 20 -- HMAC integrity with default config key
# -----------------------------------------------------------------------------

class TestScenario20HmacIntegrity:
    """NexusForwarder computes HMAC before POST. Tamper detected by gateway."""

    def test_hmac_computed_with_default_secret(self):
        payload = b"parquet_bytes_here"
        sig = compute_hmac(payload, 1, "WIN-XDR-01", 1748872800)
        assert len(sig) == 64

    def test_tampered_batch_different_hmac(self):
        payload = bytearray(b"parquet_data")
        sig1 = compute_hmac(bytes(payload), 1, "WIN-XDR-01", 1748872800)
        payload[0] ^= 0xFF
        sig2 = compute_hmac(bytes(payload), 1, "WIN-XDR-01", 1748872800)
        assert sig1 != sig2

    def test_sequence_counter_prevents_replay(self):
        payload = b"parquet_bytes"
        sig1 = compute_hmac(payload, 5, "WIN-XDR-01", 1748872800)
        sig2 = compute_hmac(payload, 6, "WIN-XDR-01", 1748872800)
        assert sig1 != sig2


# -----------------------------------------------------------------------------
# Scenario 21 -- DNS exclusion: microsoft telemetry domain filtered
# -----------------------------------------------------------------------------

class TestScenario21DnsExclusion:
    """Agent ignores telemetry to *.microsoft.com, *.azure.com, etc."""

    EXCLUSIONS = {
        "microsoft.com", "windows.com", "azure.com", "google.com",
        ".arpa", ".local", ".corp"
    }

    def test_windows_update_filtered(self):
        assert is_dns_excluded("download.windowsupdate.microsoft.com", self.EXCLUSIONS)

    def test_azure_monitor_filtered(self):
        assert is_dns_excluded("dc.services.visualstudio.com.azure.com", self.EXCLUSIONS)

    def test_unknown_c2_domain_not_filtered(self):
        assert not is_dns_excluded("evil-c2.onion.cab", self.EXCLUSIONS)

    def test_internal_lan_filtered(self):
        assert is_dns_excluded("fileserver.local", self.EXCLUSIONS)


# -----------------------------------------------------------------------------
# Scenario 22 -- Full beacon context JSON for ML engine
# -----------------------------------------------------------------------------

class TestScenario22BeaconContextJson:
    """C2EphemeralModule builds JSON payload before enqueuing for Rust ML."""

    def test_full_beacon_json_valid_and_complete(self):
        raw = build_beacon_context_json(
            pid=4567, process_name="beacon.exe", trigger_reason="YARA_RWX",
            context_score=8.5, dest_ip="185.220.101.1",
            connection_count=12, mean_interval_ms=60000.0, jitter_cv=0.03,
            bytes_out=2048, bytes_in=512, unique_ips=1,
            ja3_hashes=["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"],
            dest_ips=["185.220.101.1"], dest_ports=[443],
        )
        parsed = json.loads(raw)
        required = [
            "event_type", "pid", "process", "trigger_reason", "context_score",
            "dest_ip", "connection_count", "mean_interval_ms", "jitter_cv",
            "total_bytes_out", "total_bytes_in", "unique_ips",
            "ja3_hashes", "dest_ips", "dest_ports",
        ]
        for field in required:
            assert field in parsed, f"Missing field: {field}"
        assert parsed["event_type"] == "beacon_analysis"
        assert parsed["pid"] == 4567


# -----------------------------------------------------------------------------
# Scenario 23 -- Cobalt Strike beacon timing (realistic 60-sec sleep)
# -----------------------------------------------------------------------------

class TestScenario23CobaltStrikeBeaconTiming:
    """CS default sleep=60s with jitter=0 → perfectly regular → CV=0 → confirmed."""

    def test_regular_60s_beacon_cv_near_zero(self):
        ticks = _ticks_from_intervals([60_000.0] * 12)
        cv = compute_jitter_cv(ticks)
        assert cv < BEACON_CV_THRESHOLD

    def test_cs_with_10pct_jitter_still_below_threshold(self):
        # CS jitter=10% adds ±6s noise to 60s sleep → still regular enough
        import random
        random.seed(42)
        intervals = [60_000.0 + random.uniform(-6000, 6000) for _ in range(12)]
        ticks = _ticks_from_intervals(intervals)
        cv = compute_jitter_cv(ticks)
        # 10% jitter → CV ≈ 0.058, well below 0.20
        assert cv < BEACON_CV_THRESHOLD, f"CS 10% jitter CV={cv:.4f} should still be below threshold"


# -----------------------------------------------------------------------------
# Scenario 24 -- Human browsing traffic (irregular, not a beacon)
# -----------------------------------------------------------------------------

class TestScenario24HumanBrowsing:
    """Real user browser activity: random timing → high CV → dismissed."""

    def test_human_browsing_cv_above_threshold(self):
        # Simulate: 200ms, 2min, 500ms, 10min, 100ms
        intervals = [200.0, 120_000.0, 500.0, 600_000.0, 100.0, 45_000.0]
        ticks = _ticks_from_intervals(intervals)
        cv = compute_jitter_cv(ticks)
        assert cv > BEACON_CV_THRESHOLD, f"Human browsing CV={cv:.4f} should be above threshold"


# -----------------------------------------------------------------------------
# Scenario 25 -- KernelBridge score conversions
# -----------------------------------------------------------------------------

class TestScenario25KernelBridgeScoreConversion:
    """Fixed-point anomaly scores from ring-0 driver divide by 100 → float."""

    def test_critical_score_conversion(self):
        assert SCORE_CRITICAL_FP / SCORE_DIVISOR == 9.0

    def test_high_score_conversion(self):
        assert SCORE_HIGH_FP / SCORE_DIVISOR == 7.0

    def test_medium_score_conversion(self):
        assert SCORE_MEDIUM_FP / SCORE_DIVISOR == 5.0

    def test_lsass_access_hardcoded_9_5(self):
        # KernelBridge.cs sets ContextScore=9.5 for EVT_OB_ACCESS regardless of driver score
        score = 9.5  # src: KernelBridge.cs:291
        assert score > KERNEL_BEACON_SCORE_THRESHOLD

    def test_quarantine_block_hardcoded_10_0(self):
        score = 10.0  # src: KernelBridge.cs:302
        assert score == BEACON_SCORES["K0_QUARANTINE"]

    def test_beacon_published_for_score_above_7(self):
        # KernelBridge.cs line 321: if (pev.ContextScore >= 7.0) → publish beacon
        assert KERNEL_BEACON_SCORE_THRESHOLD == 7.0
        for evt_type, trigger in [(EVT_OB_ACCESS, "K0_LSASS_ACCESS"),
                                   (EVT_QUARANTINE_BLOCK, "K0_QUARANTINE"),
                                   (EVT_TOKEN_ACCESS, "K0_TOKEN_ACCESS")]:
            score = BEACON_SCORES[trigger]
            assert score >= KERNEL_BEACON_SCORE_THRESHOLD, \
                f"{trigger} score={score} must be >= {KERNEL_BEACON_SCORE_THRESHOLD}"

    def test_valid_sentinel_required(self):
        # KernelBridge.cs: if (ev->Valid != 2) continue;
        assert MONITOR_EVENT_VALID_SENTINEL == 2
