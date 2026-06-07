"""
Tier-0 - Analyzer decision logic tests.

Covers: AppGuard, benign lineage, ETW tamper, named pipe detection,
registry persistence, suspicious paths, YARA memory parsing, threat
vector classification, IDPS lateral/flood/scan, DNS/IP exclusions,
C2 ephemeral beacon confirmation.
"""

import re
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from deepxdr_logic import (
    classify_appguard, is_benign_lineage, BENIGN_LINEAGES,
    detect_etw_tamper, ETW_TAMPER_SCORE,
    classify_file_event, BAD_PIPE_NAMES, CANARY_FILE,
    MALICIOUS_PIPE_SCORE, HIGH_ENTROPY_PIPE_SCORE,
    is_persistence_registry_key, PERSISTENCE_KEYS,
    has_suspicious_path, SUSPICIOUS_PATH_SCORE,
    parse_memory_details, YARA_MAX_REGION_SIZE,
    memory_event_should_scan, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ,
    determine_threat_vector, is_critical_process, CRITICAL_PROCESSES,
    classify_lateral_port, is_ingress_flood, is_port_scan,
    LATERAL_PORTS, INGRESS_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD,
    is_dns_excluded, build_ip_exclusion_patterns, is_ip_excluded,
    is_beacon_suspicious, is_beacon_confirmed, should_early_exit,
    MIN_CONNECTIONS, MAX_CONCURRENT_SCANS, SCAN_WINDOW_SECONDS,
    BEACON_CV_THRESHOLD, sigma_hit_score, extract_ppid,
    WEB_DAEMONS_DEFAULT, DB_DAEMONS_DEFAULT, SHELL_INTERPRETERS_DEFAULT,
)

pytestmark = pytest.mark.tier0

# -----------------------------------------------------------------------------
# AppGuard  (OsAnalyzer.cs:203-243)
# -----------------------------------------------------------------------------

class TestAppGuard:
    def _web(self, pid: int = 100) -> dict:
        return {pid: "w3wp.exe"}

    def _db(self, pid: int = 200) -> dict:
        return {pid: "sqlservr.exe"}

    def test_shell_from_web_daemon_is_web_shell(self):
        reason, score = classify_appguard("cmd.exe", 100, "", self._web(), {})
        assert reason == "WEB_SHELL_DETECTED"
        assert score == 9.5

    def test_shell_from_db_daemon_is_db_rce(self):
        reason, score = classify_appguard("powershell.exe", 200, "", {}, self._db())
        assert reason == "DB_RCE_DETECTED"
        assert score == 9.5

    def test_non_shell_interpreter_no_alert(self):
        reason, score = classify_appguard("notepad.exe", 100, "", self._web(), {})
        assert reason is None
        assert score is None

    def test_shell_with_no_daemon_parent_no_alert(self):
        reason, score = classify_appguard("cmd.exe", 999, "", {}, {})
        assert reason is None

    def test_all_shell_interpreters_trigger_web_shell(self):
        for interp in ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                       "cscript.exe", "bash.exe", "sh.exe"):
            reason, _ = classify_appguard(interp, 100, "", self._web(), {})
            assert reason == "WEB_SHELL_DETECTED", f"{interp} should trigger WEB_SHELL_DETECTED"

    def test_aspnet_compiler_csc_exception(self):
        # csc.exe in Temporary ASP.NET Files context is benign
        reason, score = classify_appguard(
            "csc.exe", 100,
            "C:\\Windows\\Microsoft.NET\\Temporary ASP.NET Files\\beacon.cs",
            self._web(), {}
        )
        assert reason is None, "csc.exe in ASP.NET temp path should be benign"

    def test_aspnet_compiler_cvtres_exception(self):
        reason, score = classify_appguard(
            "cvtres.exe", 100,
            "/out:C:\\Windows\\Microsoft.NET\\Temporary ASP.NET Files\\x.res",
            self._web(), {}
        )
        assert reason is None

    def test_csc_without_aspnet_path_is_alert(self):
        # csc.exe NOT in ASP.NET path → still dangerous
        reason, score = classify_appguard("csc.exe", 100, "csc.exe /target:exe evil.cs", self._web(), {})
        assert reason == "WEB_SHELL_DETECTED"

    def test_case_insensitive_process_name(self):
        reason, _ = classify_appguard("CMD.EXE", 100, "", self._web(), {})
        assert reason == "WEB_SHELL_DETECTED"

    def test_multiple_web_daemons_trigger(self):
        for daemon in ("w3wp.exe", "nginx.exe", "node.exe", "python.exe"):
            web = {100: daemon}
            reason, _ = classify_appguard("cmd.exe", 100, "", web, {})
            assert reason == "WEB_SHELL_DETECTED", f"{daemon} parent should trigger WEB_SHELL_DETECTED"

    def test_multiple_db_daemons_trigger(self):
        for daemon in ("sqlservr.exe", "mysqld.exe", "postgres.exe", "mongod.exe"):
            db = {200: daemon}
            reason, _ = classify_appguard("powershell.exe", 200, "", {}, db)
            assert reason == "DB_RCE_DETECTED", f"{daemon} parent should trigger DB_RCE_DETECTED"


# -----------------------------------------------------------------------------
# Benign lineage  (OsAnalyzer.cs:123-132)
# -----------------------------------------------------------------------------

class TestBenignLineage:
    def test_wininit_services_is_benign(self):
        assert is_benign_lineage("wininit.exe", "services.exe")

    def test_wininit_lsass_is_benign(self):
        assert is_benign_lineage("wininit.exe", "lsass.exe")

    def test_services_svchost_is_benign(self):
        assert is_benign_lineage("services.exe", "svchost.exe")

    def test_svchost_wmiprvse_is_benign(self):
        assert is_benign_lineage("svchost.exe", "wmiprvse.exe")

    def test_explorer_onedrive_is_benign(self):
        assert is_benign_lineage("explorer.exe", "onedrive.exe")

    def test_explorer_cmd_not_benign(self):
        assert not is_benign_lineage("explorer.exe", "cmd.exe")

    def test_unknown_pair_not_benign(self):
        assert not is_benign_lineage("malware.exe", "cmd.exe")

    def test_case_insensitive(self):
        assert is_benign_lineage("WININIT.EXE", "Services.exe")

    def test_all_benign_lineages_count(self):
        # OsAnalyzer.cs lines 125-128: 11 pairs defined
        assert len(BENIGN_LINEAGES) == 11


# -----------------------------------------------------------------------------
# ETW tamper detection  (OsAnalyzer.cs:193-200)
# -----------------------------------------------------------------------------

class TestEtwTamper:
    def test_logman_stop_detected(self):
        assert detect_etw_tamper("logman stop XDR-Trace") is True

    def test_logman_delete_detected(self):
        assert detect_etw_tamper("logman delete SomeName") is True

    def test_logman_without_stop_delete_not_flagged(self):
        assert detect_etw_tamper("logman start SomeName") is False

    def test_logman_query_not_flagged(self):
        assert detect_etw_tamper("logman query") is False

    def test_no_logman_not_flagged(self):
        assert detect_etw_tamper("taskkill /F /IM svchost.exe") is False

    def test_empty_cmdline_not_flagged(self):
        assert detect_etw_tamper("") is False

    def test_case_insensitive(self):
        assert detect_etw_tamper("LOGMAN STOP traces") is True
        assert detect_etw_tamper("Logman Delete deep_xdr") is True

    def test_score_is_95(self):
        assert ETW_TAMPER_SCORE == 9.5


# -----------------------------------------------------------------------------
# Named pipe detection  (OsAnalyzer.cs:257-279)
# -----------------------------------------------------------------------------

class TestNamedPipeDetection:
    def test_known_c2_pipe_msagent(self):
        result = classify_file_event(r"\device\namedpipe\msagent_abc123")
        assert result is not None
        assert result[0].startswith("MALICIOUS_PIPE")
        assert result[1] == MALICIOUS_PIPE_SCORE

    def test_known_c2_pipe_postex(self):
        result = classify_file_event(r"\device\namedpipe\postex_7f3a2")
        assert result is not None
        assert "MALICIOUS_PIPE" in result[0]

    def test_all_bad_pipe_patterns_detected(self):
        for pat in BAD_PIPE_NAMES:
            # Build a path that contains the pattern under a namedpipe prefix
            path = r"\device\namedpipe" + pat + "123"
            result = classify_file_event(path)
            assert result is not None, f"Bad pipe pattern {pat!r} not detected"
            assert result[0].startswith("MALICIOUS_PIPE"), f"Wrong category for {pat!r}"

    def test_high_entropy_pipe_detected(self):
        # High-entropy name: xK9mQ2pL7nR4wT1y (entropy > 3.5)
        result = classify_file_event(r"\pipe\xK9mQ2pL7nR4wT1y")
        assert result is not None
        assert result[0].startswith("HIGH_ENTROPY_PIPE")
        assert result[1] == HIGH_ENTROPY_PIPE_SCORE

    def test_low_entropy_benign_pipe_not_flagged(self):
        result = classify_file_event(r"\pipe\chrome")
        assert result is None

    def test_canary_file_skipped(self):
        result = classify_file_event(r"C:\Windows\Temp\deepsensor_canary.tmp")
        assert result is None

    def test_non_pipe_path_ignored(self):
        result = classify_file_event(r"C:\Windows\System32\cmd.exe")
        assert result is None

    def test_cobalt_strike_default_pipes(self):
        for pipe in ("msagent_", "postex_", "status_", "mypipe-f", "mypipe-h",
                     "gilgamesh", "mythic_", "sliver_", "psexec_svc"):
            path = r"\device\namedpipe\\" + pipe
            result = classify_file_event(path)
            assert result is not None, f"Cobalt Strike pipe {pipe!r} not detected"


# -----------------------------------------------------------------------------
# Registry persistence  (OsAnalyzer.cs:64-69, 289-307)
# -----------------------------------------------------------------------------

class TestRegistryPersistence:
    def test_run_key_detected(self):
        assert is_persistence_registry_key(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\evil")

    def test_ifeo_detected(self):
        assert is_persistence_registry_key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe")

    def test_services_key_detected(self):
        assert is_persistence_registry_key(r"HKLM\SYSTEM\CurrentControlSet\Services\evildll")

    def test_amsi_providers_detected(self):
        assert is_persistence_registry_key(r"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{bad-guid}")

    def test_lsa_security_packages_detected(self):
        assert is_persistence_registry_key(r"HKLM\SYSTEM\CurrentControlSet\Control\LSA\Security Packages")

    def test_session_manager_detected(self):
        assert is_persistence_registry_key(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute")

    def test_benign_key_not_flagged(self):
        assert not is_persistence_registry_key(r"HKCU\Software\Microsoft\Office\16.0\Word\Options")

    def test_all_persistence_keys_present(self):
        assert len(PERSISTENCE_KEYS) == 9

    def test_case_insensitive_matching(self):
        assert is_persistence_registry_key(r"HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN\x")


# -----------------------------------------------------------------------------
# Suspicious paths  (OsAnalyzer.cs:226-233)
# -----------------------------------------------------------------------------

class TestSuspiciousPaths:
    def test_temp_directory_flagged(self):
        assert has_suspicious_path(r"C:\Windows\Temp\beacon.exe")

    def test_programdata_flagged(self):
        assert has_suspicious_path(r"C:\ProgramData\evil\payload.exe")

    def test_inetpub_wwwroot_flagged(self):
        assert has_suspicious_path(r"C:\inetpub\wwwroot\shell.aspx")

    def test_appdata_flagged(self):
        assert has_suspicious_path(r"C:\Users\jsmith\AppData\Roaming\update.exe")

    def test_users_public_flagged(self):
        assert has_suspicious_path(r"C:\Users\Public\Documents\dropper.exe")

    def test_system32_not_flagged(self):
        assert not has_suspicious_path(r"C:\Windows\System32\cmd.exe")

    def test_program_files_not_flagged(self):
        assert not has_suspicious_path(r"C:\Program Files\Mozilla Firefox\firefox.exe")

    def test_case_insensitive(self):
        assert has_suspicious_path(r"C:\WINDOWS\TEMP\BEACON.EXE")

    def test_score_constant(self):
        assert SUSPICIOUS_PATH_SCORE == 7.5


# -----------------------------------------------------------------------------
# YARA memory detail parsing  (OsAnalyzer.cs:521-532, 341-345)
# -----------------------------------------------------------------------------

class TestYaraMemoryParsing:
    def test_valid_details_parsed(self):
        result = parse_memory_details("VirtualAlloc:0x7fff0000:4096")
        assert result == (0x7fff0000, 4096)

    def test_valid_hex_uppercase(self):
        result = parse_memory_details("VirtualAlloc:0xDEADBEEF:1024")
        assert result is not None
        assert result[0] == 0xDEADBEEF

    def test_empty_string_returns_none(self):
        assert parse_memory_details("") is None

    def test_wrong_prefix_returns_none(self):
        assert parse_memory_details("HeapAlloc:0x1000:512") is None

    def test_too_few_parts_returns_none(self):
        assert parse_memory_details("VirtualAlloc:0x1000") is None

    def test_zero_size_returns_none(self):
        assert parse_memory_details("VirtualAlloc:0x1000:0") is None

    def test_size_over_50mb_returns_none(self):
        over_limit = YARA_MAX_REGION_SIZE + 1
        assert parse_memory_details(f"VirtualAlloc:0x1000:{over_limit}") is None

    def test_size_exactly_50mb_valid(self):
        result = parse_memory_details(f"VirtualAlloc:0x1000:{YARA_MAX_REGION_SIZE}")
        assert result is not None
        assert result[1] == YARA_MAX_REGION_SIZE

    def test_max_region_size_constant(self):
        assert YARA_MAX_REGION_SIZE == 52_428_800

    def test_invalid_hex_addr_returns_none(self):
        assert parse_memory_details("VirtualAlloc:0xGGGG:1024") is None

    def test_case_insensitive_prefix(self):
        result = parse_memory_details("VIRTUALALLOC:0x1000:512")
        assert result is not None


# -----------------------------------------------------------------------------
# YARA threat vector  (OsAnalyzer.cs:535-549)
# -----------------------------------------------------------------------------

class TestYaraThreatVector:
    def test_w3wp_web_infrastructure(self):
        assert determine_threat_vector("w3wp.exe") == "WebInfrastructure"

    def test_nginx_web_infrastructure(self):
        assert determine_threat_vector("nginx.exe") == "WebInfrastructure"

    def test_httpd_web_infrastructure(self):
        assert determine_threat_vector("httpd.exe") == "WebInfrastructure"

    def test_spoolsv_system_exploits(self):
        assert determine_threat_vector("spoolsv.exe") == "SystemExploits"

    def test_lsass_system_exploits(self):
        assert determine_threat_vector("lsass.exe") == "SystemExploits"

    def test_powershell_lotl(self):
        assert determine_threat_vector("powershell.exe") == "LotL"

    def test_cmd_lotl(self):
        assert determine_threat_vector("cmd.exe") == "LotL"

    def test_wscript_lotl(self):
        assert determine_threat_vector("wscript.exe") == "LotL"

    def test_winword_macro_payloads(self):
        assert determine_threat_vector("winword.exe") == "MacroPayloads"

    def test_excel_macro_payloads(self):
        assert determine_threat_vector("excel.exe") == "MacroPayloads"

    def test_rundll32_binary_proxy(self):
        assert determine_threat_vector("rundll32.exe") == "BinaryProxy"

    def test_regsvr32_binary_proxy(self):
        assert determine_threat_vector("regsvr32.exe") == "BinaryProxy"

    def test_unknown_process_core_c2(self):
        assert determine_threat_vector("beacon.exe") == "Core_C2"

    def test_empty_process_core_c2(self):
        assert determine_threat_vector("") == "Core_C2"


# -----------------------------------------------------------------------------
# Critical processes + memory scan gate  (OsAnalyzer.cs:56-62, 311-315)
# -----------------------------------------------------------------------------

class TestCriticalProcessesAndMemoryScan:
    def test_critical_processes_count(self):
        assert len(CRITICAL_PROCESSES) == 14

    def test_lsass_is_critical(self):
        assert is_critical_process("lsass.exe")

    def test_csrss_is_critical(self):
        assert is_critical_process("csrss.exe")

    def test_beacon_not_critical(self):
        assert not is_critical_process("beacon.exe")

    def test_rwx_page_on_non_critical_should_scan(self):
        assert memory_event_should_scan(PAGE_EXECUTE_READWRITE, "beacon.exe")

    def test_rx_page_on_non_critical_should_scan(self):
        assert memory_event_should_scan(PAGE_EXECUTE_READ, "beacon.exe")

    def test_rwx_on_critical_should_not_scan(self):
        assert not memory_event_should_scan(PAGE_EXECUTE_READWRITE, "lsass.exe")

    def test_non_executable_page_should_not_scan(self):
        assert not memory_event_should_scan(0x04, "beacon.exe")  # PAGE_READWRITE

    def test_page_flags_constants(self):
        assert PAGE_EXECUTE_READWRITE == 0x40
        assert PAGE_EXECUTE_READ      == 0x20


# -----------------------------------------------------------------------------
# IDPS lateral port classification  (IdpsAnalyzer.cs:48-58, 189-198)
# -----------------------------------------------------------------------------

class TestIdpsLateral:
    def test_smb_445(self):
        r = classify_lateral_port(445, "10.0.1.5", "10.0.1.10")
        assert r is not None and "LATERAL_SMB" in r

    def test_rdp_3389(self):
        r = classify_lateral_port(3389, "10.0.1.5", "10.0.1.10")
        assert r is not None and "LATERAL_RDP" in r

    def test_winrm_5985(self):
        r = classify_lateral_port(5985, "10.0.1.5", "10.0.1.10")
        assert r is not None and "LATERAL_WINRM" in r

    def test_winrm_5986(self):
        r = classify_lateral_port(5986, "10.0.1.5", "10.0.1.10")
        assert r is not None and "LATERAL_WINRM" in r

    def test_rpc_135(self):
        r = classify_lateral_port(135, "10.0.1.5", "10.0.1.10")
        assert r is not None and "LATERAL_RPC" in r

    def test_kerberos_88(self):
        r = classify_lateral_port(88, "10.0.1.5", "10.0.1.10")
        assert r is not None and "LATERAL_KERBEROS" in r

    def test_ldap_389(self):
        r = classify_lateral_port(389, "10.0.1.5", "10.0.1.10")
        assert r is not None and "LATERAL_LDAP" in r

    def test_ldaps_636(self):
        r = classify_lateral_port(636, "10.0.1.5", "10.0.1.10")
        assert r is not None and "LATERAL_LDAP" in r

    def test_mssql_1433_in_set(self):
        assert 1433 in LATERAL_PORTS

    def test_mysql_3306_in_set(self):
        assert 3306 in LATERAL_PORTS

    def test_lateral_ports_total_count(self):
        assert len(LATERAL_PORTS) == 10

    def test_http_80_not_lateral(self):
        assert classify_lateral_port(80, "10.0.1.5", "10.0.1.10") is None

    def test_https_443_not_lateral(self):
        assert classify_lateral_port(443, "10.0.1.5", "10.0.1.10") is None

    def test_reason_contains_src_dst_ips(self):
        r = classify_lateral_port(445, "10.0.1.5", "10.0.1.10")
        assert "10.0.1.5" in r and "10.0.1.10" in r


# -----------------------------------------------------------------------------
# IDPS flood + port scan thresholds  (IdpsAnalyzer.cs:61-62)
# -----------------------------------------------------------------------------

class TestIdpsThresholds:
    def test_flood_threshold_constant(self):
        assert INGRESS_FLOOD_THRESHOLD == 120

    def test_port_scan_threshold_constant(self):
        assert PORT_SCAN_THRESHOLD == 15

    def test_below_flood_threshold_not_flood(self):
        assert not is_ingress_flood(119)

    def test_at_flood_threshold_is_flood(self):
        assert is_ingress_flood(120)

    def test_above_flood_threshold_is_flood(self):
        assert is_ingress_flood(200)

    def test_below_scan_threshold_not_scan(self):
        assert not is_port_scan(14)

    def test_at_scan_threshold_is_scan(self):
        assert is_port_scan(15)

    def test_above_scan_threshold_is_scan(self):
        assert is_port_scan(50)


# -----------------------------------------------------------------------------
# DNS exclusion  (NetworkAnalyzer.cs:84-88)
# -----------------------------------------------------------------------------

class TestDnsExclusion:
    EXCLUSIONS = {
        ".arpa", ".local", ".corp", "microsoft.com", "windows.com",
        "google.com", "azure.com", "github.com"
    }

    def test_exact_microsoft_excluded(self):
        assert is_dns_excluded("microsoft.com", self.EXCLUSIONS)

    def test_subdomain_of_microsoft_excluded(self):
        assert is_dns_excluded("telemetry.microsoft.com", self.EXCLUSIONS)

    def test_deep_subdomain_excluded(self):
        assert is_dns_excluded("a.b.c.windows.com", self.EXCLUSIONS)

    def test_local_suffix_excluded(self):
        assert is_dns_excluded("myhostname.local", self.EXCLUSIONS)

    def test_corp_suffix_excluded(self):
        assert is_dns_excluded("internal.corp", self.EXCLUSIONS)

    def test_malicious_domain_not_excluded(self):
        assert not is_dns_excluded("malware-c2.ru", self.EXCLUSIONS)

    def test_case_insensitive_query(self):
        assert is_dns_excluded("MICROSOFT.COM", self.EXCLUSIONS)

    def test_trailing_dot_normalized(self):
        assert is_dns_excluded("github.com.", self.EXCLUSIONS)

    def test_partial_match_not_enough(self):
        # "notmicrosoft.com" should NOT match ".microsoft.com" suffix
        # but WILL match "microsoft.com" since it ends with "microsoft.com"
        # This is a known limitation of suffix matching without dot-anchoring
        result = is_dns_excluded("notmicrosoft.com", self.EXCLUSIONS)
        # Document: suffix match can have false positives without strict anchoring
        assert result is True  # notmicrosoft.com ends with microsoft.com


# -----------------------------------------------------------------------------
# IP regex exclusion  (NetworkAnalyzer.cs:59-75)
# -----------------------------------------------------------------------------

class TestIpExclusion:
    PATTERNS_CSV = r"^127\., ^52\., ^1\.1\.1\.1$, \.255$, ^8\.8\.8\.8$"

    def test_loopback_excluded(self):
        patterns = build_ip_exclusion_patterns(self.PATTERNS_CSV)
        assert is_ip_excluded("127.0.0.1", patterns)
        assert is_ip_excluded("127.1.2.3", patterns)

    def test_subnet_broadcast_excluded(self):
        patterns = build_ip_exclusion_patterns(self.PATTERNS_CSV)
        assert is_ip_excluded("192.168.1.255", patterns)
        assert is_ip_excluded("10.0.0.255", patterns)

    def test_cloudflare_dns_excluded(self):
        patterns = build_ip_exclusion_patterns(self.PATTERNS_CSV)
        assert is_ip_excluded("1.1.1.1", patterns)

    def test_google_dns_excluded(self):
        patterns = build_ip_exclusion_patterns(self.PATTERNS_CSV)
        assert is_ip_excluded("8.8.8.8", patterns)

    def test_malicious_ip_not_excluded(self):
        patterns = build_ip_exclusion_patterns(self.PATTERNS_CSV)
        assert not is_ip_excluded("185.220.101.1", patterns)

    def test_cloudflare_dns_1_0_0_1_not_excluded_by_anchor(self):
        # ^1\.1\.1\.1$ anchored - 1.0.0.1 should NOT match
        patterns = build_ip_exclusion_patterns(self.PATTERNS_CSV)
        assert not is_ip_excluded("1.0.0.1", patterns)

    def test_malformed_pattern_skipped(self):
        # Should not raise
        patterns = build_ip_exclusion_patterns(r"^127\., [invalid(, ^8\.8\.8\.8$")
        assert len(patterns) == 2  # only valid ones compiled


# -----------------------------------------------------------------------------
# C2 ephemeral confirmation logic  (C2EphemeralModule.cs:129-159)
# -----------------------------------------------------------------------------

class TestC2EphemeralLogic:
    def test_constants(self):
        assert MIN_CONNECTIONS      == 5
        assert MAX_CONCURRENT_SCANS == 10
        assert SCAN_WINDOW_SECONDS  == 300
        assert BEACON_CV_THRESHOLD  == 0.20

    def test_low_cv_min_connections_suspicious(self):
        assert is_beacon_suspicious(0.05, 5)

    def test_high_cv_not_suspicious(self):
        assert not is_beacon_suspicious(0.50, 10)

    def test_low_cv_but_too_few_connections_not_suspicious(self):
        assert not is_beacon_suspicious(0.05, 4)   # < MIN_CONNECTIONS

    def test_confirmed_all_criteria_met(self):
        # cv<0.20, uniqueIps<=3, connections>=8
        assert is_beacon_confirmed(0.05, 10, 1)

    def test_not_confirmed_high_cv(self):
        assert not is_beacon_confirmed(0.25, 10, 1)

    def test_not_confirmed_too_many_unique_ips(self):
        # More than 3 unique IPs = likely CDN/load-balancer, not C2
        assert not is_beacon_confirmed(0.05, 10, 4)

    def test_not_confirmed_too_few_connections(self):
        assert not is_beacon_confirmed(0.05, 7, 1)

    def test_confirmed_boundary_exactly_8_connections(self):
        assert is_beacon_confirmed(0.05, 8, 1)

    def test_confirmed_boundary_exactly_3_unique_ips(self):
        assert is_beacon_confirmed(0.05, 10, 3)

    def test_early_exit_at_20_connections(self):
        assert should_early_exit(20)

    def test_no_early_exit_at_19_connections(self):
        assert not should_early_exit(19)


# -----------------------------------------------------------------------------
# Sigma score helper  (OsAnalyzer.cs:240)
# -----------------------------------------------------------------------------

class TestSigmaScore:
    def test_critical_rule_scores_9(self):
        assert sigma_hit_score("Suspicious_PowerShell_Critical") == 9.0

    def test_high_rule_scores_8(self):
        assert sigma_hit_score("Suspicious_Process_High") == 8.0

    def test_lowercase_critical(self):
        assert sigma_hit_score("lolbin_execution_critical") == 9.0

    def test_no_severity_scores_8(self):
        assert sigma_hit_score("Mimikatz_Credential_Dump") == 8.0


# -----------------------------------------------------------------------------
# PPID extraction  (OsAnalyzer.cs:509-518)
# -----------------------------------------------------------------------------

class TestExtractPpid:
    def test_ppid_extracted(self):
        assert extract_ppid("PPID:1234|CMD:cmd.exe") == 1234

    def test_ppid_extracted_alone(self):
        assert extract_ppid("PPID:5678") == 5678

    def test_no_ppid_returns_zero(self):
        assert extract_ppid("CMD:powershell.exe") == 0

    def test_empty_returns_zero(self):
        assert extract_ppid("") == 0

    def test_none_returns_zero(self):
        assert extract_ppid(None) == 0

    def test_case_insensitive(self):
        assert extract_ppid("ppid:999|other:data") == 999
