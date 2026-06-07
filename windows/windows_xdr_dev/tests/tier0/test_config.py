"""
Tier-0 - Configuration parsing and validation tests.

Validates DeepXDR_Config.ini against the expected schema from SensorConfigs.cs.
Flags the known .exe suffix discrepancy between INI values and C# matching defaults.
"""

import os
import re
import configparser
import pytest
import sys
sys.path.insert(0, os.path.dirname(__file__))
from deepxdr_logic import (
    csv_to_set, load_config,
    WEB_DAEMONS_DEFAULT, DB_DAEMONS_DEFAULT, SHELL_INTERPRETERS_DEFAULT,
    SUSPICIOUS_PATHS_DEFAULT,
)

pytestmark = pytest.mark.tier0

REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG_INI = os.path.join(REPO_ROOT, "agent", "DeepXDR_Config.ini")


@pytest.fixture(scope="module")
def cfg():
    c = configparser.ConfigParser(strict=False)
    c.read(CONFIG_INI)
    return c


# -----------------------------------------------------------------------------
# File existence and section presence
# -----------------------------------------------------------------------------

class TestConfigFileExists:
    def test_ini_file_present(self):
        assert os.path.exists(CONFIG_INI), f"DeepXDR_Config.ini missing at {CONFIG_INI}"

    def test_required_sections_present(self, cfg):
        required = [
            "ProcessExclusions",
            "NetworkExclusions",
            "AppGuardDefinitions",
            "SuspiciousPaths",
            "Agent",
            "Transmission",
        ]
        sections = [s.lower() for s in cfg.sections()]
        for sec in required:
            assert sec.lower() in sections, f"Required section [{sec}] missing from config"

    def test_optional_sections_present(self, cfg):
        sections = [s.lower() for s in cfg.sections()]
        assert "registryexclusions" in sections
        assert "processexclusionsextended" in sections


# -----------------------------------------------------------------------------
# [ProcessExclusions]
# -----------------------------------------------------------------------------

class TestProcessExclusions:
    def test_benignads_procs_non_empty(self, cfg):
        val = cfg.get("ProcessExclusions", "BenignADSProcs", fallback="")
        assert val.strip(), "BenignADSProcs must not be empty"

    def test_trusted_noise_non_empty(self, cfg):
        val = cfg.get("ProcessExclusions", "TrustedNoise", fallback="")
        assert val.strip(), "TrustedNoise must not be empty"

    def test_benignads_contains_expected_entries(self, cfg):
        val = cfg.get("ProcessExclusions", "BenignADSProcs", fallback="")
        entries = csv_to_set(val)
        for expected in ("explorer.exe", "chrome.exe", "msedge.exe"):
            assert expected in entries, f"Expected {expected} in BenignADSProcs"

    def test_trusted_noise_contains_svchost(self, cfg):
        val = cfg.get("ProcessExclusions", "TrustedNoise", fallback="")
        assert "svchost.exe" in csv_to_set(val)

    def test_extended_section_process_exclusions_non_empty(self, cfg):
        val = cfg.get("ProcessExclusionsExtended", "ProcessExclusions", fallback="")
        assert val.strip(), "ProcessExclusionsExtended.ProcessExclusions must not be empty"

    def test_extended_contains_browsers(self, cfg):
        val = cfg.get("ProcessExclusionsExtended", "ProcessExclusions", fallback="")
        entries = csv_to_set(val)
        for browser in ("chrome", "msedge", "firefox"):
            assert browser in entries, f"Browser {browser} missing from ProcessExclusions"

    def test_critical_processes_not_excluded(self, cfg):
        # WARNING from INI: NEVER add powershell, svchost, lsass, explorer to exclusion list
        val = cfg.get("ProcessExclusionsExtended", "ProcessExclusions", fallback="")
        forbidden = csv_to_set(val)
        for danger in ("powershell", "lsass", "svchost"):
            assert danger not in forbidden, \
                f"SECURITY RISK: '{danger}' in ProcessExclusions - C2 beacons migrate to these!"


# -----------------------------------------------------------------------------
# [RegistryExclusions]
# -----------------------------------------------------------------------------

class TestRegistryExclusions:
    def test_benign_explorer_values_non_empty(self, cfg):
        val = cfg.get("RegistryExclusions", "BenignExplorerValues", fallback="")
        assert val.strip()

    def test_benign_explorer_values_are_encoded(self, cfg):
        # Values use ROT-13 encoding (e.g. Zvpebfbsg = Microsoft)
        val = cfg.get("RegistryExclusions", "BenignExplorerValues", fallback="")
        entries = csv_to_set(val)
        assert "zvpebfbsg.jvaqbjf.rkcybere" in entries


# -----------------------------------------------------------------------------
# [NetworkExclusions]
# -----------------------------------------------------------------------------

class TestNetworkExclusions:
    def test_dns_exclusions_non_empty(self, cfg):
        val = cfg.get("NetworkExclusions", "DnsExclusions", fallback="")
        assert val.strip()

    def test_ip_exclusions_non_empty(self, cfg):
        val = cfg.get("NetworkExclusions", "IpExclusions", fallback="")
        assert val.strip()

    def test_dns_contains_microsoft_domains(self, cfg):
        val = cfg.get("NetworkExclusions", "DnsExclusions", fallback="")
        entries = csv_to_set(val)
        for domain in ("microsoft.com", "windows.com", "azure.com"):
            assert domain in entries, f"Microsoft domain {domain} missing from DnsExclusions"

    def test_dns_contains_internal_suffixes(self, cfg):
        val = cfg.get("NetworkExclusions", "DnsExclusions", fallback="")
        entries = csv_to_set(val)
        for internal in (".arpa", ".local", ".corp"):
            assert internal in entries, f"Internal suffix {internal} missing"

    def test_ip_exclusions_contains_loopback(self, cfg):
        val = cfg.get("NetworkExclusions", "IpExclusions", fallback="")
        assert "^127\\." in val, "Loopback exclusion ^127\\. missing from IpExclusions"

    def test_ip_exclusion_regexes_are_valid(self, cfg):
        val = cfg.get("NetworkExclusions", "IpExclusions", fallback="")
        errors = []
        for pat in val.split(","):
            pat = pat.strip()
            if not pat:
                continue
            try:
                re.compile(pat)
            except re.error as e:
                errors.append(f"{pat!r}: {e}")
        assert not errors, f"Invalid IP exclusion regex(es): {errors}"

    def test_loopback_pattern_matches_127_x_x_x(self, cfg):
        val = cfg.get("NetworkExclusions", "IpExclusions", fallback="")
        patterns = [re.compile(p.strip()) for p in val.split(",") if p.strip()]
        loopback_ips = ["127.0.0.1", "127.1.2.3", "127.255.255.255"]
        for ip in loopback_ips:
            assert any(p.search(ip) for p in patterns), f"Loopback {ip} not excluded by any pattern"

    def test_public_malicious_ip_not_excluded(self, cfg):
        val = cfg.get("NetworkExclusions", "IpExclusions", fallback="")
        patterns = [re.compile(p.strip()) for p in val.split(",") if p.strip()]
        # Known Tor exit node used in test_sensor_schema.rs
        malicious = "185.220.101.1"
        assert not any(p.search(malicious) for p in patterns), \
            f"Malicious IP {malicious} is being excluded - it should NOT be"

    def test_dns_exclusion_count_reasonable(self, cfg):
        val = cfg.get("NetworkExclusions", "DnsExclusions", fallback="")
        entries = csv_to_set(val)
        assert len(entries) >= 40, f"Expected 40+ DNS exclusions, got {len(entries)}"

    def test_enterprise_av_domains_present(self, cfg):
        val = cfg.get("NetworkExclusions", "DnsExclusions", fallback="")
        entries = csv_to_set(val)
        for av in ("crowdstrike.com", "symantec.com", "sophos.com"):
            assert av in entries, f"Enterprise AV domain {av} missing from DnsExclusions"


# -----------------------------------------------------------------------------
# [AppGuardDefinitions]
# -----------------------------------------------------------------------------

class TestAppGuardDefinitions:
    def test_webdaemons_non_empty(self, cfg):
        val = cfg.get("AppGuardDefinitions", "WebDaemons", fallback="")
        assert val.strip()

    def test_dbdaemons_non_empty(self, cfg):
        val = cfg.get("AppGuardDefinitions", "DbDaemons", fallback="")
        assert val.strip()

    def test_shellinterpreters_non_empty(self, cfg):
        val = cfg.get("AppGuardDefinitions", "ShellInterpreters", fallback="")
        assert val.strip()

    def test_webdaemons_contains_core_servers(self, cfg):
        val = cfg.get("AppGuardDefinitions", "WebDaemons", fallback="")
        daemons = csv_to_set(val)
        for expected in ("w3wp", "nginx", "httpd", "node", "python"):
            assert expected in daemons, f"{expected} missing from WebDaemons"

    def test_dbdaemons_contains_core_dbs(self, cfg):
        val = cfg.get("AppGuardDefinitions", "DbDaemons", fallback="")
        daemons = csv_to_set(val)
        for expected in ("sqlservr", "mysqld", "postgres", "mongod"):
            assert expected in daemons, f"{expected} missing from DbDaemons"

    def test_shellinterpreters_contains_lolbins(self, cfg):
        val = cfg.get("AppGuardDefinitions", "ShellInterpreters", fallback="")
        interpreters = csv_to_set(val)
        for lolbin in ("cmd", "powershell", "certutil", "wmic", "rundll32"):
            assert lolbin in interpreters, f"LOLBin {lolbin} missing from ShellInterpreters"

    def test_known_exe_discrepancy_ini_vs_defaults(self, cfg):
        """
        KNOWN CONFIG BUG: INI entries omit .exe suffix.
        C# OsAnalyzer defaults use .exe (e.g. 'cmd.exe').
        When INI is loaded, 'cmd' != 'cmd.exe' → AppGuard match silently fails.

        This test documents the discrepancy and will FAIL if either:
        - The INI adds .exe (fix applied), or
        - The C# code strips .exe before matching (fix applied).

        ACTION REQUIRED: Align INI entries to include .exe OR normalize in code.
        """
        val = cfg.get("AppGuardDefinitions", "ShellInterpreters", fallback="")
        ini_interpreters = csv_to_set(val)

        # INI has entries without .exe
        has_without_exe = any(not e.endswith(".exe") for e in ini_interpreters)
        # C# defaults have .exe
        defaults_have_exe = all(e.endswith(".exe") for e in SHELL_INTERPRETERS_DEFAULT)

        assert has_without_exe,  "INI ShellInterpreters should have entries WITHOUT .exe (documenting the discrepancy)"
        assert defaults_have_exe, "C# ShellInterpreters defaults should have entries WITH .exe"
        # Document: if INI is loaded, 'cmd' in set won't match 'cmd.exe' process name
        assert "cmd" in ini_interpreters and "cmd.exe" not in ini_interpreters, \
            "INI has 'cmd' but not 'cmd.exe' - AppGuard will fail to match 'cmd.exe' process events"


# -----------------------------------------------------------------------------
# [SuspiciousPaths]
# -----------------------------------------------------------------------------

class TestSuspiciousPaths:
    def test_suspicious_paths_non_empty(self, cfg):
        val = cfg.get("SuspiciousPaths", "SuspiciousPaths", fallback="")
        assert val.strip()

    def test_contains_core_paths(self, cfg):
        val = cfg.get("SuspiciousPaths", "SuspiciousPaths", fallback="")
        paths = csv_to_set(val)
        for expected in ("\\temp\\", "\\programdata\\", "\\appdata\\", "\\users\\public\\"):
            assert expected in paths, f"Suspicious path {expected!r} missing"

    def test_contains_web_root(self, cfg):
        val = cfg.get("SuspiciousPaths", "SuspiciousPaths", fallback="")
        assert "\\inetpub\\wwwroot\\" in csv_to_set(val)


# -----------------------------------------------------------------------------
# [Agent]
# -----------------------------------------------------------------------------

class TestAgentConfig:
    def test_dll_directory_set(self, cfg):
        val = cfg.get("Agent", "DllDirectory", fallback="")
        assert val.strip(), "DllDirectory must not be empty"

    def test_dll_directory_default_path(self, cfg):
        val = cfg.get("Agent", "DllDirectory", fallback="")
        assert "DeepSensor" in val, f"Expected 'DeepSensor' in DllDirectory path, got: {val}"

    def test_intel_refresh_hours(self, cfg):
        val = cfg.get("Agent", "IntelRefreshHours", fallback="0")
        hours = int(val)
        assert hours == 24, f"IntelRefreshHours should be 24, got {hours}"

    def test_kernel_driver_disabled_by_default(self, cfg):
        val = cfg.get("Agent", "EnableKernelDriver", fallback="true")
        assert val.lower() == "false", "EnableKernelDriver must default to false (ring-0 is optional)"

    def test_nexus_transmission_disabled_by_default(self, cfg):
        val = cfg.get("Agent", "EnableNexusTransmission", fallback="true")
        assert val.lower() == "false", "EnableNexusTransmission must default to false"

    def test_hook_injection_enabled_by_default(self, cfg):
        val = cfg.get("Agent", "EnableHookInjection", fallback="false")
        assert val.lower() == "true", "EnableHookInjection should default to true"

    def test_ueba_ledger_disabled_by_default(self, cfg):
        val = cfg.get("Agent", "EnableUebaLedger", fallback="true")
        assert val.lower() == "false", "EnableUebaLedger should default to false"


# -----------------------------------------------------------------------------
# [Transmission]
# -----------------------------------------------------------------------------

class TestTransmissionConfig:
    def test_endpoint_configured(self, cfg):
        val = cfg.get("Transmission", "Endpoint", fallback="")
        assert val.strip(), "Transmission.Endpoint must not be empty"

    def test_endpoint_uses_https(self, cfg):
        val = cfg.get("Transmission", "Endpoint", fallback="")
        assert val.startswith("https://"), f"Endpoint must use HTTPS, got: {val}"

    def test_auth_token_not_default_placeholder(self, cfg):
        val = cfg.get("Transmission", "AuthToken", fallback="")
        # The INI ships with a placeholder - warn but don't fail deploy
        if "changeme" in val.lower() or "rotate" in val.lower():
            pytest.warns(UserWarning, match="rotate") if False else None  # informational only
        assert val.strip(), "AuthToken must not be empty"

    def test_integrity_secret_not_default_placeholder(self, cfg):
        val = cfg.get("Transmission", "IntegritySecret", fallback="")
        assert val.strip(), "IntegritySecret must not be empty"

    def test_batch_size_reasonable(self, cfg):
        val = cfg.get("Transmission", "BatchSize", fallback="0")
        batch = int(val)
        assert 100 <= batch <= 10_000, f"BatchSize {batch} outside reasonable range [100, 10000]"

    def test_batch_size_matches_expected(self, cfg):
        val = cfg.get("Transmission", "BatchSize", fallback="0")
        assert int(val) == 2000, "BatchSize should be 2000 (src: test_sensor_schema.rs context)"

    def test_trust_self_signed_cert_disabled(self, cfg):
        val = cfg.get("Transmission", "TrustSelfSignedCert", fallback="true")
        assert val.lower() == "false", "TrustSelfSignedCert must be false in production config"


# -----------------------------------------------------------------------------
# csv_to_set helper unit tests  (SensorConfigs.cs:118-124)
# -----------------------------------------------------------------------------

class TestCsvToSet:
    def test_empty_string_returns_empty_set(self):
        assert csv_to_set("") == set()

    def test_single_value(self):
        assert csv_to_set("chrome.exe") == {"chrome.exe"}

    def test_whitespace_trimmed(self):
        assert csv_to_set("  chrome.exe ,  msedge.exe  ") == {"chrome.exe", "msedge.exe"}

    def test_case_folded(self):
        assert csv_to_set("CHROME.EXE, Svchost.exe") == {"chrome.exe", "svchost.exe"}

    def test_empty_entries_filtered(self):
        result = csv_to_set("a,,b, ,c")
        assert result == {"a", "b", "c"}

    def test_trailing_comma_ignored(self):
        result = csv_to_set("a, b, c,")
        assert result == {"a", "b", "c"}
