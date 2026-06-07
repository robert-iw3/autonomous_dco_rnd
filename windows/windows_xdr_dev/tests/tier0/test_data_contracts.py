"""
Tier-0 - Data contract tests.

Validates PlatformEvent field sizes, enum values, channel capacity
constants, BeaconSuspicion fields, and KernelBridge IPC contracts.
"""

import json
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from deepxdr_logic import (
    SensorType, EventCategory, TrafficDirection,
    FIXED_ARRAY_PROCESS_NAME, FIXED_ARRAY_PARENT_NAME,
    FIXED_ARRAY_CMD, FIXED_ARRAY_PATH, truncate_to_fixed_array,
    CHANNEL_TELEMETRY_ROUTER, CHANNEL_BEACON, CHANNEL_YARA_QUEUE,
    CHANNEL_ML_QUEUE, IP_EXCLUSION_CACHE_CAP,
    IOCTL_GET_EVENTS, IOCTL_QUARANTINE_PID, IOCTL_RELEASE_PID,
    EVT_PROCESS_CREATE, EVT_PROCESS_STOP, EVT_THREAD_CREATE,
    EVT_FILE_CREATE, EVT_FILE_READ, EVT_FILE_WRITE,
    EVT_REGISTRY_SET, EVT_NETWORK_CONNECT, EVT_OB_ACCESS,
    EVT_QUARANTINE_BLOCK, EVT_TOKEN_ACCESS,
    SCORE_DIVISOR, SCORE_CRITICAL_FP, SCORE_HIGH_FP, SCORE_MEDIUM_FP,
    MONITOR_EVENT_SIZE, MAX_EVENTS_PER_POLL, RING_BUFFER_CAPACITY,
    MAX_QUARANTINE_PIDS, KERNEL_BEACON_SCORE_THRESHOLD,
    MONITOR_EVENT_VALID_SENTINEL, fnv1a_hash, build_beacon_context_json,
    BEACON_SCORES,
)

pytestmark = pytest.mark.tier0

# -----------------------------------------------------------------------------
# Enum values  (PlatformEvent.cs:7-27)
# -----------------------------------------------------------------------------

class TestSensorTypeEnum:
    def test_unknown_is_zero(self):
        assert SensorType.Unknown == 0

    def test_etw_kernel_is_one(self):
        assert SensorType.ETW_Kernel == 1

    def test_ndis_is_two(self):
        assert SensorType.NDIS == 2

    def test_no_gaps(self):
        values = [SensorType.Unknown, SensorType.ETW_Kernel, SensorType.NDIS]
        assert sorted(values) == [0, 1, 2]


class TestEventCategoryEnum:
    def test_unknown_is_zero(self):
        assert EventCategory.Unknown == 0

    def test_process_start_is_one(self):
        assert EventCategory.ProcessStart == 1

    def test_tcp_connect_is_two(self):
        assert EventCategory.TcpConnect == 2

    def test_file_write_is_three(self):
        assert EventCategory.FileWrite == 3

    def test_registry_mod_is_four(self):
        assert EventCategory.RegistryMod == 4

    def test_image_load_is_five(self):
        assert EventCategory.ImageLoad == 5

    def test_memory_alloc_is_six(self):
        assert EventCategory.MemoryAlloc == 6

    def test_process_stop_is_seven(self):
        assert EventCategory.ProcessStop == 7

    def test_all_values_sequential(self):
        vals = [
            EventCategory.Unknown, EventCategory.ProcessStart,
            EventCategory.TcpConnect, EventCategory.FileWrite,
            EventCategory.RegistryMod, EventCategory.ImageLoad,
            EventCategory.MemoryAlloc, EventCategory.ProcessStop,
        ]
        assert sorted(vals) == list(range(8))


class TestTrafficDirectionEnum:
    def test_unknown_is_zero(self):
        assert TrafficDirection.Unknown == 0

    def test_egress_is_one(self):
        assert TrafficDirection.Egress == 1

    def test_ingress_is_two(self):
        assert TrafficDirection.Ingress == 2

    def test_lateral_is_three(self):
        assert TrafficDirection.Lateral == 3

    def test_no_gaps(self):
        vals = [TrafficDirection.Unknown, TrafficDirection.Egress,
                TrafficDirection.Ingress, TrafficDirection.Lateral]
        assert sorted(vals) == [0, 1, 2, 3]


# -----------------------------------------------------------------------------
# PlatformEvent field-size contracts  (PlatformEvent.cs:56-59)
# -----------------------------------------------------------------------------

class TestPlatformEventFieldSizes:
    def test_process_name_capacity(self):
        assert FIXED_ARRAY_PROCESS_NAME == 256

    def test_parent_process_name_capacity(self):
        assert FIXED_ARRAY_PARENT_NAME == 256

    def test_cmd_capacity(self):
        assert FIXED_ARRAY_CMD == 1024

    def test_path_capacity(self):
        assert FIXED_ARRAY_PATH == 512

    def test_process_name_truncated_at_255_chars(self):
        long_name = "a" * 300
        result = truncate_to_fixed_array(long_name, FIXED_ARRAY_PROCESS_NAME)
        assert len(result) == 255  # capacity - 1 (null terminator)

    def test_short_value_not_truncated(self):
        result = truncate_to_fixed_array("cmd.exe", FIXED_ARRAY_PROCESS_NAME)
        assert result == "cmd.exe"

    def test_cmd_truncated_at_1023_chars(self):
        long_cmd = "x" * 2000
        result = truncate_to_fixed_array(long_cmd, FIXED_ARRAY_CMD)
        assert len(result) == 1023

    def test_path_truncated_at_511_chars(self):
        long_path = "p" * 600
        result = truncate_to_fixed_array(long_path, FIXED_ARRAY_PATH)
        assert len(result) == 511

    def test_empty_string_preserved(self):
        result = truncate_to_fixed_array("", FIXED_ARRAY_PROCESS_NAME)
        assert result == ""

    def test_exact_capacity_minus_one_not_truncated(self):
        exact = "a" * 255
        result = truncate_to_fixed_array(exact, FIXED_ARRAY_PROCESS_NAME)
        assert len(result) == 255

    def test_process_name_hash_depends_on_value(self):
        h1 = fnv1a_hash("cmd.exe")
        h2 = fnv1a_hash("powershell.exe")
        assert h1 != h2


# -----------------------------------------------------------------------------
# Channel capacity contracts
# -----------------------------------------------------------------------------

class TestChannelCapacities:
    def test_telemetry_router_capacity(self):
        assert CHANNEL_TELEMETRY_ROUTER == 150_000

    def test_beacon_channel_capacity(self):
        assert CHANNEL_BEACON == 2_000

    def test_yara_queue_capacity(self):
        assert CHANNEL_YARA_QUEUE == 2_000

    def test_ml_queue_capacity(self):
        assert CHANNEL_ML_QUEUE == 50_000

    def test_ip_exclusion_cache_cap(self):
        assert IP_EXCLUSION_CACHE_CAP == 50_000

    def test_telemetry_router_largest(self):
        assert CHANNEL_TELEMETRY_ROUTER > CHANNEL_ML_QUEUE > CHANNEL_BEACON

    def test_beacon_equals_yara(self):
        assert CHANNEL_BEACON == CHANNEL_YARA_QUEUE


# -----------------------------------------------------------------------------
# KernelBridge IPC constants  (KernelBridge.cs vs ipc.rs - must match exactly)
# -----------------------------------------------------------------------------

class TestIoctlCodes:
    def test_get_events_code(self):
        assert IOCTL_GET_EVENTS == 0x80002004

    def test_quarantine_pid_code(self):
        assert IOCTL_QUARANTINE_PID == 0x80002008

    def test_release_pid_code(self):
        assert IOCTL_RELEASE_PID == 0x8000200C

    def test_codes_are_distinct(self):
        codes = [IOCTL_GET_EVENTS, IOCTL_QUARANTINE_PID, IOCTL_RELEASE_PID]
        assert len(set(codes)) == 3

    def test_codes_have_high_bit_set(self):
        # All DeepXDR IOCTLs use 0x8000xxxx (device-custom method)
        for code in [IOCTL_GET_EVENTS, IOCTL_QUARANTINE_PID, IOCTL_RELEASE_PID]:
            assert code & 0x80000000, f"IOCTL {hex(code)} missing high bit"


class TestEventTypeCodes:
    def test_process_create_is_zero(self):
        assert EVT_PROCESS_CREATE == 0

    def test_process_stop_is_one(self):
        assert EVT_PROCESS_STOP == 1

    def test_thread_create_is_two(self):
        assert EVT_THREAD_CREATE == 2

    def test_file_create_is_three(self):
        assert EVT_FILE_CREATE == 3

    def test_file_read_is_four(self):
        assert EVT_FILE_READ == 4

    def test_file_write_is_five(self):
        assert EVT_FILE_WRITE == 5

    def test_registry_set_is_six(self):
        assert EVT_REGISTRY_SET == 6

    def test_network_connect_is_seven(self):
        assert EVT_NETWORK_CONNECT == 7

    def test_ob_access_is_eight(self):
        assert EVT_OB_ACCESS == 8

    def test_quarantine_block_is_nine(self):
        assert EVT_QUARANTINE_BLOCK == 9

    def test_token_access_is_ten(self):
        assert EVT_TOKEN_ACCESS == 10

    def test_all_event_types_sequential(self):
        codes = [
            EVT_PROCESS_CREATE, EVT_PROCESS_STOP, EVT_THREAD_CREATE,
            EVT_FILE_CREATE, EVT_FILE_READ, EVT_FILE_WRITE,
            EVT_REGISTRY_SET, EVT_NETWORK_CONNECT, EVT_OB_ACCESS,
            EVT_QUARANTINE_BLOCK, EVT_TOKEN_ACCESS,
        ]
        assert sorted(codes) == list(range(11))

    def test_event_types_are_distinct(self):
        codes = [
            EVT_PROCESS_CREATE, EVT_PROCESS_STOP, EVT_THREAD_CREATE,
            EVT_FILE_CREATE, EVT_FILE_READ, EVT_FILE_WRITE,
            EVT_REGISTRY_SET, EVT_NETWORK_CONNECT, EVT_OB_ACCESS,
            EVT_QUARANTINE_BLOCK, EVT_TOKEN_ACCESS,
        ]
        assert len(set(codes)) == 11


class TestMonitorEventLayout:
    def test_event_size_is_682(self):
        assert MONITOR_EVENT_SIZE == 682

    def test_max_events_per_poll_is_64(self):
        assert MAX_EVENTS_PER_POLL == 64

    def test_poll_buffer_size(self):
        # KernelBridge.cs: POLL_BUFFER_SIZE = MAX_EVENTS_PER_POLL * MONITOR_EVENT_SIZE
        assert MAX_EVENTS_PER_POLL * MONITOR_EVENT_SIZE == 43648

    def test_ring_buffer_capacity(self):
        assert RING_BUFFER_CAPACITY == 4096

    def test_max_quarantine_pids(self):
        assert MAX_QUARANTINE_PIDS == 128

    def test_valid_sentinel_is_two(self):
        # KernelBridge.cs line 222: if (ev->Valid != 2) continue;
        assert MONITOR_EVENT_VALID_SENTINEL == 2


class TestScoreFixedPoint:
    def test_score_divisor(self):
        assert SCORE_DIVISOR == 100.0

    def test_critical_fp_is_900(self):
        assert SCORE_CRITICAL_FP == 900

    def test_high_fp_is_700(self):
        assert SCORE_HIGH_FP == 700

    def test_medium_fp_is_500(self):
        assert SCORE_MEDIUM_FP == 500

    def test_critical_converts_to_9(self):
        assert SCORE_CRITICAL_FP / SCORE_DIVISOR == 9.0

    def test_high_converts_to_7(self):
        assert SCORE_HIGH_FP / SCORE_DIVISOR == 7.0

    def test_medium_converts_to_5(self):
        assert SCORE_MEDIUM_FP / SCORE_DIVISOR == 5.0

    def test_kernel_beacon_threshold_is_7(self):
        assert KERNEL_BEACON_SCORE_THRESHOLD == 7.0


# -----------------------------------------------------------------------------
# BeaconSuspicion contract  (BeaconSuspicion.cs)
# -----------------------------------------------------------------------------

class TestBeaconSuspicionContract:
    def _make(self, pid=1234, process="beacon.exe", reason="YARA_RWX", score=8.5):
        return {
            "pid":           pid,
            "process_name":  process,
            "trigger_reason": reason,
            "context_score": score,
            "dest_ip":       "185.220.101.1",
            "dest_port":     443,
        }

    def test_pid_non_zero(self):
        b = self._make(pid=1234)
        assert b["pid"] > 0

    def test_score_in_range(self):
        for score in [7.5, 8.0, 8.5, 9.0, 9.5, 10.0]:
            b = self._make(score=score)
            assert 0.0 <= b["context_score"] <= 10.0

    def test_trigger_reason_non_empty(self):
        b = self._make(reason="ETW_TAMPER")
        assert b["trigger_reason"]

    def test_all_beacon_scores_in_range(self):
        for trigger, score in BEACON_SCORES.items():
            assert 0.0 <= score <= 10.0, f"Beacon score for {trigger} out of range: {score}"

    def test_etw_tamper_score(self):
        assert BEACON_SCORES["ETW_TAMPER"] == 9.5

    def test_web_shell_score(self):
        assert BEACON_SCORES["WEB_SHELL_DETECTED"] == 9.5

    def test_db_rce_score(self):
        assert BEACON_SCORES["DB_RCE_DETECTED"] == 9.5

    def test_yara_rwx_score(self):
        assert BEACON_SCORES["YARA_RWX"] == 8.5

    def test_malicious_pipe_score(self):
        assert BEACON_SCORES["MALICIOUS_PIPE"] == 8.5

    def test_suspicious_path_score(self):
        assert BEACON_SCORES["SUSPICIOUS_PATH"] == 7.5

    def test_high_entropy_pipe_score(self):
        assert BEACON_SCORES["HIGH_ENTROPY_PIPE"] == 7.5

    def test_k0_quarantine_max_score(self):
        assert BEACON_SCORES["K0_QUARANTINE"] == 10.0

    def test_k0_lsass_access_score(self):
        assert BEACON_SCORES["K0_LSASS_ACCESS"] == 9.5


# -----------------------------------------------------------------------------
# Beacon context JSON structure  (C2EphemeralModule.cs:162-188)
# -----------------------------------------------------------------------------

class TestBeaconContextJson:
    def _build(self, **kwargs):
        defaults = dict(
            pid=1234, process_name="beacon.exe", trigger_reason="YARA_RWX",
            context_score=8.5, dest_ip="185.220.101.1", connection_count=10,
            mean_interval_ms=30000.0, jitter_cv=0.05, bytes_out=2000,
            bytes_in=500, unique_ips=1, ja3_hashes=["abc123", "def456"],
            dest_ips=["185.220.101.1"], dest_ports=[443],
        )
        defaults.update(kwargs)
        return build_beacon_context_json(**defaults)

    def test_output_is_valid_json(self):
        raw = self._build()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_event_type_field(self):
        parsed = json.loads(self._build())
        assert parsed["event_type"] == "beacon_analysis"

    def test_all_required_fields_present(self):
        required = [
            "event_type", "pid", "process", "trigger_reason", "context_score",
            "dest_ip", "connection_count", "mean_interval_ms", "jitter_cv",
            "total_bytes_out", "total_bytes_in", "unique_ips",
            "ja3_hashes", "dest_ips", "dest_ports",
        ]
        parsed = json.loads(self._build())
        for field in required:
            assert field in parsed, f"Missing field: {field}"

    def test_ja3_hashes_are_list(self):
        parsed = json.loads(self._build())
        assert isinstance(parsed["ja3_hashes"], list)

    def test_dest_ips_are_list(self):
        parsed = json.loads(self._build())
        assert isinstance(parsed["dest_ips"], list)

    def test_dest_ports_are_list(self):
        parsed = json.loads(self._build())
        assert isinstance(parsed["dest_ports"], list)

    def test_score_rounded_to_two_decimals(self):
        parsed = json.loads(self._build(context_score=8.567))
        # Should be 8.57 after rounding
        assert parsed["context_score"] == 8.57

    def test_jitter_cv_rounded_to_four_decimals(self):
        parsed = json.loads(self._build(jitter_cv=0.123456789))
        assert parsed["jitter_cv"] == 0.1235

    def test_quote_in_process_name_escaped(self):
        raw = self._build(process_name='evil"exe')
        parsed = json.loads(raw)
        assert '"' in parsed["process"]

    def test_pid_is_integer(self):
        parsed = json.loads(self._build(pid=4567))
        assert parsed["pid"] == 4567
        assert isinstance(parsed["pid"], int)
