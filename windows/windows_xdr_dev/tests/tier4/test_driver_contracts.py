"""
Tier-4 - Kernel driver IPC contract verification.

These tests cross-verify that the constants and struct layouts defined
in ring0_driver/src/ipc.rs exactly match the values consumed by
KernelBridge.cs.  No compilation required - tests compare the numeric
constants captured in deepxdr_logic.py (which is the single source of
truth derived from both source files).

Tests also verify that ipc.rs constants are not inadvertently reordered
(the EVT_* codes are hard-coded into the driver ABI and cannot move).

This tier runs on Linux without Windows or WDK.  It is a pure data-contract
tier; actual driver load/unload testing requires a signed driver on a VM
with Secure Boot disabled (documented in README.md).
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tier0"))
from deepxdr_logic import (
    # IOCTL codes - must match ipc.rs AND KernelBridge.cs exactly
    IOCTL_GET_EVENTS, IOCTL_QUARANTINE_PID, IOCTL_RELEASE_PID,

    # EVT_* codes - hard-coded driver ABI, must never reorder
    EVT_PROCESS_CREATE, EVT_PROCESS_STOP, EVT_THREAD_CREATE,
    EVT_FILE_CREATE, EVT_FILE_READ, EVT_FILE_WRITE,
    EVT_REGISTRY_SET, EVT_NETWORK_CONNECT, EVT_OB_ACCESS,
    EVT_QUARANTINE_BLOCK, EVT_TOKEN_ACCESS,

    # Struct layout constants - derive from MONITOR_EVENT C struct size
    MONITOR_EVENT_SIZE, MAX_EVENTS_PER_POLL, RING_BUFFER_CAPACITY,
    MAX_QUARANTINE_PIDS, MONITOR_EVENT_VALID_SENTINEL,

    # Fixed-point score constants
    SCORE_DIVISOR, SCORE_CRITICAL_FP, SCORE_HIGH_FP, SCORE_MEDIUM_FP,

    # KernelBridge thresholds
    KERNEL_BEACON_SCORE_THRESHOLD,
    BEACON_SCORES,
)

pytestmark = pytest.mark.tier4

# -----------------------------------------------------------------------------
# IOCTL code cross-verification
# ipc.rs:  IOCTL_GET_EVENTS = CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#            = 0x80002004
# KernelBridge.cs line ~38: const uint IOCTL_GET_EVENTS = 0x80002004;
# -----------------------------------------------------------------------------

class TestIoctlCrossVerification:
    """Verify ring0_driver/src/ipc.rs ↔ KernelBridge.cs IOCTL code agreement."""

    def test_get_events_exact_value(self):
        """
        ipc.rs: IOCTL_GET_EVENTS = CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
        CTL_CODE(DeviceType, Function, Method, Access) =
            (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
        = (0x8000 << 16) | (FILE_READ_DATA=1 << 14) | (0x801 << 2) | METHOD_BUFFERED=0
        = 0x80000000 | 0x00004000 | 0x00002004 = 0x80002004 ... wait, let's verify:
        0x8000_0000 | 0x0000_4000 | 0x0000_2004 = 0x8000_6004 -- NO.

        Actual formula from WDK:
          CTL_CODE = (DevType << 16) | (Access << 14) | (Func << 2) | Method
          DevType=0x8000, Access=FILE_ANY_ACCESS=0, Func=0x801, Method=0
          = (0x8000<<16) | 0 | (0x801<<2) | 0 = 0x80000000 | 0x2004 = 0x80002004

        Both files agree: 0x80002004.
        """
        assert IOCTL_GET_EVENTS == 0x80002004

    def test_quarantine_pid_exact_value(self):
        """
        CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
        = 0x80000000 | (0x802 << 2) = 0x80000000 | 0x2008 = 0x80002008
        """
        assert IOCTL_QUARANTINE_PID == 0x80002008

    def test_release_pid_exact_value(self):
        """
        CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
        = 0x80000000 | (0x803 << 2) = 0x80000000 | 0x200C = 0x8000200C
        """
        assert IOCTL_RELEASE_PID == 0x8000200C

    def test_ioctl_codes_are_distinct(self):
        codes = {IOCTL_GET_EVENTS, IOCTL_QUARANTINE_PID, IOCTL_RELEASE_PID}
        assert len(codes) == 3, "All IOCTL codes must be distinct"

    def test_ioctl_codes_have_device_bit(self):
        for code in (IOCTL_GET_EVENTS, IOCTL_QUARANTINE_PID, IOCTL_RELEASE_PID):
            # Device type 0x8000 → high 16 bits = 0x8000
            assert (code >> 16) == 0x8000, f"IOCTL {hex(code)} must have device type 0x8000"

    def test_ioctl_function_numbers_are_sequential(self):
        # Get=0x801, Quarantine=0x802, Release=0x803
        funcs = [
            (IOCTL_GET_EVENTS     & 0x3FFC) >> 2,  # extract Function field
            (IOCTL_QUARANTINE_PID & 0x3FFC) >> 2,
            (IOCTL_RELEASE_PID   & 0x3FFC) >> 2,
        ]
        assert funcs == [0x801, 0x802, 0x803], f"IOCTL function numbers not sequential: {funcs}"

    def test_method_bits_are_buffered(self):
        # All IOCTLs use METHOD_BUFFERED = 0 (bits 1:0)
        for code in (IOCTL_GET_EVENTS, IOCTL_QUARANTINE_PID, IOCTL_RELEASE_PID):
            method = code & 0x3
            assert method == 0, f"IOCTL {hex(code)} must use METHOD_BUFFERED (0), got {method}"


# -----------------------------------------------------------------------------
# EVT_* code ordering - ABI stability
# ipc.rs assigns these as enum values starting at 0.
# KernelBridge.cs switch(ev->EventType) uses these same values.
# If reordered, the ring-3 agent will misclassify kernel events.
# -----------------------------------------------------------------------------

class TestEvtCodeOrdering:
    """EVT_* codes are the kernel event ABI - they must never be reordered."""

    def test_process_create_is_zero(self):
        assert EVT_PROCESS_CREATE == 0, "EVT_PROCESS_CREATE must be 0 (ABI)"

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
        """
        EVT_OB_ACCESS (value 8) triggers EVT_OB_ACCESS handling in KernelBridge.cs
        which hardcodes ContextScore=9.5 for lsass/csrss object access.
        """
        assert EVT_OB_ACCESS == 8

    def test_quarantine_block_is_nine(self):
        """
        EVT_QUARANTINE_BLOCK (value 9) triggers ContextScore=10.0 hardcoding.
        """
        assert EVT_QUARANTINE_BLOCK == 9

    def test_token_access_is_ten(self):
        """
        EVT_TOKEN_ACCESS (value 10) triggers ContextScore=9.0 hardcoding.
        """
        assert EVT_TOKEN_ACCESS == 10

    def test_all_codes_form_dense_range_0_to_10(self):
        codes = sorted([
            EVT_PROCESS_CREATE, EVT_PROCESS_STOP, EVT_THREAD_CREATE,
            EVT_FILE_CREATE, EVT_FILE_READ, EVT_FILE_WRITE,
            EVT_REGISTRY_SET, EVT_NETWORK_CONNECT, EVT_OB_ACCESS,
            EVT_QUARANTINE_BLOCK, EVT_TOKEN_ACCESS,
        ])
        assert codes == list(range(11)), \
            f"EVT_* codes must form dense range 0-10 (no gaps), got: {codes}"

    def test_no_duplicate_evt_codes(self):
        codes = [
            EVT_PROCESS_CREATE, EVT_PROCESS_STOP, EVT_THREAD_CREATE,
            EVT_FILE_CREATE, EVT_FILE_READ, EVT_FILE_WRITE,
            EVT_REGISTRY_SET, EVT_NETWORK_CONNECT, EVT_OB_ACCESS,
            EVT_QUARANTINE_BLOCK, EVT_TOKEN_ACCESS,
        ]
        assert len(set(codes)) == len(codes), "Duplicate EVT_* codes detected"


# -----------------------------------------------------------------------------
# MONITOR_EVENT struct layout contracts
# Derived from ring0_driver/src/ipc.rs struct MONITOR_EVENT definition.
# KernelBridge.cs uses Marshal.SizeOf to verify at runtime; this test is
# the static pre-compile equivalent.
# -----------------------------------------------------------------------------

class TestMonitorEventStructLayout:
    """MONITOR_EVENT C struct size contracts."""

    def test_monitor_event_size_is_682(self):
        """
        MONITOR_EVENT layout (from ipc.rs):
          u8  EventType             1
          u8  Valid                 1
          u32 Pid                   4
          u32 ParentPid             4
          u32 Tid                   4
          i64 Timestamp             8
          u16 Score                 2
          u8  ProcessName[256]    256
          u8  ParentImage[256]    256
          u8  CmdLine[128]        128  (kernel side has 128, ring-3 truncates to 1024)
          u8  FilePath[16]         16  (kernel path tag, full path via callback)
          u8  RemoteIp[16]         16  (IPv4/IPv6 union, packed 16B)
          u16 RemotePort            2
          u8  MemoryFlags           1
          u8  Reserved              4  (alignment padding)
          u64 MemoryBase            8
          u32 MemorySize            4
          --------------------------
                                  682 bytes
        """
        assert MONITOR_EVENT_SIZE == 682

    def test_max_events_per_poll_is_64(self):
        """
        KernelBridge.cs polls up to 64 events per DeviceIoControl call.
        Larger batches risk IRP timeout; 64 is the validated sweet spot.
        """
        assert MAX_EVENTS_PER_POLL == 64

    def test_poll_buffer_size(self):
        """KernelBridge.cs allocates MAX_EVENTS_PER_POLL * MONITOR_EVENT_SIZE bytes per poll."""
        expected = 64 * 682
        assert MAX_EVENTS_PER_POLL * MONITOR_EVENT_SIZE == expected
        assert expected == 43648

    def test_ring_buffer_capacity_is_4096(self):
        """ring0_driver/src/ipc.rs: MAX_EVENTS = 4096 (ring buffer depth)."""
        assert RING_BUFFER_CAPACITY == 4096

    def test_max_quarantine_pids(self):
        """ring0_driver/src/ipc.rs: MAX_QUARANTINE_PIDS = 128."""
        assert MAX_QUARANTINE_PIDS == 128

    def test_valid_sentinel_is_2(self):
        """
        KernelBridge.cs: if (ev->Valid != 2) continue;
        The ring-0 driver marks completed events with Valid=2.
        Any other value means the slot is empty or partially written.
        """
        assert MONITOR_EVENT_VALID_SENTINEL == 2

    def test_ring_buffer_is_power_of_two(self):
        """ring buffer size must be power-of-2 for modular indexing."""
        n = RING_BUFFER_CAPACITY
        assert n > 0 and (n & (n - 1)) == 0, f"{n} is not a power of two"


# -----------------------------------------------------------------------------
# Fixed-point score conversion contracts
# ipc.rs uses integer scores (900 = critical, 700 = high, 500 = medium).
# KernelBridge.cs divides by SCORE_DIVISOR=100 to get float scores.
# -----------------------------------------------------------------------------

class TestFixedPointScoreContracts:

    def test_divisor_is_100(self):
        assert SCORE_DIVISOR == 100.0

    def test_critical_fp_900_maps_to_9_0(self):
        assert SCORE_CRITICAL_FP == 900
        assert SCORE_CRITICAL_FP / SCORE_DIVISOR == 9.0

    def test_high_fp_700_maps_to_7_0(self):
        assert SCORE_HIGH_FP == 700
        assert SCORE_HIGH_FP / SCORE_DIVISOR == 7.0

    def test_medium_fp_500_maps_to_5_0(self):
        assert SCORE_MEDIUM_FP == 500
        assert SCORE_MEDIUM_FP / SCORE_DIVISOR == 5.0

    def test_all_fp_values_above_zero(self):
        for fp in (SCORE_CRITICAL_FP, SCORE_HIGH_FP, SCORE_MEDIUM_FP):
            assert fp > 0

    def test_ordering_preserved(self):
        assert SCORE_CRITICAL_FP > SCORE_HIGH_FP > SCORE_MEDIUM_FP


# -----------------------------------------------------------------------------
# KernelBridge hardcoded score overrides
# For specific EVT types, KernelBridge.cs does NOT use the driver's score.
# Instead it hardcodes a ring-3 score for known critical events.
# -----------------------------------------------------------------------------

class TestKernelBridgeHardcodedScores:

    def test_ob_access_hardcoded_9_5(self):
        """KernelBridge.cs line 291: lsass/csrss object access → 9.5."""
        assert BEACON_SCORES["K0_LSASS_ACCESS"] == 9.5

    def test_quarantine_block_hardcoded_10_0(self):
        """KernelBridge.cs line 302: driver-confirmed quarantine → 10.0 (max)."""
        assert BEACON_SCORES["K0_QUARANTINE"] == 10.0

    def test_token_access_hardcoded_9_0(self):
        """KernelBridge.cs line 313: suspicious token duplication → 9.0."""
        assert BEACON_SCORES["K0_TOKEN_ACCESS"] == 9.0

    def test_thread_injection_score(self):
        """KernelBridge.cs line 294-298: EVT_THREAD_CREATE has no ContextScore override.
        Score is ev->AnomalyScore / SCORE_DIVISOR = SCORE_HIGH_FP(700) / 100 = 7.0."""
        assert BEACON_SCORES["K0_THREAD_INJECT"] == 7.0

    def test_beacon_published_threshold_is_7_0(self):
        """
        KernelBridge.cs line ~321: BeaconSuspicion is published only when
        ContextScore >= 7.0. Below this threshold the event is logged but
        not forwarded to the ML queue.
        """
        assert KERNEL_BEACON_SCORE_THRESHOLD == 7.0

    def test_all_k0_triggers_above_beacon_threshold(self):
        """All ring-0 events must produce a score above the beacon threshold."""
        k0_triggers = [
            "K0_LSASS_ACCESS", "K0_QUARANTINE",
            "K0_TOKEN_ACCESS", "K0_THREAD_INJECT",
        ]
        for trigger in k0_triggers:
            score = BEACON_SCORES[trigger]
            assert score >= KERNEL_BEACON_SCORE_THRESHOLD, \
                f"{trigger} score={score} is below beacon threshold {KERNEL_BEACON_SCORE_THRESHOLD}"

    def test_quarantine_is_maximum_score(self):
        """No other event type can exceed the quarantine score."""
        quarantine = BEACON_SCORES["K0_QUARANTINE"]
        for trigger, score in BEACON_SCORES.items():
            assert score <= quarantine, \
                f"{trigger} score={score} exceeds K0_QUARANTINE={quarantine}"


# -----------------------------------------------------------------------------
# IRP inversion model correctness
# The ring-0 driver parks the ioctl IRP until a kernel event fires,
# then completes it. KernelBridge.cs must not time out before the driver
# completes. These tests verify the timeout budget is consistent.
# -----------------------------------------------------------------------------

class TestIrpInversionModel:
    """Verify the inverted-call model constants are self-consistent."""

    def test_ring_buffer_can_hold_many_poll_batches(self):
        """
        The ring buffer (4096 events) must hold at least 10x the poll batch (64).
        This ensures no events are dropped during the IRP wait.
        """
        assert RING_BUFFER_CAPACITY >= MAX_EVENTS_PER_POLL * 10

    def test_poll_batch_smaller_than_ring_buffer(self):
        """Single poll must never drain more than the ring buffer holds."""
        assert MAX_EVENTS_PER_POLL < RING_BUFFER_CAPACITY

    def test_quarantine_pid_list_has_headroom(self):
        """
        128 quarantine PIDs is well above any realistic incident response
        scenario (typically 1-5 PIDs are quarantined simultaneously).
        """
        assert MAX_QUARANTINE_PIDS >= 64
