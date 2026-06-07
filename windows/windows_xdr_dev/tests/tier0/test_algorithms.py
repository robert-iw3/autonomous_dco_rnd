"""
Tier-0 - Pure algorithm tests.

Covers: FNV-1a hash, Shannon entropy, jitter CV, asymmetry score,
mean interval, IP uint conversion.

Every constant is taken verbatim from the C# source so a change
to any algorithm constant immediately breaks the corresponding test.
"""

import math
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from deepxdr_logic import (
    fnv1a_hash, _FNV_OFFSET, _FNV_PRIME,
    shannon_entropy, HIGH_ENTROPY_PIPE_THRESHOLD,
    compute_jitter_cv, compute_mean_interval_ms,
    BEACON_CV_THRESHOLD, TICKS_PER_MS,
    compute_asymmetry_score,
    ip_uint_to_str, ip_str_to_uint,
)

pytestmark = pytest.mark.tier0


# -----------------------------------------------------------------------------
# FNV-1a hash  (PlatformEvent.cs:122-128)
# -----------------------------------------------------------------------------

class TestFnv1aHash:
    def test_constants_match_csharp(self):
        assert _FNV_OFFSET == 14695981039346656037
        assert _FNV_PRIME  == 1099511628211

    def test_empty_string_returns_zero(self):
        assert fnv1a_hash("") == 0

    def test_none_returns_zero(self):
        assert fnv1a_hash(None) == 0

    def test_known_hash_is_64_bit(self):
        h = fnv1a_hash("cmd.exe")
        assert 0 < h <= 0xFFFFFFFFFFFFFFFF

    def test_same_string_same_hash(self):
        assert fnv1a_hash("powershell.exe") == fnv1a_hash("powershell.exe")

    def test_different_strings_different_hash(self):
        assert fnv1a_hash("cmd.exe") != fnv1a_hash("powershell.exe")

    def test_case_insensitive(self):
        # C# uses char.ToLowerInvariant before hashing
        assert fnv1a_hash("CMD.EXE") == fnv1a_hash("cmd.exe")
        assert fnv1a_hash("PowerShell.exe") == fnv1a_hash("powershell.exe")

    def test_case_insensitive_mixed(self):
        assert fnv1a_hash("W3WP.EXE") == fnv1a_hash("w3wp.exe")

    def test_hash_is_deterministic_across_calls(self):
        results = {fnv1a_hash("svchost.exe") for _ in range(100)}
        assert len(results) == 1

    def test_hash_wraps_within_u64(self):
        # Should never raise OverflowError regardless of input length
        long_str = "a" * 10_000
        h = fnv1a_hash(long_str)
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF

    def test_single_char(self):
        h = fnv1a_hash("a")
        assert h != 0

    def test_null_byte_char(self):
        h = fnv1a_hash("\x00")
        assert h != 0  # XOR with 0 still changes multiplied state


# -----------------------------------------------------------------------------
# Shannon entropy  (OsAnalyzer.cs:552-559)
# -----------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        # All prob = 1.0, log2(1) = 0
        assert shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal_prob(self):
        result = shannon_entropy("abababab")
        assert abs(result - 1.0) < 1e-9

    def test_max_entropy_uniform_distribution(self):
        # 4 symbols equal weight → entropy = log2(4) = 2.0
        result = shannon_entropy("abcdabcdabcd")
        assert abs(result - 2.0) < 0.05

    def test_high_entropy_random_looking_string(self):
        s = "xK7!mQ2#pL9@nR4$"
        assert shannon_entropy(s) > 3.5

    def test_low_entropy_repeated_string(self):
        s = "aaaaaabbbbbbb"
        assert shannon_entropy(s) < 1.5

    def test_pipe_threshold_constant(self):
        assert HIGH_ENTROPY_PIPE_THRESHOLD == 3.5

    def test_known_c2_pipe_name_high_entropy(self):
        # Cobalt Strike default pipe: random-ish characters → should exceed 3.5
        pipe = "xK9mQ2pL7nR4wT1y"
        assert shannon_entropy(pipe) > HIGH_ENTROPY_PIPE_THRESHOLD

    def test_known_benign_pipe_low_entropy(self):
        # "chrome" - very regular, very low entropy
        pipe = "chrome"
        assert shannon_entropy(pipe) < HIGH_ENTROPY_PIPE_THRESHOLD

    def test_formula_correctness_manual(self):
        # "ab": p_a=0.5, p_b=0.5, H = -(0.5*log2(0.5) + 0.5*log2(0.5)) = 1.0
        assert abs(shannon_entropy("ab") - 1.0) < 1e-9


# -----------------------------------------------------------------------------
# Jitter CV  (C2EphemeralModule.cs:257-280)
# -----------------------------------------------------------------------------

class TestJitterCV:
    def _ticks(self, intervals_ms: list[float]) -> list[int]:
        """Build arrival ticks from interval list starting at t=0."""
        ticks = [0]
        for ms in intervals_ms:
            ticks.append(ticks[-1] + int(ms * TICKS_PER_MS))
        return ticks

    def test_zero_arrivals_returns_inf(self):
        assert compute_jitter_cv([]) == float("inf")

    def test_one_arrival_returns_inf(self):
        assert compute_jitter_cv([1_000_000]) == float("inf")

    def test_perfectly_regular_beacon_cv_near_zero(self):
        # Exactly 30-second intervals - textbook beacon
        ticks = self._ticks([30_000.0] * 10)
        cv = compute_jitter_cv(ticks)
        assert cv < BEACON_CV_THRESHOLD, f"Regular beacon CV={cv:.4f} should be < {BEACON_CV_THRESHOLD}"

    def test_highly_irregular_traffic_cv_above_threshold(self):
        # Wildly varying intervals → high CV
        ticks = self._ticks([1_000.0, 60_000.0, 500.0, 120_000.0, 200.0, 90_000.0])
        cv = compute_jitter_cv(ticks)
        assert cv > BEACON_CV_THRESHOLD, f"Irregular CV={cv:.4f} should be > {BEACON_CV_THRESHOLD}"

    def test_constant_intervals_cv_is_zero(self):
        # Identical intervals → std=0 → CV=0
        ticks = self._ticks([5_000.0] * 8)
        cv = compute_jitter_cv(ticks)
        assert cv == pytest.approx(0.0, abs=1e-9)

    def test_beacon_cv_threshold_constant(self):
        assert BEACON_CV_THRESHOLD == 0.20

    def test_two_ticks_same_value_returns_inf(self):
        # Both arrive at same tick → interval = 0, filtered out → < 2 intervals
        cv = compute_jitter_cv([1_000_000, 1_000_000])
        assert cv == float("inf")

    def test_population_variance_not_sample(self):
        # CV must use population variance (divide by N), not sample (N-1)
        # C# code: variance /= intervals.Count  (not Count-1)
        ticks = self._ticks([10.0, 20.0])   # intervals = [10ms, 20ms]
        cv = compute_jitter_cv(ticks)
        # mean=15, pop_variance=(25+25)/2=25, pop_std=5, CV=5/15≈0.333
        # sample_variance=(25+25)/1=50, sample_std≈7.07, CV≈0.471
        expected_pop_cv = 5.0 / 15.0
        assert abs(cv - expected_pop_cv) < 1e-9, f"Expected population CV≈{expected_pop_cv:.4f}, got {cv:.4f}"


# -----------------------------------------------------------------------------
# Mean interval  (C2EphemeralModule.cs:221-231)
# -----------------------------------------------------------------------------

class TestMeanIntervalMs:
    def test_single_tick_returns_zero(self):
        assert compute_mean_interval_ms([100_000]) == 0.0

    def test_empty_returns_zero(self):
        assert compute_mean_interval_ms([]) == 0.0

    def test_two_ticks_correct_ms(self):
        # 30 seconds = 30_000 ms = 300_000_000 ticks
        ticks = [0, 300_000_000]
        result = compute_mean_interval_ms(ticks)
        assert abs(result - 30_000.0) < 1.0

    def test_multiple_uniform_intervals(self):
        # 5 intervals of 1000ms each
        interval_ticks = TICKS_PER_MS * 1000
        ticks = [i * interval_ticks for i in range(6)]
        result = compute_mean_interval_ms(ticks)
        assert abs(result - 1000.0) < 1.0

    def test_ticks_per_ms_constant(self):
        assert TICKS_PER_MS == 10_000


# -----------------------------------------------------------------------------
# Asymmetry score  (C2EphemeralModule.cs:211-218)
# -----------------------------------------------------------------------------

class TestAsymmetryScore:
    def test_zero_bytes_returns_zero(self):
        assert compute_asymmetry_score(0, 0) == 0.0

    def test_equal_traffic_returns_zero(self):
        assert compute_asymmetry_score(1000, 1000) == 0.0

    def test_all_outbound_returns_ten(self):
        assert compute_asymmetry_score(1000, 0) == pytest.approx(10.0)

    def test_all_inbound_returns_ten(self):
        assert compute_asymmetry_score(0, 1000) == pytest.approx(10.0)

    def test_three_to_one_outbound(self):
        # 3000 out, 1000 in → |2000|/4000 * 10 = 5.0
        assert compute_asymmetry_score(3000, 1000) == pytest.approx(5.0)

    def test_c2_beacon_typical(self):
        # C2 beacons send small keep-alives (out) and receive large payloads (in)
        result = compute_asymmetry_score(200, 50_000)
        assert result > 8.0, "Typical C2 keep-alive asymmetry should score high"

    def test_score_bounded_zero_to_ten(self):
        for out, inp in [(0, 0), (100, 0), (0, 100), (500, 500), (1, 99)]:
            score = compute_asymmetry_score(out, inp)
            assert 0.0 <= score <= 10.0, f"Score out of bounds for out={out}, in={inp}: {score}"


# -----------------------------------------------------------------------------
# IP uint ↔ string  (IdpsAnalyzer.cs:233-239)
# -----------------------------------------------------------------------------

class TestIpUtils:
    def test_zero_returns_empty(self):
        assert ip_uint_to_str(0) == ""

    def test_loopback(self):
        assert ip_uint_to_str(0x7F000001) == "127.0.0.1"

    def test_broadcast(self):
        assert ip_uint_to_str(0xFFFFFFFF) == "255.255.255.255"

    def test_private_192(self):
        assert ip_uint_to_str(0xC0A80101) == "192.168.1.1"

    def test_private_10(self):
        assert ip_uint_to_str(0x0A000132) == "10.0.1.50"

    def test_known_c2_ip(self):
        # 185.220.101.1 from test_sensor_schema.rs
        assert ip_uint_to_str(0xB9DC6501) == "185.220.101.1"

    def test_roundtrip_str_to_uint_and_back(self):
        for ip in ("1.2.3.4", "10.0.1.50", "192.168.100.200", "8.8.8.8"):
            assert ip_uint_to_str(ip_str_to_uint(ip)) == ip

    def test_big_endian_encoding(self):
        # 192.168.1.1 → 0xC0 0xA8 0x01 0x01 → uint = 0xC0A80101
        assert ip_str_to_uint("192.168.1.1") == 0xC0A80101
