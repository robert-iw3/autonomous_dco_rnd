"""
Tier-0 - Algorithmic validation for the c2_sensor ML engine.
"""

import math
import pytest

from BeaconML import (
    domain_char_entropy,
    detect_dga,
    _consonant_ratio,
    detect_beaconing_list,
)

pytestmark = pytest.mark.tier0

# -----------------------------------------------------------------------------
# Shannon entropy of domain names
# -----------------------------------------------------------------------------

class TestDomainCharEntropy:
    def test_empty_domain_is_zero(self):
        assert domain_char_entropy("") == 0.0

    def test_repeated_char_is_zero(self):
        assert domain_char_entropy("aaaaaa") == 0.0

    def test_two_symbols_equal_probability(self):
        assert math.isclose(domain_char_entropy("abab"), 1.0, abs_tol=1e-9)

    def test_higher_alphabet_increases_entropy(self):
        low = domain_char_entropy("aabbaabb")
        high = domain_char_entropy("a1b2c3d4")
        assert high > low

# -----------------------------------------------------------------------------
# DGA classification
# -----------------------------------------------------------------------------

class TestDetectDga:
    def test_empty_domain_not_flagged(self):
        is_dga, confidence, reason = detect_dga("")
        assert is_dga is False
        assert confidence == 0
        assert reason == ""

    def test_legit_short_domain_not_flagged(self):
        is_dga, confidence, reason = detect_dga("google.com")
        assert is_dga is False

    def test_high_entropy_long_label_flagged_as_dga(self):
        # Random-looking, long, consonant-heavy label -- classic DGA shape
        is_dga, confidence, reason = detect_dga("xqzvbnmkjhgfdsapoiuytrewq.net")
        assert is_dga is True
        assert confidence >= 50
        assert "entropy" in reason or "label" in reason or "consonant" in reason

    def test_confidence_capped_at_95(self):
        # Pathological worst-case input should never exceed the documented cap
        _, confidence, _ = detect_dga("zxcvbnmqwrtyplkjhgfdszxcvbnmqwrtyplkjhgfds.evil.example.attacker.test")
        assert confidence <= 95

    def test_score_threshold_is_50_for_dga_classification(self):
        # A domain engineered to land just below the DGA threshold should not flag
        is_dga, confidence, _ = detect_dga("api.example.com")
        assert is_dga is False
        assert confidence < 50

class TestConsonantRatio:
    def test_empty_string_is_zero(self):
        assert _consonant_ratio("") == 0.0

    def test_all_vowels_is_zero(self):
        assert _consonant_ratio("aeiou") == 0.0

    def test_all_consonants_is_one(self):
        assert _consonant_ratio("bcdfg") == 1.0

    def test_mixed_ratio(self):
        # "ba" -> 1 consonant / 2 alpha = 0.5
        assert math.isclose(_consonant_ratio("ba"), 0.5)

    def test_ignores_non_alpha(self):
        assert _consonant_ratio("b4c5") == _consonant_ratio("bc")

# -----------------------------------------------------------------------------
# Beaconing detection (3D feature space: interval / entropy / packet-size CV)
# -----------------------------------------------------------------------------

class TestDetectBeaconingList:
    def test_too_few_samples_returns_no_signal(self):
        result, confidence = detect_beaconing_list([10.0, 11.0])
        assert result is None
        assert confidence == 0

    def test_empty_intervals_returns_no_signal(self):
        result, confidence = detect_beaconing_list([])
        assert result is None
        assert confidence == 0

    def test_mechanical_sync_suppressed_when_low_cv_low_entropy(self):
        # Near-zero jitter, low entropy payloads -- should be suppressed as benign
        intervals = [60.0] * 12
        entropies = [1.0] * 12
        result, confidence = detect_beaconing_list(intervals, payload_entropies=entropies)
        assert result is not None and "Benign Mechanical Sync" in result
        assert confidence == 0

    def test_organic_bursty_traffic_low_confidence(self):
        # High-variance intervals -- organic/bursty, not a beacon
        intervals = [1.0, 45.0, 3.0, 90.0, 2.0, 120.0, 5.0, 80.0]
        result, confidence = detect_beaconing_list(intervals)
        assert result is not None and "Organic Bursty Traffic" in result
        assert confidence == 10

    def test_jittered_fast_path_beacon_flagged_high_confidence(self):
        # Jitter band (CV ~0.04, comfortably above the 0.02 "mechanical sync"
        # suppression floor but inside the fast-path std_int < 0.3*mean_int
        # window) with no entropy signal -- classic jittered C2 beacon shape.
        intervals = [60.0, 63.0, 57.0, 61.0, 59.0, 64.0, 56.0, 62.0, 58.0, 60.0]
        result, confidence = detect_beaconing_list(intervals)
        assert result is not None
        assert "Beaconing" in result
        assert confidence >= 78

    def test_jittered_high_entropy_beacon_scores_higher_than_plain(self):
        intervals = [60.0, 63.0, 57.0, 61.0, 59.0, 64.0, 56.0, 62.0, 58.0, 60.0]
        plain_result, plain_conf = detect_beaconing_list(list(intervals))
        entropic_result, entropic_conf = detect_beaconing_list(
            list(intervals), payload_entropies=[7.9] * len(intervals)
        )
        assert entropic_conf >= plain_conf
        assert "High Entropy" in entropic_result

    def test_confidence_never_exceeds_documented_cap(self):
        intervals = [60.0 + (i % 3) * 0.1 for i in range(40)]
        _, confidence = detect_beaconing_list(intervals, payload_entropies=[7.5] * 40, packet_sizes=[512] * 40)
        assert 0 <= confidence <= 95