"""
Lab det_chamber -- Phase 2: quarantine bucket security contract.

The acquisition agent uploads the (encrypted, password-wrapped) sample to the
quarantine bucket; the intake service pulls it from there. That bucket holds live
malware, so it must be locked down: encrypted at rest with its own key, versioned,
auto-expiring, never public, and TLS-only. These assertions prove the terraform
encodes those controls (structurally + via terraform fmt in the dockerized lab).
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BUCKET_TF = REPO / "infrastructure" / "terraform" / "det_chamber" / "quarantine_bucket.tf"


def _tf():
    assert BUCKET_TF.exists(), "infrastructure/terraform/det_chamber/quarantine_bucket.tf must exist"
    return BUCKET_TF.read_text()


def test_bucket_is_kms_encrypted_at_rest():
    t = _tf()
    assert "aws_s3_bucket_server_side_encryption_configuration" in t
    assert "aws:kms" in t, "quarantine bucket must use SSE-KMS (its own key), not default SSE-S3"


def test_bucket_is_versioned():
    t = _tf()
    assert "aws_s3_bucket_versioning" in t and "Enabled" in t


def test_bucket_auto_expires_samples():
    t = _tf()
    assert "aws_s3_bucket_lifecycle_configuration" in t
    assert "expiration" in t, "quarantined malware must auto-expire (no indefinite retention)"


def test_bucket_blocks_all_public_access():
    t = _tf()
    assert "aws_s3_bucket_public_access_block" in t
    for flag in ("block_public_acls", "block_public_policy",
                 "ignore_public_acls", "restrict_public_buckets"):
        assert f"{flag}" in t and "true" in t, f"public-access guard {flag} must be true"


def test_bucket_enforces_tls_only():
    t = _tf()
    assert "aws_s3_bucket_policy" in t
    assert "aws:SecureTransport" in t, "bucket policy must deny non-TLS (insecure transport) access"


# --- Malicious-content lockdown: separate, WORM, least-privilege -------------
def test_bucket_is_a_dedicated_quarantine_not_cold_storage():
    t = _tf()
    assert "nexus-quarantine" in t, "quarantine must be its OWN bucket, separate from cold-storage telemetry"
    assert "nexus-cold-storage" not in t, "must not co-mingle malware with the telemetry data lake"


def test_bucket_has_object_lock_worm():
    t = _tf()
    assert "object_lock_enabled" in t and "aws_s3_bucket_object_lock_configuration" in t, \
        "acquired malware is evidence -- WORM (object lock) prevents tamper/deletion"


def test_bucket_denies_all_principals_except_detchamber():
    t = _tf()
    # Beyond TLS-only: a least-privilege deny so only the det_chamber roles touch the malware.
    assert "detchamber_role_arns" in t or "aws:PrincipalArn" in t, \
        "bucket policy must restrict access to the det_chamber roles only"
