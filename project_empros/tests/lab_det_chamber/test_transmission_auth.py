"""
Lab det_chamber -- transmission authentication.

The Det Chamber rides the platform's default-deny NATS broker, so its services
must authenticate (NATS_USER/NATS_PASS as detchamber_node) -- a bare connect is
rejected. The artifact path stays integrity-protected by the chain-of-custody
sha256 manifest (the content-addressed analog of the sensor HMAC), and the
quarantine bucket upload uses S3/MinIO credentials.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INTAKE = REPO / "det_chamber" / "intake" / "intake_service.py"
ACQUIRE_WORKER = REPO / "det_chamber" / "agents" / "acquire_worker.py"


def test_intake_authenticates_to_nats():
    t = INTAKE.read_text()
    assert "NATS_USER" in t and "NATS_PASS" in t, "intake must read NATS credentials"
    assert "nats.connect(" in t
    # never connect without passing credentials
    assert "nats.connect(nats_url)" not in t, "bare connect against a default-deny broker"


def test_acquire_worker_authenticates_to_nats():
    t = ACQUIRE_WORKER.read_text()
    assert "NATS_USER" in t and "NATS_PASS" in t, "acquire worker must read NATS credentials"
    assert "nats.connect(" in t
    assert "nats.connect(nats_url)" not in t, "bare connect against a default-deny broker"


def test_intake_still_verifies_custody_for_integrity():
    # Auth on the wire does not replace content integrity -- custody verification
    # stays the artifact's integrity control.
    t = INTAKE.read_text()
    assert "verify_custody" in t
