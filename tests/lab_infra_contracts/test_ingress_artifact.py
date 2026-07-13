"""
Lab infra -- core_ingress artifact acquisition endpoint (Phase 8).

Endpoints transmit acquired files OUTBOUND over HTTPS to ingress (they can't be
reached inbound). core_ingress must expose:
  * GET  /api/v1/tasks    -- the on-host agent polls for pending acquisition tasks
  * POST /api/v1/artifact -- receives the zipped artifact (JWT + HMAC), verifies
    the chain-of-custody sha256, streams it to the quarantine bucket, and publishes
    nexus.detonation.intake.
"""

from pathlib import Path

INGRESS = (Path(__file__).resolve().parents[2] / "services" / "core_ingress"
           / "src" / "main.rs").read_text()


def test_artifact_route_registered():
    assert "/api/v1/artifact" in INGRESS, "ingress must expose the artifact upload endpoint"


def test_tasks_poll_route_registered():
    assert "/api/v1/tasks" in INGRESS, "ingress must expose the agent task-poll endpoint"


def test_artifact_handler_requires_jwt():
    # Same JWT gate as telemetry.
    assert "validate_token" in INGRESS


def test_artifact_handler_verifies_hmac_and_custody():
    # HMAC integrity over the body + the sha256 chain-of-custody header.
    assert "X-Artifact-HMAC" in INGRESS or "ARTIFACT_HMAC" in INGRESS
    assert "X-Artifact-SHA256" in INGRESS or "ARTIFACT_SHA256" in INGRESS


def test_artifact_relays_to_detonation_intake():
    # Ingress authenticates + relays over NATS; intake_service (boto3) persists the
    # artifact to the quarantine bucket and detonates.
    assert "nexus.detonation.intake" in INGRESS, \
        "after verifying the artifact, ingress must publish the detonation intake request"
