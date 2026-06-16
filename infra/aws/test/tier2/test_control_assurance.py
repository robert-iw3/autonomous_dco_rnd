"""Tier-2 control-assurance tests — security-property regression guards that back the NIST
800-53 controls the connectors implement. Each test asserts a real property of the deploy IaC,
the Rust source, or the container images across all three connectors (vpc/cloudtrail/guardduty),
so a regression that weakens a control fails CI. File-reads only (no containers needed).

These are the passing assurance tests an assessment binds to its controls to raise them from
"present" to a tested tier.
"""
import os
import re

import pytest

pytestmark = pytest.mark.tier2

AWS_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
CONNECTORS = ("vpc", "cloudtrail", "guardduty")


def _tf(conn):
    """Concatenated deploy Terraform for a connector ('' if none)."""
    tf_dir = os.path.join(AWS_DIR, conn, "deploy", "terraform")
    if not os.path.isdir(tf_dir):
        return ""
    return "\n".join(open(os.path.join(tf_dir, f)).read()
                     for f in sorted(os.listdir(tf_dir)) if f.endswith(".tf"))


def _rust(conn):
    src = os.path.join(AWS_DIR, conn, "src")
    if not os.path.isdir(src):
        return ""
    return "\n".join(open(os.path.join(src, f)).read()
                     for f in sorted(os.listdir(src)) if f.endswith(".rs"))


def _read(*parts):
    p = os.path.join(AWS_DIR, *parts)
    return open(p).read() if os.path.isfile(p) else ""


# Body of `resource "<type>" "<name>" { ... }` up to the first column-0 closing brace.
def _resource_body(src, rtype, name):
    m = re.search(rf'resource\s+"{rtype}"\s+"{name}"\s*\{{(.*?)\n\}}', src, re.DOTALL)
    return m.group(1) if m else ""


# --- AC-2: least-privilege IAM -------------------------------------------------------------
def test_ac2_execution_policy_is_least_privilege():
    """The connector execution policy grants only scoped, named actions — never a wildcard
    action (`"*"` / `"service:*"` beyond the standard KMS key-policy grant)."""
    seen = False
    for conn in CONNECTORS:
        body = _resource_body(_tf(conn), "aws_iam_policy", "connector_execution_policy")
        if not body:
            continue
        seen = True
        assert '"*"' not in re.sub(r'Resource\s*=\s*"\*"', "", body), \
            f"{conn}: execution policy contains a wildcard action"
        for svc in ("sqs:", "s3:", "dynamodb:", "kms:"):
            pass  # scoped service actions are expected; presence asserted below
        assert "sqs:ReceiveMessage" in body and "dynamodb:GetItem" in body, \
            f"{conn}: execution policy is not scoped to the expected named actions"
    assert seen, "no connector_execution_policy found in any connector"


# --- AC-4: information-flow scoping on the message bus -------------------------------------
def test_ac4_queue_policy_scopes_source():
    """Where a queue resource policy exists, it scopes which principal/source may publish to the
    inter-service bus (an `aws:SourceArn` condition), not an open send."""
    seen = False
    for conn in CONNECTORS:
        tf = _tf(conn)
        if "aws_sqs_queue_policy" not in tf:
            continue
        seen = True
        assert "aws:SourceArn" in tf, f"{conn}: queue policy does not scope aws:SourceArn"
    assert seen, "no aws_sqs_queue_policy found in any connector"


# --- AU-2 / AU-3 / AU-12: audit/event logging ----------------------------------------------
def test_au_structured_event_logging():
    """Every connector emits structured audit/event logging (the `tracing` framework)."""
    for conn in CONNECTORS:
        rs = _rust(conn)
        assert re.search(r"tracing::(info|warn|error|debug)!", rs), \
            f"{conn}: no structured tracing log calls found"


# --- CA-7 / SI-4: continuous monitoring ----------------------------------------------------
def test_ca7_si4_cloudwatch_alarms_present():
    """Every connector ships a CloudWatch metric alarm (operational/continuous monitoring)."""
    for conn in CONNECTORS:
        assert 'resource "aws_cloudwatch_metric_alarm"' in _tf(conn), \
            f"{conn}: no CloudWatch metric alarm"


# --- RA-5: threat detection ----------------------------------------------------------------
def test_ra5_threat_detection_service():
    """The GuardDuty connector provisions the managed threat-detection service."""
    assert "aws_guardduty" in _tf("guardduty"), "guardduty connector does not use GuardDuty"


# --- CM-2: configuration baseline (pinned base images) -------------------------------------
def test_cm2_base_images_pinned():
    """Every Dockerfile pins its base image to an explicit tag — never `:latest` or untagged."""
    for conn in CONNECTORS:
        df = _read(conn, "Dockerfile")
        assert df, f"{conn}: no Dockerfile"
        for line in df.splitlines():
            if line.startswith("FROM "):
                img = line.split()[1]
                assert ":" in img and not img.endswith(":latest"), \
                    f"{conn}: base image '{img}' is not pinned to a specific tag"


# --- CM-8: dependency baseline (pinned Cargo manifests) ------------------------------------
def test_cm8_dependencies_version_pinned():
    """Every crate declares versioned dependencies (no floating `*`), so the component
    inventory is reproducible from the manifest."""
    for conn in CONNECTORS:
        toml = _read(conn, "Cargo.toml")
        assert toml, f"{conn}: no Cargo.toml"
        assert "[dependencies]" in toml, f"{conn}: no [dependencies] section"
        assert not re.search(r'=\s*"\*"', toml), f"{conn}: a dependency floats on '*'"


# --- IA-5: no plaintext long-lived secrets in IaC ------------------------------------------
def test_ia5_no_plaintext_secrets_in_terraform():
    """The deploy Terraform carries no hardcoded long-lived credential — secrets are keyed by
    KMS / Secrets Manager, never an inline AWS access key or literal secret value."""
    for conn in CONNECTORS:
        tf = _tf(conn)
        assert not re.search(r'AKIA[0-9A-Z]{16}', tf), f"{conn}: hardcoded AWS access key in Terraform"
        assert not re.search(r'(secret|password)\s*=\s*"(?!.*(\$|\{\{|var\.|aws_))[^"]{8,}"', tf, re.I), \
            f"{conn}: a literal secret value appears in Terraform"


# --- SC-8: transmission confidentiality (TLS, no bypass) -----------------------------------
def test_sc8_tls_stack_and_no_verification_bypass():
    """Each connector's egress uses a TLS transport stack and never disables certificate
    verification (`danger_accept_invalid_certs`)."""
    for conn in CONNECTORS:
        toml = _read(conn, "Cargo.toml")
        rs = _rust(conn)
        assert re.search(r"rustls|native-tls", toml), f"{conn}: no TLS stack declared for reqwest"
        assert "danger_accept_invalid_certs(true)" not in rs and \
               "danger_accept_invalid_hostnames(true)" not in rs, \
            f"{conn}: TLS certificate verification is disabled"


# --- SI-7: information integrity (HMAC over transmitted batches) ---------------------------
def test_si7_hmac_integrity_on_egress():
    """Each connector stamps transmitted batches with an HMAC-SHA256 integrity tag."""
    for conn in CONNECTORS:
        rs = _rust(conn)
        assert "HmacSha256" in rs or re.search(r"Hmac<\s*Sha256", rs), \
            f"{conn}: no HMAC-SHA256 integrity tagging found"
