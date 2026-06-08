"""
Tier-2 -- security-posture regression guards for the deploy/ IaC.
"""
import re
import shutil
import subprocess
import pytest
import iac_deploy_mirror as M
import _iac_parse as P

pytestmark = pytest.mark.tier2

class TestS3StorePosture:
    def test_every_bucket_has_full_public_access_block(self, tf_src, connector_name):
        buckets = [n for n, _ in P.iter_resources(tf_src, "aws_s3_bucket")]
        pabs = list(P.iter_resources(tf_src, "aws_s3_bucket_public_access_block"))
        assert buckets, f"{connector_name}: no S3 bucket found in deploy terraform"
        assert len(pabs) >= len(buckets), (
            f"{connector_name}: {len(buckets)} bucket(s) but only {len(pabs)} public_access_block(s)"
        )
        for name, body in pabs:
            for flag in ("block_public_acls", "block_public_policy",
                         "ignore_public_acls", "restrict_public_buckets"):
                assert P.scalar(body, flag) == "true", f"{connector_name}: {name}.{flag} != true"

    def test_data_bucket_encrypted_with_cmk(self, tf_src, connector_name):
        sse = list(P.iter_resources(tf_src, "aws_s3_bucket_server_side_encryption_configuration"))
        assert sse, f"{connector_name}: no SSE configuration on any bucket"
        # The primary telemetry bucket must use the CMK (aws:kms + key ref).
        cmk = [b for _, b in sse if P.scalar(b, "sse_algorithm") == M.POSTURE["s3_sse_algorithm"]
               and M.POSTURE["s3_sse_cmk_ref"] in b]
        assert cmk, f"{connector_name}: no bucket encrypted with the Nexus CMK ({M.POSTURE['s3_sse_cmk_ref']})"

    def test_lifecycle_present(self, tf_src, connector_name):
        assert list(P.iter_resources(tf_src, "aws_s3_bucket_lifecycle_configuration")), \
            f"{connector_name}: no S3 lifecycle configuration"

class TestKmsPosture:
    def test_every_key_has_rotation_enabled(self, tf_src, connector_name):
        keys = list(P.iter_resources(tf_src, "aws_kms_key"))
        assert keys, f"{connector_name}: no KMS key in deploy terraform"
        for name, body in keys:
            assert P.scalar(body, "enable_key_rotation") == M.POSTURE["kms_key_rotation_enabled"], \
                f"{connector_name}: {name} rotation not enabled"

class TestSqsPosture:
    def test_all_queues_including_dlq_are_kms_encrypted(self, tf_src, connector_name):
        """The original VPC DLQ was unencrypted while the main queue was -- a
        real gap (CKV_AWS_27). Every queue, DLQ included, must carry the CMK."""
        queues = list(P.iter_resources(tf_src, "aws_sqs_queue"))
        assert queues, f"{connector_name}: no SQS queue found"
        for name, body in queues:
            assert "kms_master_key_id" in body and "aws_kms_key.nexus_key.arn" in body, \
                f"{connector_name}: queue {name} is not KMS-encrypted with the CMK"

    def test_processing_queue_has_bounded_dlq_redrive(self, tf_src, connector_name):
        redrive = [(n, b) for n, b in P.iter_resources(tf_src, "aws_sqs_queue")
                   if "deadLetterTargetArn" in b]
        assert redrive, f"{connector_name}: no queue declares a DLQ redrive policy"
        for name, body in redrive:
            assert P.scalar(body, "maxReceiveCount") == M.POSTURE["sqs_redrive_max_receive_count"], \
                f"{connector_name}: {name} redrive maxReceiveCount != {M.POSTURE['sqs_redrive_max_receive_count']}"

class TestDynamoPosture:
    def test_metadata_tables_encrypted_and_pitr(self, tf_src, connector_name):
        """Real gap the first run surfaced: tables had neither CMK encryption
        (CKV_AWS_119) nor point-in-time recovery (CKV_AWS_28)."""
        tables = list(P.iter_resources(tf_src, "aws_dynamodb_table"))
        assert tables, f"{connector_name}: no DynamoDB table found"
        for name, body in tables:
            assert "server_side_encryption" in body and "kms_key_arn" in body, \
                f"{connector_name}: table {name} not CMK-encrypted"
            assert re.search(r"point_in_time_recovery\s*\{[^}]*enabled\s*=\s*true", body, re.DOTALL), \
                f"{connector_name}: table {name} has no point-in-time recovery"

class TestOrchestratorPosture:
    """Only the vpc stack ships the EventBridge->Lambda orchestrator; skip where
    absent rather than assuming every connector has one."""
    def test_eventbridge_rule_targets_an_event(self, tf_src, connector_name):
        rules = list(P.iter_resources(tf_src, "aws_cloudwatch_event_rule"))
        if not rules:
            pytest.skip(f"{connector_name}: no EventBridge rule in this stack")
        assert any("eventName" in b or "detail-type" in b for _, b in rules), \
            f"{connector_name}: EventBridge rule has no event pattern"

    def test_lambda_is_hardened(self, tf_src, connector_name):
        lambdas = list(P.iter_resources(tf_src, "aws_lambda_function"))
        if not lambdas:
            pytest.skip(f"{connector_name}: no Lambda in this stack")
        for name, body in lambdas:
            assert P.scalar(body, "runtime"), f"{connector_name}: {name} runtime not pinned"
            assert "tracing_config" in body, f"{connector_name}: {name} has no X-Ray tracing"
            assert "dead_letter_config" in body, f"{connector_name}: {name} has no DLQ"
            assert "kms_key_arn" in body, f"{connector_name}: {name} env vars not CMK-encrypted"

class TestPolicyScanners:
    def test_checkov_enforces_all_but_documented_na(self, tf_dir, connector_name):
        if not shutil.which("checkov"):
            pytest.skip("checkov not installed (present in the tier2 container)")
        cmd = ["checkov", "-d", tf_dir, "--quiet", "--compact",
               "--framework", "terraform", "-o", "cli",
               "--skip-check", ",".join(sorted(M.CHECKOV_SKIP))]
        r = subprocess.run(cmd, capture_output=True, text=True)
        assert r.returncode == 0, (
            f"{connector_name}: checkov found real (non-N/A) findings on {tf_dir}.\n"
            f"Documented N/A skips: {sorted(M.CHECKOV_SKIP)}\n{r.stdout[-3000:]}"
        )

    def test_cfn_lint_passes_on_stackset_template(self, cfn_file, connector_name):
        if not shutil.which("cfn-lint"):
            pytest.skip("cfn-lint not installed (present in the tier2 container)")
        r = subprocess.run(["cfn-lint", cfn_file], capture_output=True, text=True)
        assert r.returncode == 0, (
            f"{connector_name}: cfn-lint failed on {cfn_file}\n{r.stdout}\n{r.stderr}"
        )