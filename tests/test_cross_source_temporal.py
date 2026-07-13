"""
test_cross_source_temporal.py -- Offline contracts for the cross-source temporal corpus

Validates both copies of the temporal staging script and both corpus_utils.py files.

Coverage:
  A. TOOL_CLASSES registry -- 10 classes (C-20), correct MITRE, generators callable
  B. Generator record shape -- messages list, classification, ttp_category, source_type
  C. TP/FP classification correctness -- TPs contain threat indicators, FPs don't
  D. Class: LinuxBeaconAfterExec -- linux_sentinel fields + C2 beacon
  E. Class: CloudLateralMovement -- azure_entraid + aws_cloudtrail IAM escalation
  F. S3_QUERIES -- all 10 classes present, no empty WHERE clauses
  G. corpus_utils.py sync -- mlops/corpus_templates copy has SENSOR_FIELD_ALIASES
     and _apply_aliases(), fmt_edr() applies aliases before _clean()
  H. Both staging scripts produce identical TOOL_CLASSES keys
  I. Class: AzureVMRunCommand -- azure_activity RunCommand + linux_sentinel exec
  J. Class: GCPSAKeyExport -- gcp_audit SA key creation + aws_cloudtrail OIDC pivot
  K. Class: RansomwarePreEncryption -- sysmon VSS deletion + network_tap staging
  L. Class: K8sLateralMovement -- linux_sentinel container exec + network_tap pod scan
  M. Class: PrivEscToCloudAPI -- sysmon lsass dump + azure_activity RBAC write
"""

import sys
import os
import json
import importlib.util as _ilu
from pathlib import Path

REPO = Path(__file__).parent.parent
MLOPS_SCRIPTS    = REPO / "mlops/scripts"
CORPUS_TEMPLATES = REPO / "mlops/corpus_templates"

sys.path.insert(0, str(MLOPS_SCRIPTS))

# ── Load mlops/scripts/stage_cross_source_temporal.py ────────────────────────
_spec = _ilu.spec_from_file_location(
    "stage_cross_source_temporal",
    str(MLOPS_SCRIPTS / "stage_cross_source_temporal.py"),
)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

TOOL_CLASSES = _mod.TOOL_CLASSES
S3_QUERIES   = _mod.S3_QUERIES
generate     = _mod.generate

# ── Load mlops/corpus_templates/cross_source_temporal.py ─────────────────────
_act_spec = _ilu.spec_from_file_location(
    "cross_source_temporal_act",
    str(CORPUS_TEMPLATES / "cross_source_temporal.py"),
)
_act_mod = _ilu.module_from_spec(_act_spec)
_act_spec.loader.exec_module(_act_mod)

# ── Load mlops/corpus_templates/corpus_utils.py ───────────────────────────────
_cu_spec = _ilu.spec_from_file_location(
    "corpus_utils_act",
    str(CORPUS_TEMPLATES / "corpus_utils.py"),
)
_cu_mod = _ilu.module_from_spec(_cu_spec)
_cu_spec.loader.exec_module(_cu_mod)


# ── A. TOOL_CLASSES registry ──────────────────────────────────────────────────

class TestToolClassesRegistry:

    def test_ten_classes_registered(self):
        assert len(TOOL_CLASSES) == 10

    def test_required_class_names_present(self):
        expected = {
            "LateralMovementPsExec", "C2CheckinAfterLOTL", "CredentialTheftExfil",
            "LinuxBeaconAfterExec", "CloudLateralMovement",
            "AzureVMRunCommand", "GCPSAKeyExport", "RansomwarePreEncryption",
            "K8sLateralMovement", "PrivEscToCloudAPI",
        }
        assert set(TOOL_CLASSES.keys()) == expected

    def test_each_class_has_mitre_and_two_generators(self):
        for name, (mitre, tp_fn, fp_fn) in TOOL_CLASSES.items():
            assert isinstance(mitre, list) and len(mitre) >= 1, f"{name}: empty MITRE list"
            assert callable(tp_fn), f"{name}: tp_fn not callable"
            assert callable(fp_fn), f"{name}: fp_fn not callable"

    def test_linux_beacon_mitre_includes_script_execution(self):
        mitre, _, _ = TOOL_CLASSES["LinuxBeaconAfterExec"]
        assert any("T1059" in t for t in mitre)

    def test_cloud_lateral_mitre_includes_cloud_accounts(self):
        mitre, _, _ = TOOL_CLASSES["CloudLateralMovement"]
        assert "T1078.004" in mitre

    def test_azure_runcommand_mitre_includes_t1651(self):
        mitre, _, _ = TOOL_CLASSES["AzureVMRunCommand"]
        assert "T1651" in mitre

    def test_gcp_sa_key_mitre_includes_t1552(self):
        mitre, _, _ = TOOL_CLASSES["GCPSAKeyExport"]
        assert "T1552.001" in mitre

    def test_ransomware_mitre_includes_t1490(self):
        mitre, _, _ = TOOL_CLASSES["RansomwarePreEncryption"]
        assert "T1490" in mitre

    def test_k8s_lateral_mitre_includes_t1609(self):
        mitre, _, _ = TOOL_CLASSES["K8sLateralMovement"]
        assert "T1609" in mitre

    def test_privesc_cloud_mitre_includes_t1134(self):
        mitre, _, _ = TOOL_CLASSES["PrivEscToCloudAPI"]
        assert "T1134.001" in mitre


# ── B. Generator record shape ─────────────────────────────────────────────────

class TestRecordShape:

    def _gen(self, name, n_tp=2, n_fp=1):
        return generate(name, n_tp, n_fp)

    def test_lateral_movement_generates_records(self):
        recs = self._gen("LateralMovementPsExec")
        assert len(recs) == 3

    def test_linux_beacon_generates_records(self):
        recs = self._gen("LinuxBeaconAfterExec")
        assert len(recs) == 3

    def test_cloud_lateral_generates_records(self):
        recs = self._gen("CloudLateralMovement")
        assert len(recs) == 3

    def test_record_has_required_keys(self):
        for cls in TOOL_CLASSES:
            for rec in generate(cls, 1, 1):
                for key in ("ttp_category", "tool_class", "mitre_techniques",
                            "source_type", "vector_name", "classification", "messages", "event_id"):
                    assert key in rec, f"{cls}: missing key {key!r}"

    def test_messages_is_three_turn_list(self):
        for cls in TOOL_CLASSES:
            for rec in generate(cls, 1, 1):
                msgs = rec["messages"]
                assert isinstance(msgs, list) and len(msgs) == 3
                roles = [m["role"] for m in msgs]
                assert roles == ["system", "user", "assistant"], f"{cls}: bad roles {roles}"

    def test_source_type_is_multi_sensor(self):
        for cls in TOOL_CLASSES:
            for rec in generate(cls, 1, 0):
                assert rec["source_type"] == "multi_sensor"

    def test_vector_name_is_c2_math(self):
        for cls in TOOL_CLASSES:
            for rec in generate(cls, 1, 0):
                assert rec["vector_name"] == "c2_math"

    def test_ttp_category_is_cross_source_temporal(self):
        for cls in TOOL_CLASSES:
            for rec in generate(cls, 1, 0):
                assert rec["ttp_category"] == "CrossSourceTemporal"


# ── C. TP/FP classification correctness ──────────────────────────────────────

class TestClassificationCorrectness:

    def test_tp_records_classified_true_positive(self):
        for cls in TOOL_CLASSES:
            recs = generate(cls, 3, 0)
            for r in recs:
                assert r["classification"] == "true_positive", f"{cls} TP record misclassified"

    def test_fp_records_classified_false_positive(self):
        for cls in TOOL_CLASSES:
            recs = generate(cls, 0, 2)
            for r in recs:
                assert r["classification"] == "false_positive", f"{cls} FP record misclassified"

    def test_tp_assistant_says_true_positive(self):
        for cls in TOOL_CLASSES:
            for rec in generate(cls, 2, 0):
                asst = rec["messages"][2]["content"]
                assert "TRUE POSITIVE" in asst, f"{cls} TP missing TRUE POSITIVE in CoT"

    def test_fp_assistant_says_false_positive(self):
        for cls in TOOL_CLASSES:
            for rec in generate(cls, 0, 2):
                asst = rec["messages"][2]["content"]
                assert "FALSE POSITIVE" in asst, f"{cls} FP missing FALSE POSITIVE in CoT"

    def test_tp_contains_contain_action(self):
        for cls in TOOL_CLASSES:
            for rec in generate(cls, 2, 0):
                asst = rec["messages"][2]["content"]
                assert "contain" in asst.lower() or "isolate" in asst.lower() or \
                       "block" in asst.lower() or "revoke" in asst.lower(), \
                    f"{cls} TP CoT missing remediation action"

    def test_fp_contains_dismiss_action(self):
        for cls in TOOL_CLASSES:
            for rec in generate(cls, 0, 2):
                asst = rec["messages"][2]["content"]
                assert "RECOMMENDED_ACTION: dismiss" in asst, \
                    f"{cls} FP CoT missing RECOMMENDED_ACTION: dismiss"


# ── D. LinuxBeaconAfterExec specifics ────────────────────────────────────────

class TestLinuxBeaconAfterExec:

    def setup_method(self):
        self._tps = generate("LinuxBeaconAfterExec", 5, 0)
        self._fps = generate("LinuxBeaconAfterExec", 0, 3)

    def test_tp_user_prompt_contains_linux_sentinel(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "linux_sentinel" in user_text

    def test_tp_user_prompt_contains_network_tap(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "network_tap" in user_text

    def test_tp_prompt_contains_tmp_path(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "/tmp/" in user_text or "/var/tmp/" in user_text

    def test_tp_prompt_contains_cert_self_signed(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "cert_self_signed=True" in user_text

    def test_tp_cot_references_implant_or_c2(self):
        for rec in self._tps:
            asst = rec["messages"][2]["content"].lower()
            assert "implant" in asst or "c2" in asst or "beacon" in asst

    def test_fp_prompt_contains_opt_path(self):
        for rec in self._fps:
            user_text = rec["messages"][1]["content"]
            assert "/opt/" in user_text

    def test_fp_prompt_contains_uid_998(self):
        for rec in self._fps:
            user_text = rec["messages"][1]["content"]
            assert "uid=998" in user_text

    def test_mitre_in_tp_cot(self):
        for rec in self._tps:
            asst = rec["messages"][2]["content"]
            assert "T1059" in asst

    def test_records_reference_linux_interpreter(self):
        all_text = " ".join(r["messages"][1]["content"] for r in self._tps)
        assert any(interp in all_text for interp in ("python3", "bash", "perl"))


# ── E. CloudLateralMovement specifics ────────────────────────────────────────

class TestCloudLateralMovement:

    def setup_method(self):
        self._tps = generate("CloudLateralMovement", 5, 0)
        self._fps = generate("CloudLateralMovement", 0, 3)

    def test_tp_user_prompt_contains_azure_entraid(self):
        for rec in self._tps:
            assert "azure_entraid" in rec["messages"][1]["content"]

    def test_tp_user_prompt_contains_aws_cloudtrail(self):
        for rec in self._tps:
            assert "aws_cloudtrail" in rec["messages"][1]["content"]

    def test_tp_prompt_contains_impossible_travel(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "impossible_travel" in user_text

    def test_tp_prompt_contains_iam_escalation_event(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "AttachUserPolicy" in user_text

    def test_tp_prompt_contains_admin_policy(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert any(p in user_text for p in (
                "AdministratorAccess", "PowerUserAccess", "IAMFullAccess"
            ))

    def test_tp_cot_references_credential_compromise(self):
        for rec in self._tps:
            asst = rec["messages"][2]["content"].lower()
            assert "credential" in asst or "compromise" in asst or "stolen" in asst

    def test_tp_mitre_present_in_cot(self):
        for rec in self._tps:
            asst = rec["messages"][2]["content"]
            assert "T1078.004" in asst

    def test_fp_prompt_references_azure_ad_connect(self):
        for rec in self._fps:
            user_text = rec["messages"][1]["content"]
            assert "Active Directory Connect" in user_text or "svc_migration" in user_text

    def test_fp_uses_read_only_aws_action(self):
        for rec in self._fps:
            user_text = rec["messages"][1]["content"]
            assert "ListAttachedUserPolicies" in user_text


# ── F. S3_QUERIES completeness ────────────────────────────────────────────────

class TestS3Queries:

    def test_all_ten_classes_have_s3_query(self):
        for cls in TOOL_CLASSES:
            assert cls in S3_QUERIES, f"Missing S3_QUERY for {cls}"

    def test_no_empty_where_clauses(self):
        for cls, q in S3_QUERIES.items():
            assert q.get("where"), f"{cls}: empty WHERE clause"

    def test_linux_beacon_query_uses_linux_sentinel(self):
        assert S3_QUERIES["LinuxBeaconAfterExec"]["sensor"] == "linux_sentinel"

    def test_cloud_lateral_query_uses_azure_entraid(self):
        assert S3_QUERIES["CloudLateralMovement"]["sensor"] == "azure_entraid"

    def test_linux_beacon_where_uses_comm_field(self):
        where = S3_QUERIES["LinuxBeaconAfterExec"]["where"]
        assert "comm" in where

    def test_linux_beacon_where_uses_tmp_path(self):
        where = S3_QUERIES["LinuxBeaconAfterExec"]["where"]
        assert "/tmp/" in where

    def test_cloud_lateral_where_uses_result_type(self):
        where = S3_QUERIES["CloudLateralMovement"]["where"]
        assert "result_type" in where

    def test_cloud_lateral_where_uses_sign_in(self):
        where = S3_QUERIES["CloudLateralMovement"]["where"]
        assert "Sign-in" in where

    def test_azure_runcommand_uses_azure_activity(self):
        assert S3_QUERIES["AzureVMRunCommand"]["sensor"] == "azure_activity"

    def test_azure_runcommand_where_uses_runcommand(self):
        where = S3_QUERIES["AzureVMRunCommand"]["where"]
        assert "runCommand" in where

    def test_gcp_sa_key_uses_gcp_audit(self):
        assert S3_QUERIES["GCPSAKeyExport"]["sensor"] == "gcp_audit"

    def test_gcp_sa_key_where_uses_createkey_method(self):
        where = S3_QUERIES["GCPSAKeyExport"]["where"]
        assert "CreateServiceAccountKey" in where

    def test_ransomware_uses_sysmon_sensor(self):
        assert S3_QUERIES["RansomwarePreEncryption"]["sensor"] == "sysmon_sensor"

    def test_ransomware_where_uses_vssadmin_or_wmic(self):
        where = S3_QUERIES["RansomwarePreEncryption"]["where"]
        assert "vssadmin" in where or "wmic" in where

    def test_k8s_lateral_uses_linux_sentinel(self):
        assert S3_QUERIES["K8sLateralMovement"]["sensor"] == "linux_sentinel"

    def test_k8s_lateral_where_uses_t1609(self):
        where = S3_QUERIES["K8sLateralMovement"]["where"]
        assert "T1609" in where

    def test_privesc_cloud_uses_sysmon_sensor(self):
        assert S3_QUERIES["PrivEscToCloudAPI"]["sensor"] == "sysmon_sensor"

    def test_privesc_cloud_where_uses_lsass(self):
        where = S3_QUERIES["PrivEscToCloudAPI"]["where"]
        assert "lsass" in where


# ── G. corpus_utils.py sync (mlops/corpus_templates copy) ────────────────────

class TestCorpusUtilsSync:

    def test_sensor_field_aliases_present(self):
        assert hasattr(_cu_mod, "SENSOR_FIELD_ALIASES"), \
            "mlops/corpus_templates/corpus_utils.py missing SENSOR_FIELD_ALIASES"

    def test_apply_aliases_present(self):
        assert hasattr(_cu_mod, "_apply_aliases"), \
            "mlops/corpus_templates/corpus_utils.py missing _apply_aliases()"

    def test_windows_deepsensor_aliases_match_mlops(self):
        from corpus_utils import SENSOR_FIELD_ALIASES as mlops_aliases
        act_aliases = _cu_mod.SENSOR_FIELD_ALIASES
        assert act_aliases["windows_deepsensor"] == mlops_aliases["windows_deepsensor"]

    def test_linux_c2_aliases_match_mlops(self):
        from corpus_utils import SENSOR_FIELD_ALIASES as mlops_aliases
        act_aliases = _cu_mod.SENSOR_FIELD_ALIASES
        assert act_aliases.get("linux_c2") == mlops_aliases.get("linux_c2")

    def test_apply_aliases_maps_path_to_image(self):
        result = _cu_mod._apply_aliases({"path": "cmd.exe", "pid": 1234}, "windows_deepsensor")
        assert "Image" in result
        assert result["Image"] == "cmd.exe"
        assert "path" not in result

    def test_apply_aliases_maps_command_line_to_CommandLine(self):
        result = _cu_mod._apply_aliases({"command_line": "foo -bar", "pid": 1}, "windows_deepsensor")
        assert result["CommandLine"] == "foo -bar"
        assert "command_line" not in result

    def test_apply_aliases_no_op_for_unknown_sensor(self):
        payload = {"comm": "bash", "pid": 100}
        result = _cu_mod._apply_aliases(payload, "sysmon_sensor")
        assert result == payload

    def test_fmt_edr_accepts_live_sensor_field_names(self):
        result = _cu_mod.fmt_edr("HOST-01", {
            "path": "C:\\Temp\\beacon.exe",
            "command_line": "beacon.exe -silent",
            "parent_pid": 5678,
            "destination_ip": "185.220.101.1",
        })
        assert "windows_deepsensor" in result
        assert "HOST-01" in result
        assert "beacon.exe" in result

    def test_fmt_edr_canonical_fields_still_work(self):
        result = _cu_mod.fmt_edr("HOST-02", {
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ppid": 1234,
        })
        assert "cmd.exe" in result


# ── H. Both staging scripts have identical TOOL_CLASSES keys ─────────────────

class TestBothScriptsSynced:

    def test_tool_classes_keys_match_between_copies(self):
        mlops_keys = set(TOOL_CLASSES.keys())
        act_keys   = set(_act_mod.TOOL_CLASSES.keys())
        assert mlops_keys == act_keys, \
            f"TOOL_CLASSES mismatch: mlops={mlops_keys - act_keys} missing from ACT, " \
            f"ACT={act_keys - mlops_keys} missing from mlops"

    def test_s3_query_keys_match_between_copies(self):
        mlops_keys = set(S3_QUERIES.keys())
        act_keys   = set(_act_mod.S3_QUERIES.keys())
        assert mlops_keys == act_keys

    def test_mitre_techniques_match_between_copies(self):
        for cls in TOOL_CLASSES:
            mlops_mitre = TOOL_CLASSES[cls][0]
            act_mitre   = _act_mod.TOOL_CLASSES[cls][0]
            assert sorted(mlops_mitre) == sorted(act_mitre), \
                f"{cls}: MITRE mismatch between copies"


# ── I. AzureVMRunCommand specifics ───────────────────────────────────────────

class TestAzureVMRunCommand:

    def setup_method(self):
        self._tps = generate("AzureVMRunCommand", 5, 0)
        self._fps = generate("AzureVMRunCommand", 0, 3)

    def test_tp_prompt_contains_azure_activity(self):
        for rec in self._tps:
            assert "azure_activity" in rec["messages"][1]["content"]

    def test_tp_prompt_contains_linux_sentinel(self):
        for rec in self._tps:
            assert "linux_sentinel" in rec["messages"][1]["content"]

    def test_tp_prompt_contains_runcommand(self):
        for rec in self._tps:
            assert "runCommand" in rec["messages"][1]["content"]

    def test_tp_prompt_contains_c2_callback(self):
        for rec in self._tps:
            assert "network_tap" in rec["messages"][1]["content"]

    def test_tp_cot_references_implant_or_c2(self):
        for rec in self._tps:
            asst = rec["messages"][2]["content"].lower()
            assert "implant" in asst or "c2" in asst or "callback" in asst

    def test_tp_mitre_t1651_in_cot(self):
        for rec in self._tps:
            assert "T1651" in rec["messages"][2]["content"]

    def test_fp_prompt_contains_change_ticket(self):
        for rec in self._fps:
            assert "change_ticket" in rec["messages"][1]["content"]

    def test_fp_cot_is_dismiss(self):
        for rec in self._fps:
            assert "RECOMMENDED_ACTION: dismiss" in rec["messages"][2]["content"]


# ── J. GCPSAKeyExport specifics ──────────────────────────────────────────────

class TestGCPSAKeyExport:

    def setup_method(self):
        self._tps = generate("GCPSAKeyExport", 5, 0)
        self._fps = generate("GCPSAKeyExport", 0, 3)

    def test_tp_prompt_contains_gcp_audit(self):
        for rec in self._tps:
            assert "gcp_audit" in rec["messages"][1]["content"]

    def test_tp_prompt_contains_aws_cloudtrail(self):
        for rec in self._tps:
            assert "aws_cloudtrail" in rec["messages"][1]["content"]

    def test_tp_prompt_contains_user_managed_key(self):
        for rec in self._tps:
            assert "USER_MANAGED" in rec["messages"][1]["content"]

    def test_tp_prompt_contains_assumerolewithwebidentity(self):
        for rec in self._tps:
            assert "AssumeRoleWithWebIdentity" in rec["messages"][1]["content"]

    def test_tp_cot_references_cross_cloud_pivot(self):
        for rec in self._tps:
            asst = rec["messages"][2]["content"].lower()
            assert "pivot" in asst or "cross-cloud" in asst or "lateral" in asst

    def test_tp_mitre_t1552_in_cot(self):
        for rec in self._tps:
            assert "T1552.001" in rec["messages"][2]["content"]

    def test_fp_prompt_contains_ci_cd_context(self):
        for rec in self._fps:
            user_text = rec["messages"][1]["content"]
            assert "change_ticket" in user_text or "CiCd" in user_text

    def test_fp_cot_is_dismiss(self):
        for rec in self._fps:
            assert "RECOMMENDED_ACTION: dismiss" in rec["messages"][2]["content"]


# ── K. RansomwarePreEncryption specifics ─────────────────────────────────────

class TestRansomwarePreEncryption:

    def setup_method(self):
        self._tps = generate("RansomwarePreEncryption", 5, 0)
        self._fps = generate("RansomwarePreEncryption", 0, 3)

    def test_tp_prompt_contains_sysmon_vssadmin(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "sysmon_sensor" in user_text
            assert "vssadmin" in user_text.lower() or "shadowcopy" in user_text.lower()

    def test_tp_prompt_contains_network_tap(self):
        for rec in self._tps:
            assert "network_tap" in rec["messages"][1]["content"]

    def test_tp_prompt_has_high_entropy_download(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "entropy" in user_text

    def test_tp_cot_references_ransomware_or_recovery(self):
        for rec in self._tps:
            asst = rec["messages"][2]["content"].lower()
            assert "ransomware" in asst or "recovery" in asst or "vss" in asst

    def test_tp_mitre_t1490_in_cot(self):
        for rec in self._tps:
            assert "T1490" in rec["messages"][2]["content"]

    def test_fp_prompt_uses_oldest_flag(self):
        for rec in self._fps:
            assert "/oldest" in rec["messages"][1]["content"]

    def test_fp_prompt_references_backup_tool(self):
        for rec in self._fps:
            user_text = rec["messages"][1]["content"]
            assert any(t in user_text for t in ("Veeam", "Commvault", "Acronis"))

    def test_fp_cot_is_dismiss(self):
        for rec in self._fps:
            assert "RECOMMENDED_ACTION: dismiss" in rec["messages"][2]["content"]


# ── L. K8sLateralMovement specifics ─────────────────────────────────────────

class TestK8sLateralMovement:

    def setup_method(self):
        self._tps = generate("K8sLateralMovement", 5, 0)
        self._fps = generate("K8sLateralMovement", 0, 3)

    def test_tp_prompt_contains_linux_sentinel_container_exec(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "linux_sentinel" in user_text
            assert "container exec" in user_text or "T1609" in user_text

    def test_tp_prompt_contains_network_tap_scan(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "network_tap" in user_text

    def test_tp_prompt_uid_is_root(self):
        for rec in self._tps:
            assert "uid=0" in rec["messages"][1]["content"]

    def test_tp_prompt_high_packet_count(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "packets_src=412" in user_text

    def test_tp_cot_references_lateral_movement_or_pivot(self):
        for rec in self._tps:
            asst = rec["messages"][2]["content"].lower()
            assert "lateral" in asst or "pivot" in asst or "scan" in asst

    def test_tp_mitre_t1609_in_cot(self):
        for rec in self._tps:
            assert "T1609" in rec["messages"][2]["content"]

    def test_fp_prompt_contains_prometheus(self):
        for rec in self._fps:
            assert "prometheus" in rec["messages"][1]["content"].lower()

    def test_fp_prompt_uid_is_non_root(self):
        for rec in self._fps:
            assert "uid=1000" in rec["messages"][1]["content"]

    def test_fp_cot_is_dismiss(self):
        for rec in self._fps:
            assert "RECOMMENDED_ACTION: dismiss" in rec["messages"][2]["content"]


# ── M. PrivEscToCloudAPI specifics ───────────────────────────────────────────

class TestPrivEscToCloudAPI:

    def setup_method(self):
        self._tps = generate("PrivEscToCloudAPI", 5, 0)
        self._fps = generate("PrivEscToCloudAPI", 0, 3)

    def test_tp_prompt_contains_sysmon_lsass_dump(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "sysmon_sensor" in user_text
            assert "lsass" in user_text

    def test_tp_prompt_has_full_access_granted(self):
        for rec in self._tps:
            assert "0x1fffff" in rec["messages"][1]["content"]

    def test_tp_prompt_contains_azure_activity_rbac_write(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert "azure_activity" in user_text
            assert "roleAssignments/write" in user_text

    def test_tp_prompt_assigns_high_privilege_role(self):
        for rec in self._tps:
            user_text = rec["messages"][1]["content"]
            assert any(r in user_text for r in ("Owner", "Contributor", "User Access Administrator"))

    def test_tp_cot_references_credential_dump_or_escalation(self):
        for rec in self._tps:
            asst = rec["messages"][2]["content"].lower()
            assert "dump" in asst or "escalat" in asst or "token" in asst

    def test_tp_mitre_t1134_in_cot(self):
        for rec in self._tps:
            assert "T1134.001" in rec["messages"][2]["content"]

    def test_fp_prompt_low_access_rights(self):
        for rec in self._fps:
            assert "0x1000" in rec["messages"][1]["content"]

    def test_fp_prompt_assigns_reader_role(self):
        for rec in self._fps:
            assert "Reader" in rec["messages"][1]["content"]

    def test_fp_cot_is_dismiss(self):
        for rec in self._fps:
            assert "RECOMMENDED_ACTION: dismiss" in rec["messages"][2]["content"]
