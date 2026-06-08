"""
Tier-2 -- IaC <-> connector runtime-contract conformance.
"""
import pytest
import iac_deploy_mirror as M
import aws_connectors_logic_mirror as CM  # tier0 connector mirror (on sys.path via root conftest)
import _iac_parse as P

pytestmark = pytest.mark.tier2

class TestIamGrantsCoverConnectorRuntime:
    def test_policy_grants_every_required_runtime_action(self, tf_src, connector_name):
        granted = P.iam_allowed_actions(tf_src, "connector_execution_policy")
        assert granted, f"{connector_name}: connector_execution_policy not found"
        missing = M.REQUIRED_RUNTIME_ACTIONS - granted
        assert not missing, f"{connector_name}: policy missing runtime actions {sorted(missing)}"

    def test_no_unexpected_actions(self, tf_src, connector_name):
        granted = P.iam_allowed_actions(tf_src, "connector_execution_policy")
        unexpected = granted - M.REQUIRED_RUNTIME_ACTIONS - M.KNOWN_OVERGRANTS
        assert not unexpected, f"{connector_name}: un-mirrored actions {sorted(unexpected)}"

    def test_each_statement_scoped_to_a_resource_this_stack_owns(self, tf_src, connector_name):
        """Name-independent least-privilege check: every statement Resource must
        resolve to a concrete resource the stack defines -- never '*', and never
        a dangling reference."""
        defined = P.resource_addresses(tf_src)
        stmts = P.iam_policy_statements(tf_src, "connector_execution_policy")
        assert stmts, f"{connector_name}: no statements parsed"
        for actions, resources in stmts:
            for resource in resources:
                addr = P.ref_to_address(resource)
                assert addr is not None, f"{connector_name}: wildcard/unscoped Resource on {actions}"
                assert addr in defined, (
                    f"{connector_name}: {actions} scoped to {addr!r}, "
                    f"which is not a resource defined in this stack"
                )

class TestIngestFormatMatchesConnector:
    def test_notification_suffix_matches_connector_source_format(self, tf_src, connector_name):
        """The bucket notification filter_suffix is the *source* log format this
        connector ingests (per-connector: .parquet/.json.gz/.jsonl.gz) -- NOT the
        Parquet it re-emits to Nexus. (Conflating the two was wrong in the first
        cut: it only coincidentally held for vpc.)"""
        profile = M.CONNECTOR_PROFILE.get(connector_name)
        if not profile:
            pytest.skip(f"{connector_name}: no profile")
        suffix = P.s3_notification_suffix(tf_src)
        assert suffix == profile["source_suffix"], (
            f"{connector_name}: notification filters {suffix!r}, "
            f"expected source format {profile['source_suffix']!r}"
        )

    def test_connector_egress_is_still_parquet(self):
        """Independent fact (not tied to the ingest suffix): the connector's
        egress to Nexus is Parquet. Guards against the tier0 contract drifting."""
        assert CM.CONTENT_TYPE == "application/vnd.apache.parquet"

class TestMetadataStoreKeying:
    def test_a_table_is_keyed_the_way_this_connector_looks_up(self, tf_src, connector_name):
        profile = M.CONNECTOR_PROFILE.get(connector_name)
        if not profile:
            pytest.skip(f"{connector_name}: no profile")
        tables = list(P.iter_resources(tf_src, "aws_dynamodb_table"))
        assert tables, f"{connector_name}: no DynamoDB table"
        keys = {P.scalar(b, "hash_key") for _, b in tables}
        assert None not in keys, f"{connector_name}: a table has no hash_key"
        assert profile["metadata_key"] in keys, (
            f"{connector_name}: no table keyed by {profile['metadata_key']!r} "
            f"(connector keys its lookup by that); found {sorted(keys)}"
        )

class TestFlowLogStackSet:
    def test_flowlog_emits_parquet_to_s3_with_vpc_id(self, cfn_doc, connector_name):
        """Asserts the CORRECT CloudFormation shape: FileFormat /
        HiveCompatiblePartitions live under DestinationOptions. (The original
        template put them at top level / used the non-existent
        'LogFileNameFormat' -- invalid CFN that would not deploy.)"""
        flowlogs = P.cfn_resources_of_type(cfn_doc, M.FLOWLOG["cfn_type"])
        assert flowlogs, f"{connector_name}: no {M.FLOWLOG['cfn_type']} in template"
        props = next(iter(flowlogs.values()))
        assert props["TrafficType"] == M.FLOWLOG["traffic_type"]
        assert props["LogDestinationType"] == M.FLOWLOG["log_destination_type"]
        assert M.FLOWLOG["log_format_requires"] in props["LogFormat"]
        dest = props.get("DestinationOptions")
        assert isinstance(dest, dict), (
            f"{connector_name}: FlowLog has no DestinationOptions block -- "
            f"FileFormat/HiveCompatiblePartitions must live there"
        )
        assert dest["FileFormat"] == M.FLOWLOG["destination_file_format"]
        assert bool(dest["HiveCompatiblePartitions"]) is M.FLOWLOG["hive_compatible_partitions"]