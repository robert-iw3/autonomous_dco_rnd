"""
Tier-0 -- Schema-contract validation for the falco_runtime (k8s) sensor.

Validates the wire-contract column layout (see falco_logic_mirror.FALCO_SCHEMA_COLUMNS,
mirrored from falco_schema() in main.rs), the X-Sensor-Type wire literal, the
default gateway URL, and -- via TestCentralRegistration -- that falco_runtime
is fully registered in the central nexus.toml [schema_mappings.*] /
[qdrant.named_vectors] contract and routed by both worker_qdrant and
worker_rules's duck-typing chains (a real integration gap found and closed
while building this workbench; see readme.md "Findings fixed").
"""
import os
import re
import pytest

from falco_logic_mirror import (
    FALCO_SCHEMA_COLUMNS,
    SENSOR_TYPE,
    DEFAULT_GATEWAY_URL,
)

pytestmark = pytest.mark.tier0

def _read(*parts):
    with open(os.path.join(*parts)) as fh:
        return fh.read()

class TestSchemaColumnStructure:
    """The transmitter emits a flat, raw-telemetry schema (string/int columns
    plus a `raw_fields` JSON catch-all) -- no computed numeric feature/vector
    columns. Confirm the mirrored layout is well-formed and matches the source
    field-builder order 1:1."""

    def test_no_duplicate_columns(self):
        assert len(FALCO_SCHEMA_COLUMNS) == len(set(FALCO_SCHEMA_COLUMNS))

    def test_identifier_and_routing_columns_present(self):
        assert "sensor_id" in FALCO_SCHEMA_COLUMNS
        assert "sensor_type" in FALCO_SCHEMA_COLUMNS
        # sensor_id/sensor_type are appended last by events_to_parquet()'s builder loop.
        assert FALCO_SCHEMA_COLUMNS[-2:] == ["sensor_id", "sensor_type"]

    def test_raw_fields_catchall_column_present(self):
        # output_fields (the full Falco/sysdig field map) is preserved verbatim
        # as JSON for downstream enrichment -- see raw_b.append_value(serde_json::to_string(f)...).
        assert "raw_fields" in FALCO_SCHEMA_COLUMNS

    def test_mirrored_column_count_and_order_matches_real_schema_definition(self, repo_root):
        src = _read(repo_root, "transmitter", "src", "main.rs")
        m = re.search(r"fn falco_schema\(\).*?Schema::new\(vec!\[(.*?)\]\)\)", src, re.DOTALL)
        assert m, "could not locate falco_schema() in main.rs"
        real_columns = re.findall(r'Field::new\("([a-zA-Z0-9_]+)"', m.group(1))
        assert real_columns == FALCO_SCHEMA_COLUMNS, (
            "falco_logic_mirror.FALCO_SCHEMA_COLUMNS is out of sync with the real "
            "falco_schema() column order in main.rs"
        )

class TestSensorTypeContract:
    def test_wire_sensor_type_matches_transmitter_source(self, repo_root):
        src = _read(repo_root, "transmitter", "src", "main.rs")
        # Both the schema column value (stype_b.append_value) and the
        # X-Sensor-Type request header must agree on the literal.
        assert src.count(f'"{SENSOR_TYPE}"') >= 2, (
            f"expected the literal {SENSOR_TYPE!r} to appear at least twice in "
            f"main.rs (schema column value + X-Sensor-Type header)"
        )
        assert f'.header("X-Sensor-Type", "{SENSOR_TYPE}")' in src

    def test_wire_sensor_type_is_lowercase_snake_case(self):
        # Distinguishes this sensor from e.g. linux_sentinel, whose wire literal
        # ("Linux-Sentinel") intentionally differs in case/punctuation from its
        # nexus.toml table key. falco_runtime has neither -- confirm its actual
        # form so nobody "normalizes" it into a mismatch later.
        assert SENSOR_TYPE == SENSOR_TYPE.lower()
        assert "-" not in SENSOR_TYPE
        assert SENSOR_TYPE == "falco_runtime"

class TestGatewayUrlContract:
    def test_default_gateway_points_at_telemetry_route(self):
        from urllib.parse import urlparse
        assert urlparse(DEFAULT_GATEWAY_URL).path == "/api/v1/telemetry"

    def test_default_gateway_url_matches_source(self, repo_root):
        src = _read(repo_root, "transmitter", "src", "main.rs")
        assert DEFAULT_GATEWAY_URL in src, (
            "falco_logic_mirror.DEFAULT_GATEWAY_URL is out of sync with "
            "Config::from_env()'s NEXUS_GATEWAY_URL fallback in main.rs"
        )

    def test_launch_script_default_matches(self, repo_root):
        src = _read(repo_root, "launch.sh")
        assert DEFAULT_GATEWAY_URL in src

    def test_gateway_requires_https(self):
        assert DEFAULT_GATEWAY_URL.startswith("https://")

    def test_gateway_port_matches_canonical_ingress_bind_port(self, repo_root, nexus_toml_path):
        """falco_transmitter's default ('nexus-edge:8080') differs in hostname
        style from sentinel/network_tap/c2_sensor's HAProxy-fronted default
        ('nexus-edge.local:443'), but its port must still agree with the
        canonical core_ingress [ingress] bind_addr -- confirms it's pointed at
        the same gateway, just addressed directly (e.g. in-cluster DNS) rather
        than through the TLS-terminating proxy."""
        import tomllib
        from urllib.parse import urlparse
        with open(nexus_toml_path, "rb") as fh:
            nexus = tomllib.load(fh)
        bind_port = nexus["ingress"]["bind_addr"].rsplit(":", 1)[-1]
        assert urlparse(DEFAULT_GATEWAY_URL).port == int(bind_port)

class TestCentralRegistration:
    """Confirms `falco_runtime` is registered end to end in the central Nexus
    pipeline -- closing a real, previously-undetected integration gap this
    workbench discovered (see readme.md "Findings fixed during workbench
    validation" for the full trace of how it was found and closed):

      - `nexus.toml` now has a `[schema_mappings.falco_runtime]` table whose
        `identifier_column` ("rule") is a real, non-nullable FALCO_SCHEMA_COLUMNS
        field, and a `falco_math` (4D) entry in `[qdrant.named_vectors]`.
      - `falco_transmitter` now computes and emits four pre-normalised [0,1]
        derived feature columns (`priority_score`, `container_scope_score`,
        `network_activity_score`, `privileged_score`) plus a stable
        content-derived `event_id` -- the numeric ML feature vector
        FALCO_SCHEMA_COLUMNS previously lacked entirely.
      - `worker_qdrant`'s duck-typing chain now routes on
        `has_col(&self.mappings.falco_runtime.identifier_column) && has_col("evt_type")`
        and normalises the `falco_math` vector space (clamped [0,1] passthrough,
        consistent with sysmon/trellix's pre-normalised-input pattern).
      - `worker_rules`'s duck-typing chain now routes on
        `has_col("rule") && has_col("evt_type")` into a `"falco_runtime"`
        source_type, with its OS-agnostic field-extraction fallback chains
        extended for Falco's native field names (proc_name, proc_cmdline,
        fd_dip, rule, user_uid).

    Net effect: the "Frontline Detection (Falco Engine)" -> "Swarm Evaluation
    (Sentinel Nexus)" pipeline this sensor's own readme.md describes now runs
    for Falco/k8s telemetry -- it is vectorized into Qdrant, rule-evaluated,
    and archived, not just archived.
    """

    def test_falco_runtime_is_registered_for_downstream_processing(self, nexus_toml_path, repo_root):
        import tomllib
        with open(nexus_toml_path, "rb") as fh:
            nexus = tomllib.load(fh)

        assert SENSOR_TYPE in nexus.get("schema_mappings", {}), (
            f"no [schema_mappings.{SENSOR_TYPE}] in nexus.toml"
        )
        mapping = nexus["schema_mappings"][SENSOR_TYPE]
        identifier_column = mapping["identifier_column"]
        assert identifier_column in FALCO_SCHEMA_COLUMNS

        vector_name = mapping["vector_name"]
        assert vector_name in nexus["qdrant"]["named_vectors"]
        assert nexus["qdrant"]["named_vectors"][vector_name] == len(mapping["vector_columns"])
        for col in mapping["vector_columns"]:
            assert col in FALCO_SCHEMA_COLUMNS, f"vector_column {col!r} not in FALCO_SCHEMA_COLUMNS"

        qdrant_src = _read(repo_root, "..", "..", "project_empros", "services", "worker_qdrant", "src", "main.rs")
        assert f'has_col(&self.mappings.{SENSOR_TYPE}' in qdrant_src or f'has_col("{identifier_column}")' in qdrant_src
        assert f'"{vector_name}"' in qdrant_src

        rules_src = _read(repo_root, "..", "..", "project_empros", "services", "worker_rules", "src", "main.rs")
        assert f'has_col("{identifier_column}")' in rules_src
        assert f'"{SENSOR_TYPE}"' in rules_src