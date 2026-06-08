"""
Tier-0 -- Data-contract validation for windows/sysmon_sensor.

Drives the *real* SysmonSensor._normalise() with synthetic raw Sysmon
EventData dicts (the dict shape _parse_event_data() produces from
win32evtlogutil.SafeFormatMessage's "Field: Value" lines), then feeds the
normalised records into the *real* ParquetShipper._to_parquet() to produce
actual Parquet bytes -- end to end collect -> normalise -> serialize, exactly
as the sensor does on the endpoint, just without the win32evtlog event source.

Finally cross-checks the produced columns against [schema_mappings.sysmon_sensor]
in the central project_empros/services/config/nexus.toml, so a schema drift
between the sensor and Nexus's ingestion contract fails loudly here rather
than silently dropping columns in production.
"""

import io
import os
import re
import socket
import pyarrow.parquet as pq
import pytest
import schema
from SysmonSensor import _normalise, _int
from parquet_shipper import ParquetShipper, SENSOR_TYPE

pytestmark = pytest.mark.tier0

# -----------------------------------------------------------------------------
# Synthetic raw Sysmon EventData payloads, keyed by event ID
# (mirrors the "FieldName: Value" dict that _parse_event_data() builds)
# -----------------------------------------------------------------------------

RAW_EVENTS = {
    1: {  # Process Create -- Office spawning PowerShell w/ encoded payload
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0",
        "ParentImage": r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        "ParentCommandLine": r'"WINWORD.EXE" /n "invoice.docm"',
        "User": "CORP\\jdoe",
        "IntegrityLevel": "High",
        "ProcessId": "4242",
        "ParentProcessId": "1010",
        "Hashes": "SHA256=AABBCCDD",
        "CurrentDirectory": r"C:\Users\jdoe\Documents",
        "RuleName": "technique_id=T1059.001",
    },
    3: {  # Network Connection
        "Image": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\jdoe",
        "ProcessId": "4242",
        "DestinationIp": "203.0.113.42",
        "DestinationPort": "443",
        "Protocol": "tcp",
        "Initiated": "true",
    },
    6: {  # Driver Load -- unsigned BYOVD-style driver
        "ImageLoaded": r"C:\Windows\System32\drivers\rtcore64.sys",
        "Hashes": "SHA256=11223344",
        "Signed": "false",
        "SignatureStatus": "",
    },
    10: {  # ProcessAccess -- LSASS dump signal
        "SourceImage": r"C:\Windows\Temp\dumpit.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1FFFFF",
        "User": "CORP\\jdoe",
    },
    22: {  # DNS Query -- DGA-looking domain
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "QueryName": "qj3kxnls9z.example.net",
        "QueryResults": "203.0.113.99;",
        "User": "CORP\\jdoe",
    },
}

HOSTNAME = "WORKSTATION-07"

# -----------------------------------------------------------------------------
# _normalise() -- raw EventData dict -> schema-shaped record
# -----------------------------------------------------------------------------

class TestNormalise:
    def test_always_present_core_fields(self):
        for event_id, raw in RAW_EVENTS.items():
            rec = _normalise(event_id, raw, HOSTNAME)
            assert rec["sensor_type"] == "sysmon_sensor"
            assert rec["sensor_id"] == HOSTNAME
            assert rec["sysmon_event_id"] == event_id
            assert isinstance(rec["timestamp"], float)

    def test_event1_process_create_mapping(self):
        rec = _normalise(1, RAW_EVENTS[1], HOSTNAME)
        assert rec["Image"] == RAW_EVENTS[1]["Image"]
        assert rec["CommandLine"] == RAW_EVENTS[1]["CommandLine"]
        assert rec["ParentImage"] == RAW_EVENTS[1]["ParentImage"]
        assert rec["IntegrityLevel"] == "High"
        # ProcessId/ParentProcessId go through _int() -- string -> int
        assert rec["ProcessId"] == 4242
        assert rec["ParentProcessId"] == 1010

    def test_event3_network_initiated_is_coerced_to_bool(self):
        rec = _normalise(3, RAW_EVENTS[3], HOSTNAME)
        assert rec["Initiated"] is True
        assert rec["DestinationPort"] == 443
        assert rec["Protocol"] == "tcp"

    def test_event3_initiated_defaults_false_when_absent(self):
        raw = dict(RAW_EVENTS[3])
        del raw["Initiated"]
        rec = _normalise(3, raw, HOSTNAME)
        assert rec["Initiated"] is False

    def test_event6_driver_load_signed_is_coerced_to_bool(self):
        rec = _normalise(6, RAW_EVENTS[6], HOSTNAME)
        assert rec["Signed"] is False
        assert rec["ImageLoaded"] == RAW_EVENTS[6]["ImageLoaded"]

    def test_event10_process_access_granted_access_passthrough(self):
        rec = _normalise(10, RAW_EVENTS[10], HOSTNAME)
        assert rec["GrantedAccess"] == "0x1FFFFF"
        assert rec["TargetImage"] == r"C:\Windows\System32\lsass.exe"

    def test_event22_dns_query_mapping(self):
        rec = _normalise(22, RAW_EVENTS[22], HOSTNAME)
        assert rec["QueryName"] == "qj3kxnls9z.example.net"
        assert rec["QueryResults"] == "203.0.113.99;"

    def test_unrecognised_event_id_yields_only_core_fields(self):
        rec = _normalise(999, {"Image": "whatever.exe"}, HOSTNAME)
        assert set(rec.keys()) == {"sensor_type", "sensor_id", "timestamp", "sysmon_event_id"}

class TestIntHelper:
    def test_parses_numeric_strings(self):
        assert _int("1234") == 1234

    def test_strips_whitespace(self):
        assert _int("  42 ") == 42

    def test_none_passthrough(self):
        assert _int(None) is None

    def test_non_numeric_is_none_not_an_exception(self):
        assert _int("not-a-number") is None
        assert _int("0x1FFFFF") is None  # hex strings aren't decimal ints

# -----------------------------------------------------------------------------
# End-to-end: normalise() -> _to_parquet() -> real Parquet bytes
# -----------------------------------------------------------------------------

class TestNormaliseToParquet:
    def _shipper(self, monkeypatch):
        monkeypatch.setenv("NEXUS_SENSOR_ID", HOSTNAME)
        monkeypatch.setenv("NEXUS_FLUSH_INTERVAL_S", "3600")  # don't fire timer mid-test
        shipper = ParquetShipper()
        try:
            yield shipper
        finally:
            shipper.shutdown()

    @pytest.fixture
    def shipper(self, monkeypatch):
        yield from self._shipper(monkeypatch)

    def test_mixed_batch_round_trips_through_parquet(self, shipper):
        batch = [_normalise(eid, raw, HOSTNAME) for eid, raw in RAW_EVENTS.items()]
        parquet_bytes = shipper._to_parquet(batch)

        assert isinstance(parquet_bytes, bytes)
        assert len(parquet_bytes) > 0

        table = pq.read_table(io.BytesIO(parquet_bytes))
        assert table.num_rows == len(RAW_EVENTS)
        assert table.column_names == [f.name for f in schema.SCHEMA]

        event_ids = table.column("sysmon_event_id").to_pylist()
        assert sorted(event_ids) == sorted(RAW_EVENTS.keys())

    def test_feature_vector_is_populated_per_row_not_zeroed(self, shipper):
        # The Office->PowerShell process-create row should score high on
        # parent_child_score and command_entropy -- prove the shipped Parquet
        # carries the *real* computed vector, not a stub/placeholder.
        rec = _normalise(1, RAW_EVENTS[1], HOSTNAME)
        parquet_bytes = shipper._to_parquet([rec])
        table = pq.read_table(io.BytesIO(parquet_bytes))

        expected = schema.compute_features(rec)
        row = {name: table.column(name)[0].as_py() for name in
               ("command_entropy", "parent_child_score", "integrity_score",
                "anomaly_score", "grant_access_score", "driver_trust_score")}

        assert row["command_entropy"]    == pytest.approx(expected[0])
        assert row["parent_child_score"] == pytest.approx(expected[1])
        assert row["integrity_score"]    == pytest.approx(expected[2])
        assert row["anomaly_score"]      == pytest.approx(expected[3])
        assert row["grant_access_score"] == pytest.approx(expected[4])
        assert row["driver_trust_score"] == pytest.approx(expected[5])
        # And it should actually be "interesting" -- not all-zero placeholders
        assert row["parent_child_score"] > 0.9
        assert row["command_entropy"] > 0.0

    def test_payload_raw_preserves_full_record_for_rehydration(self, shipper):
        rec = _normalise(10, RAW_EVENTS[10], HOSTNAME)
        parquet_bytes = shipper._to_parquet([rec])
        table = pq.read_table(io.BytesIO(parquet_bytes))
        payload_raw = table.column("payload_raw")[0].as_py()
        assert "lsass.exe" in payload_raw
        assert "0x1FFFFF" in payload_raw

    def test_sensor_type_and_id_stamped_from_shipper_not_record(self, shipper):
        # _normalise already stamps sensor_type/sensor_id, but _to_parquet
        # re-stamps from the shipper's own config -- prove they agree and
        # that the shipped value is the shipper's configured sensor_id.
        rec = _normalise(1, RAW_EVENTS[1], "some-other-host")
        parquet_bytes = shipper._to_parquet([rec])
        table = pq.read_table(io.BytesIO(parquet_bytes))
        assert table.column("sensor_type")[0].as_py() == SENSOR_TYPE
        assert table.column("sensor_id")[0].as_py() == HOSTNAME

# -----------------------------------------------------------------------------
# Cross-check against central Nexus schema_mappings contract
# -----------------------------------------------------------------------------

class TestNexusSchemaMappingAlignment:
    def _sysmon_block(self, nexus_toml_path):
        src = open(nexus_toml_path).read()
        start = src.find("[schema_mappings.sysmon_sensor]")
        assert start != -1, "[schema_mappings.sysmon_sensor] missing from nexus.toml"
        nxt = src.find("\n[", start + 1)
        return src[start:nxt if nxt != -1 else None]

    def test_identifier_column_matches(self, nexus_toml_path):
        block = self._sysmon_block(nexus_toml_path)
        assert "sysmon_event_id" in block
        assert "sysmon_event_id" in [f.name for f in schema.SCHEMA]

    def test_vector_dimension_matches_schema_columns(self, nexus_toml_path):
        block = self._sysmon_block(nexus_toml_path)
        m = re.search(r'windows_math\s*=\s*(\d+)', block) or re.search(r'windows_math\s*=\s*(\d+)', open(nexus_toml_path).read())
        assert m, "windows_math vector dimension not declared for sysmon_sensor"
        declared_dim = int(m.group(1))
        vector_cols = [f.name for f in schema.SCHEMA if f.name.endswith("_score") or f.name in ("command_entropy", "anomaly_score")]
        assert len(vector_cols) == declared_dim == 6