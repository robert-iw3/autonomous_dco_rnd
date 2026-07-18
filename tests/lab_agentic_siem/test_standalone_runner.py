"""
Standalone SIEM analysis — the promoted analytics modules, end to end.

Exercises the REAL `analytics/llm_hunter/siem_analysis/` package (not the lab's
deterministic stand-in) against a mock SIEM transport: request schema, CIM/ECS
entity extraction, the read-only + bounded + untrusted-wrapped pivot with its
SIEM_UNAVAILABLE fail-open, seed synthesis into the strict UnifiedAlertSchema,
the full standalone run producing a grounded report + the WS-I containment
protocol with heuristic verdicts gated to operator approval, the coverage/gap +
environment-profile artifacts, verdict-ledger auditing (hash chain verifies),
and the nexus.siem.analyze consumer.

LLM/langchain seams are stubbed exactly like the other analytics labs.
"""
import asyncio
import importlib
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
HUNTER = ROOT / "analytics" / "llm_hunter"

# -- stub langchain_core (tools + messages) and register the hunter packages --
_lc = types.ModuleType("langchain_core")
_lc_tools = types.ModuleType("langchain_core.tools")
_lc_tools.BaseTool = type("BaseTool", (), {"__init__": lambda self, **kw: None})
_lc_msgs = types.ModuleType("langchain_core.messages")
_lc_msgs.BaseMessage = type("BaseMessage", (), {})
_lc_msgs.RemoveMessage = type("RemoveMessage", (), {})
_lc.tools, _lc.messages = _lc_tools, _lc_msgs
sys.modules.setdefault("langchain_core", _lc)
sys.modules.setdefault("langchain_core.tools", _lc_tools)
sys.modules.setdefault("langchain_core.messages", _lc_msgs)

for pkg, path in (("tools", HUNTER / "tools"), ("agents", HUNTER / "agents"),
                  ("siem_analysis", HUNTER / "siem_analysis")):
    mod = types.ModuleType(pkg)
    mod.__path__ = [str(path)]
    sys.modules.setdefault(pkg, mod)
sys.path.insert(0, str(HUNTER))

req_mod = importlib.import_module("siem_analysis.request")
ee = importlib.import_module("siem_analysis.entity_extractor")
pv = importlib.import_module("siem_analysis.pivot")
sd = importlib.import_module("siem_analysis.seed")
sa = importlib.import_module("siem_analysis.standalone")
cov = importlib.import_module("siem_analysis.coverage")
entry = importlib.import_module("siem_analysis.entry")
ledger = importlib.import_module("agents.verdict_ledger")

SiemAnalysisRequest = req_mod.SiemAnalysisRequest

# -- mock SIEM: the web-shell attack chain as CIM-shaped Splunk export rows ---
ATTACK_ROWS = [
    {"_time": "11:05", "host": "web-01", "user": "www-data", "process": "bash",
     "parent_process": "nginx", "index": "nexus_endpoint", "mitre": "T1505.003"},
    {"_time": "11:05", "host": "web-01", "user": "www-data", "process": "whoami",
     "parent_process": "bash", "mitre": "T1059"},
    {"_time": "11:06", "host": "web-01", "user": "www-data", "process": "curl",
     "parent_process": "bash", "dest_ip": "203.0.113.66", "dns_query": "evil-c2.example",
     "mitre": "T1071", "severity": "high"},
    {"_time": "11:08", "host": "web-01", "user": "www-data", "process": "ssh",
     "parent_process": "bash", "dest_ip": "10.0.0.12", "mitre": "T1021"},
]

QUERY = ("search index=nexus_endpoint host=web-01 user=www-data "
         "process IN (bash,whoami,curl,ssh)")


def _siem_config():
    return {"backends": {"splunk-prod": {"active": True, "dialect": "spl",
                                         "allowed_indexes": ["nexus_*"],
                                         "search_url": "https://splunk.mock",
                                         "token": "t"}},
            "default_window_hours": 6, "max_rows": 200}


class MockTransport:
    """Splunk oneshot-export stand-in; records every dispatched query."""

    def __init__(self, rows=None, fail=False):
        self.rows = ATTACK_ROWS if rows is None else rows
        self.fail = fail
        self.queries = []

    def __call__(self, method, url, **kw):
        query = (kw.get("data") or {}).get("search", "")
        self.queries.append(query)
        if self.fail:
            raise ConnectionError("SIEM down")
        return 200, {"results": self.rows}


def _request(**over):
    base = dict(backend="splunk-prod", dialect="spl", query=QUERY,
                detection_name="Suspicious Process Spawned by Web Server",
                product="linux", entry_point="operator", requested_by="analyst1")
    base.update(over)
    return SiemAnalysisRequest(**base)


def _run(tmp_path, transport=None, **over):
    transport = transport or MockTransport()
    report = sa.run_standalone_analysis(
        _request(**over), siem_config=_siem_config(), transport=transport,
        ledger_path=str(tmp_path / "ledger.jsonl"))
    return report, transport


# ── SA-1: request schema ─────────────────────────────────────────────────────

class TestSiemAnalysisRequest:
    def test_query_xor_detection_id(self):
        with pytest.raises(Exception):
            SiemAnalysisRequest(backend="b", dialect="spl")
        with pytest.raises(Exception):
            SiemAnalysisRequest(backend="b", dialect="spl", query="search x",
                                detection_id="d-1")

    def test_source_type_from_product(self):
        assert _request(product="linux").source_type() == "linux_sentinel"
        assert _request(product="aws").source_type() == "aws_cloudtrail"
        assert _request(product="").source_type() == "qdrant_vector"

    def test_credentials_are_references_not_secrets(self):
        r = _request(read_creds_ref="nexus/siem/splunk_read")
        assert "password" not in r.model_dump()
        assert r.read_creds_ref.startswith("nexus/")


# ── SA-2: entity extraction ──────────────────────────────────────────────────

class TestEntityExtraction:
    def test_cim_flat_fields_typed(self):
        ents = ee.extract_entities(ATTACK_ROWS)
        assert ents["203.0.113.66"]["type"] == "ip"
        assert ents["evil-c2.example"]["type"] == "domain"
        assert ents["www-data"]["type"] == "user"
        assert ents["10.0.0.12"]["type"] == "ip"
        assert all(e["status"] == "investigating" for e in ents.values())

    def test_ecs_fields_typed(self):
        rows = [{"host.name": "srv-9", "source.ip": "198.51.100.7",
                 "user.name": "jdoe", "dns.question.name": "bad.example",
                 "process.name": "mshta.exe"}]
        ents = ee.extract_entities(rows)
        assert ents["198.51.100.7"]["type"] == "ip"
        assert ents["bad.example"]["type"] == "domain"
        assert ents["jdoe"]["type"] == "user"
        assert "srv-9" not in ents, "hosts are epicenters, not board entities"
        assert ee.hosts_in(rows) == ["srv-9"]

    def test_cim_src_dest_value_typed(self):
        rows = [{"src": "10.1.2.3", "dest": "db-server-02"}]
        ents = ee.extract_entities(rows)
        assert ents["10.1.2.3"]["type"] == "ip"
        assert "db-server-02" not in ents
        assert "db-server-02" in ee.hosts_in(rows)

    def test_noise_values_dropped(self):
        assert ee.extract_entities([{"user": "-", "dest_ip": "0.0.0.0",
                                     "dns_query": "null"}]) == {}

    def test_grounding_every_entity_is_a_row_value(self):
        ents = ee.extract_entities(ATTACK_ROWS)
        universe = {str(v) for r in ATTACK_ROWS for v in r.values()}
        assert set(ents) <= universe

    def test_mark_malicious_promotes_status(self):
        ents = ee.mark_malicious(ee.extract_entities(ATTACK_ROWS), note="confirmed")
        assert all(e["status"] == "malicious" for e in ents.values())


# ── SA-3/4: standalone pivot — guards + fail-open ────────────────────────────

class TestStandalonePivot:
    def test_ok_pivot_bounds_and_wraps(self):
        t = MockTransport()
        res = pv.run_siem_pivot(_request(), _siem_config(), t)
        assert res["status"] == pv.STATUS_OK and res["row_count"] == len(ATTACK_ROWS)
        dispatched = t.queries[0]
        assert "earliest=" in dispatched and "| head" in dispatched, \
            "bounds must be enforced on the dispatched query"
        assert all(str(v).startswith("<untrusted_payload>")
                   for r in res["rows"] for v in r.values())

    def test_mutating_query_rejected_before_transport(self):
        t = MockTransport()
        res = pv.run_siem_pivot(_request(query="search index=nexus_endpoint | delete"),
                                _siem_config(), t)
        assert res["status"] == pv.STATUS_REJECTED
        assert t.queries == [], "a rejected query must never reach the SIEM"

    def test_unlisted_index_rejected(self):
        res = pv.run_siem_pivot(_request(query="search index=hr_payroll foo"),
                                _siem_config(), MockTransport())
        assert res["status"] == pv.STATUS_REJECTED and "allowlist" in res["reason"]

    def test_scope_narrows_never_widens(self):
        res = pv.run_siem_pivot(_request(scope_indexes=["some_other_index"]),
                                _siem_config(), MockTransport())
        assert res["status"] == pv.STATUS_REJECTED

    def test_inactive_backend_fails_open(self):
        cfg = _siem_config()
        cfg["backends"]["splunk-prod"]["active"] = False
        res = pv.run_siem_pivot(_request(), cfg, MockTransport())
        assert res["status"] == pv.STATUS_UNAVAILABLE

    def test_transport_failure_fails_open(self):
        res = pv.run_siem_pivot(_request(), _siem_config(), MockTransport(fail=True))
        assert res["status"] == pv.STATUS_UNAVAILABLE
        assert "ConnectionError" in res["reason"]

    def test_unwrap_rows_restores_plain_values(self):
        res = pv.run_siem_pivot(_request(), _siem_config(), MockTransport())
        plain = pv.unwrap_rows(res["rows"])
        assert plain[2]["dest_ip"] == "203.0.113.66"


# ── SA-5: seed synthesis ─────────────────────────────────────────────────────

class TestSeedSynthesis:
    def test_seed_validates_against_unified_alert_schema(self):
        seed = sd.synthesize_seed(_request(), ATTACK_ROWS, "bounded q", now=1000.0)
        model = sd.validate_seed(seed)
        assert model.source_type == "linux_sentinel"
        assert model.sensor_id == "web-01"
        assert model.event_id.startswith("siem-")
        assert model.raw_event["siem"]["backend"] == "splunk-prod"

    def test_anomaly_score_from_row_severity(self):
        assert sd.seed_anomaly_score(ATTACK_ROWS) == 0.85    # "high"
        assert sd.seed_anomaly_score([{"risk_score": "90"}]) == 0.9
        assert sd.seed_anomaly_score([{"host": "a"}]) == 0.75  # default


# ── SA-6: standalone run — report + gated containment + audit ────────────────

class TestStandaloneAnalysis:
    def test_report_complete_with_gated_containment(self, tmp_path):
        r, _ = _run(tmp_path)
        assert r["analyzed"] and r["verdict"]["is_true_positive"]
        assert r["verdict"]["confidence"] <= sa.HEURISTIC_CONFIDENCE_CAP, \
            "a heuristic verdict must stay below the corroboration threshold"
        for key in ("summary", "timeline", "attack_graph", "blast_radius", "mitre",
                    "affected_hosts", "containment", "seed"):
            assert r[key] not in (None, "", []), f"missing/empty report section: {key}"
        acts = {(s["action"], s["target"]) for s in r["containment"]["steps"]}
        assert ("isolate_host", "web-01") in acts
        assert ("block_ip", "203.0.113.66") in acts
        assert ("dns_sinkhole", "evil-c2.example") in acts
        assert r["evidence_wrapped"] is True

    def test_heuristic_steps_gate_to_operator(self, tmp_path):
        r, _ = _run(tmp_path)
        gates = {s["gate"] for s in r["containment"]["steps"]}
        assert gates <= {"operator_approval"}, \
            f"heuristic-verdict containment must not auto-execute (got {gates})"

    def test_grounding_no_hallucinated_nodes(self, tmp_path):
        r, _ = _run(tmp_path)
        universe = {str(v) for row in ATTACK_ROWS for v in row.values()}
        assert set(r["attack_graph"]["nodes"]) <= universe
        assert set(r["blast_radius"]) <= universe
        assert set(r["mitre"]) == {"T1505.003", "T1059", "T1071", "T1021"}

    def test_no_rows_is_benign_no_containment(self, tmp_path):
        r, _ = _run(tmp_path, transport=MockTransport(rows=[]))
        assert r["analyzed"] and not r["verdict"]["is_true_positive"]
        assert r["containment"]["steps"] == [] and r["blast_radius"] == []

    def test_siem_down_fails_open_with_honest_report(self, tmp_path):
        r, _ = _run(tmp_path, transport=MockTransport(fail=True))
        assert r["analyzed"] is False
        assert "SIEM_UNAVAILABLE" in r["summary"]
        assert r["containment"]["steps"] == []

    def test_every_query_and_verdict_audited_chain_verifies(self, tmp_path):
        _run(tmp_path)
        path = str(tmp_path / "ledger.jsonl")
        entries = ledger.load_ledger(path)
        kinds = [(e.get("record") or {}).get("kind") for e in entries]
        assert "siem_standalone_query" in kinds and "siem_standalone_verdict" in kinds
        assert ledger.verify_ledger(path)["valid"] is True

    def test_investigate_seam_receives_schema_valid_seed(self, tmp_path):
        seen = {}

        def swarm_stub(request, seed, entities, rows):
            seen["seed"] = seed
            sd.validate_seed(seed)
            return {"is_true_positive": True, "confidence": 0.93,
                    "recommended_action": "contain", "justification": "swarm-corroborated"}

        report = sa.run_standalone_analysis(
            _request(), siem_config=_siem_config(), transport=MockTransport(),
            investigate=swarm_stub, ledger_path=str(tmp_path / "l.jsonl"))
        assert seen["seed"]["vector_name"] == "siem_pivot"
        assert report["verdict"]["confidence"] == 0.93
        gates = {s["gate"] for s in report["containment"]["steps"]}
        assert "auto" in gates, "a corroborated swarm verdict unlocks autonomous wave-1"


# ── SA-5b/6b: coverage + environment profile ─────────────────────────────────

class TestCoverageAndProfile:
    def test_endpoint_fields_satisfy_lineage_but_not_l7(self):
        fields = {f for r in ATTACK_ROWS for f in r}
        rep = cov.coverage_report("splunk-prod", fields)
        assert "process_lineage" in rep["satisfied"]
        assert "l7_payload" in rep["gaps"]
        assert any("network-tap" in r for r in rep["sensor_recommendations"])

    def test_cloud_only_fields_flag_endpoint_gaps(self):
        rep = cov.coverage_report("elastic-cloud",
                                  {"user", "src_ip", "event_action", "cloud_instance"})
        assert "process_lineage" in rep["gaps"] and "cloud_api" in rep["satisfied"]
        assert any("endpoint sensor" in r for r in rep["sensor_recommendations"])

    def test_partial_detected(self):
        rep = cov.coverage_report("x", {"process"})   # lineage needs parent too
        assert "process_lineage" in rep["partial"]

    def test_environment_profile_inventory_and_egress(self):
        prof = cov.environment_profile(ATTACK_ROWS)
        assert prof["hosts"] == ["web-01"]
        assert prof["identities"] == ["www-data"]
        assert "203.0.113.66" in prof["egress_surface"]["external_ips"]
        assert "10.0.0.12" in prof["egress_surface"]["internal_ips"]
        assert prof["window"]["events"] == len(ATTACK_ROWS)

    def test_report_includes_artifacts_when_requested(self, tmp_path):
        r, _ = _run(tmp_path, include_coverage_report=True)
        assert "coverage_report" in r and "environment_profile" in r


# ── SA-11: nexus.siem.analyze consumer ───────────────────────────────────────

class FakeNC:
    def __init__(self):
        self.published = []
        self.handlers = {}

    async def subscribe(self, subject, cb):
        self.handlers[subject] = cb

    async def publish(self, subject, data):
        self.published.append((subject, json.loads(data.decode())))


class FakeMsg:
    def __init__(self, payload: dict):
        self.data = json.dumps(payload).encode()


class TestAnalyzeConsumer:
    def _serve(self, payload, monkeypatch, tmp_path):
        monkeypatch.setattr(sa, "run_standalone_analysis",
                            lambda request: {"analyzed": True,
                                             "incident_id": f"siem-{request.request_id}"})
        monkeypatch.setattr(entry, "run_standalone_analysis",
                            sa.run_standalone_analysis)
        nc = FakeNC()

        async def _drive():
            await entry.consume(nc)
            await nc.handlers[entry.SUBJECT_ANALYZE](FakeMsg(payload))

        asyncio.run(_drive())
        return nc

    def test_valid_request_yields_report(self, monkeypatch, tmp_path):
        nc = self._serve({"backend": "splunk-prod", "dialect": "spl",
                          "query": QUERY, "entry_point": "detection"},
                         monkeypatch, tmp_path)
        subject, body = nc.published[0]
        assert subject == entry.SUBJECT_REPORT and body["analyzed"] is True

    def test_malformed_request_reported_not_fatal(self, monkeypatch, tmp_path):
        nc = self._serve({"backend": "splunk-prod"}, monkeypatch, tmp_path)
        subject, body = nc.published[0]
        assert subject == entry.SUBJECT_REPORT
        assert body["analyzed"] is False and "malformed" in body["error"]
