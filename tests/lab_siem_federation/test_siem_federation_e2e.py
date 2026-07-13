"""
Lab 15 (WS-G / G4) -- SIEM-federated investigation, mock end-to-end.

This proves the FULL loop the swarm relies on, with no live SIEM:

  internal event ──CIM/ECS fanout (the REAL mapping YAMLs)──► mock Splunk/Elastic
       (index store)                                                     ▲
       swarm SiemQueryTool ──build_spl/build_esql + read-only guard──────┘
                              └─► write↔read CONSERVATION + counterpart disproof

The fanout is replicated from `middleware/config/{cim,ecs}_mappings.yaml` so the
indexed doc is shaped exactly as the middleware would write it; the mock evaluates
the swarm's actual query against those docs. If the tool ever builds a query whose
field/index doesn't match what the fanout produces, the round-trip returns nothing
and conservation FAILS -- the contract break surfaces here, not in production.
"""
import json
import re
import sys
import threading
import types
from collections import defaultdict
from fnmatch import fnmatch
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import pytest
import yaml

PE = Path(__file__).parent.parent.parent
HUNTER = PE / "analytics/llm_hunter"

# ── stub langchain + tools package; load the REAL siem_query ────────────────
_lc = types.ModuleType("langchain_core")
_lc_tools = types.ModuleType("langchain_core.tools")
_lc_tools.BaseTool = type("BaseTool", (), {"__init__": lambda self, **kw: None})
_lc.tools = _lc_tools
sys.modules.setdefault("langchain_core", _lc)
sys.modules.setdefault("langchain_core.tools", _lc_tools)
_tools_pkg = types.ModuleType("tools")
_tools_pkg.__path__ = [str(HUNTER / "tools")]
sys.modules["tools"] = _tools_pkg
sys.path.insert(0, str(HUNTER / "tools"))
sys.path.insert(0, str(HUNTER))
import importlib
sq = importlib.import_module("tools.siem_query")


# ── the fanout, replicated from the middleware mapping YAMLs ─────────────────
_CIM = yaml.safe_load(open(PE / "middleware/config/cim_mappings.yaml"))["schemas"]
_ECS = yaml.safe_load(open(PE / "middleware/config/ecs_mappings.yaml"))["schemas"]


def _project(event, schemas):
    for sch in schemas:
        mf, mv = sch.get("match_field", ""), sch.get("match_value", "")
        if mf == "" or str(event.get(mf, "")) == str(mv):
            doc = {}
            for tgt, src in (sch.get("fields") or {}).items():
                if isinstance(src, str) and src.startswith('"') and src.endswith('"'):
                    doc[tgt] = src.strip('"')               # literal
                else:
                    doc[tgt] = event.get(src)               # projected field
            return {k: v for k, v in doc.items() if v is not None}, sch.get("name")
    return {}, None


def cim_fanout(event):
    return _project(event, _CIM)


def ecs_fanout(event):
    return _project(event, _ECS)


# ── mock SIEM: an index store + a tiny SPL/ES|QL evaluator ──────────────────
class _Store:
    def __init__(self):
        self.docs = []   # (index, dialect, doc)

    def index(self, index, dialect, doc):
        self.docs.append((index, dialect, doc))

    def clear(self):
        self.docs.clear()


STORE = _Store()


def _eval_spl(spl):
    idxs = re.findall(r"index=([A-Za-z0-9_*\-]+)", spl)
    docs = [d for (i, dl, d) in STORE.docs
            if dl == "cim" and any(i == x or fnmatch(i, x) for x in idxs)]
    preds = re.findall(r'(\w+)="([^"]+)"', spl)
    if preds:
        docs = [d for d in docs if any(str(d.get(f)) == v for f, v in preds)]
    if "dc(src)" in spl or "distinct_sources" in spl:
        groups = defaultdict(set)
        for d in docs:
            groups[d.get("sourcetype", "")].add(d.get("src"))
        return [{"sourcetype": st, "distinct_sources": len(s)} for st, s in groups.items()]
    return docs


def _eval_esql(esql):
    m = re.match(r"\s*FROM\s+([^|]+)", esql)
    idxs = [s.strip() for s in m.group(1).split(",")] if m else []
    docs = [d for (i, dl, d) in STORE.docs
            if dl == "ecs" and any(i == x or fnmatch(i, x) for x in idxs)]
    preds = re.findall(r'([\w.@]+)\s*==\s*"([^"]+)"', esql)
    if preds:
        docs = [d for d in docs if any(str(d.get(f)) == v for f, v in preds)]
    cols = sorted({k for d in docs for k in d})
    return {"columns": [{"name": c} for c in cols],
            "values": [[d.get(c) for c in cols] for d in docs]}


class _MockSiem(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if self.path.endswith("/services/search/jobs/export"):
            spl = parse_qs(raw).get("search", [""])[0]
            body = "".join(json.dumps({"result": r}) + "\n" for r in _eval_spl(spl))
            self._send(200, body)
        elif self.path.endswith("/_query"):
            esql = json.loads(raw).get("query", "")
            self._send(200, json.dumps(_eval_esql(esql)))
        else:
            self._send(404, "nope")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())


@pytest.fixture(scope="module")
def siem_url():
    srv = HTTPServer(("127.0.0.1", 0), _MockSiem)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(autouse=True)
def _clean_store():
    STORE.clear()
    yield
    STORE.clear()


def _cfg(url, dialect, allowed):
    return {"default_window_hours": 6, "max_rows": 200, "any_active": True,
            "backends": {"b": {"dialect": dialect, "search_url": url, "token": "t",
                               "verify_tls": False, "allowed_indexes": list(allowed),
                               "active": True}}}


DST = "203.0.113.7"


def _nettap_event(src="10.0.0.5", dst=DST):
    return {"sensor_type": "network_tap", "timestamp_start": 1_700_000_000,
            "src_ip": src, "dst_ip": dst, "dst_port": 443, "protocol_name": "tcp",
            "bytes_src": 1200, "bytes_dst": 4500, "session_duration_ms": 60000}


# ── the fanout itself is faithful to the mapping ────────────────────────────
class TestFanoutProjection:
    def test_nettap_cim_projection_puts_dst_in_dest(self):
        doc, name = cim_fanout(_nettap_event())
        assert name == "network_tap"
        assert doc["dest"] == DST and doc["src"] == "10.0.0.5"
        assert doc["sourcetype"] == "nexus:nettap:session"

    def test_nettap_ecs_projection_puts_dst_in_destination_ip(self):
        doc, _ = ecs_fanout(_nettap_event())
        assert doc["destination.ip"] == DST and doc["source.ip"] == "10.0.0.5"


# ── Splunk: write→fanout→index→swarm-pivot→read CONSERVATION ────────────────
class TestSplunkConservation:
    def test_fanned_out_event_is_retrievable_via_swarm_pivot(self, siem_url):
        doc, _ = cim_fanout(_nettap_event())
        STORE.index("nexus_network", "cim", doc)                 # the fanout write
        tool = sq.SiemQueryTool(siem_config=_cfg(siem_url, "spl", ["nexus_network"]))
        out = tool._run("scope the dst across the fleet", "b",
                        sq.build_spl(DST, ["nexus_network"], 6, 200))   # the swarm read
        assert "returned 1 row" in out and DST in out, "conservation broken: fanned-out event not retrieved"

    def test_cross_source_index_reachable(self, siem_url):
        # (B) an OTHER source the SIEM holds -- a firewall log Nexus never ingested
        STORE.index("fw_traffic", "cim", {"src": "10.9.9.9", "dest": DST,
                                          "sourcetype": "fw:traffic"})
        tool = sq.SiemQueryTool(siem_config=_cfg(siem_url, "spl", ["nexus_network", "fw_traffic"]))
        out = tool._run("check fw logs for dst", "b", sq.build_spl(DST, ["fw_traffic"], 6, 200))
        assert DST in out and "fw:traffic" in out


# ── counterpart disproof: cross-source prevalence ───────────────────────────
class TestCounterpartPrevalenceDisproof:
    def test_many_distinct_sources_surface_as_benign_signal(self, siem_url):
        # 40 distinct hosts all reach DST on the same cadence -> CDN/updater, not C2
        for i in range(40):
            STORE.index("nexus_network", "cim",
                        {"src": f"10.0.{i}.2", "dest": DST, "sourcetype": "nexus:nettap:session"})
        tool = sq.SiemQueryTool(siem_config=_cfg(siem_url, "spl", ["nexus_network", "fw_traffic"]))
        prevalence = (f'search (index=nexus_network) dest="{DST}" earliest=-24h '
                      f'| stats dc(src) AS distinct_sources BY sourcetype')
        out = tool._run("counterpart disproof via prevalence", "b", prevalence)
        assert "distinct_sources" in out and "40" in out, "prevalence disproof did not aggregate"


# ── Elastic: ES|QL conservation ─────────────────────────────────────────────
class TestElasticConservation:
    def test_fanned_out_event_retrievable_via_esql(self, siem_url):
        doc, _ = ecs_fanout(_nettap_event())
        STORE.index("nexus-network", "ecs", doc)
        tool = sq.SiemQueryTool(siem_config=_cfg(siem_url, "esql", ["nexus-network"]))
        out = tool._run("scope dst", "b", sq.build_esql(DST, ["nexus-network"], 6, 200))
        assert DST in out, "ECS conservation broken: fanned-out event not retrieved via ES|QL"
