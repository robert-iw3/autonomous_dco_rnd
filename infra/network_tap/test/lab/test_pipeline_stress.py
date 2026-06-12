"""
Data-flow stress lab -- proves no data is lost through the ENTIRE pipeline
under escalating load.

A mock Gigamon tap (loadgen) dual-writes synthetic Arkime SPI to Redpanda (ML
path) and OpenSearch (forensic path), exactly as Arkime would. For each load tier
(low → medium → high → very-high) the driver produces the batch, waits for the
pipeline to drain, then LOGS a per-component ledger and asserts conservation:

    produced -- forensic --► opensearch docs   == produced        (keep-all)
             └- ML -► gateway received==produced, accepted==produced-noise,
                      spooled==accepted, transmitted==accepted,
                      mock-ingress rows == accepted               (no loss)

Requires podman (or docker) + time (first run builds the gateway image). Run:
    pytest infra/network_tap/test/lab/test_pipeline_stress.py -s -v
"""
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import requests

HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "compose.lab.yml"
RESULT_DIR = HERE / "result"
ENGINE = os.environ.get("LAB_ENGINE", "podman")

GW_METRICS = "http://127.0.0.1:19090/metrics"
MOCK_STATS = "https://127.0.0.1:18443/stats"
OS_URL = "http://127.0.0.1:19200"
OS_INDEX = "arkime_sessions3-lab"

TIERS = [
    ("low",       int(os.environ.get("LAB_LOW", "1000"))),
    ("medium",    int(os.environ.get("LAB_MEDIUM", "20000"))),
    ("high",      int(os.environ.get("LAB_HIGH", "100000"))),
    ("very-high", int(os.environ.get("LAB_VERYHIGH", "500000"))),
]

requests.packages.urllib3.disable_warnings()  # self-signed mock ingress


def compose(*args, check=True, capture=False, timeout=None):
    cmd = [ENGINE, "compose", "-f", str(COMPOSE), *args]
    return subprocess.run(cmd, check=check, timeout=timeout,
                          capture_output=capture, text=True, cwd=str(HERE))


# -- metric collection per component ------------------------------------------
_SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([0-9.eE+-]+)$")


def gw_metrics() -> dict:
    """Scrape the gateway Prometheus endpoint into {canonical_name: float}."""
    out = {}
    text = requests.get(GW_METRICS, timeout=10).text
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        m = _SAMPLE.match(line.strip())
        if not m:
            continue
        name, _labels, val = m.group(1), m.group(2), float(m.group(3))
        canon = name[:-6] if name.endswith("_total") else name
        out[canon] = out.get(canon, 0.0) + val
    return out


def gwc(metrics: dict, base: str) -> int:
    return int(metrics.get(base, 0))


def mock_rows() -> int:
    return int(requests.get(MOCK_STATS, timeout=10, verify=False).json()["rows"])


def os_docs() -> int:
    requests.post(f"{OS_URL}/{OS_INDEX}/_refresh", timeout=30)
    r = requests.get(f"{OS_URL}/{OS_INDEX}/_count", timeout=30)
    return int(r.json().get("count", 0)) if r.ok else 0


def write_result(record: dict):
    """Persist per-tier evidence into result/ (JSON + a human-readable table),
    even when a tier FAILS -- the directory is the end-to-end validation record."""
    RESULT_DIR.mkdir(exist_ok=True)
    (RESULT_DIR / f"tier_{record['tier']}.json").write_text(json.dumps(record, indent=2))

    records = sorted(
        (json.loads(p.read_text()) for p in RESULT_DIR.glob("tier_*.json")),
        key=lambda r: r["produced"],
    )
    (RESULT_DIR / "summary.json").write_text(json.dumps(records, indent=2))

    lines = [
        "# Data-flow validation results",
        "",
        "Each tier sends a known count of mock Gigamon/Arkime sessions and TRACKS it as",
        "it reaches every component. The ML path narrows once (intentional noise filter,",
        "accounted — not lost); every hop after must hold 100% of the accepted set, and",
        "the forensic path must hold 100% of everything sent. `% of sent` / `% of accepted`",
        "are the share of data that traversed the pipeline to that hop.",
        "",
        "## Summary",
        "",
        "| tier | produced | forensic % | ML path % | ML sink % | noise % | sessions/s | verdict |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in records:
        t = r["traversal_pct"]
        lines.append(
            f"| {r['tier']} | {r['produced']:,} | {t['forensic_path_pct']}% | {t['ml_path_pct']}% "
            f"| {t['ml_sink_delivered_pct']}% | {t['noise_filtered_pct']}% "
            f"| {r['throughput_sessions_per_sec']:,} | {r['verdict']} |"
        )
    for r in records:
        lines += ["", f"## Tracker — tier `{r['tier']}` (sent {r['produced']:,})", "",
                  "| hop | component | count | % of sent | % of accepted |", "|---|---|---|---|---|"]
        for s in r["tracker"]:
            lines.append(
                f"| {s['hop']} | {s['component']} | {s['count']:,} "
                f"| {s.get('pct_of_sent', '')} | {s.get('pct_of_accepted', '')} |"
            )
        dl = r["data_loss"]
        lines.append(f"\n**loss:** forensic={dl['forensic_path']}, ML={dl['ml_path']} — "
                     f"**{r['verdict']}**")
        if r.get("evidence"):
            lines += ["", f"### Component processing evidence — `{r['tier']}` (from each container's log)", ""]
            for comp, snips in r["evidence"].items():
                lines.append(f"- **{comp}**")
                lines.append("  ```")
                for s in snips:
                    lines.append(f"  {s}")
                lines.append("  ```")
    (RESULT_DIR / "RESULTS.md").write_text("\n".join(lines) + "\n")


def produce(count: int) -> dict:
    """Run the mock tap for `count` sessions; return its ledger."""
    res = compose("exec", "-T", "loadgen", "python", "loadgen.py", "--count", str(count),
                  capture=True, timeout=max(600, count // 200))
    last = [l for l in res.stdout.strip().splitlines() if l.strip().startswith("{")]
    assert last, f"loadgen produced no ledger:\nSTDOUT={res.stdout}\nSTDERR={res.stderr}"
    return json.loads(last[-1])


def log_snippet(service: str, patterns, n=3, tail=600):
    """Capture a component's container log (full copy saved to result/logs/) and
    return the last `n` lines matching any pattern -- the proof that THIS component
    actually processed the data."""
    res = compose("logs", "--tail", str(tail), service, capture=True, check=False, timeout=60)
    text = (res.stdout or "") + (res.stderr or "")
    (RESULT_DIR / "logs").mkdir(parents=True, exist_ok=True)
    (RESULT_DIR / "logs" / f"{service}.log").write_text(text)
    hits = [l.strip() for l in text.splitlines() if any(p in l for p in patterns)]
    return hits[-n:] if hits else [l.strip() for l in text.splitlines() if l.strip()][-n:]


# -- lab lifecycle ------------------------------------------------------------
@pytest.fixture(scope="module")
def lab():
    if shutil.which(ENGINE) is None:
        pytest.skip(f"{ENGINE} not available")
    subprocess.run([str(HERE / "gen_certs.sh")], check=True)
    print(f"\n[lab] building + starting stack via {ENGINE} (first build compiles the gateway)...")
    compose("up", "-d", "--build", timeout=2700)
    try:
        deadline = time.time() + 2700
        while time.time() < deadline:
            try:
                if gwc(gw_metrics(), "gateway_consumer_heartbeat_seconds") > 0 and mock_rows() >= 0:
                    requests.put(f"{OS_URL}/{OS_INDEX}", timeout=30)  # ensure index exists
                    print("[lab] stack healthy.")
                    break
            except Exception:
                pass
            time.sleep(3)
        else:
            compose("logs", "--tail", "50", check=False)
            pytest.fail("lab did not become healthy in time")
        yield
    finally:
        print("\n[lab] tearing down...")
        compose("down", "-v", check=False, timeout=120)


def _drain(produced, expected_accepted, base_gw, base_mock, base_os, budget):
    """Poll until both paths have absorbed the tier (or budget elapses)."""
    deadline = time.time() + budget
    last = {}
    while time.time() < deadline:
        m = gw_metrics()
        last = {
            "received":    gwc(m, "gateway_messages_received") - base_gw["received"],
            "filtered":    gwc(m, "gateway_sessions_filtered_noise") - base_gw["filtered"],
            "accepted":    gwc(m, "gateway_sessions_accepted") - base_gw["accepted"],
            "parse_err":   gwc(m, "gateway_json_parse_errors") - base_gw["parse_err"],
            "spooled":     gwc(m, "gateway_spool_rows_written") - base_gw["spooled"],
            "transmitted": gwc(m, "gateway_nexus_rows_transmitted") - base_gw["transmitted"],
            "mock":        mock_rows() - base_mock,
            "os":          os_docs() - base_os,
        }
        if (last["received"] >= produced and last["transmitted"] >= expected_accepted
                and last["mock"] >= expected_accepted and last["os"] >= produced):
            return last, True
        time.sleep(2)
    return last, False


@pytest.mark.parametrize("tier,count", TIERS)
def test_pipeline_no_data_loss(lab, tier, count):
    m0 = gw_metrics()
    base_gw = {
        "received":    gwc(m0, "gateway_messages_received"),
        "filtered":    gwc(m0, "gateway_sessions_filtered_noise"),
        "accepted":    gwc(m0, "gateway_sessions_accepted"),
        "parse_err":   gwc(m0, "gateway_json_parse_errors"),
        "spooled":     gwc(m0, "gateway_spool_rows_written"),
        "transmitted": gwc(m0, "gateway_nexus_rows_transmitted"),
    }
    base_mock, base_os = mock_rows(), os_docs()

    t0 = time.time()
    led = produce(count)
    produced, noise, expected = led["produced"], led["noise"], led["expected_accepted"]

    budget = max(120, count // 400)
    d, drained = _drain(produced, expected, base_gw, base_mock, base_os, budget)
    elapsed = time.time() - t0
    rps = produced / elapsed if elapsed else 0

    # -- per-component ledger (the "metrics via logging" the lab is for) ------
    print(f"\n================  TIER {tier.upper()}  (produced={produced})  ================")
    print(f"  tap (gigamon/arkime)  produced={produced:>8}  noise={noise:>7}  -> expected_accepted={expected}")
    print(f"  forensic  OpenSearch  docs=+{d['os']:>8}                         LOSS={produced - d['os']}")
    print(f"  broker    Redpanda    consumed(gateway received)=+{d['received']}")
    print(f"  gateway   received=+{d['received']}  filtered=+{d['filtered']}  accepted=+{d['accepted']}"
          f"  spooled=+{d['spooled']}  transmitted=+{d['transmitted']}  parse_err=+{d['parse_err']}")
    print(f"  ML sink   mock-ingress rows=+{d['mock']:>8}                      LOSS={expected - d['mock']}")
    print(f"  drained={drained}  in {elapsed:.1f}s  (~{rps:,.0f} sessions/s end-to-end)")
    print("=" * 64)

    forensic_loss = produced - d["os"]
    ml_loss = max(0, expected - d["mock"])

    def pct(n, base):
        return round(100.0 * n / base, 3) if base else 0.0

    # -- Tracker: a known count is "sent" then logged as it reaches each hop, so
    # the end results reconcile and show the % of data that traversed the pipeline.
    # The ML path narrows by the noise it intentionally drops (accounted, not lost);
    # every hop AFTER the filter must hold 100% of the accepted set.
    stages = [
        {"hop": "1_tap_sent",        "component": "Gigamon tap / Arkime (mock)",  "count": produced,        "pct_of_sent": 100.0},
        {"hop": "2_forensic_os",     "component": "OpenSearch (forensic path)",   "count": d["os"],         "pct_of_sent": pct(d["os"], produced)},
        {"hop": "3_broker_gateway",  "component": "Redpanda → gateway (received)","count": d["received"],   "pct_of_sent": pct(d["received"], produced)},
        {"hop": "4_filter_accepted", "component": "gateway filter (non-noise)",   "count": d["accepted"],   "pct_of_sent": pct(d["accepted"], produced), "pct_of_accepted": pct(d["accepted"], expected)},
        {"hop": "5_spool_sqlite",    "component": "SQLite WAL spool",             "count": d["spooled"],    "pct_of_accepted": pct(d["spooled"], expected)},
        {"hop": "6_transmit_parquet","component": "Parquet → HTTPS",              "count": d["transmitted"],"pct_of_accepted": pct(d["transmitted"], expected)},
        {"hop": "7_ml_sink",         "component": "Nexus/Axum ingress (ML sink)", "count": d["mock"],       "pct_of_accepted": pct(d["mock"], expected)},
    ]
    traversal = {
        "forensic_path_pct": pct(d["os"], produced),         # of everything sent -> must be 100
        "ml_path_pct": pct(d["transmitted"], expected),      # of the accepted set -> must be 100
        "ml_sink_delivered_pct": pct(d["mock"], expected),   # rows actually landed at the sink -> 100
        "noise_filtered_pct": pct(d["filtered"], produced),  # intentionally dropped (accounted)
    }
    conserved = (
        drained
        and d["received"] == produced
        and d["parse_err"] == 0
        and d["filtered"] + d["accepted"] == d["received"]
        and d["accepted"] == expected
        and d["spooled"] == d["accepted"]
        and d["transmitted"] == d["accepted"]
        and ml_loss == 0
        and forensic_loss == 0
    )

    # log the tracker waterfall (data logged as it reaches each component)
    print("  TRACKER (sent → each hop):")
    for s in stages:
        extra = f"  ({s['pct_of_accepted']}% of accepted)" if "pct_of_accepted" in s else ""
        sent_pct = f"{s.get('pct_of_sent', ''):>6}% of sent" if "pct_of_sent" in s else ""
        print(f"    {s['hop']:<18} {s['component']:<34} {s['count']:>9}  {sent_pct}{extra}")
    print(f"  TRAVERSAL  forensic={traversal['forensic_path_pct']}%  "
          f"ml={traversal['ml_path_pct']}%  ml_sink={traversal['ml_sink_delivered_pct']}%  "
          f"(noise filtered={traversal['noise_filtered_pct']}%)")

    # ── component log snippets: each box on the diagram, proven from its own log ──
    evidence = {
        "tap_gigamon (loadgen)": [json.dumps(led)],
        "broker (redpanda)": log_snippet("redpanda", ["arkime-spi-raw", "Successfully", "Leader", "kafka"], n=2),
        "gateway spool (SQLite WAL)": log_snippet("ml-gateway", ["spooled batch"], n=2),
        "gateway transmit (Parquet→HTTPS)": log_snippet("ml-gateway", ["transmitted Parquet batch"], n=2),
        "ML sink (mock nexus ingress)": log_snippet("mock-ingress", ["[mock-ingress] batch"], n=3),
        "forensic (opensearch)": [f"index {OS_INDEX}: {d['os']} docs (verified via _count API)"],
    }
    print("  COMPONENT EVIDENCE (from each container's own log):")
    for comp, lines in evidence.items():
        for ln in lines:
            print(f"    [{comp}] {ln[:160]}")

    record = {
        "tier": tier, "produced": produced, "noise": noise, "expected_accepted": expected,
        "tracker": stages,
        "traversal_pct": traversal,
        "evidence": evidence,
        "components": {
            "tap_gigamon": {"produced": produced, "noise": noise},
            "forensic_opensearch": {"docs": d["os"]},
            "broker_redpanda": {"consumed_by_gateway": d["received"]},
            "gateway": {
                "received": d["received"], "filtered": d["filtered"], "accepted": d["accepted"],
                "spooled": d["spooled"], "transmitted": d["transmitted"], "parse_errors": d["parse_err"],
            },
            "ml_sink_mock_ingress": {"rows": d["mock"]},
        },
        "data_loss": {"forensic_path": forensic_loss, "ml_path": ml_loss},
        "drained": drained,
        "elapsed_sec": round(elapsed, 1),
        "throughput_sessions_per_sec": round(rps),
        "verdict": "PASS" if conserved else "FAIL",
    }
    write_result(record)

    # -- conservation: nothing lost on EITHER path ---------------------------
    assert drained, f"pipeline did not drain tier {tier} within {budget}s: {d}"
    assert d["received"] == produced, "broker→gateway lost messages"
    assert d["parse_err"] == 0, "gateway failed to parse mock SPI"
    assert d["filtered"] + d["accepted"] == d["received"], "gateway accounting leak"
    assert d["accepted"] == expected, f"noise filter mismatch: {d['accepted']} != {expected}"
    assert d["spooled"] == d["accepted"], "accepted→SQLite spool lost rows"
    assert d["transmitted"] == d["accepted"], "spool→Nexus transmit lost rows"
    assert ml_loss == 0, "ML-path sink received fewer rows than accepted (DATA LOSS)"
    assert forensic_loss == 0, "forensic-path (OpenSearch) lost sessions (DATA LOSS)"
