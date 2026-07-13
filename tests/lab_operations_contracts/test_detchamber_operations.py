"""
Lab operations -- Phase 6: Det Chamber observability + operator surface.

During an investigation the operator must see acquire → detonate → verdict, and
the platform Prometheus must scrape the intake service. These contracts wire the
detonation lifecycle into the operations stack.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROM = ROOT / "infrastructure" / "prometheus" / "prometheus.yml"
N8N = ROOT / "operations" / "n8n" / "workflows" / "Detonation.json"
WEBUI = ROOT / "operations" / "webui" / "config" / "config.yml"


def test_prometheus_scrapes_intake():
    t = PROM.read_text()
    assert "detchamber" in t.lower() or "det_chamber" in t.lower(), \
        "prometheus.yml must scrape the det_chamber intake service (DC-F5)"


def test_detonation_n8n_workflow_exists_and_valid():
    assert N8N.exists(), "operations/n8n/workflows/Detonation.json must exist"
    data = json.loads(N8N.read_text())          # must be valid JSON
    blob = json.dumps(data)
    assert "webhook" in blob.lower(), "the detonation workflow needs a webhook trigger"
    assert "detonation" in blob.lower()


def test_webui_surfaces_detonation():
    t = WEBUI.read_text().lower()
    assert "detonation" in t or "detchamber" in t or "det_chamber" in t, \
        "the operator workspace config must surface detonation status"
