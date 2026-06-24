"""
Detection corpus + the lab's detection->mock-SIEM bindings, plus a prototype of the
mlops Track 9 spool (detection_training/ -> siem_analysis training examples).

The corpus loader reads REAL detection content from detection_training/ (Sigma YAML,
KQL, YARA-L) so the lab exercises real-world detection logic, and the spool turns that
content into query-authoring + result-analysis training examples (the wiring the WS-J
plan proposes for the live mlops pipeline).
"""
from __future__ import annotations

import random
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
DT = ROOT / "detection_training"

# ---- the lab's bound detections (raw query validated read-only; matcher selects rows) ----
# Matchers encode the detection logic over the mock datasets; benign rows are excluded.
LAB_DETECTIONS = [
    {
        "id": "web-shell-linux", "name": "Suspicious Process Spawned by Web Server",
        "siem": "splunk-prod", "product": "linux", "dialect": "spl",
        "raw_query": "search index=nexus_endpoint host=web-01 user=www-data "
                     "process IN (bash,whoami,curl,ssh) | table _time host user process dest_ip",
        "matcher": lambda e: e.get("host") == "web-01" and e.get("user") == "www-data"
                   and e.get("process") in ("bash", "whoami", "curl", "ssh"),
    },
    {
        "id": "iam-abuse-aws", "name": "Anomalous IAM Key Creation + Instance Modify",
        "siem": "elastic-cloud", "product": "aws", "dialect": "esql",
        "raw_query": "FROM nexus_cloud | WHERE user == \"svc_deploy\" | KEEP _time,user,src_ip,event_action,cloud_instance",
        "matcher": lambda e: e.get("user") == "svc_deploy",
    },
    {
        "id": "mshta-powershell-win", "name": "Encoded PowerShell via MSHTA",
        "siem": "sentinel-corp", "product": "windows", "dialect": "kql",
        "raw_query": "SecurityEvent | where ParentProcessName == \"mshta.exe\" and ProcessName == \"powershell.exe\"",
        "matcher": lambda e: e.get("parent_process") == "mshta.exe",
    },
    {   # benign control: matches only benign activity -> must adjudicate FP, no containment
        "id": "benign-logins", "name": "Interactive Logins (baseline)",
        "siem": "splunk-prod", "product": "linux", "dialect": "spl",
        "raw_query": "search index=nexus_endpoint action=login OR process=cron | table _time host user",
        "matcher": lambda e: e.get("action") == "login" or e.get("process") == "cron",
    },
]


def load_detection_corpus(max_per_siem: int = 50) -> list[dict]:
    """Read real detection files from detection_training/ -> [{path, siem, dialect, title, mitre}]."""
    corpus = []
    sources = [
        ("sigma", "sigma/custom", ("*.yml", "*.yaml")),
        ("sentinel", "kql/queries", ("*.kql",)),
        ("secops", "google-secops/rules", ("*.yaral", "*.yar")),
    ]
    for siem, sub, globs in sources:
        base = DT / sub
        if not base.exists():
            continue
        files = sorted(f for g in globs for f in base.rglob(g))[:max_per_siem]
        for f in files:
            text = f.read_text(errors="replace")
            mitre = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)
                               + [t.split(".")[-1].upper() for t in re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)", text)]))
            title = ""
            m = re.search(r"(?:^title:\s*|//\s*Name:\s*)(.+)", text, re.M)
            if m:
                title = m.group(1).strip()
            corpus.append({"path": str(f.relative_to(ROOT)), "siem": siem,
                           "dialect": {"sigma": "sigma", "sentinel": "kql", "secops": "yaral"}[siem],
                           "title": title or f.stem, "mitre": mitre})
    return corpus


def pick_detections(corpus: list[dict], n: int, seed: int = 1337) -> list[dict]:
    """Deterministic random sample across SIEMs (reproducible 'randomly pick' for CI)."""
    rng = random.Random(seed)
    return rng.sample(corpus, min(n, len(corpus)))


def spool_siem_analysis_examples(corpus: list[dict]) -> list[dict]:
    """Prototype mlops Track 9: each detection -> two training example families."""
    out = []
    for d in corpus:
        out.append({"track": "siem_analysis", "kind": "query_authoring",
                    "prompt": f"Author a read-only {d['dialect']} detection for: {d['title']}",
                    "labels": {"dialect": d["dialect"], "mitre": d["mitre"]}})
        out.append({"track": "siem_analysis", "kind": "result_analysis",
                    "prompt": f"Given results matching '{d['title']}', produce a finding + containment class.",
                    "labels": {"mitre": d["mitre"], "siem": d["siem"]}})
    return out
