"""
Tamper-evident verdict lineage (NC-9; Risk 2.8 Information Integrity).

An append-only SHA-256 hash chain over verdict / audit records: each persisted
entry binds the previous entry's hash, so any post-hoc edit, deletion, or reorder
of the ledger breaks verification. Gives the swarm's autonomous-containment
decisions a verifiable, tamper-evident trail. Hash logic is the pure code in
`agents.controls`; this adds the durable append + whole-ledger verify.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from agents.controls import GENESIS_HASH, lineage_entry, verify_lineage

DEFAULT_LEDGER = os.getenv("NEXUS_VERDICT_LEDGER", "/var/lib/nexus/verdict_lineage_v1.jsonl")


def load_ledger(ledger_path: str = DEFAULT_LEDGER) -> List[Dict[str, Any]]:
    p = Path(ledger_path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def append_verdict(record: dict, ledger_path: str = DEFAULT_LEDGER) -> dict:
    """Append `record` as the next hash-chain entry. Returns the chain entry."""
    entries = load_ledger(ledger_path)
    prev = entries[-1]["entry_hash"] if entries else GENESIS_HASH
    entry = lineage_entry(prev, record)
    p = Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def verify_ledger(ledger_path: str = DEFAULT_LEDGER) -> dict:
    """Verify the whole persisted chain (valid / first broken index)."""
    return verify_lineage(load_ledger(ledger_path))
