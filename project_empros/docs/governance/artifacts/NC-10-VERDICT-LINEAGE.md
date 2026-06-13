# NC-10-VERDICT-LINEAGE — Tamper-evident verdict lineage

*Implementation: `analytics/llm_hunter/agents/verdict_ledger.py`*

**Execution chain:** Invocation → Logic → Logic → Execution

**1. Invocation** — Wired into the terminal node: every investigation hands its final verdict to the lineage append (fail-soft).

`analytics/llm_hunter/agents/response.py:L167-L177`

```python
    try:
        verdict_ledger.append_verdict(
            {
                "event_id": event_id,
                "is_true_positive": bool(verdict.get("is_true_positive")),
                "confidence": float(verdict.get("confidence", 0.0) or 0.0),
                "recommended_action": verdict.get("recommended_action", "monitor"),
                "report_sha256": hashlib.sha256((incident_report or "").encode("utf-8")).hexdigest(),
            },
            ledger_path=os.getenv("NEXUS_VERDICT_LEDGER", verdict_ledger.DEFAULT_LEDGER),
        )
```

**2. Logic** — Builds one chain entry binding a record to the previous entry's hash.

`analytics/llm_hunter/agents/controls.py:L480-L483`

```python
def lineage_entry(prev_hash, record) -> dict:
    """Build one chain entry linking `record` to `prev_hash` (genesis if None)."""
    prev = prev_hash or GENESIS_HASH
    return {"record": record, "prev_hash": prev, "entry_hash": _entry_hash(prev, record)}
```

**3. Logic** — Verifies the SHA-256 chain end to end; any edit, deletion, or reorder is detected and the first broken index returned.

`analytics/llm_hunter/agents/controls.py:L486-L496`

```python
def verify_lineage(entries) -> dict:
    """Verify the hash chain. Returns the first broken index (or None if valid)."""
    prev = GENESIS_HASH
    for i, e in enumerate(entries or []):
        if e.get("prev_hash") != prev:
            return {"valid": False, "broken_at": i, "reason": "prev_hash mismatch"}
        if e.get("entry_hash") != _entry_hash(prev, e.get("record")):
            return {"valid": False, "broken_at": i, "reason": "entry_hash mismatch"}
        prev = e["entry_hash"]
    return {"valid": True, "broken_at": None, "reason": ""}

```

**4. Execution** — Durable append: every verdict is chained onto the prior entry's hash on disk.

`analytics/llm_hunter/agents/verdict_ledger.py:L37-L46`

```python
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
```
