# NC-10-VERDICT-LINEAGE — Tamper-evident verdict lineage

*Implementation: `analytics/llm_hunter/agents/verdict_ledger.py`*

SHA-256 hash chain over verdict records: each entry binds the previous hash, so any edit, deletion, or reorder is detected and the first broken index returned.

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

Durable append: every verdict is chained onto the prior entry's hash, giving autonomous-containment decisions a tamper-evident trail.

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
