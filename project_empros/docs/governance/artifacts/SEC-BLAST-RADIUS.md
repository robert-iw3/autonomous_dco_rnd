# SEC-BLAST-RADIUS — Blast-radius cap & entity state machine

*Implementation: `analytics/llm_hunter/state.py`*

Entity state is a monotonic, conflict-resolving state machine; containment status only escalates, capping the blast radius of any single action.

`analytics/llm_hunter/state.py:L181-L211`

```python
def merge_entities(left: Dict[str, dict], right: Dict[str, dict]):
    """
    Intelligently updates entity status. If an entity is already 'malicious',
    it cannot be downgraded. Public resolvers / broadcast addresses in
    GLOBAL_DO_NOT_PIVOT are dropped at merge time so the blast radius can never
    explode through them (the "8.8.8.8 problem").
    """
    merged = {k: v for k, v in left.items() if str(k) not in GLOBAL_DO_NOT_PIVOT}

    # Severity hierarchy to prevent accidental downgrades.
    status_weights = {"pending": 0, "investigating": 1, "cleared": 2, "malicious": 3}

    for entity_id, new_data in right.items():
        if str(entity_id) in GLOBAL_DO_NOT_PIVOT:
            continue  # never track public infrastructure
        if entity_id not in merged:
            # Ensure a 'type' is always present so EntityTracking stays valid.
            merged[entity_id] = {"type": new_data.get("type", "ip"), **new_data}
        else:
            old_weight = status_weights.get(merged[entity_id].get("status", "pending"), 0)
            new_weight = status_weights.get(new_data.get("status", "pending"), 0)
            if new_weight > old_weight:
                merged[entity_id]["status"] = new_data["status"]
            if new_data.get("notes"):
                combined = f"{merged[entity_id].get('notes', '')} | {new_data['notes']}".strip(" |")
                # Bound note growth across many turns.
                merged[entity_id]["notes"] = combined[-800:]

    return merged

# ─── Context Window Manager ────────────────────────────────────────
```
