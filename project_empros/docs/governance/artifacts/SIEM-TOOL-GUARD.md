# SIEM-TOOL-GUARD — SIEM query tool — read-only / bounded / allowlist

*Implementation: `analytics/llm_hunter/tools/siem_query.py`*

**Execution chain:** Logic → Logic → Logic → Execution

**1. Logic** — Only read-only search verbs are permitted; any mutating/command pipeline is rejected.

`analytics/llm_hunter/tools/siem_query.py:L110-L128`

```python
def validate_readonly(query: str, dialect: str) -> Tuple[bool, str]:
    """Reject any query that could mutate the SIEM or run code. Pure."""
    q = (query or "").strip()
    if not q:
        return False, "empty query"
    if dialect == "spl":
        if _SPL_FORBIDDEN.search(q):
            return False, ("SPL generating/destructive command blocked (read-only sandbox): "
                           "delete/outputlookup/collect/sendalert/script/rest/run/... are forbidden")
        if not _SPL_VALID_START.match(q):
            return False, "SPL must begin with a bounded retrieval (search/tstats/from/inputlookup/datamodel)"
        return True, ""
    if dialect in ("esql", "kql"):
        if not _ESQL_FROM.match(q):
            return False, "ES|QL must begin with a FROM source command (read-only)"
        # ES|QL has no write commands; the FROM-start check is the gate.
        return True, ""
    return False, f"unknown dialect '{dialect}'"

```

**2. Logic** — Queries may only touch allowlisted indexes (fnmatch) — the agent cannot exfiltrate from arbitrary SIEM data.

`analytics/llm_hunter/tools/siem_query.py:L142-L154`

```python
def validate_indexes(query: str, dialect: str, allowed: List[str]) -> Tuple[bool, str]:
    """Every referenced index must match the config allowlist (fnmatch, so
    wildcard allowlist entries like `logs-firewall-*` work). Pure."""
    refs = query_indexes(query, dialect)
    if not refs:
        return False, "query targets no index (an explicit index/FROM is required)"
    for idx in refs:
        if not any(fnmatch(idx, patt) or fnmatch(idx, f"{patt}*") for patt in allowed):
            return False, (f"index '{idx}' is not in the configured allowlist {allowed} "
                           f"-- only Nexus telemetry + operator-approved sources are reachable")
    return True, ""


```

**3. Logic** — Every query is force-bounded by a time window and a max-row cap before execution.

`analytics/llm_hunter/tools/siem_query.py:L155-L173`

```python
def enforce_bounds(query: str, dialect: str, window_hours: int, max_rows: int) -> str:
    """Force a time window + row cap onto a query that omitted them. Pure."""
    q = (query or "").strip()
    if dialect == "spl":
        if not _SPL_TIME.search(q):
            q = f"{q} earliest=-{window_hours}h"
        if not _SPL_HEAD.search(q):
            q = f"{q} | head {max_rows}"
        return q
    if dialect in ("esql", "kql"):
        if not _ESQL_TIME.search(q):
            q = f"{q} | WHERE @timestamp >= NOW() - {window_hours} hours"
        if not _ESQL_LIMIT.search(q):
            q = f"{q} | LIMIT {max_rows}"
        return q
    return q


# -- Query builders (generic entity pivot; the cookbook adds richer patterns) -
```

**4. Execution** — Wired into the tool's _run: a query is rejected unless it passes read-only + index-allowlist checks, then is force-bounded before any adapter runs it.

`analytics/llm_hunter/tools/siem_query.py:L348-L356`

```python
        ok, reason = validate_readonly(query, dialect)
        if not ok:
            return f"SIEM_QUERY_REJECTED: {reason}"
        ok, reason = validate_indexes(query, dialect, b.get("allowed_indexes", []))
        if not ok:
            return f"SIEM_QUERY_REJECTED: {reason}"

        bounded = enforce_bounds(query, dialect, siem.get("default_window_hours", 6),
                                 siem.get("max_rows", 200))
```
