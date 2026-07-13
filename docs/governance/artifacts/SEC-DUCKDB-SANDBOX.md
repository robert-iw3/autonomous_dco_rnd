# SEC-DUCKDB-SANDBOX — Read-only data-lake query sandbox

*Implementation: `analytics/llm_hunter/tools/duckdb_query.py`*

**Execution chain:** Invocation → Execution

**1. Invocation** — The agent-facing data-lake tool — the only path by which an LLM can query cold storage.

`analytics/llm_hunter/tools/duckdb_query.py:L27-L30`

```python
class DuckDBQueryTool(BaseTool):
    name: str = "query_parquet_data_lake"
    description: str = (
        "Executes a read-only DuckDB SQL query against the S3 cold storage data lake. "
```

**2. Execution** — Every call rejects anything but read-only SELECT and runs against a read-only connection with an auto LIMIT — the agent cannot mutate or exfiltrate the lake.

`analytics/llm_hunter/tools/duckdb_query.py:L78-L104`

```python
    def _run(self, reasoning: str, query: str) -> str:
        """Executes the query synchronously within a safe, ephemeral sandbox."""
        logger.info(f"[Tool Execution] Reasoning: {reasoning}")

        if self._FORBIDDEN.search(query):
            return ("SQL Error: Only read-only SELECT/DESCRIBE statements are permitted. "
                    "DDL, DML, and session-control statements are blocked in this sandbox.")
        if self._LOCAL_FS.search(query):
            return ("SQL Error: Local filesystem access is disabled. "
                    "Only s3://nexus-cold-storage/... sources are permitted.")

        is_describe = query.strip().upper().startswith("DESCRIBE")

        # ── Guardrail B: Token Overflow Protection ──
        if not is_describe and not re.search(r"\bLIMIT\b", query, re.IGNORECASE):
            query = f"{query}\nLIMIT {self.MAX_ROWS_LIMIT}"
            logger.debug(f"Auto-injected LIMIT {self.MAX_ROWS_LIMIT} to query.")

        # ── Ephemeral Sandbox Initialization (per-call, never shared) ──
        con = duckdb.connect(database=":memory:")
        try:
            con.execute("INSTALL httpfs; LOAD httpfs;")

            # ── Guardrail C: lock the sandbox down to S3 only ──
            # Block the local filesystem at the engine level (belt-and-suspenders
            # with the regex above). Supported on DuckDB >= 0.10.
            try:
```
