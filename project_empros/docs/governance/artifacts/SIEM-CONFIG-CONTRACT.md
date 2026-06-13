# SIEM-CONFIG-CONTRACT — SIEM config ↔ fanout index contract

*Implementation: `analytics/llm_hunter/tools/nexus_config.py`*

SIEM access is sovereign-by-default and double-gated; the allowed index set is the fan-out's own indexes plus an explicit operator allowlist.

`analytics/llm_hunter/tools/nexus_config.py:L118-L148`

```python
def get_siem_config(config: dict = None) -> dict:
    """
    Resolve the [siem] table into per-backend connection settings for the swarm's
    SiemQueryTool (WS-G).

    Sovereign-by-default + double-gated, mirroring [threat_intel].enabled_providers:
    a backend is *active* (reachable) only if it is listed in `enabled_backends`
    AND its token/api-key env var is set. An empty/absent [siem] table => the swarm
    has no SIEM surface at all (air-gapped default).

    `allowed_indexes` is `nexus_indexes | extra_indexes` — the fanned-out telemetry
    plus operator-approved OTHER sources the SIEM collects (firewall/proxy/IAM/...),
    since the CIM/ECS normalization lets the same query skills span both. Anything
    outside this set is rejected by the tool's index allowlist.

    Pass `config=` to resolve a synthetic config (tests); defaults to global CONFIG.
    """
    root = (CONFIG if config is None else config).get("siem", {}) or {}
    enabled = list(root.get("enabled_backends", []) or [])
    backends: dict = {}
    for name in enabled:
        bcfg = root.get(name)
        if not isinstance(bcfg, dict) or not bcfg:
            continue  # listed but undefined -> skip (never half-configure a backend)
        token_env = bcfg.get("token_env_var") or bcfg.get("apikey_env_var") or ""
        token = os.environ.get(token_env, "") if token_env else ""
        nexus_idx = list(bcfg.get("nexus_indexes", []) or [])
        extra_idx = list(bcfg.get("extra_indexes", []) or [])
        backends[name] = {
            "dialect": bcfg.get("dialect", ""),
            "search_url": bcfg.get("search_url", ""),
```
