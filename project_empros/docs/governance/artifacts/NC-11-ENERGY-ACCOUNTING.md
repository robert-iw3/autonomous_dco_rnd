# NC-11-ENERGY-ACCOUNTING — Per-run inference energy accounting

*Implementation: `analytics/llm_hunter/agents/energy_accounting.py`*

**Execution chain:** Invocation → Logic → Execution

**1. Invocation** — Wired into the terminal node: every investigation records a per-run energy/carbon estimate over the measured inference window (fail-soft).

`analytics/llm_hunter/agents/response.py:L182-L186`

```python
    try:
        energy_accounting.record_run(
            inference_s, NEXUS_AVG_POWER_W, event_id=event_id,
            ledger_path=os.getenv("NEXUS_ENERGY_LEDGER", energy_accounting.DEFAULT_LEDGER),
        )
```

**2. Logic** — Deterministic per-run energy (Wh) and carbon (gCO2e): power × time × PUE, with an explicit grid-intensity factor.

`analytics/llm_hunter/agents/controls.py:L506-L517`

```python
def estimate_inference_energy(duration_s, avg_power_w, pue: float = 1.5,
                              grid_gco2_per_kwh: float = 400.0) -> dict:
    """Per-run energy (Wh) and carbon (gCO2e) estimate. Negative inputs clamp to 0."""
    duration_s = max(0.0, float(duration_s))
    avg_power_w = max(0.0, float(avg_power_w))
    pue = float(pue)
    energy_wh = avg_power_w * (duration_s / 3600.0) * pue
    co2e_g = (energy_wh / 1000.0) * float(grid_gco2_per_kwh)
    return {
        "energy_wh": round(energy_wh, 6),
        "co2e_g": round(co2e_g, 6),
        "duration_s": duration_s,
```

**3. Execution** — Each run's estimate is appended to an energy ledger the MLOps metric plane rolls up via totals().

`analytics/llm_hunter/agents/energy_accounting.py:L23-L33`

```python
def record_run(duration_s, avg_power_w, event_id: str = "", pue: float = 1.5,
               grid_gco2_per_kwh: float = 400.0,
               ledger_path: str = DEFAULT_LEDGER) -> dict:
    """Estimate + append one run's energy/carbon. Returns the record."""
    rec = estimate_inference_energy(duration_s, avg_power_w, pue, grid_gco2_per_kwh)
    rec["event_id"] = event_id
    rec["ts"] = time.time()
    p = Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(rec) + "\n")
```
