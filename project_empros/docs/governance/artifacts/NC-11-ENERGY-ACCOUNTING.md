# NC-11-ENERGY-ACCOUNTING — Per-run inference energy accounting

*Implementation: `analytics/llm_hunter/agents/energy_accounting.py`*

Deterministic per-run energy (Wh) and carbon (gCO2e): power × time × PUE, with an explicit grid-intensity factor.

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

Each run's estimate is appended to an energy ledger the MLOps metric plane rolls up via totals().

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
