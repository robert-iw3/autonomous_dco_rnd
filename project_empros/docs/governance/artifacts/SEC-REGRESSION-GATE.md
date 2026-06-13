# SEC-REGRESSION-GATE — Deterministic regression / deploy gate

*Implementation: `mlops/scripts/03_eval_model.py`*

**Execution chain:** Logic → Execution

**1. Logic** — Deterministic regression gauntlet (OS-context, schema, injection, spatial, SIEM-pivot validity) over a locked corpus.

`mlops/scripts/03_eval_model.py:L312-L338`

```python
def run_regression_suite():
    logging.info(f"Loading merged spatial model from {MODEL_PATH}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        device_map="auto",
        torch_dtype=torch.bfloat16
    )

    logging.info(f"Loading Multi-Head Spatial Projector from {PROJECTOR_PATH}...")
    projector = SpatialProjector().to(model.device).to(torch.bfloat16)
    projector.load_state_dict(load_file(PROJECTOR_PATH))
    projector.eval()

    for name, dim in VECTOR_DIMS.items():
        logging.info(f"  Projector head '{name}': {dim}D → 4096D")

    projector_token_id = tokenizer.convert_tokens_to_ids(PROJECTOR_TOKEN)
    eval_data, vector_registry = load_eval_data()

    _run_gauntlet(tokenizer, model, projector, projector_token_id, eval_data, vector_registry)
    run_calibration_sweep(model, tokenizer, projector, projector_token_id, vector_registry, eval_data)
    logging.info("[+] Full eval suite (gauntlet + M-10 calibration) complete.")


if __name__ == "__main__":
    run_regression_suite()
```

**2. Execution** — Hard go/no-go: a candidate below the 99% zero-hallucination floor halts deployment (exit 1).

`mlops/scripts/03_eval_model.py:L198-L200`

```python
    if accuracy < 99.0:
        logging.critical("Model failed 'Zero-Hallucination' threshold. Deployment halted.")
        exit(1)
```
