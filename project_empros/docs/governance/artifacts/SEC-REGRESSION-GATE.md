# SEC-REGRESSION-GATE — Deterministic regression / deploy gate

*Implementation: `mlops/scripts/03_eval_model.py`*

Deterministic regression suite gates promotion: a candidate that regresses against the locked thresholds cannot be deployed.

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
