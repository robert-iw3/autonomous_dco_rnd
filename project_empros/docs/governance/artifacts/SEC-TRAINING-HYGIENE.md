# SEC-TRAINING-HYGIENE — Training-data hygiene & credential scrubbing

*Implementation: `mlops/scripts/01_spool_datasets.py`*

**Execution chain:** Logic

**1. Logic** — Training-pipeline credentials are resolved from Vault (env fallback only for offline test) — no secrets are baked into the corpus or the code.

`mlops/scripts/01_spool_datasets.py:L47-L58`

```python
# Vault-backed credentials with env-var fallback for offline/test runs.
# vault_client raises VaultError if VAULT_TOKEN is unset; fallback prevents breaking tests.
def _vault_secret(path: str, env_var: str, default: str = "") -> str:
    if os.getenv("VAULT_TOKEN"):
        try:
            from vault_client import get_secret as _gs
            return _gs(path)
        except Exception as _e:
            logging.warning("vault: could not read %s, falling back to env (%s)", path, _e)
    return os.getenv(env_var, default)

S3_SECRET_KEY    = _vault_secret("nexus/s3/secret_key",     "S3_SECRET_KEY",    "ChangeMe123")
```
