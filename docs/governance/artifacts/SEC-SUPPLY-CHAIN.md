# SEC-SUPPLY-CHAIN — Cryptographic model supply-chain integrity (SHA-384)

*Implementation: `mlops/serve_vllm.sh`*

**Execution chain:** Logic → Execution

**1. Logic** — SHA-384-verifies model weights against a signed integrity manifest; a mismatch aborts the launch.

`mlops/serve_vllm.sh:L48-L66`

```bash
verify_integrity() {
    local model_path="$1"
    local manifest="${model_path}/integrity_manifest.sha384"
    if [ ! -f "${manifest}" ]; then
        echo -e "${C_RED}[!] CRITICAL: Manifest missing at ${manifest}${C_RESET}"
        exit 1
    fi
    echo -e "[*] Validating SHA-384 signatures for ${model_path}..."
    if ! (cd "${model_path}" && sha384sum --status --check "integrity_manifest.sha384"); then
        echo -e "${C_RED}[!] CRITICAL: Integrity check failed — weights may be tampered.${C_RESET}"
        exit 1
    fi
    echo -e "${C_GREEN}[+] Integrity verified.${C_RESET}"
}

# ── Model dispatch ────────────────────────────────────────────────────────────
case "${MODEL_TYPE}" in

  model_a)
```

**2. Execution** — The check is invoked on the resolved model path at every server launch — no model is ever served unverified.

`mlops/serve_vllm.sh:L68-L69`

```bash
    MODEL_PATH=${MODEL_PATH:-"${MLOPS_BASE}/models/baseline"}
    verify_integrity "${MODEL_PATH}"
```
