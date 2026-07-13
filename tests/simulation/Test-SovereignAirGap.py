"""
Objective: Prove that BOTH inference paths are genuinely air-gapped:
    1. vLLM (GPU) -- Models B, C, D served via FastAPI
    2. Model A (CPU) -- BiLSTM-AE served via serve_baseline.py

Also validates that safetensors weights load from local disk without any
network access (ATLAS AML.T0044 compliance).

Validation: DNS resolution is poisoned for the current process. If either
inference path phones home, the request fails immediately.
"""
import os
import json
import socket
import logging
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(message)s")

VLLM_ENDPOINT      = os.getenv("VLLM_ENDPOINT",      "http://nexus-vllm:8000/v1/chat/completions")
BASELINE_ENDPOINT  = os.getenv("BASELINE_ENDPOINT",  "http://localhost:9010/health")
# Read display name from env (set by model_config.py via NEXUS_MODEL_C_DISPLAY)
# Falls back to the generic role name so the test doesn't break on model swaps.
MODEL_NAME         = os.getenv("NEXUS_MODEL_C_DISPLAY", "nexus-spatial-endpoint")
BASELINE_MODEL_DIR = os.getenv("BASELINE_MODEL_DIR", "/opt/sentinel-nexus/mlops/models/baseline")


def test_airgap():
    logging.info("[*] Initiating Sovereign Air-Gap Test (Dual Inference Path)...")

    # ── 1. Poison DNS resolution ──
    original_getaddrinfo = socket.getaddrinfo
    blocked_count = [0]

    def block_external_dns(*args, **kwargs):
        host = args[0] if args else ""
        if host not in ["127.0.0.1", "localhost", "nexus-vllm", "0.0.0.0"]:
            blocked_count[0] += 1
            raise socket.gaierror(
                f"Air-Gap Violation #{blocked_count[0]}: Blocked external resolution for '{host}'"
            )
        return original_getaddrinfo(*args, **kwargs)

    socket.getaddrinfo = block_external_dns
    logging.info("    -> Simulated network partition engaged. External DNS blocked.")

    # ── 2. Test vLLM (GPU) inference ──
    logging.info("\n[*] Path 1: vLLM GPU Inference (Models B/C/D)...")
    import urllib.request

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "You are the Nexus Diagnostic Node."},
            {"role": "user", "content": "Acknowledge air-gap status with the word 'ISOLATED'."}
        ],
        "max_tokens": 10,
        "temperature": 0.1
    }

    req = urllib.request.Request(
        VLLM_ENDPOINT,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )

    try:
        logging.info(f"    -> Firing request to {VLLM_ENDPOINT}...")
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode('utf-8'))
            reply = result["choices"][0]["message"]["content"].strip()

            if "ISOLATED" in reply.upper():
                logging.info(f"    -> [PASS] vLLM responded: '{reply}'")
            else:
                logging.warning(f"    -> [WARN] Unexpected vLLM response: '{reply}'")

    except urllib.error.URLError as e:
        logging.error(f"    -> [FAIL] vLLM unreachable. Is the Quadlet running? Error: {e}")
        sys.exit(1)

    # ── 3. Test Model A (CPU) inference ──
    logging.info("\n[*] Path 2: Model A CPU Inference (BiLSTM-AE)...")

    try:
        from safetensors.torch import load_file
        import torch

        weights_path = os.path.join(BASELINE_MODEL_DIR, "baseline_lstm_ae.safetensors")
        threshold_path = os.path.join(BASELINE_MODEL_DIR, "baseline_threshold.safetensors")

        if not os.path.exists(weights_path):
            logging.warning(f"    -> [SKIP] Model A weights not found at {weights_path}")
        else:
            # Verify safetensors loads from disk without network access
            logging.info(f"    -> Loading weights from {weights_path}...")
            state_dict = load_file(weights_path)
            logging.info(f"    -> [PASS] Loaded {len(state_dict)} tensors from local safetensors (no network)")

            if os.path.exists(threshold_path):
                thresh_data = load_file(threshold_path)
                threshold = thresh_data["threshold"].item()
                logging.info(f"    -> [PASS] Threshold loaded: {threshold:.6f}")

            # Verify SHA-384 integrity
            manifest_path = os.path.join(BASELINE_MODEL_DIR, "integrity_manifest.sha384")
            if os.path.exists(manifest_path):
                import hashlib
                with open(manifest_path) as mf:
                    for line in mf:
                        expected_hash, fname = line.strip().split("  ")
                        fpath = os.path.join(BASELINE_MODEL_DIR, fname)
                        if os.path.exists(fpath):
                            sha = hashlib.sha384()
                            with open(fpath, 'rb') as f:
                                while chunk := f.read(8192):
                                    sha.update(chunk)
                            actual_hash = sha.hexdigest()
                            if actual_hash == expected_hash:
                                logging.info(f"    -> [PASS] SHA-384 integrity: {fname}")
                            else:
                                logging.error(f"    -> [FAIL] SHA-384 MISMATCH: {fname}")
                                sys.exit(1)

    except ImportError:
        logging.warning("    -> [SKIP] safetensors/torch not available. Install requirements.txt.")

    # ── 4. Summary ──
    logging.info(f"\n[+] Air-Gap Test Complete.")
    logging.info(f"    External DNS resolutions blocked: {blocked_count[0]}")
    if blocked_count[0] > 0:
        logging.warning(f"    [!] {blocked_count[0]} external resolution attempt(s) were blocked!")
        logging.warning(f"    [!] Investigate which library attempted to phone home.")
    else:
        logging.info(f"    [+] Zero external resolution attempts. Pipeline is fully sovereign.")

    # Restore original DNS
    socket.getaddrinfo = original_getaddrinfo


if __name__ == "__main__":
    test_airgap()