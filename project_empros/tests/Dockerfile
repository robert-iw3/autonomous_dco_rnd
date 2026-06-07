FROM docker.io/alpine:3.23

RUN apk add --no-cache \
    python3 \
    python3-dev \
    py3-pip \
    gcc \
    g++ \
    musl-dev \
    linux-headers \
    libffi-dev \
    openssl-dev \
    gcompat \
    libstdc++

ENV PIP_BREAK_SYSTEM_PACKAGES=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_DATASETS_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

WORKDIR /app

# ── Layer 1: test framework + lightweight packages ─────────────────────────────
# Pinned to versions in tests/requirements.in; split from data/ML layers so
# bumping test helpers doesn't bust the large-download layers below.
RUN pip3 install --no-cache-dir \
    "pytest>=7.4.0" \
    "pytest-asyncio>=0.23.0" \
    "fakeredis>=2.20.0" \
    "nats-py>=2.7.0" \
    "pydantic>=2.7.1" \
    "requests>=2.31.0" \
    "aiohttp>=3.9.0" \
    "tomli>=2.0.1" \
    "redis>=5.0.0" \
    "httpx>=0.27.0" \
    "PyJWT>=2.8.0" \
    "numpy>=2.0.0"

# ── Layer 2: data packages ─────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir \
    "duckdb>=0.10.2" \
    "pandas>=2.2.0" \
    "pyarrow>=16.0.0" \
    "qdrant-client>=1.9.0"

# ── Layer 3: serialization + HuggingFace ecosystem ────────────────────────────
# safetensors installs without torch; torch is installed next so the torch
# backend is picked up automatically on subsequent imports.
RUN pip3 install --no-cache-dir \
    "safetensors>=0.4.2" \
    "transformers>=4.40.0" \
    "accelerate>=0.28.0" \
    "peft>=0.10.0" \
    "trl>=0.8.0"

# ── Layer 4: PyTorch CPU ───────────────────────────────────────────────────────
# CPU-only wheel from pytorch.org; gcompat above satisfies the glibc dependency.
# GPU/CUDA tests are guarded by pytest.importorskip("torch.cuda") in the suite.
RUN pip3 install --no-cache-dir \
    --index-url https://download.pytorch.org/whl/cpu \
    "torch>=2.3.0"

# ── Layer 5: bitsandbytes (quantization) ─────────────────────────────────────
# Best-effort: no CUDA available in this image so QLoRA tests will be skipped
# automatically via the SKIP_GPU_TESTS env var checked in the test suite.
RUN pip3 install --no-cache-dir bitsandbytes || \
    echo "[warn] bitsandbytes not installed -- quantization tests will be skipped"

# ── Project source ─────────────────────────────────────────────────────────────
COPY mlops/      /app/mlops/
COPY analytics/  /app/analytics/
COPY services/   /app/services/
COPY tests/      /app/tests/

# mlops/scripts is on PYTHONPATH so test_turbovec_mlops.py importlib loads work
ENV PYTHONPATH=/app/mlops/scripts:/app/analytics:/app

# ── Default command ────────────────────────────────────────────────────────────
# -m "not s3_live"   : skip tests that require a live MinIO/S3 endpoint
# --ignore simulation: simulation scripts are not pytest tests
# --ignore deploy    : deployment orchestration, not unit tests
# --ignore mlops_eval_minilab: has its own Dockerfile.eval
CMD ["python3", "-m", "pytest", "tests/", \
     "-v", "--tb=short", \
     "-m", "not s3_live", \
     "--ignore=tests/simulation", \
     "--ignore=tests/deploy", \
     "--ignore=tests/mlops_eval_minilab"]
