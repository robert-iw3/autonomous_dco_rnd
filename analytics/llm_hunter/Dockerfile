# ──────────────────────────────────────────────────────────────────────────
# Layer-3 LLM Hunter -- glibc (Debian slim) multi-stage build.
#
# The embedding model is BAKED INTO THE IMAGE at build time so that, at
# air-gapped runtime, no Hugging Face network call is attempted (TRANSFORMERS_
# OFFLINE=1, HF_HUB_OFFLINE=1).
# ──────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Pre-bake the embedding model into a known cache directory.
ENV HF_HOME=/opt/hf
ARG NEXUS_EMBED_MODEL=all-MiniLM-L6-v2
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('${NEXUS_EMBED_MODEL}')"

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=UTC \
    PATH="/opt/venv/bin:$PATH" \
    HF_HOME=/opt/hf \
    TRANSFORMERS_OFFLINE=1 \
    HF_HUB_OFFLINE=1 \
    NEXUS_EMBED_MODEL=all-MiniLM-L6-v2

WORKDIR /app

RUN groupadd -g 1000 hunter \
    && useradd -u 1000 -g hunter -s /usr/sbin/nologin -M hunter \
    && mkdir -p /app/data \
    && chown -R hunter:hunter /app

# ── Optional internal-CA trust (on-prem MinIO / MISP self-signed TLS) ──
# Drop your internal root CA(s) as .crt files into the build context's ca/ dir.
# If ca/ contains no certs this is a harmless no-op -- no rebuild coupling. Once
# baked, the system bundle is trusted by DuckDB httpfs (OpenSSL), boto, and
# requests (the latter two via *_CA_BUNDLE env in hunter.env), so an https
# endpoint with a private CA works without disabling verification anywhere.
COPY ca/ /usr/local/share/ca-certificates/nexus-internal/
RUN update-ca-certificates 2>/dev/null || true

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder --chown=hunter:hunter /opt/hf /opt/hf
COPY --chown=hunter:hunter . .

USER hunter
ENTRYPOINT ["/opt/venv/bin/python", "orchestrator.py"]