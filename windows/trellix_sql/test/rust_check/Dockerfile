FROM rust:1-slim-bookworm AS deps

RUN \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Layer 1: resolve and cache dependencies ──────────────────────────────────
COPY sensor_middleware/core_ingress/Cargo.toml ./Cargo.toml
RUN \
    mkdir -p src && printf 'fn main() {}\n' > src/main.rs && \
    cargo fetch && \
    cargo check 2>&1 || true

# ── Layer 2: verify real source compiles ─────────────────────────────────────
COPY sensor_middleware/core_ingress/src ./src/
RUN cargo check 2>&1 && \
    echo "==> core_ingress cargo check: PASSED"