# ==============================================================================
# Sentinel Nexus Middleware -- Multi-service image
# Build context: middleware/   (self-contained workspace, NO services involved)
#
# The middleware/Cargo.toml defines a standalone workspace covering only:
#   src/lib_etl, src/lib_middleware, src/core_ingress,
#   src/worker_nexus, src/worker_splunk, src/worker_elastic, src/worker_sql
#
# Uses glibc (not musl) because reqwest links OpenSSL dynamically.
# ==============================================================================

FROM docker.io/library/rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the middleware self-contained workspace
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

RUN cargo build --release \
        -p middleware_ingress \
        -p worker_nexus \
        -p worker_splunk \
        -p worker_elastic
        # -p worker_sql

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM docker.io/library/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system middleware \
    && adduser --system --ingroup middleware middleware

WORKDIR /app
COPY --from=builder /build/target/release/core_ingress   /app/core_ingress
COPY --from=builder /build/target/release/worker_nexus   /app/worker_nexus
COPY --from=builder /build/target/release/worker_splunk  /app/worker_splunk
COPY --from=builder /build/target/release/worker_elastic /app/worker_elastic
# COPY --from=builder /build/target/release/worker_sql     /app/worker_sql

RUN mkdir -p /var/lib/nexus-middleware && chown middleware:middleware /var/lib/nexus-middleware
USER middleware
ENV MIDDLEWARE_CONFIG=/config/middleware.toml
ENV STATE_DIR=/var/lib/nexus-middleware
ENTRYPOINT ["/app/core_ingress"]
