# ==============================================================================
# PROJECT_EMPROS/Dockerfile
#
# Builds any workspace member from a single Dockerfile:
#   podman build --build-arg SERVICE=core_ingress      -t sentinel/core_ingress:v0.1 .
#   podman build --build-arg SERVICE=worker_qdrant     -t sentinel/worker_qdrant:v0.1 .
#   podman build --build-arg SERVICE=worker_s3_archive -t sentinel/worker_s3_archive:v0.1 .
#   podman build --build-arg SERVICE=worker_rules      -t sentinel/worker_rules:v0.1 .
#   podman build --build-arg SERVICE=worker_rlhf       -t sentinel/worker_rlhf:v0.1 .
#   podman build --build-arg SERVICE=worker_soar       -t sentinel/worker_soar:v0.1 .
#
# ==============================================================================

ARG SERVICE=core_ingress

# -- Stage 1: Dependency Cache -------------------------------------------------
FROM rust:1-slim-bookworm AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/nexus

COPY Cargo.toml Cargo.lock ./

COPY libs/lib_siem_core/Cargo.toml                 libs/lib_siem_core/Cargo.toml
COPY services/core_ingress/Cargo.toml              services/core_ingress/Cargo.toml
COPY services/worker_qdrant/Cargo.toml             services/worker_qdrant/Cargo.toml
COPY services/worker_s3_archive/Cargo.toml         services/worker_s3_archive/Cargo.toml
COPY services/worker_rules/Cargo.toml              services/worker_rules/Cargo.toml
COPY services/worker_rlhf/Cargo.toml               services/worker_rlhf/Cargo.toml
COPY services/worker_soar/Cargo.toml               services/worker_soar/Cargo.toml

RUN set -eux; \
    mkdir -p libs/lib_siem_core/src; \
    printf 'pub mod models;\n' > libs/lib_siem_core/src/lib.rs; \
    printf 'use serde::{Deserialize, Serialize};\n\
#[derive(Debug, Serialize, Deserialize, Clone)]\n\
pub struct DynamicUebaVector {\n\
    pub endpoint_id: String,\n\
    pub timestamp: String,\n\
    pub source_type: String,\n\
    pub vector_name: String,\n\
    pub vector_data: Vec<f32>,\n\
    pub raw_payload: serde_json::Value,\n\
}\n' > libs/lib_siem_core/src/models.rs; \
    for svc in core_ingress worker_qdrant worker_s3_archive worker_rules worker_rlhf worker_soar; do \
        mkdir -p "services/${svc}/src"; \
        echo 'fn main(){}' > "services/${svc}/src/main.rs"; \
    done

RUN cargo build --release --workspace 2>/dev/null; exit 0

# -- Stage 2: Build Actual Source ----------------------------------------------
FROM deps AS builder

ARG SERVICE=core_ingress

COPY libs/    libs/
COPY services/ services/

RUN touch libs/lib_siem_core/src/lib.rs && \
    find services/ -name "*.rs" -exec touch {} +

RUN cargo build --release -p "${SERVICE}"

RUN test -x "/usr/src/nexus/target/release/${SERVICE}" || \
    (echo "FATAL: Binary not found: target/release/${SERVICE}" && exit 1)

# -- Stage 3: Minimal Runtime -------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
ARG SERVICE=core_ingress
COPY --from=builder /usr/src/nexus/target/release/${SERVICE} /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]