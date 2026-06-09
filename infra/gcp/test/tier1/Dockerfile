# Tier 1 -- Build/compile validation (cargo check) for all 3 GCP connector crates

FROM docker.io/rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app/gcp

COPY audit/Cargo.toml audit/Cargo.lock* audit/
COPY audit/src audit/src
COPY scc/Cargo.toml scc/Cargo.lock* scc/
COPY scc/src scc/src
COPY vpc/Cargo.toml vpc/Cargo.lock* vpc/
COPY vpc/src vpc/src

ENV CARGO_TERM_COLOR=always
ENV CARGO_TARGET_DIR=/app/target

CMD ["sh", "-c", "set -e; for c in audit scc vpc; do echo \"--- cargo check: $c ---\"; (cd $c && cargo check); done"]