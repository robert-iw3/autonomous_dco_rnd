# Tier 1 -- Build/compile validation (cargo check) for all 3 Azure connector crates
#
# nsg/activity/entraid are independent binary-only Rust crates (no path
# dependencies, no [lib]/src/lib.rs, no #[cfg(test)] unit tests -- confirmed
# via grep) sharing a near-identical dependency set (all pure-Rust / rustls-tls,
# no rdkafka/cmake/libcurl unlike network_tap). A single shared CARGO_TARGET_DIR
# lets the three builds reuse each other's compiled dependency artifacts.
#
# Build context is infra/azure/ (the parent of nsg/, activity/, entraid/, test/).

FROM docker.io/rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app/azure

COPY nsg/Cargo.toml nsg/Cargo.lock* nsg/
COPY nsg/src nsg/src
COPY activity/Cargo.toml activity/Cargo.lock* activity/
COPY activity/src activity/src
COPY entraid/Cargo.toml entraid/Cargo.lock* entraid/
COPY entraid/src entraid/src

ENV CARGO_TERM_COLOR=always
ENV CARGO_TARGET_DIR=/app/target

CMD ["sh", "-c", "set -e; for c in nsg activity entraid; do echo \"--- cargo check: $c ---\"; (cd $c && cargo check); done"]
