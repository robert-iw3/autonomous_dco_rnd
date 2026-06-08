# Tier 1 -- Build/compile validation (cargo check) for all 3 AWS connector crates
#
# vpc/cloudtrail/guardduty are independent binary-only Rust crates (no path
# dependencies, no [lib]/src/lib.rs, no #[cfg(test)] unit tests -- confirmed
# via grep) sharing a near-identical dependency set (all pure-Rust / rustls-tls,
# no rdkafka/cmake/libcurl unlike network_tap). A single shared CARGO_TARGET_DIR
# lets the three builds reuse each other's compiled dependency artifacts.
#
# Build context is infra/aws/ (the parent of vpc/, cloudtrail/, guardduty/, test/).

FROM docker.io/rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app/aws

COPY vpc/Cargo.toml vpc/Cargo.lock* vpc/
COPY vpc/src vpc/src
COPY cloudtrail/Cargo.toml cloudtrail/Cargo.lock* cloudtrail/
COPY cloudtrail/src cloudtrail/src
COPY guardduty/Cargo.toml guardduty/Cargo.lock* guardduty/
COPY guardduty/src guardduty/src

ENV CARGO_TERM_COLOR=always
ENV CARGO_TARGET_DIR=/app/target

CMD ["sh", "-c", "set -e; for c in vpc cloudtrail guardduty; do echo \"--- cargo check: $c ---\"; (cd $c && cargo check); done"]
