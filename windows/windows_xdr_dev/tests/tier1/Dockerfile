# Tier 1 -- Rust workspace validation

FROM docker.io/rust:latest

RUN \
    rustup toolchain install nightly --profile minimal \
    && rustup default nightly \
    && rustup component add clippy rustfmt

WORKDIR /workspace

COPY Cargo.toml Cargo.lock* ./
COPY ml_ueba/Cargo.toml     ml_ueba/
COPY nexus_integrity/Cargo.toml nexus_integrity/
COPY transmission/Cargo.toml   transmission/

RUN \
    mkdir -p ml_ueba/src nexus_integrity/src transmission/src \
    && echo "pub fn _stub() {}" > ml_ueba/src/lib.rs \
    && echo "pub fn _stub() {}" > nexus_integrity/src/lib.rs \
    && echo "pub fn _stub() {}" > transmission/src/lib.rs \
    && cargo fetch --locked 2>/dev/null || cargo fetch

COPY . .

# Validate step -- run as a single layered RUN so exit code propagates.
# Each step gated: failures abort immediately.
RUN \
    set -e && \
    echo "=== [Tier1] cargo check workspace ===" && \
    cargo check --workspace --all-targets 2>&1 && \
    echo "=== [Tier1] cargo test -p xdr_nexus ===" && \
    cargo test -p xdr_nexus -- --nocapture 2>&1 && \
    echo "=== [Tier1] cargo test -p nexus_integrity ===" && \
    cargo test -p nexus_integrity -- --nocapture 2>&1 && \
    echo "=== [Tier1] cargo test -p xdr_ml_engine ===" && \
    cargo test -p xdr_ml_engine -- --nocapture 2>&1 && \
    echo "=== [Tier1] cargo clippy workspace ===" && \
    cargo clippy --workspace --all-targets -- \
        -D warnings \
        -A clippy::result_unit_err \
        -A clippy::missing_errors_doc \
        2>&1 && \
    echo "=== [Tier1] PASS ==="

CMD ["echo", "Tier 1 validation complete -- re-run 'docker build' to validate changes."]
