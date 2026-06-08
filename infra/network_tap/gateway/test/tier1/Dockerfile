# Tier 1 -- Build/compile + algorithmic validation (cargo check && cargo test)
#
# arkime-ml-gateway is a self-contained Rust binary crate (no path dependencies
# on sibling workspaces -- its "Integrity stamping" comment in Cargo.toml notes
# the HMAC code is "vendored locally" specifically to avoid a cross-workspace
# path dependency). The build context is therefore just the gateway crate dir.
#
# System deps mirror the production builder stage in ../../Dockerfile
# (cmake + pkg-config + libssl-dev + libsasl2-dev for rdkafka's
# cmake-build/ssl-vendored features), plus libsqlite3-dev for sqlx's
# sqlite feature and pkg-config-discovered native libs.

FROM docker.io/rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config libssl-dev libsasl2-dev \
        libcurl4-openssl-dev sqlite3 libsqlite3-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app/gateway

COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

ENV CARGO_TERM_COLOR=always

CMD ["sh", "-c", "cargo check && cargo test --bin arkime-ml-gateway -- --nocapture"]