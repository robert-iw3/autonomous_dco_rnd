# Tier 1 -- Build/compile + algorithmic validation (cargo check && cargo test)

FROM docker.io/rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev sqlite3 libsqlite3-dev \
        make clang llvm libelf-dev zlib1g-dev linux-headers-generic \
        automake autoconf libtool bison flex curl ca-certificates \
        bpftool linux-perf && \
    rm -rf /var/lib/apt/lists/*

ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib

RUN rustup component add rustfmt

WORKDIR /app

COPY linux/sentinel /app/linux/sentinel

COPY project_empros/middleware/config/sensor_profiles /app/project_empros/middleware/config/sensor_profiles

WORKDIR /app/linux/sentinel

ENV CARGO_TERM_COLOR=always

# Run the WHOLE suite (lib + binary unit tests + integration), not just one target,
# so the response/integrity/agent-task module #[cfg(test)] golden-vector tests --
# which recompute the HMAC and fail on any canonical/signing drift -- actually run.
CMD ["sh", "-c", "cargo check --features integrity && cargo test --features integrity -- --nocapture"]