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

COPY windows/windows_xdr_dev/Cargo.toml /app/windows/windows_xdr_dev/Cargo.toml
COPY windows/windows_xdr_dev/nexus_integrity /app/windows/windows_xdr_dev/nexus_integrity
COPY windows/windows_xdr_dev/ml_ueba /app/windows/windows_xdr_dev/ml_ueba
COPY windows/windows_xdr_dev/transmission /app/windows/windows_xdr_dev/transmission

COPY linux/sentinel /app/linux/sentinel

COPY project_empros/middleware/config/sensor_profiles /app/project_empros/middleware/config/sensor_profiles

WORKDIR /app/linux/sentinel

ENV CARGO_TERM_COLOR=always

CMD ["sh", "-c", "cargo check --features integrity && cargo test --features integrity --test test_sensor_pipeline -- --nocapture"]