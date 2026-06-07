FROM docker.io/library/rust:slim

RUN \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        pkg-config \
        git; \
    rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-audit

WORKDIR /audit