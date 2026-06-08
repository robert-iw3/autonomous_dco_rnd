FROM docker.io/rust:1-bookworm AS builder

RUN apt-get -qq update && \
    apt-get install -yq --no-install-recommends \
    cmake pkg-config libssl-dev libsasl2-dev libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

RUN cargo build --release && \
    strip target/release/arkime-ml-gateway

FROM docker.io/debian:12-slim

RUN apt-get -qq update && \
    apt-get install -yq --no-install-recommends \
    libssl3 libsasl2-2 curl ca-certificates tini && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data/spool /data/config/certs && \
    useradd -r -s /usr/sbin/nologin gateway && \
    chown -R gateway:gateway /data

COPY --from=builder /build/target/release/arkime-ml-gateway /usr/local/bin/
COPY config.toml /data/config/config.toml

USER gateway
EXPOSE 9090

ENV GATEWAY_CONFIG="/data/config/config.toml"
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/arkime-ml-gateway"]
