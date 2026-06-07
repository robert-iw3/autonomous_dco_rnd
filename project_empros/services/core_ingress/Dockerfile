FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/nexus
COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl -p core_ingress

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /usr/src/nexus/target/x86_64-unknown-linux-musl/release/core_ingress /core_ingress
USER nonroot:nonroot
EXPOSE 8080 9000
ENTRYPOINT ["/core_ingress"]