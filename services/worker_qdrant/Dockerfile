FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    build-essential \
    pkg-config \
    libssl-dev \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/nexus
COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl -p worker_qdrant

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /usr/src/nexus/target/x86_64-unknown-linux-musl/release/worker_qdrant /worker_qdrant
USER nonroot:nonroot
EXPOSE 8080 9001
ENTRYPOINT ["/worker_qdrant"]