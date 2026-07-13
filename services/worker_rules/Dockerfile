FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/nexus
COPY . .

RUN cargo build --release -p worker_rules

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /usr/src/nexus/target/release/worker_rules /worker_rules
USER nonroot:nonroot
EXPOSE 8080 9002
ENTRYPOINT ["/worker_rules"]