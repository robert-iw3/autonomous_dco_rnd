FROM rust:1 AS builder
RUN rustup target add x86_64-unknown-linux-musl
# protobuf-compiler is required because google-cloud-pubsub pulls in tonic/prost.
RUN apt-get update && apt-get install -y musl-tools pkg-config libssl-dev gcc protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --target x86_64-unknown-linux-musl --release 2>/dev/null || true
COPY src ./src
RUN touch src/main.rs && cargo build --target x86_64-unknown-linux-musl --release

# NOTE: if the gRPC stack (tonic + ring/aws-lc) fails to link against musl,
# switch the target to x86_64-unknown-linux-gnu and the runtime base to a
# debian-slim image. The musl path is preferred for image size parity with the
# other connectors.

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -S nexus && adduser -S nexus -G nexus
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/nexus-gcp-audit-connector /app/connector
RUN mkdir -p /app/data/spool && chown -R nexus:nexus /app
USER nexus
ENV SPOOL_DIR=/app/data/spool
VOLUME ["/app/data/spool"]
ENTRYPOINT ["/app/connector"]