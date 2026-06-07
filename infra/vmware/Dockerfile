FROM rust:1 AS builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools pkg-config libssl-dev gcc && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --target x86_64-unknown-linux-musl --release 2>/dev/null || true
COPY src ./src
RUN touch src/main.rs && cargo build --target x86_64-unknown-linux-musl --release

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -S nexus && adduser -S nexus -G nexus
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/nexus-vmware-connector /app/connector
RUN mkdir -p /app/data/spool && chown -R nexus:nexus /app
USER nexus
ENV SPOOL_DIR=/app/data/spool
ENV SYSLOG_BIND=0.0.0.0:1514
# Syslog ingress. Bind >1024 so the non-root user can listen without
# CAP_NET_BIND_SERVICE; map 514->1514 at the Service/LB if 514 is required.
EXPOSE 1514/tcp
EXPOSE 1514/udp
VOLUME ["/app/data/spool"]
ENTRYPOINT ["/app/connector"]