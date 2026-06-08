# Tier 1 -- Build/compile validation (cargo check && cargo test)

FROM docker.io/rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

ENV CARGO_TERM_COLOR=always

CMD ["sh", "-c", "cargo check && cargo test -- --nocapture"]