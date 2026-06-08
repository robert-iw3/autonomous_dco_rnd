# Tier 1 -- Rust workspace build/compile validation (cargo check)
#
# Validates that the active_defender / api_server / core_hunter /
# shared_models / telemetry_ingest workspace members compile cleanly.
# Telemetry transmission itself lives in python_engine (covered by tier0);
# this tier guards the surrounding Rust agent against build regressions.

FROM docker.io/rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev sqlite3 libsqlite3-dev \
        make clang llvm libelf-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

ENV CARGO_TERM_COLOR=always

CMD ["cargo", "check", "--workspace"]
