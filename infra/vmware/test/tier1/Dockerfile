FROM rust:1.78-slim-bookworm
WORKDIR /connector
COPY infra/vmware/ .
RUN cargo check 2>&1