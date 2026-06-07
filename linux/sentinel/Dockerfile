# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b"

FROM ${repo}/${base_image}@sha256:${image_hash} AS builder

RUN apk add --no-cache \
        build-base \
        clang \
        clang-dev \
        llvm \
        linux-headers \
        libbpf-dev \
        zlib-dev \
        elfutils-dev \
        pkgconf \
        curl \
        bpftool \
        automake \
        autoconf \
        libtool \
        openssl-dev

RUN apk add --no-cache \
        --repository=https://dl-cdn.alpinelinux.org/alpine/edge/main \
        --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
        rust \
        cargo

ENV LIBCLANG_PATH="/usr/lib"

WORKDIR /usr/src/linux-sentinel

COPY . .

RUN cargo build --release && strip target/release/linux-sentinel

FROM ${repo}/${base_image}@sha256:${image_hash}

LABEL org.opencontainers.image.name='linux-sentinel' \
      org.opencontainers.image.description='Rust-based Linux Sentinel Security Monitoring Tool' \
      version="0.3.0" \
      maintainer="@RW"

RUN apk add --no-cache \
        ca-certificates \
        libgcc \
        libbpf \
        libelf \
        zlib \
        clamav && \
    update-ca-certificates && \
    printf '\nDatabaseOwner root\nDropPrivileges no\nForeground yes\n' >> /etc/clamav/freshclam.conf

COPY --from=builder /usr/src/linux-sentinel/target/release/linux-sentinel /opt/linux-sentinel/linux-sentinel

RUN mkdir -p /var/log/linux-sentinel/diagnostics \
             /var/backups/linux-sentinel/parquet \
             /opt/linux-sentinel/rules.d/yara \
             /opt/linux-sentinel/sigma/rules \
             /opt/linux-sentinel/intel \
             /var/lib/clamav && \
    chown -R clamav:clamav /var/lib/clamav && \
    chmod 770 /var/lib/clamav && \
    chmod 750 /var/log/linux-sentinel && \
    chmod 750 /var/log/linux-sentinel/diagnostics && \
    chmod -R 750 /var/backups/linux-sentinel /opt/linux-sentinel/rules.d && \
    chmod 755 /opt/linux-sentinel/linux-sentinel

WORKDIR /opt/linux-sentinel

ENV DASHBOARD_PORT=8080
ENTRYPOINT ["/opt/linux-sentinel/linux-sentinel"]
EXPOSE 8080