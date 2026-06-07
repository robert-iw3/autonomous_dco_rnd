# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b"

FROM ${repo}/${base_image}@sha256:${image_hash} AS builder

RUN apk add --no-cache \
        build-base \
        pkgconf \
        openssl-dev \
        sqlite-dev

RUN apk add --no-cache \
        --repository=https://dl-cdn.alpinelinux.org/alpine/edge/main \
        --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
        rust \
        cargo

WORKDIR /build
COPY . .

RUN cargo build --release --bin api_server && \
    strip target/release/api_server

FROM ${repo}/${base_image}@sha256:${image_hash}

LABEL org.opencontainers.image.name='c2-sensor-api' \
      org.opencontainers.image.description='Web Dashboard for C2 Sensor' \
      version="0.7.0" \
      maintainer="@RW"

RUN apk add --no-cache \
        ca-certificates \
        libgcc \
        sqlite-libs \
        bash \
        su-exec; \
    update-ca-certificates

WORKDIR /app

COPY --from=builder /build/target/release/api_server /usr/local/bin/api_server
COPY ui/static/ /app/ui/static/

EXPOSE 8443
CMD ["api_server"]