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
        openssl-dev \
        sqlite-dev \
        python3 \
        py3-pip \
        python3-dev \
        musl-dev \
        py3-pyarrow \
        py3-numpy \
        py3-scikit-learn

RUN apk add --no-cache \
        --repository=https://dl-cdn.alpinelinux.org/alpine/edge/main \
        --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
        rust \
        cargo

ENV LIBCLANG_PATH="/usr/lib"

WORKDIR /build
COPY . .

RUN cd ebpf_probes && make

RUN cargo build --release \
        --bin telemetry_ingest \
        --bin core_hunter \
        --bin active_defender && \
    strip target/release/telemetry_ingest && \
    strip target/release/core_hunter && \
    strip target/release/active_defender

RUN python3 -m venv --system-site-packages /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --ignore-installed -r python_engine/requirements.txt

FROM ${repo}/${base_image}@sha256:${image_hash}

LABEL org.opencontainers.image.name='c2-sensor-core' \
      org.opencontainers.image.description='Alpine eBPF Full Stack for C2 Sensor' \
      version="0.7.0" \
      maintainer="@RW"

RUN apk add --no-cache \
        ca-certificates \
        libgcc \
        libstdc++ \
        libbpf \
        libelf \
        zlib \
        sqlite-libs \
        python3 \
        py3-pyarrow \
        py3-numpy \
        py3-scikit-learn \
        bash \
        iproute2; \
    update-ca-certificates

WORKDIR /app

COPY --from=builder /build/ebpf_probes/c2_probe.bpf.o /app/ebpf/probes/c2_probe.bpf.o
COPY --from=builder /build/target/release/telemetry_ingest /usr/local/bin/
COPY --from=builder /build/target/release/core_hunter /usr/local/bin/
COPY --from=builder /build/target/release/active_defender /usr/local/bin/
COPY --from=builder /opt/venv /opt/venv
COPY python_engine/ /app/python_engine/

ENV PATH="/opt/venv/bin:$PATH"
COPY deploy/start_core.sh /app/start_core.sh
RUN chmod +x /app/start_core.sh
CMD ["/app/start_core.sh"]