# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/venv/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN \
    addgroup -g 65535 guarddog; \
    adduser --shell /sbin/nologin --disabled-password -h /home/guarddog --uid 65535 --ingroup guarddog guarddog; \
    apk add --no-cache bash python3-dev py3-pip musl-dev gcc linux-headers ca-certificates; \
    python3 -m venv /venv; \
    /venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel guarddog; \
    rm -rf /var/cache/apk/* /root/.cache/*

USER guarddog
CMD ["tail", "-f", "/dev/null"]