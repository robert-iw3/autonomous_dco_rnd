# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.23" \
    image_hash="4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b"

FROM ${repo}/${base_image}@sha256:${image_hash} AS builder

RUN apk add --no-cache \
    python3 \
    py3-pip \
    python3-dev \
    gcc \
    musl-dev \
    linux-headers \
    sqlite-dev

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

FROM ${repo}/${base_image}@sha256:${image_hash}

LABEL org.opencontainers.image.name='linux-sentinel-hud' \
      org.opencontainers.image.description='Web HUD for Linux Sentinel Security Monitoring Tool' \
      version="0.3.0" \
      maintainer="@RW"

RUN apk add --no-cache \
    python3 \
    sqlite-libs \
    bash \
    su-exec

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN addgroup -g 10001 sentinelgroup && \
    adduser -u 10001 -S sentinelui -G sentinelgroup -H -D

WORKDIR /app

COPY api_server.py /app/
COPY static/ /app/static/
COPY entrypoint.sh /app/

RUN chown -R sentinelui:sentinelgroup /app && \
    chmod 750 /app && \
    chmod -R 640 /app/static/* && \
    chmod 750 /app/api_server.py && \
    chown root:root /app/entrypoint.sh && \
    chmod 755 /app/entrypoint.sh

EXPOSE 8443
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", \
     "api_server:app", \
     "--host", "0.0.0.0", \
     "--port", "8443", \
     "--ssl-keyfile=/certs/dashboard_key.pem", \
     "--ssl-certfile=/certs/dashboard_cert.pem"]