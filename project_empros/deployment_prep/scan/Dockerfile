# syntax=docker/dockerfile:1
# syft: SBOM generator -- https://github.com/anchore/syft
# grype: Vulnerability scanner -- https://github.com/anchore/grype
ARG repo="docker.io" \
    base_image="alpine:latest" \
    image_hash="4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b"

FROM ${repo}/${base_image}@sha256:${image_hash} AS base

LABEL \
    org.opencontainers.image.name='Anchore Tools -- Sentinel Nexus' \
    org.opencontainers.image.description='Scan for Vulnerabilities and generate SBOM for all Nexus images.' \
    org.opencontainers.image.usage='https://anchore.com/opensource/' \
    org.opencontainers.image.url='https://anchore.com/opensource/' \
    org.opencontainers.image.vendor='Anchore' \
    org.opencontainers.image.licenses='Apache License 2.0' \
    org.opencontainers.image.schema-version='Grype 0.112.0, Syft 1.45.0'

FROM base AS go-builder

ENV SYFT_VER=1.45.0 \
    GRYPE_VER=0.112.0 \
    GOPATH=/usr/local/bin/go

RUN \
    apk add --no-cache -t .anchore-deps \
        ca-certificates \
        go \
        git; \
    apk add --no-cache -t .av-scan \
        clamav \
        freshclam; \
    mkdir -p ${GOPATH}/src/github.com/syft; \
    cd ${GOPATH}/src/github.com/syft; \
    git clone --depth 1 --branch v${SYFT_VER} https://github.com/anchore/syft; \
    export GO111MODULE=on; \
    cd syft/cmd/syft/; \
    go install; \
    mkdir -p ${GOPATH}/src/github.com/grype; \
    cd ${GOPATH}/src/github.com/grype; \
    git clone --depth 1 --branch v${GRYPE_VER} https://github.com/anchore/grype; \
    cd grype/cmd/grype; \
    go install; \
    apk del --no-network --purge .anchore-deps; \
    freshclam; \
    clamscan -rvi -l /clamav_scan.log --exclude-dir="^/sys|^/dev" /; \
    grep -Hrn FOUND /clamav_scan.log; \
    apk del --no-network --purge .av-scan; \
    rm -rf /var/cache/apk/*; \
    rm -rf ${GOPATH}/src/github.com

FROM base

RUN \
    addgroup -g 65535 anchore; \
    adduser --shell /sbin/nologin --disabled-password -h /home/anchore --uid 65535 --ingroup anchore anchore

COPY --chown=anchore:anchore --from=go-builder /usr/local/bin/go/bin/ /usr/local/bin
COPY --chown=anchore:anchore --from=go-builder /clamav_scan.log /home/anchore

WORKDIR /home/anchore/
USER anchore
