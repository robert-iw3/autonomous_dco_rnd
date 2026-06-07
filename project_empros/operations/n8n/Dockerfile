FROM docker.io/n8nio/n8n:latest
USER root

# Base tools: SSH client for linux/windows playbooks; python3 for JSON output
RUN apk add --no-cache \
    openssh-client \
    python3 \
    curl \
    unzip \
    bash \
    jq

# -- AWS CLI v2 -----------------------------------------------------------------
# Alpine uses musl libc; AWS CLI v2 ships a bundled glibc interpreter.
# We install the official musl-compatible build from awscli-alpine package or
# fall back to pip-installed awscli v1 which works on musl.
RUN apk add --no-cache py3-pip && \
    pip3 install --no-cache-dir awscli && \
    aws --version

# -- Azure CLI ------------------------------------------------------------------
# azure-cli is a Python package; install via pip (no repo package on Alpine).
RUN pip3 install --no-cache-dir azure-cli && \
    az --version

# -- Google Cloud SDK -----------------------------------------------------------
# Download the Alpine-compatible tarballed SDK and install to /usr/local/gcloud.
RUN curl -fsSL "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz" \
        -o /tmp/gcloud.tar.gz && \
    tar -xzf /tmp/gcloud.tar.gz -C /usr/local && \
    rm /tmp/gcloud.tar.gz && \
    /usr/local/google-cloud-sdk/install.sh \
        --quiet \
        --usage-reporting=false \
        --path-update=true \
        --bash-completion=false 2>/dev/null && \
    ln -sf /usr/local/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud && \
    ln -sf /usr/local/google-cloud-sdk/bin/gsutil /usr/local/bin/gsutil && \
    gcloud --version

USER node
