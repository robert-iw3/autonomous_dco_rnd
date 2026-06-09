FROM python:3.12-slim-bookworm

ARG TF_VERSION=1.9.5
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates git && \
    curl -fsSL "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip" \
        -o /tmp/tf.zip && \
    unzip /tmp/tf.zip -d /usr/local/bin && \
    rm /tmp/tf.zip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir checkov pytest
WORKDIR /workspace
COPY infra/vmware/ infra/vmware/
ENV PYTHONPATH=/workspace/infra/vmware/test
ENTRYPOINT ["pytest", "-v", "infra/vmware/test/tier2/"]