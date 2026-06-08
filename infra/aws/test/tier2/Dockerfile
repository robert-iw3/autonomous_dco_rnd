ARG TERRAFORM_VERSION=1.9
FROM docker.io/hashicorp/terraform:${TERRAFORM_VERSION} AS tf
FROM docker.io/python:3.12-slim-bookworm

COPY --from=tf /bin/terraform /usr/local/bin/terraform

RUN pip install --no-cache-dir \
        pytest \
        "moto[server]" \
        boto3 \
        checkov \
        cfn-lint \
        python-hcl2 \
        pyyaml

WORKDIR /work
COPY . /work

CMD ["python3", "-m", "pytest", "/work/test/tier2", "-v", "--tb=short", \
     "-p", "no:cacheprovider"]