# worker_memory — pulls the DFIR platform's sealed findings projection, verifies it against
# the contract in dfir_platform/, and publishes nexus.memory.enrichment.
#
# Built with context = this directory (the memory_worker role rsyncs services/worker_memory/
# and then integrations/dfir_platform/ into dfir_platform/ beside it), matching the
# worker_ti_ingest convention. No container runtime and no object-store credentials: this
# worker neither analyzes evidence nor stores it — the platform does both.
FROM docker.io/alpine:3.24

RUN apk add --no-cache python3 py3-pip
ENV PIP_BREAK_SYSTEM_PACKAGES=1 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY *.py .
# The integration boundary. Same package name here as in the repo, so an import reads the
# same in a test and in production.
COPY dfir_platform/ ./dfir_platform/

# /var/lib/nexus holds the ledger of published bundle ids — what makes a re-delivered
# projection idempotent across a restart.
RUN adduser -S -u 10072 nexus \
    && mkdir -p /var/lib/nexus && chown nexus /var/lib/nexus
USER nexus
ENTRYPOINT ["python3", "main.py"]
