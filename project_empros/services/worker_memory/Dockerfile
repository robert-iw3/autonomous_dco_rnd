# worker_memory — consumes nexus.memory.intake, runs the IR memory analyzer in an
# ephemeral container, writes the WORM evidence record + nexus.memory.enrichment.
# Built with context = this directory (the memory_worker role rsyncs services/worker_memory/),
# matching the worker_ti_ingest convention. Needs the host container runtime mounted
# at runtime to spawn the analyzer; analysis image + toolkit staged offline (air-gap).
FROM docker.io/alpine:3.24

RUN apk add --no-cache python3 py3-pip
ENV PIP_BREAK_SYSTEM_PACKAGES=1 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY *.py .

RUN adduser -S -u 10072 nexus
USER nexus
ENTRYPOINT ["python3", "main.py"]