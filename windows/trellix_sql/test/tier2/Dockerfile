FROM python:3.12-slim-bookworm

RUN \
    apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY test/tier2/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY transmit/      /app/transmit/
COPY test/tier2/    /app/tests/

ENV PYTHONPATH=/app/transmit

RUN mkdir -p /reports

CMD ["pytest", "/app/tests/", \
     "--ignore=/app/tests/Dockerfile", \
     "--ignore=/app/tests/run.sh", \
     "--ignore=/app/tests/requirements.txt", \
     "-v", "--tb=short", \
     "--junitxml=/reports/tier2_report.xml", \
     "--json-report", "--json-report-file=/reports/tier2_report.json"]