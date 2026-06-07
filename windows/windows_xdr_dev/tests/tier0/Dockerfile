# Tier 0 -- Python logic tests

FROM docker.io/alpine:3.23

RUN \
    apk add --no-cache python3 py3-pip && \
    pip3 install --no-cache-dir --break-system-packages \
        pytest \
        pytest-cov \
        pytest-html \
        colorama

WORKDIR /app

COPY tests/requirements.txt   tests/requirements.txt
COPY tests/conftest.py        tests/conftest.py
COPY tests/tier0/             tests/tier0/
COPY tests/tier4/             tests/tier4/

COPY agent/DeepXDR_Config.ini agent/DeepXDR_Config.ini

# Expose reports mount point
VOLUME ["/app/tests/reports"]

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["python3", "-m", "pytest", \
     "tests/tier0", \
     "tests/tier4", \
     "-v", \
     "--tb=short", \
     "--color=yes", \
     "--cov=tests/tier0", \
     "--cov-report=term-missing"]
