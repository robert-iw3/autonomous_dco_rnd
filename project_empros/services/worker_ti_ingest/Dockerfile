FROM python:3.13-slim

ENV TRANSFORMERS_OFFLINE=1 \
    HF_DATASETS_OFFLINE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .

# Pre-downloaded model volumes are mounted at these paths:
#   /opt/models/bge-m3          -- BAAI/bge-m3 embedding model
#   /opt/models/reranker        -- cross-encoder/ms-marco-MiniLM-L-6-v2
#   /opt/ti_index/              -- TurboVec .tq index (optional, rebuilt from Qdrant if missing)
VOLUME ["/opt/models", "/opt/ti_index"]

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8010/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010", \
     "--workers", "1", "--log-level", "info"]