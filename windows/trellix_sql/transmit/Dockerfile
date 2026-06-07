FROM python:3.12-slim-bookworm

LABEL maintainer="@RW" \
      description="Trellix ENS transmission container: SQL → UEBA → Parquet → Nexus"

# Install mssql-tools18 + ODBC Driver 18 from local mirror
# In a production air-gap environment, copy the .deb packages to /opt/pkgs/
# and replace the apt commands below with:
#   dpkg -i /opt/pkgs/msodbcsql18*.deb /opt/pkgs/mssql-tools18*.deb

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        curl \
        gnupg2 \
        unixodbc \
        unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

# Microsoft ODBC 18 -- pull from local mirror or pre-baked layer.
# NOTE: Adjust the APT source URL to point to your internal mirror.
RUN curl -sSL https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor > /etc/apt/trusted.gpg.d/microsoft.gpg && \
    echo "deb [arch=amd64] https://packages.microsoft.com/debian/12/prod bookworm main" \
        > /etc/apt/sources.list.d/mssql.list && \
    apt-get update -qq && \
    ACCEPT_EULA=Y apt-get install -y --no-install-recommends \
        msodbcsql18 \
        mssql-tools18 \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/mssql-tools18/bin:$PATH"

# App
WORKDIR /app

COPY requirements.txt .

# Air-gap install: use local mirror if /opt/pip-mirror exists, else fall back to PyPI.
# In production: mount /opt/pip-mirror volume containing all wheels.
RUN if [ -d /opt/pip-mirror ]; then \
        pip install --no-index --find-links /opt/pip-mirror -r requirements.txt; \
    else \
        pip install --no-cache-dir -r requirements.txt; \
    fi

COPY ueba_engine.py schema.py reader.py config.json ./

# Persistence volume for SQLite WAL (frequency counter)
RUN mkdir -p /app/ueba_state
VOLUME ["/app/ueba_state"]

# Non-root user
RUN useradd -r -u 1001 transmit && chown -R transmit:transmit /app
USER transmit

ENV PYTHONUNBUFFERED=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_DATASETS_OFFLINE=1

ENTRYPOINT ["python", "reader.py"]
