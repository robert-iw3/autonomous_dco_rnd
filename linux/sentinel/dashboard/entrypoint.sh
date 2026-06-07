#!/bin/bash
set -e

until [ -f "/var/log/linux-sentinel/sentinel.db" ]; do
    echo "[*] Waiting for core agent to initialize telemetry database..."
    sleep 2
done

mkdir -p /var/log/linux-sentinel/dashboard
mkdir -p /app/data

echo "[+] Initializing API Server..."
exec "$@"