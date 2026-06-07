"""
Sentinel Nexus -- Mock EDR & Firewall Simulation Server
Configurable via CLI args or environment variables.
Supports health checks, request auditing, and latency simulation.
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Request, Path
from fastapi.responses import JSONResponse
import uvicorn

# -- Configuration --
PORT = int(os.getenv("NEXUS_MOCK_API_PORT", "9999"))
LATENCY_MS = int(os.getenv("NEXUS_MOCK_LATENCY_MS", "0"))
AUDIT_LOG = os.getenv("NEXUS_MOCK_AUDIT_LOG", "")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("nexus-mock")

app = FastAPI(title="Nexus Mock EDR & Firewall", version="2.0")
request_log: list[dict] = []


# -- Middleware: Latency simulation --
@app.middleware("http")
async def simulate_latency(request: Request, call_next):
    if LATENCY_MS > 0:
        await asyncio.sleep(LATENCY_MS / 1000.0)
    response = await call_next(request)
    return response


# -- Health Endpoint --
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "requests_served": len(request_log),
        "uptime_check": datetime.now(timezone.utc).isoformat()
    }


# -- Request Audit --
def audit(provider: str, action: str, target: str, success: bool, detail: str = ""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": provider,
        "action": action,
        "target": target,
        "success": success,
        "detail": detail,
    }
    request_log.append(entry)
    if AUDIT_LOG:
        try:
            with open(AUDIT_LOG, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except IOError:
            logger.warning(f"Failed to write audit log to {AUDIT_LOG}")


# -- 1. Mock EDR Provider (custom_edr_v1) --
@app.post("/v2/devices/isolate")
async def isolate_host(request: Request, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        audit("EDR", "isolate_host", "unknown", False, "Missing Bearer token")
        raise HTTPException(status_code=401, detail="Unauthorized: Bearer token required")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    target_ip = payload.get("target_ip")
    isolation_mode = payload.get("isolation_mode")
    audit_comment = payload.get("audit_comment", "No comment")

    if not target_ip:
        audit("EDR", "isolate_host", "missing", False, "No target_ip")
        raise HTTPException(status_code=400, detail="Missing target_ip field")

    if isolation_mode != "strict":
        audit("EDR", "isolate_host", target_ip, False, f"Invalid mode: {isolation_mode}")
        raise HTTPException(status_code=400, detail="isolation_mode must be 'strict'")

    logger.info(f"[EDR] Successfully isolated {target_ip}. Audit: {audit_comment}")
    audit("EDR", "isolate_host", target_ip, True, audit_comment)
    return {
        "status": "success",
        "action": "isolated",
        "target": target_ip,
        "mitigation_id": f"MOCK-EDR-{len(request_log):04d}",
    }


# -- 2. Mock Firewall Provider (custom_fw_v1) --
@app.put("/api/v1/objects/address/{target}")
async def block_ip(request: Request, target: str = Path(...), x_api_key: str = Header(None)):
    if not x_api_key:
        audit("FW", "block_ip", target, False, "Missing X-API-Key")
        raise HTTPException(status_code=401, detail="Unauthorized: X-API-Key required")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    name = payload.get("name")
    ip_netmask = payload.get("ip_netmask")
    description = payload.get("description", "")

    if not name:
        audit("FW", "block_ip", target, False, "Missing name")
        raise HTTPException(status_code=400, detail="Missing 'name' field")

    if not ip_netmask or not str(ip_netmask).endswith("/32"):
        audit("FW", "block_ip", target, False, f"Invalid netmask: {ip_netmask}")
        raise HTTPException(status_code=400, detail="/32 netmask required")

    logger.info(f"[FW] Successfully blocked {target} ({ip_netmask}) under rule '{name}'")
    audit("FW", "block_ip", target, True, description)
    return {
        "status": "success",
        "action": "blocked",
        "target": target,
        "rule_id": f"MOCK-FW-{len(request_log):04d}",
    }


# -- 3. Audit Dump (for test assertions) --
@app.get("/audit")
async def get_audit():
    return {"total": len(request_log), "entries": request_log}


# -- Graceful Shutdown --
def handle_signal(signum, frame):
    logger.info(f"Received signal {signum}. Shutting down gracefully...")
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nexus Mock Containment API")
    parser.add_argument("--port", type=int, default=PORT, help="Listen port")
    parser.add_argument("--latency", type=int, default=LATENCY_MS, help="Simulated latency (ms)")
    parser.add_argument("--audit-log", type=str, default=AUDIT_LOG, help="Path to audit log file")
    args = parser.parse_args()

    PORT = args.port
    LATENCY_MS = args.latency
    AUDIT_LOG = args.audit_log

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info(f"Starting mock API on port {PORT} (latency={LATENCY_MS}ms)")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")