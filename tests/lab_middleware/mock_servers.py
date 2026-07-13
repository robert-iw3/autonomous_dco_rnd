#!/usr/bin/env python3
"""
mock_servers.py -- Lab 5 mock destination endpoints

Runs four HTTP servers on separate ports:
  :8088  Splunk HEC   POST /services/collector/event
  :8089  Nexus gateway mock  POST /api/v1/telemetry
  :9201  Elastic mock  POST /_bulk
  :9202  Control API   GET /health, POST /set-mode, GET /received/{dest}

All received requests are stored in-memory.
A control endpoint allows tests to:
  - Toggle destination failure mode (returns 500 instead of 200)
  - Read recorded requests per destination

Usage: python3 mock_servers.py
"""

import json
import threading
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer


# ── Shared state ──────────────────────────────────────────────────────────────

_lock = threading.Lock()
_received: dict[str, list[dict]] = defaultdict(list)
_fail_mode: dict[str, bool] = {
    "splunk": False,
    "elastic": False,
    "nexus": False,
}


def _record(dest: str, body: bytes, headers: dict) -> None:
    import base64
    with _lock:
        _received[dest].append({
            "body":    body.decode("utf-8", errors="replace"),
            "body_b64": base64.b64encode(body).decode(),
            "headers": headers,
        })


def _should_fail(dest: str) -> bool:
    with _lock:
        return _fail_mode.get(dest, False)


# ── Splunk HEC mock (:8088) ───────────────────────────────────────────────────

class SplunkHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_POST(self):
        if self.path != "/services/collector/event":
            self._send(404, b"Not Found")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        _record("splunk", body, dict(self.headers))
        if _should_fail("splunk"):
            self._send(500, json.dumps({"text": "internal error", "code": 8}).encode())
        else:
            self._send(200, json.dumps({"text": "Success", "code": 0}).encode())

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


# ── Elastic bulk mock (:9201) ─────────────────────────────────────────────────

class ElasticHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_POST(self):
        if not self.path.endswith("/_bulk"):
            self._send(404, b"Not Found")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        _record("elastic", body, dict(self.headers))
        if _should_fail("elastic"):
            self._send(500, json.dumps({"error": "simulated failure"}).encode())
        else:
            self._send(200, json.dumps({"took": 1, "errors": False, "items": []}).encode())

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


# ── Nexus gateway mock (:8089) ────────────────────────────────────────────────

class NexusHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200); self.end_headers(); self.wfile.write(b"OK")
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path != "/api/v1/telemetry":
            self._send(404, b"Not Found")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        _record("nexus", body, dict(self.headers))
        if _should_fail("nexus"):
            self._send(500, b"")
        else:
            self._send(202, b"")

    def _send(self, code, body):
        self.send_response(code)
        self.end_headers()
        self.wfile.write(body)


# ── Control API (:9202) ───────────────────────────────────────────────────────

class ControlHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok"})
        elif self.path.startswith("/received/"):
            dest = self.path.split("/received/", 1)[1]
            with _lock:
                data = list(_received.get(dest, []))
            self._json(200, {"dest": dest, "count": len(data), "requests": data})
        elif self.path == "/received":
            with _lock:
                summary = {k: len(v) for k, v in _received.items()}
            self._json(200, summary)
        elif self.path == "/fail-modes":
            with _lock:
                modes = dict(_fail_mode)
            self._json(200, modes)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        if self.path == "/set-mode":
            try:
                payload = json.loads(body)
                with _lock:
                    for dest, fail in payload.items():
                        _fail_mode[dest] = bool(fail)
                self._json(200, {"ok": True, "modes": dict(_fail_mode)})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif self.path == "/clear":
            with _lock:
                _received.clear()
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler_class, port):
    server = HTTPServer(("0.0.0.0", port), handler_class)
    print(f"[mock] {handler_class.__name__} listening on :{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    threads = [
        threading.Thread(target=_serve, args=(SplunkHandler,  8088), daemon=True),
        threading.Thread(target=_serve, args=(NexusHandler,   8089), daemon=True),
        threading.Thread(target=_serve, args=(ElasticHandler, 9201), daemon=True),
        threading.Thread(target=_serve, args=(ControlHandler, 9202), daemon=True),
    ]
    for t in threads:
        t.start()
    print("[mock] All endpoints ready", flush=True)
    for t in threads:
        t.join()
