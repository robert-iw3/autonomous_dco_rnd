#!/usr/bin/env python3
"""
Mock Nexus / Axum ingress (nexus-edge stand-in) for the data-flow lab.

Receives the gateway's HTTPS Parquet POSTs, parses each body with pyarrow to count
ACTUAL rows (proving rows arrived, not just bytes), and logs a running total so the
lab shows the ML-path sink handling every accepted session. GET /stats returns the
running ledger for the driver.
"""
import io
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pyarrow.parquet as pq

LOCK = threading.Lock()
STATE = {"rows": 0, "batches": 0, "bytes": 0}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):  # silence default access log; we print our own
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        if self.path == "/stats":
            with LOCK:
                self._send(200, dict(STATE))
        else:
            self._send(200, {"ok": True})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            table = pq.read_table(io.BufferedReader(io.BytesIO(body)))
            rows = table.num_rows
        except Exception as e:
            self._send(400, {"error": f"bad parquet: {e}"})
            return
        with LOCK:
            STATE["rows"] += rows
            STATE["batches"] += 1
            STATE["bytes"] += len(body)
            total, batches = STATE["rows"], STATE["batches"]
        seq = self.headers.get("X-Batch-Sequence", "?")
        print(f"[mock-ingress] batch #{batches} seq={seq}: {rows} rows "
              f"({len(body)} B) -- running total {total} rows", flush=True)
        self._send(200, {"received": rows, "total": total})


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="/certs/mock-cert.pem", keyfile="/certs/mock-key.pem")
    srv = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("[mock-ingress] HTTPS ingress listening on :8443", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
