### Metrics Web HUD

Data pipeline dashboards + KPI metrics.

```
├── package.json
├── src/
│   ├── app.html
│   ├── lib/
│   │   └── stores.ts                     ← Full pipeline state: 7 stores + derived + helpers
│   └── routes/
│       ├── +page.svelte                  ← 6-view dashboard (overview, ingress, workers, storage, baseline, alerts)
│       └── api/
│           └── firehose/
│               └── +server.ts            ← SSE endpoint: NATS multi-subject + Prometheus scraping
├── tailwind.config.js
└── Dockerfile
```

**How it works end to end:**

The `+server.ts` SSE endpoint does two things in parallel. It subscribes to three NATS subject patterns (`nexus.hud.>`, `nexus.alerts.>`, `nexus.*.telemetry`) for real-time events, and every 2 seconds it scrapes Prometheus text metrics from all 6 service endpoints (core_ingress:9000, worker_qdrant:9001, worker_rules:9001, worker_s3_archive:9002, worker_soar:9003, worker_rlhf:9001). The Prometheus text format is parsed server-side into flat key→value maps and pushed to the client as SSE `data:` frames. Each worker endpoint URL is configurable via env vars.

The `stores.ts` file defines typed stores for every pipeline subsystem: `IngressMetrics` (18 fields covering every counter from core_ingress), `WorkerMetrics` (per-worker rate/total/latency/retries/DLQ/circuit breaker), `BaselineMetrics` (Model A flows/alerts/pairs/threshold), `S3Metrics`, `NatsMetrics`, `SystemHealth` (7 subsystem status indicators), and `TelemetryEvent` (alert firehose with all sensor/vector/MITRE fields). Derived stores compute `totalThroughput`, `totalErrors`, and `healthScore` (0-100) from the raw data. Throughput and error rate history arrays (60 data points) feed the sparkline chart.

The `+page.svelte` has 6 views, all driven by the same SSE stream:

**Overview** -- Four KPI cards (throughput/s, accepted, integrity verified, total errors), a Chart.js sparkline showing 60s throughput history, a 5-column worker fleet grid showing per-worker rate/DLQ/retries at a glance, and a 6-column integrity security summary (HMAC failures, replays, drift, cross-OS, banned, auth).

**Ingress Gateway** -- Deep dive into core_ingress. Three top-level cards (total requests, accepted with accept rate %, broker faults). Below that, a detailed breakdown of all 8 integrity violation types with descriptions explaining what each one means.

**Workers** -- One expanded card per worker (qdrant, rules, s3_archive, soar, rlhf). Each shows status badge, rate/s, total messages, batch latency, retries, DLQ count, and circuit breaker trips. The status dot glows green/amber/red with CSS box-shadow.

**Storage & Vector** -- Split view: S3/MinIO on the left (archived count, upload latency, failures), Qdrant on the right (named vector spaces and their dimensions, index types).

**Model A Baseline** -- Four cards (flows processed, alerts fired, tracked IP pairs, calibrated threshold). Below that, an architecture diagram showing the encoder/decoder/detection pipeline in three boxes.

**Alert Firehose** -- The existing telemetry table, upgraded with sensor type, vector name, and Model A reconstruction error columns. Clicking a row opens the slide-out inspector panel with command line, anomaly score, reconstruction error, destination IP, PID/PPID, and full raw JSON payload.

The sidebar shows the navigation, a health score bar (0-100 derived from how many of the 7 subsystems are online), individual subsystem status dots, and uptime counter.