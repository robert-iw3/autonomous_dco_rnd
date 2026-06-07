import { connect, StringCodec } from 'nats';

const NATS_URL = process.env.NATS_URL || 'nats://nats:4222';

// Worker Prometheus endpoints (metrics port per service)
const PROM_ENDPOINTS: Record<string, string> = {
    core_ingress:     process.env.INGRESS_METRICS_URL     || 'http://nexus-edge:9000/metrics',
    worker_qdrant:    process.env.QDRANT_METRICS_URL      || 'http://worker-qdrant:9001/metrics',
    worker_rules:     process.env.RULES_METRICS_URL       || 'http://worker-rules:9001/metrics',
    worker_s3_archive: process.env.S3_METRICS_URL         || 'http://worker-s3:9002/metrics',
    worker_soar:      process.env.SOAR_METRICS_URL        || 'http://worker-soar:9003/metrics',
    worker_rlhf:      process.env.RLHF_METRICS_URL        || 'http://worker-rlhf:9001/metrics',
};

// NATS subjects to subscribe to for real-time events
const NATS_SUBJECTS = [
    'nexus.hud.>',              // HUD-specific events
    'nexus.alerts.>',           // All alert subjects (baseline, synthetic, etc.)
    'nexus.*.telemetry',        // Sensor telemetry (wildcard all types)
];

export async function GET() {
    let nc: any;
    try {
        nc = await connect({ servers: NATS_URL });
    } catch (err) {
        return new Response(JSON.stringify({ error: 'NATS Connection Failed' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    const sc = StringCodec();
    let closed = false;

    const stream = new ReadableStream({
        async start(controller) {
            const enqueue = (payload: object) => {
                if (!closed) {
                    try {
                        controller.enqueue(`data: ${JSON.stringify(payload)}\n\n`);
                    } catch { /* controller closed */ }
                }
            };

            // ── NATS subscriptions ───────────────────────────────────────
            const subs = await Promise.all(
                NATS_SUBJECTS.map(subject => nc.subscribe(subject))
            );

            // Process NATS messages in background
            for (const sub of subs) {
                (async () => {
                    for await (const msg of sub) {
                        if (closed) break;
                        try {
                            const raw = sc.decode(msg.data);
                            const data = JSON.parse(raw);
                            enqueue({
                                type: 'nats_event',
                                subject: msg.subject,
                                ...data,
                            });
                        } catch {
                            // Non-JSON payload (binary Parquet) -- count it
                            enqueue({
                                type: 'nats_binary',
                                subject: msg.subject,
                                bytes: msg.data.length,
                            });
                        }
                    }
                })();
            }

            // ── Prometheus metric scraping (every 2 seconds) ─────────────
            const metricsInterval = setInterval(async () => {
                if (closed) return;

                const results: Record<string, any> = {};

                await Promise.all(
                    Object.entries(PROM_ENDPOINTS).map(async ([name, url]) => {
                        try {
                            const resp = await fetch(url, { signal: AbortSignal.timeout(2000) });
                            if (resp.ok) {
                                const text = await resp.text();
                                results[name] = parsePrometheusText(text);
                                results[name]._status = 'online';
                            } else {
                                results[name] = { _status: 'degraded' };
                            }
                        } catch {
                            results[name] = { _status: 'offline' };
                        }
                    })
                );

                enqueue({ type: 'metrics', workers: results, ts: Date.now() });
            }, 2000);

            // ── Keepalive ping (every 15 seconds) ────────────────────────
            const pingInterval = setInterval(() => {
                enqueue({ type: 'ping', ts: Date.now() });
            }, 15000);

            // ── NATS server health check (every 5 seconds) ──────────────
            const natsHealthInterval = setInterval(() => {
                const status = nc.isClosed() ? 'offline' : 'online';
                enqueue({ type: 'nats_health', status, ts: Date.now() });
            }, 5000);

            // Cleanup on stream cancel
            const cleanup = () => {
                closed = true;
                clearInterval(metricsInterval);
                clearInterval(pingInterval);
                clearInterval(natsHealthInterval);
                subs.forEach(s => s.unsubscribe());
            };

            // Store cleanup fn for cancel handler
            (stream as any).__cleanup = cleanup;
        },

        cancel() {
            closed = true;
            if ((stream as any).__cleanup) (stream as any).__cleanup();
            nc.close();
        },
    });

    return new Response(stream, {
        headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        },
    });
}

// ── Prometheus Text Format Parser ────────────────────────────────────────────
// Parses Prometheus exposition format into a flat key→value map.
// Only extracts counters and gauges (ignores histograms/summaries for now).

function parsePrometheusText(text: string): Record<string, number> {
    const metrics: Record<string, number> = {};

    for (const line of text.split('\n')) {
        if (line.startsWith('#') || line.trim() === '') continue;

        // Match: metric_name{labels} value
        // or:    metric_name value
        const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(?:\{[^}]*\})?\s+([\d.eE+-]+)/);
        if (match) {
            const name = match[1];
            const value = parseFloat(match[2]);
            if (!isNaN(value)) {
                metrics[name] = value;
            }
        }
    }

    return metrics;
}