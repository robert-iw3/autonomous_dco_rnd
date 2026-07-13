/**
 * /api/ti -- Proxy endpoints to worker_ti_ingest service.
 *
 * Routes:
 *   POST   /api/ti           Upload document (forwards multipart to ingest service)
 *   GET    /api/ti           List corpus documents + stats
 *   DELETE /api/ti?doc_id=X  Retract document
 *   GET    /api/ti/status    SSE stream of nexus.ti.status NATS events
 */

import { connect, StringCodec } from 'nats';
import type { RequestEvent } from '@sveltejs/kit';

const TI_INGEST_URL = process.env.TI_INGEST_URL || 'http://worker-ti-ingest:8010';
const NATS_URL      = process.env.NATS_URL       || 'nats://nats:4222';

// ── Upload ───────────────────────────────────────────────────────────────────

export async function POST({ request }: RequestEvent) {
    try {
        const formData = await request.formData();

        // Forward the multipart body directly to the ingest service
        const resp = await fetch(`${TI_INGEST_URL}/ingest`, {
            method:  'POST',
            body:    formData,
            signal:  AbortSignal.timeout(10_000),
        });

        const json = await resp.json();
        return new Response(JSON.stringify(json), {
            status:  resp.status,
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err: any) {
        return new Response(
            JSON.stringify({ error: `Ingest service unreachable: ${err.message}` }),
            { status: 502, headers: { 'Content-Type': 'application/json' } },
        );
    }
}

// ── Corpus list ───────────────────────────────────────────────────────────────

export async function GET({ url }: RequestEvent) {
    const action = url.searchParams.get('action');

    // SSE status stream
    if (action === 'status') {
        return statusStream();
    }

    // Corpus list
    try {
        const resp = await fetch(`${TI_INGEST_URL}/corpus`, {
            signal: AbortSignal.timeout(5_000),
        });
        const json = await resp.json();
        return new Response(JSON.stringify(json), {
            status:  resp.status,
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err: any) {
        return new Response(
            JSON.stringify({ error: `Ingest service unreachable: ${err.message}`,
                             stats: { total_docs: 0, total_chunks: 0, last_ingest_ts: 0 },
                             documents: [] }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
    }
}

// ── Retract document ─────────────────────────────────────────────────────────

export async function DELETE({ url }: RequestEvent) {
    const docId = url.searchParams.get('doc_id');
    if (!docId) {
        return new Response(JSON.stringify({ error: 'doc_id required' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    try {
        const resp = await fetch(`${TI_INGEST_URL}/document/${encodeURIComponent(docId)}`, {
            method: 'DELETE',
            signal: AbortSignal.timeout(10_000),
        });
        const json = await resp.json();
        return new Response(JSON.stringify(json), {
            status:  resp.status,
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (err: any) {
        return new Response(
            JSON.stringify({ error: err.message }),
            { status: 502, headers: { 'Content-Type': 'application/json' } },
        );
    }
}

// ── SSE status stream (NATS nexus.ti.status) ─────────────────────────────────

function statusStream() {
    let nc: any;
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

            try {
                nc = await connect({ servers: NATS_URL });
                const sc  = StringCodec();
                const sub = nc.subscribe('nexus.ti.status');

                (async () => {
                    for await (const msg of sub) {
                        if (closed) break;
                        try {
                            const data = JSON.parse(sc.decode(msg.data));
                            enqueue({ type: 'ti_status', ...data, ts: Date.now() });
                        } catch { /* non-JSON */ }
                    }
                })();
            } catch {
                enqueue({ type: 'ti_status', status: 'nats_unavailable', ts: Date.now() });
            }

            // Keepalive
            const ping = setInterval(() => enqueue({ type: 'ping', ts: Date.now() }), 15_000);
            (stream as any).__cleanup = () => {
                closed = true;
                clearInterval(ping);
                nc?.close();
            };
        },
        cancel() {
            if ((stream as any).__cleanup) (stream as any).__cleanup();
        },
    });

    return new Response(stream, {
        headers: {
            'Content-Type':  'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection':    'keep-alive',
            'X-Accel-Buffering': 'no',
        },
    });
}
