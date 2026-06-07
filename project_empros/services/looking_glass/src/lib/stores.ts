import { writable, derived } from 'svelte/store';

// -- Types --------------------------------------------------------------------

export interface WorkerMetrics {
    name: string;
    status: 'online' | 'degraded' | 'offline';
    messagesTotal: number;
    messagesRate: number;      // per second
    batchLatencyMs: number;
    retries: number;
    dlqRouted: number;
    circuitBreakerTrips: number;
    lastSeen: number;          // epoch ms
}

export interface IngressMetrics {
    requestsTotal: number;
    requestsRate: number;
    acceptedTotal: number;
    authFailures: number;
    integrityVerified: number;
    hmacFailures: number;
    replayDetections: number;
    temporalDrift: number;
    crossOsCollisions: number;
    bannedAttempts: number;
    parquetParseFailures: number;
    brokerFaults: number;
    payloadTooLarge: number;
    latencyP50Ms: number;
    latencyP99Ms: number;
}

export interface NatsMetrics {
    streamMessages: number;
    streamBytes: number;
    consumers: number;
    pendingMessages: number;
    redeliveredMessages: number;
}

export interface BaselineMetrics {
    flowsProcessed: number;
    alertsFired: number;
    trackedPairs: number;
    avgReconError: number;
    threshold: number;
}

export interface S3Metrics {
    eventsArchived: number;
    uploadFailures: number;
    uploadLatencyMs: number;
    partialFailures: number;
}

export interface TelemetryEvent {
    timestamp: number;
    sensorId: string;
    sensorType: string;
    vectorName: string;
    anomalyScore: number;
    level: string;
    mitreTactic?: string;
    mitreTechnique?: string;
    process?: string;
    commandLine?: string;
    destIp?: string;
    pid?: number;
    ppid?: number;
    reconstructionError?: number;
    raw?: any;
}

export interface SystemHealth {
    ingress: 'online' | 'degraded' | 'offline';
    nats: 'online' | 'degraded' | 'offline';
    qdrant: 'online' | 'degraded' | 'offline';
    redis: 'online' | 'degraded' | 'offline';
    s3: 'online' | 'degraded' | 'offline';
    modelA: 'online' | 'degraded' | 'offline';
    vllm: 'online' | 'degraded' | 'offline';
}

// -- Stores -------------------------------------------------------------------

export const workers = writable<Record<string, WorkerMetrics>>({
    worker_qdrant:     emptyWorker('worker_qdrant'),
    worker_rules:      emptyWorker('worker_rules'),
    worker_s3_archive: emptyWorker('worker_s3_archive'),
    worker_soar:       emptyWorker('worker_soar'),
    worker_rlhf:       emptyWorker('worker_rlhf'),
});

export const ingress = writable<IngressMetrics>({
    requestsTotal: 0, requestsRate: 0, acceptedTotal: 0,
    authFailures: 0, integrityVerified: 0, hmacFailures: 0,
    replayDetections: 0, temporalDrift: 0, crossOsCollisions: 0,
    bannedAttempts: 0, parquetParseFailures: 0, brokerFaults: 0,
    payloadTooLarge: 0, latencyP50Ms: 0, latencyP99Ms: 0,
});

export const natsMetrics = writable<NatsMetrics>({
    streamMessages: 0, streamBytes: 0, consumers: 0,
    pendingMessages: 0, redeliveredMessages: 0,
});

export const baseline = writable<BaselineMetrics>({
    flowsProcessed: 0, alertsFired: 0, trackedPairs: 0,
    avgReconError: 0, threshold: 0.05,
});

export const s3Metrics = writable<S3Metrics>({
    eventsArchived: 0, uploadFailures: 0,
    uploadLatencyMs: 0, partialFailures: 0,
});

export const telemetryStream = writable<TelemetryEvent[]>([]);

export const systemHealth = writable<SystemHealth>({
    ingress: 'offline', nats: 'offline', qdrant: 'offline',
    redis: 'offline', s3: 'offline', modelA: 'offline', vllm: 'offline',
});

// Throughput history for sparklines (last 60 data points = 60 seconds)
export const throughputHistory = writable<number[]>(new Array(60).fill(0));

// Error rate history
export const errorHistory = writable<number[]>(new Array(60).fill(0));

// -- Derived ------------------------------------------------------------------

export const totalThroughput = derived(workers, ($w) =>
    Object.values($w).reduce((sum, w) => sum + w.messagesRate, 0)
);

export const totalErrors = derived([ingress, workers], ([$i, $w]) => {
    const workerErrors = Object.values($w).reduce((s, w) => s + w.dlqRouted + w.retries, 0);
    return $i.hmacFailures + $i.crossOsCollisions + $i.brokerFaults + workerErrors;
});

export const healthScore = derived(systemHealth, ($h) => {
    const values = Object.values($h);
    const online = values.filter(v => v === 'online').length;
    return Math.round((online / values.length) * 100);
});

// -- Helpers ------------------------------------------------------------------

function emptyWorker(name: string): WorkerMetrics {
    return {
        name, status: 'offline', messagesTotal: 0, messagesRate: 0,
        batchLatencyMs: 0, retries: 0, dlqRouted: 0,
        circuitBreakerTrips: 0, lastSeen: 0,
    };
}

export function appendTelemetry(event: TelemetryEvent, maxLimit = 500) {
    telemetryStream.update(current => {
        const updated = [event, ...current];
        return updated.slice(0, maxLimit);
    });
}

export function pushThroughput(rate: number) {
    throughputHistory.update(h => {
        const next = [...h.slice(1), rate];
        return next;
    });
}

export function pushError(count: number) {
    errorHistory.update(h => {
        const next = [...h.slice(1), count];
        return next;
    });
}

// -- TI Intelligence stores ---------------------------------------------------

export interface TIDocument {
    doc_id:       string;
    filename:     string;
    source_type:  'pdf' | 'stix' | 'sigma' | 'jsonl' | 'ioc_csv';
    sensor_types: string[];
    chunk_count:  number;
    ingest_ts:    number;
}

export interface TICorpusStats {
    total_docs:    number;
    total_chunks:  number;
    last_ingest_ts: number;
}

export interface TIUploadEvent {
    job_id:    string;
    filename:  string;
    status:    'processing' | 'done' | 'error';
    chunks?:   number;
    doc_id?:   string;
    error?:    string;
    ts:        number;
}

export const tiDocuments = writable<TIDocument[]>([]);

export const tiStats = writable<TICorpusStats>({
    total_docs: 0, total_chunks: 0, last_ingest_ts: 0,
});

export const tiUploadLog = writable<TIUploadEvent[]>([]);

export const tiIngestUrl = writable<string>('');

export function appendTIUploadEvent(evt: TIUploadEvent) {
    tiUploadLog.update(log => [evt, ...log].slice(0, 100));
}

export async function refreshTICorpus(ingestUrl: string) {
    try {
        const resp = await fetch(`${ingestUrl}/corpus`);
        if (!resp.ok) return;
        const data = await resp.json();
        tiStats.set(data.stats ?? { total_docs: 0, total_chunks: 0, last_ingest_ts: 0 });
        tiDocuments.set(data.documents ?? []);
    } catch { /* service may not be up yet */ }
}