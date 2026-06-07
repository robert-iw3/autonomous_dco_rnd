<script lang="ts">
    import { onMount } from 'svelte';
    import {
        workers, ingress, natsMetrics, baseline, s3Metrics,
        telemetryStream, systemHealth, throughputHistory, errorHistory,
        totalThroughput, totalErrors, healthScore,
        appendTelemetry, pushThroughput, pushError,
        tiDocuments, tiStats, tiUploadLog, appendTIUploadEvent, refreshTICorpus,
        type WorkerMetrics, type TelemetryEvent, type IngressMetrics,
        type TIDocument, type TIUploadEvent,
    } from '$lib/stores';
    import Chart from 'chart.js/auto';

    let activeView = 'overview';
    let selectedEvent: TelemetryEvent | null = null;
    let showInspector = false;
    let uptimeStart = Date.now();
    let now = Date.now();
    let sparkCanvas: HTMLCanvasElement;
    let sparkChart: Chart | null = null;

    // TI Intelligence state
    let tiUploading = false;
    let tiDragOver = false;
    let tiDropEl: HTMLElement;
    let tiSseSource: EventSource | null = null;
    const TI_API = '/api/ti';

    // ── TI helpers ───────────────────────────────────────────────────────
    async function tiUploadFile(file: File) {
        if (tiUploading) return;
        tiUploading = true;
        const fd = new FormData();
        fd.append('file', file);
        try {
            const resp = await fetch(TI_API, { method: 'POST', body: fd });
            const data = await resp.json();
            if (data.error) {
                appendTIUploadEvent({ job_id: '', filename: file.name,
                    status: 'error', error: data.error, ts: Date.now() });
            } else {
                appendTIUploadEvent({ job_id: data.job_id, filename: data.filename,
                    status: 'processing', ts: Date.now() });
            }
        } catch (e: any) {
            appendTIUploadEvent({ job_id: '', filename: file.name,
                status: 'error', error: e.message, ts: Date.now() });
        } finally {
            tiUploading = false;
        }
    }

    function tiHandleDrop(e: DragEvent) {
        e.preventDefault();
        tiDragOver = false;
        for (const f of Array.from(e.dataTransfer?.files ?? [])) tiUploadFile(f);
    }

    async function tiDeleteDoc(doc_id: string) {
        if (!confirm('Remove this document from the TI corpus?')) return;
        try {
            await fetch(`${TI_API}?doc_id=${encodeURIComponent(doc_id)}`, { method: 'DELETE' });
            await refreshTICorpus(TI_API);
        } catch { /* ignore */ }
    }

    function tiConnectSse() {
        if (tiSseSource) tiSseSource.close();
        tiSseSource = new EventSource(`${TI_API}?action=status`);
        tiSseSource.onmessage = (e) => {
            try {
                const d = JSON.parse(e.data);
                if (d.type === 'ti_status') {
                    appendTIUploadEvent({
                        job_id: d.job_id || '', filename: d.filename || '',
                        status: d.status || 'processing',
                        chunks: d.chunks, doc_id: d.doc_id, error: d.error,
                        ts: d.ts ?? Date.now(),
                    });
                    if (d.status === 'done' || d.status === 'error') refreshTICorpus(TI_API);
                }
            } catch { /* ping frame */ }
        };
    }

    function fmtTime(ms: number): string { return new Date(ms).toLocaleTimeString(); }
    function fmtSrc(t: string): string {
        return ({ pdf:'PDF', stix:'STIX', sigma:'Sigma', jsonl:'JSONL', ioc_csv:'IOC CSV' } as Record<string,string>)[t] ?? t.toUpperCase();
    }

    // ── SSE Connection ───────────────────────────────────────────────────
    onMount(() => {
        const es = new EventSource('/api/firehose');
        const uptimeTick = setInterval(() => now = Date.now(), 1000);
        tiConnectSse();
        refreshTICorpus(TI_API);

        es.onmessage = (event) => {
            const data = JSON.parse(event.data);

            if (data.type === 'metrics') {
                processMetrics(data.workers);
            }

            if (data.type === 'nats_event') {
                if (data.subject?.includes('alerts')) {
                    appendTelemetry(mapAlertEvent(data));
                }
            }

            if (data.type === 'nats_health') {
                systemHealth.update(h => ({ ...h, nats: data.status }));
            }
        };

        es.onerror = () => {
            systemHealth.update(h => ({ ...h, nats: 'degraded' }));
        };

        return () => {
            es.close();
            tiSseSource?.close();
            clearInterval(uptimeTick);
            sparkChart?.destroy();
        };
    });

    // ── Metric Processing ────────────────────────────────────────────────
    function processMetrics(workerData: Record<string, any>) {
        // Update system health
        systemHealth.update(h => {
            const updated = { ...h };
            if (workerData.core_ingress?._status) updated.ingress = workerData.core_ingress._status;
            if (workerData.worker_qdrant?._status) updated.qdrant = workerData.worker_qdrant._status === 'online' ? 'online' : 'degraded';
            if (workerData.worker_s3_archive?._status) updated.s3 = workerData.worker_s3_archive._status;
            return updated;
        });

        // Update ingress metrics
        if (workerData.core_ingress?._status === 'online') {
            const m = workerData.core_ingress;
            ingress.set({
                requestsTotal: m.nexus_ingress_requests_total || 0,
                requestsRate: 0, // Computed from delta
                acceptedTotal: m.nexus_ingress_events_accepted_total || 0,
                authFailures: m.nexus_ingress_auth_failures_total || 0,
                integrityVerified: m.nexus_ingress_integrity_verified_total || 0,
                hmacFailures: m.nexus_ingress_hmac_failures_total || 0,
                replayDetections: m.nexus_ingress_replay_detections_total || 0,
                temporalDrift: m.nexus_ingress_temporal_drift_total || 0,
                crossOsCollisions: m.nexus_ingress_cross_os_collision_total || 0,
                bannedAttempts: m.nexus_ingress_banned_sensor_attempts_total || 0,
                parquetParseFailures: m.nexus_ingress_parquet_parse_failures_total || 0,
                brokerFaults: m.nexus_ingress_broker_faults_total || 0,
                payloadTooLarge: m.nexus_ingress_payload_too_large_total || 0,
                latencyP50Ms: 0,
                latencyP99Ms: 0,
            });
        }

        // Update per-worker metrics
        workers.update(w => {
            for (const [name, m] of Object.entries(workerData)) {
                if (name === 'core_ingress') continue;
                if (!w[name]) continue;

                const prev = w[name].messagesTotal;
                const current = (m as any).nexus_worker_messages_acknowledged_total || 0;

                w[name] = {
                    ...w[name],
                    status: (m as any)._status || 'offline',
                    messagesTotal: current,
                    messagesRate: Math.max(0, (current - prev) / 2), // 2s scrape interval
                    batchLatencyMs: ((m as any).nexus_worker_transmission_latency_seconds || 0) * 1000,
                    retries: (m as any).nexus_worker_transmission_retries_total || 0,
                    dlqRouted: (m as any).nexus_worker_dlq_routed_total || 0,
                    circuitBreakerTrips: (m as any).nexus_worker_circuit_breaker_trips_total || 0,
                    lastSeen: Date.now(),
                };
            }
            return w;
        });

        // Update S3 metrics
        if (workerData.worker_s3_archive?._status === 'online') {
            const m = workerData.worker_s3_archive;
            s3Metrics.set({
                eventsArchived: m.nexus_s3_events_archived_total || 0,
                uploadFailures: m.nexus_s3_upload_failures_total || 0,
                uploadLatencyMs: (m.nexus_s3_upload_latency_seconds || 0) * 1000,
                partialFailures: m.nexus_s3_partial_failures_total || 0,
            });
        }

        // Push throughput/error history for sparklines
        const rate = Object.values(workerData)
            .filter((m: any) => m._status === 'online')
            .reduce((s: number, m: any) => s + ((m as any).nexus_worker_messages_acknowledged_total || 0), 0);
        pushThroughput(rate);

        const errors = Object.values(workerData)
            .reduce((s: number, m: any) => s + ((m as any).nexus_worker_dlq_routed_total || 0), 0);
        pushError(errors);
    }

    function mapAlertEvent(data: any): TelemetryEvent {
        return {
            timestamp: data.timestamp || Date.now() / 1000,
            sensorId: data.sensor_id || data.sensorId || '',
            sensorType: data.source_type || data.sensorType || '',
            vectorName: data.vector_name || data.vectorName || '',
            anomalyScore: data.anomaly_score || data.anomalyScore || 0,
            level: (data.anomaly_score || 0) > 0.9 ? 'CRITICAL' : 'WARNING',
            mitreTactic: data.mitre_tactic,
            mitreTechnique: data.mitre_technique,
            process: data.comm || data.Image || data.process_name,
            commandLine: data.command_line || data.CommandLine,
            destIp: data.dest_ip || data.dst_ip || data.DestIp,
            pid: data.pid,
            ppid: data.ppid,
            reconstructionError: data.reconstruction_error,
            raw: data,
        };
    }

    // ── Sparkline Renderer ───────────────────────────────────────────────
    function renderSparkline(canvas: HTMLCanvasElement, data: number[], color: string) {
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        if (sparkChart) sparkChart.destroy();

        sparkChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map((_, i) => i),
                datasets: [{
                    data,
                    borderColor: color,
                    backgroundColor: color + '20',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    borderWidth: 1.5,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { display: false },
                    y: { display: false, beginAtZero: true },
                },
                animation: false,
            },
        });
    }

    // ── Formatters ───────────────────────────────────────────────────────
    function fmtNum(n: number): string {
        if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
        if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
        return n.toFixed(0);
    }

    function fmtUptime(startMs: number, nowMs: number): string {
        const secs = Math.floor((nowMs - startMs) / 1000);
        const h = Math.floor(secs / 3600);
        const m = Math.floor((secs % 3600) / 60);
        const s = secs % 60;
        return `${h}h ${m}m ${s}s`;
    }

    function statusColor(s: string): string {
        if (s === 'online') return 'bg-emerald-500';
        if (s === 'degraded') return 'bg-amber-500';
        return 'bg-red-500';
    }

    function statusGlow(s: string): string {
        if (s === 'online') return 'shadow-[0_0_8px_rgba(16,185,129,0.6)]';
        if (s === 'degraded') return 'shadow-[0_0_8px_rgba(245,158,11,0.6)]';
        return 'shadow-[0_0_8px_rgba(239,68,68,0.6)]';
    }

    // Reactive declarations
    $: if (sparkCanvas && activeView === 'overview') {
        renderSparkline(sparkCanvas, $throughputHistory, '#06b6d4');
    }
</script>

<div class="grid grid-cols-[220px_1fr] h-screen bg-[#050505] text-slate-200 font-['IBM_Plex_Mono',monospace] overflow-hidden">

    <!-- ═══════ LEFT SIDEBAR ═══════ -->
    <aside class="bg-[rgba(8,12,20,0.95)] border-r border-slate-800/60 flex flex-col">
        <!-- Brand -->
        <div class="px-5 py-5 border-b border-slate-800/40">
            <div class="flex items-center gap-2">
                <div class="w-2 h-2 rounded-full {statusColor($systemHealth.nats)} {statusGlow($systemHealth.nats)} animate-pulse"></div>
                <h1 class="text-sm font-bold tracking-[0.25em] text-cyan-400 uppercase">Sentinel</h1>
            </div>
            <p class="text-[9px] uppercase tracking-[0.2em] text-slate-600 mt-1 ml-4">Operations HUD</p>
        </div>

        <!-- Health Score -->
        <div class="px-5 py-4 border-b border-slate-800/40">
            <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-1">System Health</div>
            <div class="flex items-end gap-2">
                <span class="text-3xl font-bold {$healthScore >= 80 ? 'text-emerald-400' : $healthScore >= 50 ? 'text-amber-400' : 'text-red-400'}">{$healthScore}</span>
                <span class="text-[10px] text-slate-500 mb-1">/ 100</span>
            </div>
            <div class="w-full h-1 bg-slate-800 rounded-full mt-2 overflow-hidden">
                <div class="h-full rounded-full transition-all duration-500 {$healthScore >= 80 ? 'bg-emerald-500' : $healthScore >= 50 ? 'bg-amber-500' : 'bg-red-500'}" style="width: {$healthScore}%"></div>
            </div>
        </div>

        <!-- Navigation -->
        <nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
            {#each [
                { id: 'overview', label: 'Overview', icon: '◉' },
                { id: 'ingress', label: 'Ingress Gateway', icon: '⬡' },
                { id: 'workers', label: 'Workers', icon: '⚙' },
                { id: 'storage', label: 'Storage & Vector', icon: '⬢' },
                { id: 'baseline', label: 'Model A Baseline', icon: '◈' },
                { id: 'alerts', label: 'Alert Firehose', icon: '⚡' },
                { id: 'ti', label: 'TI Intelligence', icon: '◎' },
            ] as view}
                <button
                    class="w-full text-left px-3 py-2 text-[11px] rounded transition-all flex items-center gap-2.5
                        {activeView === view.id
                            ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                            : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/30 border border-transparent'}"
                    on:click={() => activeView = view.id}
                >
                    <span class="text-sm opacity-60">{view.icon}</span>
                    {view.label}
                </button>
            {/each}
        </nav>

        <!-- Subsystem Indicators -->
        <div class="px-5 py-4 border-t border-slate-800/40 space-y-2">
            <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-2">Subsystems</div>
            {#each Object.entries($systemHealth) as [name, status]}
                <div class="flex items-center justify-between text-[10px]">
                    <span class="text-slate-400">{name}</span>
                    <div class="w-1.5 h-1.5 rounded-full {statusColor(status)}"></div>
                </div>
            {/each}
        </div>

        <!-- Uptime -->
        <div class="px-5 py-3 border-t border-slate-800/40 text-[9px] text-slate-600">
            Uptime: {fmtUptime(uptimeStart, now)}
        </div>
    </aside>

    <!-- ═══════ MAIN CONTENT ═══════ -->
    <main class="overflow-y-auto">

        <!-- ── OVERVIEW ───────────────────────────────────────────────── -->
        {#if activeView === 'overview'}
            <div class="p-6 space-y-6">
                <div>
                    <h2 class="text-lg font-bold tracking-wide">Pipeline Overview</h2>
                    <p class="text-[10px] uppercase tracking-widest text-slate-500 mt-0.5">Real-time data flow metrics across all services</p>
                </div>

                <!-- KPI Cards -->
                <div class="grid grid-cols-4 gap-4">
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Throughput</div>
                        <div class="text-2xl font-bold text-cyan-400 mt-1">{fmtNum($totalThroughput)}<span class="text-xs text-slate-500">/s</span></div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Ingress Accepted</div>
                        <div class="text-2xl font-bold text-emerald-400 mt-1">{fmtNum($ingress.acceptedTotal)}</div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Integrity Verified</div>
                        <div class="text-2xl font-bold text-blue-400 mt-1">{fmtNum($ingress.integrityVerified)}</div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Total Errors</div>
                        <div class="text-2xl font-bold {$totalErrors > 0 ? 'text-red-400' : 'text-emerald-400'} mt-1">{fmtNum($totalErrors)}</div>
                    </div>
                </div>

                <!-- Throughput Sparkline -->
                <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                    <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-3">Throughput (60s window)</div>
                    <div class="h-24">
                        <canvas bind:this={sparkCanvas}></canvas>
                    </div>
                </div>

                <!-- Worker Status Grid -->
                <div>
                    <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-3">Worker Fleet</div>
                    <div class="grid grid-cols-5 gap-3">
                        {#each Object.values($workers) as w}
                            <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-3">
                                <div class="flex items-center justify-between mb-2">
                                    <span class="text-[10px] text-slate-400 truncate">{w.name.replace('worker_', '')}</span>
                                    <div class="w-1.5 h-1.5 rounded-full {statusColor(w.status)}"></div>
                                </div>
                                <div class="text-lg font-bold text-slate-200">{fmtNum(w.messagesRate)}<span class="text-[9px] text-slate-500">/s</span></div>
                                <div class="flex justify-between mt-2 text-[9px]">
                                    <span class="text-slate-500">DLQ</span>
                                    <span class="{w.dlqRouted > 0 ? 'text-red-400' : 'text-slate-600'}">{w.dlqRouted}</span>
                                </div>
                                <div class="flex justify-between text-[9px]">
                                    <span class="text-slate-500">Retries</span>
                                    <span class="{w.retries > 0 ? 'text-amber-400' : 'text-slate-600'}">{w.retries}</span>
                                </div>
                            </div>
                        {/each}
                    </div>
                </div>

                <!-- Integrity Security Summary -->
                <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                    <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-3">Integrity Verification</div>
                    <div class="grid grid-cols-6 gap-4 text-center">
                        {#each [
                            { label: 'HMAC Fail', val: $ingress.hmacFailures, danger: true },
                            { label: 'Replay', val: $ingress.replayDetections, danger: true },
                            { label: 'Drift', val: $ingress.temporalDrift, danger: false },
                            { label: 'Cross-OS', val: $ingress.crossOsCollisions, danger: true },
                            { label: 'Banned', val: $ingress.bannedAttempts, danger: true },
                            { label: 'Auth Fail', val: $ingress.authFailures, danger: false },
                        ] as m}
                            <div>
                                <div class="text-xl font-bold {m.val > 0 ? (m.danger ? 'text-red-400' : 'text-amber-400') : 'text-slate-600'}">{m.val}</div>
                                <div class="text-[8px] uppercase text-slate-500 mt-0.5">{m.label}</div>
                            </div>
                        {/each}
                    </div>
                </div>
            </div>
        {/if}

        <!-- ── INGRESS GATEWAY ────────────────────────────────────────── -->
        {#if activeView === 'ingress'}
            <div class="p-6 space-y-6">
                <div>
                    <h2 class="text-lg font-bold">Ingress Gateway (core_ingress)</h2>
                    <p class="text-[10px] uppercase tracking-widest text-slate-500 mt-0.5">Axum Zero-Trust Gateway · TLS 1.3 · JWT · 3-Tier Integrity</p>
                </div>

                <div class="grid grid-cols-3 gap-4">
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Total Requests</div>
                        <div class="text-3xl font-bold text-cyan-400 mt-1">{fmtNum($ingress.requestsTotal)}</div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Accepted</div>
                        <div class="text-3xl font-bold text-emerald-400 mt-1">{fmtNum($ingress.acceptedTotal)}</div>
                        <div class="text-[9px] text-slate-500 mt-1">
                            {$ingress.requestsTotal > 0 ? (($ingress.acceptedTotal / $ingress.requestsTotal) * 100).toFixed(1) : 0}% accept rate
                        </div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Broker Faults</div>
                        <div class="text-3xl font-bold {$ingress.brokerFaults > 0 ? 'text-red-400' : 'text-emerald-400'} mt-1">{$ingress.brokerFaults}</div>
                    </div>
                </div>

                <!-- Integrity Breakdown -->
                <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-5">
                    <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-4">Integrity Verification Breakdown</div>
                    <div class="space-y-3">
                        {#each [
                            { label: 'HMAC Verification Failures', val: $ingress.hmacFailures, desc: 'Sensor shared secret mismatch or payload tampering' },
                            { label: 'Sequence Replay Detections', val: $ingress.replayDetections, desc: 'Duplicate sequence numbers within replay window' },
                            { label: 'Temporal Drift Violations', val: $ingress.temporalDrift, desc: 'Batch timestamp exceeds ±120s clock skew limit' },
                            { label: 'Cross-OS Schema Collisions', val: $ingress.crossOsCollisions, desc: 'Foreign columns detected in sensor Parquet schema' },
                            { label: 'Banned Sensor Attempts', val: $ingress.bannedAttempts, desc: 'Previously banned sensors attempting reconnection' },
                            { label: 'Parquet Parse Failures', val: $ingress.parquetParseFailures, desc: 'Unreadable Parquet metadata in payload' },
                            { label: 'JWT Auth Failures', val: $ingress.authFailures, desc: 'Invalid or expired Bearer token' },
                            { label: 'Payload Too Large', val: $ingress.payloadTooLarge, desc: 'Payload exceeds MAX_PAYLOAD_BYTES limit' },
                        ] as row}
                            <div class="flex items-center justify-between py-2 border-b border-slate-800/30">
                                <div>
                                    <div class="text-[11px] text-slate-300">{row.label}</div>
                                    <div class="text-[9px] text-slate-600">{row.desc}</div>
                                </div>
                                <span class="text-sm font-bold font-mono {row.val > 0 ? 'text-red-400' : 'text-slate-600'}">{row.val}</span>
                            </div>
                        {/each}
                    </div>
                </div>
            </div>
        {/if}

        <!-- ── WORKERS ────────────────────────────────────────────────── -->
        {#if activeView === 'workers'}
            <div class="p-6 space-y-6">
                <div>
                    <h2 class="text-lg font-bold">Worker Fleet</h2>
                    <p class="text-[10px] uppercase tracking-widest text-slate-500 mt-0.5">Autonomous Rust workers · JetStream consumers · Podman Quadlets</p>
                </div>

                {#each Object.values($workers) as w}
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-5">
                        <div class="flex items-center justify-between mb-4">
                            <div class="flex items-center gap-3">
                                <div class="w-2 h-2 rounded-full {statusColor(w.status)} {statusGlow(w.status)}"></div>
                                <h3 class="text-sm font-bold text-slate-200">{w.name}</h3>
                                <span class="text-[9px] px-2 py-0.5 rounded-full border
                                    {w.status === 'online' ? 'border-emerald-800 text-emerald-400 bg-emerald-500/10' :
                                     w.status === 'degraded' ? 'border-amber-800 text-amber-400 bg-amber-500/10' :
                                     'border-red-800 text-red-400 bg-red-500/10'}"
                                >{w.status.toUpperCase()}</span>
                            </div>
                            <span class="text-[9px] text-slate-600">
                                Last seen: {w.lastSeen > 0 ? new Date(w.lastSeen).toLocaleTimeString() : 'never'}
                            </span>
                        </div>

                        <div class="grid grid-cols-6 gap-4">
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">Rate</div>
                                <div class="text-lg font-bold text-cyan-400">{fmtNum(w.messagesRate)}<span class="text-[9px] text-slate-500">/s</span></div>
                            </div>
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">Total</div>
                                <div class="text-lg font-bold text-slate-300">{fmtNum(w.messagesTotal)}</div>
                            </div>
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">Latency</div>
                                <div class="text-lg font-bold text-slate-300">{w.batchLatencyMs.toFixed(0)}<span class="text-[9px] text-slate-500">ms</span></div>
                            </div>
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">Retries</div>
                                <div class="text-lg font-bold {w.retries > 0 ? 'text-amber-400' : 'text-slate-600'}">{w.retries}</div>
                            </div>
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">DLQ</div>
                                <div class="text-lg font-bold {w.dlqRouted > 0 ? 'text-red-400' : 'text-slate-600'}">{w.dlqRouted}</div>
                            </div>
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">Circuit Trips</div>
                                <div class="text-lg font-bold {w.circuitBreakerTrips > 0 ? 'text-red-400' : 'text-slate-600'}">{w.circuitBreakerTrips}</div>
                            </div>
                        </div>
                    </div>
                {/each}
            </div>
        {/if}

        <!-- ── STORAGE & VECTOR ───────────────────────────────────────── -->
        {#if activeView === 'storage'}
            <div class="p-6 space-y-6">
                <div>
                    <h2 class="text-lg font-bold">Storage & Vector Database</h2>
                    <p class="text-[10px] uppercase tracking-widest text-slate-500 mt-0.5">S3 Cold Archive · Qdrant HNSW · Hive Partitioned Data Lake</p>
                </div>

                <div class="grid grid-cols-2 gap-4">
                    <!-- S3 -->
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-5">
                        <div class="flex items-center gap-2 mb-4">
                            <div class="w-1.5 h-1.5 rounded-full {statusColor($systemHealth.s3)}"></div>
                            <h3 class="text-sm font-bold">S3 / MinIO Archive</h3>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">Archived</div>
                                <div class="text-2xl font-bold text-emerald-400">{fmtNum($s3Metrics.eventsArchived)}</div>
                            </div>
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">Upload Latency</div>
                                <div class="text-2xl font-bold text-slate-300">{$s3Metrics.uploadLatencyMs.toFixed(0)}<span class="text-xs text-slate-500">ms</span></div>
                            </div>
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">Upload Failures</div>
                                <div class="text-2xl font-bold {$s3Metrics.uploadFailures > 0 ? 'text-red-400' : 'text-slate-600'}">{$s3Metrics.uploadFailures}</div>
                            </div>
                            <div>
                                <div class="text-[9px] uppercase text-slate-500">Partial Failures</div>
                                <div class="text-2xl font-bold {$s3Metrics.partialFailures > 0 ? 'text-amber-400' : 'text-slate-600'}">{$s3Metrics.partialFailures}</div>
                            </div>
                        </div>
                    </div>

                    <!-- Qdrant -->
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-5">
                        <div class="flex items-center gap-2 mb-4">
                            <div class="w-1.5 h-1.5 rounded-full {statusColor($systemHealth.qdrant)}"></div>
                            <h3 class="text-sm font-bold">Qdrant Vector Database</h3>
                        </div>
                        <div class="text-[10px] text-slate-400 space-y-2">
                            <div class="flex justify-between py-1 border-b border-slate-800/30">
                                <span>Named Vectors</span>
                                <span class="text-cyan-400">c2_math (8D) · sentinel_math (5D) · windows_math (6D) · deepsensor_math (4D) · trellix_math (4D) · cloud_flow (5D) · network_tap (8D)</span>
                            </div>
                            <div class="flex justify-between py-1 border-b border-slate-800/30">
                                <span>Indexes</span>
                                <span class="text-slate-300">KEYWORD: endpoint_id, source_type, vector_name · FLOAT: timestamp_epoch</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        {/if}

        <!-- ── MODEL A BASELINE ───────────────────────────────────────── -->
        {#if activeView === 'baseline'}
            <div class="p-6 space-y-6">
                <div>
                    <h2 class="text-lg font-bold">Model A -- Network Baseline Detector</h2>
                    <p class="text-[10px] uppercase tracking-widest text-slate-500 mt-0.5">BiLSTM-AE (8→64→32→64→8) · CPU Inference · serve_baseline.py</p>
                </div>

                <div class="grid grid-cols-4 gap-4">
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Flows Processed</div>
                        <div class="text-2xl font-bold text-cyan-400 mt-1">{fmtNum($baseline.flowsProcessed)}</div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Alerts Fired</div>
                        <div class="text-2xl font-bold {$baseline.alertsFired > 0 ? 'text-amber-400' : 'text-slate-600'} mt-1">{$baseline.alertsFired}</div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Tracked IP Pairs</div>
                        <div class="text-2xl font-bold text-slate-300 mt-1">{fmtNum($baseline.trackedPairs)}</div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Calibrated Threshold</div>
                        <div class="text-2xl font-bold text-slate-300 mt-1">{$baseline.threshold.toFixed(4)}</div>
                        <div class="text-[9px] text-slate-500 mt-1">μ + 3σ on eval set</div>
                    </div>
                </div>

                <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-5">
                    <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-3">Architecture</div>
                    <div class="grid grid-cols-3 gap-4 text-[10px] text-slate-400">
                        <div class="bg-black/40 p-3 rounded border border-slate-800/30">
                            <div class="text-cyan-400 font-bold mb-1">Encoder</div>
                            BiLSTM(8→64) bidirectional → Linear(128→32) latent
                        </div>
                        <div class="bg-black/40 p-3 rounded border border-slate-800/30">
                            <div class="text-cyan-400 font-bold mb-1">Decoder</div>
                            BiLSTM(32→64) bidirectional → Linear(128→8) reconstruction
                        </div>
                        <div class="bg-black/40 p-3 rounded border border-slate-800/30">
                            <div class="text-cyan-400 font-bold mb-1">Detection</div>
                            MSE(input, reconstruction) > threshold → anomaly alert to nexus.alerts.baseline
                        </div>
                    </div>
                </div>
            </div>
        {/if}

        <!-- ── ALERT FIREHOSE ─────────────────────────────────────────── -->
        {#if activeView === 'alerts'}
            <div class="p-6 flex flex-col h-full">
                <div class="mb-4">
                    <h2 class="text-lg font-bold">Alert Firehose</h2>
                    <p class="text-[10px] uppercase tracking-widest text-slate-500 mt-0.5">
                        NATS JetStream · nexus.alerts.* · Last {$telemetryStream.length} events
                    </p>
                </div>

                <div class="flex-1 border border-slate-800/50 rounded-lg bg-[#0a0e18] overflow-hidden flex flex-col relative">
                    <div class="overflow-y-auto flex-1 absolute inset-0">
                        <table class="w-full text-left text-[11px]">
                            <thead class="bg-[#080c14] text-[9px] uppercase text-slate-500 sticky top-0 z-10 border-b border-slate-800/50">
                                <tr>
                                    <th class="px-3 py-2.5">Time</th>
                                    <th class="px-3 py-2.5">Sensor</th>
                                    <th class="px-3 py-2.5">Vector</th>
                                    <th class="px-3 py-2.5">Process / IP Pair</th>
                                    <th class="px-3 py-2.5">Score</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-800/30 font-mono">
                                {#each $telemetryStream as row}
                                    <tr class="hover:bg-slate-800/40 cursor-pointer transition-colors"
                                        on:click={() => { selectedEvent = row; showInspector = true; }}>
                                        <td class="px-3 py-2 text-slate-500 whitespace-nowrap">
                                            {new Date(row.timestamp * 1000).toLocaleTimeString()}
                                        </td>
                                        <td class="px-3 py-2 text-slate-400">{row.sensorType || '--'}</td>
                                        <td class="px-3 py-2 text-blue-400">{row.vectorName || '--'}</td>
                                        <td class="px-3 py-2 text-cyan-400">
                                            {row.process || row.destIp || '--'}
                                        </td>
                                        <td class="px-3 py-2 font-bold
                                            {row.level === 'CRITICAL' ? 'text-red-400' : 'text-amber-400'}">
                                            {(row.anomalyScore * 100).toFixed(1)}%
                                            {#if row.reconstructionError}
                                                <span class="text-[9px] text-slate-500 ml-1">
                                                    MSE:{row.reconstructionError.toFixed(4)}
                                                </span>
                                            {/if}
                                        </td>
                                    </tr>
                                {/each}
                                {#if $telemetryStream.length === 0}
                                    <tr>
                                        <td colspan="5" class="px-3 py-8 text-center text-slate-600 text-xs">
                                            Awaiting alerts on nexus.alerts.*
                                        </td>
                                    </tr>
                                {/if}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        {/if}

        <!-- ── TI INTELLIGENCE ───────────────────────────────────────── -->
        {#if activeView === 'ti'}
            <div class="p-6 space-y-6">
                <div>
                    <h2 class="text-lg font-bold">TI Intelligence Corpus</h2>
                    <p class="text-[10px] uppercase tracking-widest text-slate-500 mt-0.5">Hybrid ANN+BM25+CrossEncoder · BGE-M3 1024D · TurboVec · Qdrant nexus_ti_corpus</p>
                </div>

                <!-- Stats Row -->
                <div class="grid grid-cols-3 gap-4">
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Documents</div>
                        <div class="text-3xl font-bold text-cyan-400 mt-1">{$tiStats.total_docs}</div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Chunks Indexed</div>
                        <div class="text-3xl font-bold text-blue-400 mt-1">{$tiStats.total_chunks}</div>
                    </div>
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500">Last Ingest</div>
                        <div class="text-sm font-bold text-slate-300 mt-2">
                            {$tiStats.last_ingest_ts > 0 ? fmtTime($tiStats.last_ingest_ts * 1000) : '--'}
                        </div>
                    </div>
                </div>

                <!-- Upload Dropzone -->
                <div
                    class="relative border-2 border-dashed rounded-lg p-8 text-center transition-all
                        {tiDragOver ? 'border-cyan-500 bg-cyan-500/5' : 'border-slate-700 hover:border-slate-500'}"
                    role="button"
                    tabindex="0"
                    on:dragover|preventDefault={() => tiDragOver = true}
                    on:dragleave={() => tiDragOver = false}
                    on:drop={tiHandleDrop}
                    on:keydown={(e) => e.key === 'Enter' && (document.getElementById('ti-file-input') as HTMLInputElement)?.click()}
                    on:click={() => (document.getElementById('ti-file-input') as HTMLInputElement)?.click()}
                >
                    <input
                        id="ti-file-input"
                        type="file"
                        class="hidden"
                        multiple
                        accept=".pdf,.json,.jsonl,.yaml,.yml,.csv,.txt"
                        on:change={(e) => {
                            const files = (e.target as HTMLInputElement).files;
                            if (files) for (const f of Array.from(files)) tiUploadFile(f);
                        }}
                    />
                    {#if tiUploading}
                        <div class="text-cyan-400 text-sm">Uploading...</div>
                    {:else}
                        <div class="text-slate-400 text-sm">Drop TI documents here or click to select</div>
                        <div class="text-[9px] text-slate-600 mt-1">PDF · STIX JSON · Sigma YAML · JSONL · IOC CSV</div>
                    {/if}
                </div>

                <!-- Upload Activity Log (SSE) -->
                {#if $tiUploadLog.length > 0}
                    <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg p-4">
                        <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-3">Upload Activity</div>
                        <div class="space-y-1.5 max-h-36 overflow-y-auto">
                            {#each $tiUploadLog as evt}
                                <div class="flex items-center justify-between text-[10px] font-mono py-1 border-b border-slate-800/30">
                                    <span class="text-slate-400 truncate max-w-[40%]">{evt.filename}</span>
                                    <span class="text-[9px] px-1.5 py-0.5 rounded border
                                        {evt.status === 'done' ? 'border-emerald-800 text-emerald-400 bg-emerald-500/10' :
                                         evt.status === 'error' ? 'border-red-800 text-red-400 bg-red-500/10' :
                                         'border-amber-800 text-amber-400 bg-amber-500/10'}">
                                        {evt.status.toUpperCase()}
                                        {#if evt.chunks} · {evt.chunks} chunks{/if}
                                    </span>
                                    <span class="text-slate-600">{fmtTime(evt.ts)}</span>
                                </div>
                            {/each}
                        </div>
                    </div>
                {/if}

                <!-- Document Browser -->
                <div class="bg-[#0a0e18] border border-slate-800/50 rounded-lg overflow-hidden">
                    <div class="px-4 py-3 border-b border-slate-800/40 flex items-center justify-between">
                        <span class="text-[9px] uppercase tracking-wider text-slate-500">Indexed Documents</span>
                        <button
                            class="text-[9px] text-slate-500 hover:text-slate-300 px-2 py-1 rounded border border-slate-700 hover:border-slate-500 transition-colors"
                            on:click={() => refreshTICorpus(TI_API)}
                        >Refresh</button>
                    </div>

                    {#if $tiDocuments.length === 0}
                        <div class="px-4 py-8 text-center text-[11px] text-slate-600">
                            No documents in corpus. Upload a PDF, STIX bundle, Sigma rule, or IOC CSV.
                        </div>
                    {:else}
                        <div class="overflow-x-auto">
                            <table class="w-full text-left text-[10px]">
                                <thead class="bg-[#080c14] text-[9px] uppercase text-slate-500 border-b border-slate-800/40">
                                    <tr>
                                        <th class="px-3 py-2.5">Filename</th>
                                        <th class="px-3 py-2.5">Type</th>
                                        <th class="px-3 py-2.5">Sensors</th>
                                        <th class="px-3 py-2.5">Chunks</th>
                                        <th class="px-3 py-2.5">Ingested</th>
                                        <th class="px-3 py-2.5">Doc ID</th>
                                        <th class="px-3 py-2.5"></th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-slate-800/30 font-mono">
                                    {#each $tiDocuments as doc}
                                        <tr class="hover:bg-slate-800/30 transition-colors">
                                            <td class="px-3 py-2 text-slate-300 max-w-[200px] truncate" title={doc.filename}>{doc.filename}</td>
                                            <td class="px-3 py-2">
                                                <span class="px-1.5 py-0.5 rounded border border-blue-800 text-blue-400 bg-blue-500/10 text-[9px]">
                                                    {fmtSrc(doc.source_type)}
                                                </span>
                                            </td>
                                            <td class="px-3 py-2 text-slate-500 max-w-[140px] truncate">
                                                {doc.sensor_types.length > 0 ? doc.sensor_types.join(', ') : 'all'}
                                            </td>
                                            <td class="px-3 py-2 text-cyan-400">{doc.chunk_count}</td>
                                            <td class="px-3 py-2 text-slate-500">{fmtTime(doc.ingest_ts * 1000)}</td>
                                            <td class="px-3 py-2 text-slate-600 font-mono text-[9px]">{doc.doc_id.slice(0, 12)}…</td>
                                            <td class="px-3 py-2">
                                                <button
                                                    class="text-[9px] text-red-500 hover:text-red-400 px-1.5 py-0.5 rounded border border-red-900 hover:border-red-700 transition-colors"
                                                    on:click={() => tiDeleteDoc(doc.doc_id)}
                                                >Retract</button>
                                            </td>
                                        </tr>
                                    {/each}
                                </tbody>
                            </table>
                        </div>
                    {/if}
                </div>
            </div>
        {/if}
    </main>

    <!-- ═══════ EVENT INSPECTOR (slide-out) ═══════ -->
    {#if showInspector && selectedEvent}
        <div class="fixed right-0 top-0 bottom-0 w-[420px] bg-[#080c14] border-l border-slate-800/60 z-50 flex flex-col shadow-2xl">
            <button on:click={() => showInspector = false}
                class="absolute top-4 right-4 text-slate-600 hover:text-white text-sm">✕</button>

            <div class="p-5 border-b border-slate-800/40">
                <span class="text-[9px] uppercase px-2 py-0.5 rounded border
                    {selectedEvent.level === 'CRITICAL' ? 'border-red-800 text-red-400 bg-red-500/10' : 'border-amber-800 text-amber-400 bg-amber-500/10'}">
                    {selectedEvent.level}
                </span>
                <h3 class="text-base font-bold text-cyan-400 mt-2 font-mono">
                    {selectedEvent.process || selectedEvent.destIp || selectedEvent.sensorId}
                </h3>
                <p class="text-[10px] text-slate-500 mt-1">
                    {selectedEvent.sensorType} · {selectedEvent.vectorName}
                    {#if selectedEvent.mitreTechnique}
                        · {selectedEvent.mitreTechnique}
                    {/if}
                </p>
            </div>

            <div class="p-5 flex-1 overflow-y-auto space-y-4">
                {#if selectedEvent.commandLine}
                    <div>
                        <div class="text-[9px] uppercase text-slate-500 mb-1">Command</div>
                        <div class="bg-black/60 p-2.5 rounded border border-slate-800/40 text-[10px] font-mono text-slate-300 break-all select-all">
                            {selectedEvent.commandLine}
                        </div>
                    </div>
                {/if}

                <div class="grid grid-cols-2 gap-3 text-[10px]">
                    <div class="bg-black/40 p-2.5 rounded border border-slate-800/30">
                        <span class="text-slate-500 block">Anomaly Score</span>
                        <span class="text-red-400 font-bold">{(selectedEvent.anomalyScore * 100).toFixed(1)}%</span>
                    </div>
                    {#if selectedEvent.reconstructionError}
                        <div class="bg-black/40 p-2.5 rounded border border-slate-800/30">
                            <span class="text-slate-500 block">Reconstruction Error</span>
                            <span class="text-amber-400 font-bold">{selectedEvent.reconstructionError.toFixed(6)}</span>
                        </div>
                    {/if}
                    {#if selectedEvent.destIp}
                        <div class="bg-black/40 p-2.5 rounded border border-slate-800/30">
                            <span class="text-slate-500 block">Destination</span>
                            <span class="text-cyan-400">{selectedEvent.destIp}</span>
                        </div>
                    {/if}
                    {#if selectedEvent.pid}
                        <div class="bg-black/40 p-2.5 rounded border border-slate-800/30">
                            <span class="text-slate-500 block">PID / PPID</span>
                            <span class="text-slate-300">{selectedEvent.pid} / {selectedEvent.ppid || '?'}</span>
                        </div>
                    {/if}
                </div>

                <div>
                    <div class="text-[9px] uppercase text-slate-500 mb-1">Raw Payload</div>
                    <pre class="bg-black/60 p-2.5 rounded border border-slate-800/40 text-[9px] font-mono text-slate-400 overflow-x-auto max-h-60 whitespace-pre-wrap">{JSON.stringify(selectedEvent.raw, null, 2)}</pre>
                </div>
            </div>
        </div>
    {/if}
</div>

<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&display=swap');
</style>