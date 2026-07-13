<#
.SYNOPSIS
    Nexus Validation: Playbook 1 (Windows C2 & ETW Pipeline + Model A Baseline)

.DESCRIPTION
    Simulates a fileless living-off-the-land (LotL) attack across three detection layers:
    1. worker_rules -- Sigma string matching on suspicious binaries and DGA DNS.
    2. worker_qdrant -- Cosine similarity on the 8D c2_math vector space.
    3. Model A -- BiLSTM-AE reconstruction error on the Arkime network_tap SPI stream.

    Phase 4 validates the network tap pipeline: Arkime capture → Redpanda → ML Gateway
    → feature extraction → serve_baseline.py → nexus.alerts.baseline → nettap_expert.
#>

[CmdletBinding()]
param (
    [int]$BeaconCount = 15,
    [int]$BaseDelayMs = 2000,
    [switch]$EnableJitter = $true,
    [switch]$NetworkTapValidation = $false,
    [string]$SensorType = "windows_c2"
)

Write-Host "[*] Initiating Nexus C2 Edge Simulation (sensor_type: $SensorType)..." -ForegroundColor Cyan

# ── Phase 1: Trigger the Deterministic Engine (worker_rules: Suspicious_Windows_Bin) ──
Write-Host "[*] Phase 1: Spawning anomalous discovery binaries..." -ForegroundColor Yellow
$SuspiciousBinaries = @("whoami.exe", "vssadmin.exe list shadows")

foreach ($bin in $SuspiciousBinaries) {
    try {
        Write-Host "    -> Executing: $bin" -ForegroundColor DarkGray
        Invoke-Expression $bin *>$null
    } catch {}
}

# ── Phase 1.5: Memory Injection (Host Expert -- Process Lineage) ──
Write-Host "`n[*] Phase 1.5: Simulating memory injection via obfuscated PowerShell..." -ForegroundColor Yellow
$MockPayload = "WwBSZWYs...[SYNTHETIC_BASE64_PAYLOAD]...="
try {
    $Proc = Start-Process powershell -ArgumentList "-WindowStyle Hidden -enc $MockPayload" -PassThru
    Start-Sleep -Seconds 2
    Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
    Write-Host "    -> Suspended hidden PowerShell. ETW should flag high-entropy command line." -ForegroundColor DarkGray
    Write-Host "    -> Expected source_type: $SensorType | vector_name: c2_math" -ForegroundColor DarkGray
} catch {
    Write-Host "    -> Process spawn failed (expected in sandboxed environments)." -ForegroundColor DarkYellow
}

# ── Phase 2: Trigger the DGA DNS Rule (worker_rules: Suspicious_DGA_TLD) ──
Write-Host "`n[*] Phase 2: Resolving simulated DGA infrastructure..." -ForegroundColor Yellow
$SimulatedC2 = "api.malicious-c2-sim.xyz"
try {
    Write-Host "    -> Resolving $SimulatedC2" -ForegroundColor DarkGray
    [System.Net.Dns]::GetHostAddresses($SimulatedC2) *>$null
} catch {}

# ── Phase 3: Trigger the 8D Math Vector (worker_qdrant: c2_math beaconing) ──
Write-Host "`n[*] Phase 3: Executing fileless memory beaconing loop ($BeaconCount beacons)..." -ForegroundColor Yellow
$WebClient = New-Object System.Net.WebClient
$WebClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

$BeaconStart = [System.Diagnostics.Stopwatch]::StartNew()

for ($i = 1; $i -le $BeaconCount; $i++) {
    $TargetDelay = $BaseDelayMs

    if ($EnableJitter) {
        $Jitter = Get-Random -Minimum -100 -Maximum 100
        $TargetDelay += $Jitter
    }

    Write-Host "    -> [Beacon $i/$BeaconCount] Polling C2 (Delay: ${TargetDelay}ms)..." -ForegroundColor DarkGray

    try {
        $null = $WebClient.DownloadString("https://1.1.1.1/images/favicon.ico")
    } catch {}

    Start-Sleep -Milliseconds $TargetDelay
}

$BeaconStart.Stop()
Write-Host "    -> Beacon phase complete: $($BeaconStart.ElapsedMilliseconds)ms total" -ForegroundColor DarkGray

# ── Phase 4: Model A Network Tap Baseline Trigger ──
if ($NetworkTapValidation) {
    Write-Host "`n[*] Phase 4: Model A Baseline Validation..." -ForegroundColor Cyan
    Write-Host "    -> The beacons in Phase 3 should have been captured by Arkime." -ForegroundColor DarkGray
    Write-Host "    -> Arkime → Redpanda → ML Gateway → features.rs extraction" -ForegroundColor DarkGray
    Write-Host "    -> serve_baseline.py should detect low inter-arrival variance" -ForegroundColor DarkGray
    Write-Host "    -> Expected: nexus.alerts.baseline fires with reconstruction error > threshold" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Monitoring checklist:" -ForegroundColor White
    Write-Host "      [ ] is_internal_dst = false (external beacon target)" -ForegroundColor DarkGray
    Write-Host "      [ ] port_class = 'well_known' (HTTPS/443)" -ForegroundColor DarkGray
    Write-Host "      [ ] avg_inter_arrival variance < 0.3 (programmatic)" -ForegroundColor DarkGray
    Write-Host "      [ ] nettap_expert receives baseline alert and begins L7 investigation" -ForegroundColor DarkGray
    Write-Host "      [ ] nettap_expert cross-references JA3 fingerprint against known C2 profiles" -ForegroundColor DarkGray
}

Write-Host "`n[+] Playbook 1 execution complete." -ForegroundColor Green
Write-Host "    Monitor: Redis queue, Qdrant alerts, nexus.alerts.baseline, Swarm output." -ForegroundColor Green