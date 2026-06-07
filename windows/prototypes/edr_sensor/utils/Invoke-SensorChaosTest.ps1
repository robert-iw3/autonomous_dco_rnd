<#
.SYNOPSIS
    Deep Sensor ETW Chaos & Stability Tester with Automated Telemetry Reporting

.DESCRIPTION
    Simulates high-velocity anomalous behavior across File I/O, Registry, and
    Process Creation to validate sensor buffer stability, ML queue drain rates,
    and active defense thresholds. Operates strictly with benign actions.

    Upon completion, it greps the DeepSensor_Diagnostic.log file to generate
    a comprehensive performance report mapping events/min, dropped packets,
    and queue saturation.

@RW
#>

#Requires -RunAsAdministrator

param(
    [int]$BaseVolume = 500,
    [int]$MaxConcurrency = 15,
    [string]$LogPath = "C:\ProgramData\DeepSensor\Logs\DeepSensor_Diagnostic.log"
)

$ErrorActionPreference = "SilentlyContinue"

function Write-OutputLog([string]$Message, [string]$Color = "Cyan") {
    $ts = (Get-Date).ToString("HH:mm:ss.fff")
    Write-Host "[$ts] $Message" -ForegroundColor $Color
}

$ChaosScriptBlock = {
    param($Volume, $WaveId, $ThreadId)

    $rnd = New-Object Random
    $tempDir = Join-Path $env:TEMP "DeepSensor_Chaos_$WaveId"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }

    $RegPath = "HKCU:\Software\DeepSensor_Chaos_Test"
    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

    # Av-Safe Alert Triggers (These match strings in Sigma/TTP logic but execute benignly)
    $AnomalousCommands = @(
        "cmd.exe /c echo vssadmin delete shadows",
        "cmd.exe /c echo sekurlsa::logonpasswords",
        "powershell.exe -NoProfile -EncodedCommand JABUAGUAcwB0AD0AMQA=", # $Test=1
        "ping.exe 1.1.1.1 -n 1"
    )

    for ($i = 0; $i -lt $Volume; $i++) {
        $action = $rnd.Next(1, 100)

        if ($action -lt 50) {
            # 50% Load: High-Velocity File I/O (Simulating Ransomware Encryption)
            $filePath = Join-Path $tempDir "document_encrypted_$ThreadId_$i.zepto"
            [System.IO.File]::WriteAllText($filePath, "STRESS_TEST_DATA_$i")
        }
        elseif ($action -lt 80) {
            # 30% Load: High-Velocity Registry Persistence Injection
            $keyName = "Run_Persist_$ThreadId_$i"
            $payload = "C:\ProgramData\suspicious_update_$i.exe"
            Set-ItemProperty -Path $RegPath -Name $keyName -Value $payload
        }
        else {
            # 20% Load: Process Creation Anomalies
            $cmd = $AnomalousCommands[$rnd.Next($AnomalousCommands.Count)]
            try {
                $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -WindowStyle Hidden -PassThru
                # Terminate rapidly to test ETW ProcessStop callback handling
                Start-Sleep -Milliseconds 10
                if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
            } catch {}
        }
    }

    # Thread Cleanup
    Remove-Item -Path $tempDir -Recurse -Force
    Remove-Item -Path $RegPath -Recurse -Force
}

function Invoke-ChaosWave([int]$WaveNumber, [int]$VolumeMultiplier, [int]$DelaySeconds) {
    Write-OutputLog "--- INITIATING CHAOS WAVE $WaveNumber ---" "Yellow"
    $TotalEvents = $BaseVolume * $VolumeMultiplier
    Write-OutputLog "Targeting $TotalEvents operations across $MaxConcurrency threads..." "Gray"

    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrency)
    $RunspacePool.Open()
    $Jobs = @()

    $EventsPerThread = [math]::Floor($TotalEvents / $MaxConcurrency)

    for ($t = 0; $t -lt $MaxConcurrency; $t++) {
        $Pipeline = [powershell]::Create()
        $Pipeline.RunspacePool = $RunspacePool
        $Pipeline.AddScript($ChaosScriptBlock) | Out-Null
        $Pipeline.AddArgument($EventsPerThread) | Out-Null
        $Pipeline.AddArgument($WaveNumber) | Out-Null
        $Pipeline.AddArgument($t) | Out-Null

        $Jobs += [PSCustomObject]@{
            Pipe = $Pipeline
            Result = $Pipeline.BeginInvoke()
        }
    }

    while ($Jobs.Result.IsCompleted -contains $false) {
        Start-Sleep -Milliseconds 250
    }

    foreach ($Job in $Jobs) {
        $Job.Pipe.EndInvoke($Job.Result)
        $Job.Pipe.Dispose()
    }

    $RunspacePool.Close()
    $RunspacePool.Dispose()

    Write-OutputLog "Wave $WaveNumber completed. Entering backoff protocol for $DelaySeconds seconds..." "Green"
    Start-Sleep -Seconds $DelaySeconds
}

function Generate-ChaosReport([datetime]$StartTime) {
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host " DEEP SENSOR CHAOS TEST RESULTS" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor Cyan

    if (-not (Test-Path $LogPath)) {
        Write-Host "[!] Diagnostic log not found at $LogPath" -ForegroundColor Red
        return
    }

    $rawLogs = Get-Content $LogPath -ErrorAction SilentlyContinue
    $metrics = @()
    $blindings = @()

    foreach ($line in $rawLogs) {
        # Parse standard log timestamp format: [2026-05-02 13:23:22.276]
        if ($line -match "^\[(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\]\s(.*)") {
            $logDateStr = $matches[1]
            $logContent = $matches[2]

            try {
                $logDate = [datetime]::ParseExact($logDateStr, "yyyy-MM-dd HH:mm:ss.fff", $null)

                # Only process logs that occurred AFTER the stress test started
                if ($logDate -ge $StartTime) {
                    if ($logContent -match "\[METRICS\]") {
                        $parsed = @{}
                        $parsed.Timestamp = $logDateStr

                        # Extract key-value pairs from the metrics line
                        if ($logContent -match "events/min=(\d+)") { $parsed.EventsPerMin = [long]$matches[1] }
                        if ($logContent -match "alerts/min=(\d+)") { $parsed.AlertsPerMin = [long]$matches[1] }
                        if ($logContent -match "ml_evals/min=(\d+)") { $parsed.MlEvalsPerMin = [long]$matches[1] }
                        if ($logContent -match "events_lost=(\d+)") { $parsed.EventsLost = [long]$matches[1] }
                        if ($logContent -match "ml_queue=(\d+)") { $parsed.MlQueue = [long]$matches[1] }
                        if ($logContent -match "yara_queue=(\d+)") { $parsed.YaraQueue = [long]$matches[1] }

                        $metrics += [PSCustomObject]$parsed
                    }
                    elseif ($logContent -match "SENSOR_BLINDING_DETECTED:(\d+)") {
                        $blindings += [PSCustomObject]@{
                            Timestamp = $logDateStr
                            DroppedPackets = [long]$matches[1]
                        }
                    }
                }
            } catch {}
        }
    }

    Write-Host "Test Start Time: " -NoNewline; Write-Host $StartTime.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow
    Write-Host "Total Metric Ticks Captured: " -NoNewline; Write-Host $metrics.Count -ForegroundColor Yellow

    if ($metrics.Count -gt 0) {
        $maxEvents = ($metrics | Measure-Object -Property EventsPerMin -Maximum).Maximum
        $maxAlerts = ($metrics | Measure-Object -Property AlertsPerMin -Maximum).Maximum
        $totalLost = ($metrics | Measure-Object -Property EventsLost -Sum).Sum
        $maxMlQueue = ($metrics | Measure-Object -Property MlQueue -Maximum).Maximum
        $maxYaraQueue = ($metrics | Measure-Object -Property YaraQueue -Maximum).Maximum

        Write-Host "`n--- ENGINE PERFORMANCE METRICS ---" -ForegroundColor Gray
        Write-Host "Peak Ingestion Rate: " -NoNewline; Write-Host "$maxEvents events/min" -ForegroundColor Green
        Write-Host "Peak Alerting Rate:  " -NoNewline; Write-Host "$maxAlerts alerts/min" -ForegroundColor Green
        Write-Host "Maximum ML Queue:    " -NoNewline; Write-Host "$maxMlQueue items" -ForegroundColor $(if($maxMlQueue -gt 1500) {"Red"} else {"Green"})
        Write-Host "Maximum YARA Queue:  " -NoNewline; Write-Host "$maxYaraQueue items" -ForegroundColor $(if($maxYaraQueue -gt 1500) {"Red"} else {"Green"})

        Write-Host "`n--- CHRONOLOGICAL METRIC SNAPSHOTS ---" -ForegroundColor Gray
        $metrics | Select-Object Timestamp, EventsPerMin, AlertsPerMin, EventsLost, MlQueue | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor DarkCyan
    }

    Write-Host "--- STABILITY & BLINDING EVENTS ---" -ForegroundColor Gray
    if ($blindings.Count -gt 0) {
        Write-Host "[!] SENSOR BLINDING DETECTED ($($blindings.Count) Occurrences)" -ForegroundColor Red
        foreach ($b in $blindings) {
            Write-Host "  -> At $($b.Timestamp) | Dropped: $($b.DroppedPackets) events" -ForegroundColor DarkRed
        }
    } else {
        Write-Host "[+] ZERO BLINDING EVENTS DETECTED. ETW Buffers remained stable." -ForegroundColor Green
    }

    Write-Host "================================================================`n" -ForegroundColor Cyan
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

Write-OutputLog "DEEP SENSOR STRESS TEST INITIATED" "Magenta"
Write-OutputLog "Base Volume: $BaseVolume | Threads: $MaxConcurrency" "Gray"

# Capture the exact start time to filter logs reliably
$TestStartTime = Get-Date

Start-Sleep -Seconds 2

# 1. Warmup
Invoke-ChaosWave -WaveNumber 1 -VolumeMultiplier 1 -DelaySeconds 5

# 2. Moderate Flood
Invoke-ChaosWave -WaveNumber 2 -VolumeMultiplier 5 -DelaySeconds 10

# 3. Severe Spike (Test Fast-Path & Buffer Exhaustion)
Invoke-ChaosWave -WaveNumber 3 -VolumeMultiplier 15 -DelaySeconds 15

# 4. Sustained Pulse (Test ML Drain Rate)
for ($pulse = 4; $pulse -le 8; $pulse++) {
    Invoke-ChaosWave -WaveNumber $pulse -VolumeMultiplier 3 -DelaySeconds 2
}

# 5. Terminal Flood
Invoke-ChaosWave -WaveNumber 9 -VolumeMultiplier 25 -DelaySeconds 5

Write-OutputLog "ALL WAVES COMPLETE. Entering 65-second cooldown to capture final Engine Metrics flush..." "Magenta"

$cooldown = 65
for ($i = $cooldown; $i -gt 0; $i--) {
    Write-Host "`rWaiting for ETW Watchdog flush... $i seconds remaining   " -NoNewline -ForegroundColor DarkGray
    Start-Sleep -Seconds 1
}
Write-Host ""

# Generate the grepped report
Generate-ChaosReport -StartTime $TestStartTime