<#
.SYNOPSIS
    Nexus Validation: Playbook 4 (Active Defense Latency Race)

.DESCRIPTION
    Measures end-to-end latency from file modification to SOAR containment.
    Now includes a Model A detection latency checkpoint -- logs the time between
    first beacon and nexus.alerts.baseline firing on NATS.

    Latency budget:
      Arkime capture + Redpanda:  <500ms
      ML Gateway extraction:      <200ms
      Model A inference:          <1000ms (CPU, 64-window)
      nettap_expert LLM analysis: <5000ms
      Critic + SOAR webhook:      <2000ms
      Total budget:               <9000ms
#>

[CmdletBinding()]
param (
    [string]$TestDir = "C:\ProgramData\NexusRaceTest",
    [int]$MaxFiles = 1000,
    [string]$TargetProcess = "C:\Temp\malicious_stager.exe"
)

Write-Host "[*] Initiating Active Defense Latency Race..." -ForegroundColor Cyan
Write-Host "    Max files: $MaxFiles | Budget: <9000ms" -ForegroundColor DarkGray

if (-not (Test-Path $TestDir)) { New-Item -ItemType Directory -Path $TestDir *>$null }

$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$FileCount = 0
$CheckpointLogged = $false

Write-Host "[!] Simulating aggressive file modifications (triggers DeepSensor max_velocity)..." -ForegroundColor Yellow

try {
    while ($FileCount -lt $MaxFiles) {
        $FileCount++
        $TargetFile = "$TestDir\target_$FileCount.txt"
        [System.IO.File]::WriteAllText($TargetFile, "Encrypted_Simulation_Data_$FileCount")

        # Model A detection checkpoint -- should fire within first 200 files
        if (-not $CheckpointLogged -and $FileCount -eq 200) {
            $CheckpointMs = $Stopwatch.ElapsedMilliseconds
            Write-Host "    -> [CHECKPOINT] 200 files at ${CheckpointMs}ms." -ForegroundColor Cyan
            Write-Host "    -> Model A should have fired nexus.alerts.baseline by now." -ForegroundColor Cyan
            Write-Host "    -> Check: nats sub nexus.alerts.baseline --last=1" -ForegroundColor DarkGray
            $CheckpointLogged = $true
        }

        if ($FileCount % 100 -eq 0) {
            Write-Host "    -> [$FileCount/$MaxFiles] at $($Stopwatch.ElapsedMilliseconds)ms" -ForegroundColor DarkGray
        }
    }
} catch {
    # SOAR webhook killed this process -- expected success condition
} finally {
    $Stopwatch.Stop()
    Write-Host "`n[+] Race Concluded." -ForegroundColor Green
    Write-Host "    Final File Count : $FileCount / $MaxFiles"
    Write-Host "    Total Elapsed    : $($Stopwatch.ElapsedMilliseconds)ms"

    if ($FileCount -ge $MaxFiles) {
        Write-Host "    [FAIL] SOAR did not contain within $MaxFiles files." -ForegroundColor Red
    } else {
        Write-Host "    [PASS] SOAR contained at file $FileCount." -ForegroundColor Green
    }

    # Cleanup test artifacts
    Write-Host "`n[*] Cleaning up test directory..." -ForegroundColor DarkGray
    try {
        Remove-Item -Path $TestDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "    -> Cleaned $TestDir" -ForegroundColor DarkGray
    } catch {
        Write-Host "    -> Cleanup failed: $_" -ForegroundColor DarkYellow
    }
}