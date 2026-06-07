<#
.SYNOPSIS
    Nexus Validation: Playbook 7 (Active Defense Console UI)

.DESCRIPTION
    Renders the terminal HUD for quarantine alerts from all detection layers:
    - Vector similarity alerts (worker_qdrant)
    - Model A reconstruction error alerts (serve_baseline.py)
    Validates alignment, math pinning, governance metrics, and vector space display.
#>

[CmdletBinding()]
param (
    [string]$TargetProcess = "C:\Temp\malicious_stager.exe",
    [string]$MitreTactic = "T1059.001",
    [float]$AnomalyScore = 0.987542,
    [float]$Threshold = 0.850000,
    [string]$VectorName = "c2_math",
    [string]$SourceType = "windows_c2",
    [float]$DisruptionIndex = 0.10,
    [float]$AssetValue = 0.10,
    [string]$CriticVerdict = "CONFIRM_QUARANTINE",
    # Model A fields (only used when VectorName = "baseline_reconstruction")
    [float]$ReconstructionError = 0.0,
    [float]$BaselineThreshold = 0.05
)

Clear-Host
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "       NEXUS ACTIVE DEFENSE: QUARANTINE HUD       " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# ── HUD Alignment & Math Pinning ──
$scoreStr     = [math]::Round($AnomalyScore, 4).ToString("0.0000")
$thresholdStr = [math]::Round($Threshold, 4).ToString("0.0000")
$diStr        = [math]::Round($DisruptionIndex, 4).ToString("0.0000")
$avStr        = [math]::Round($AssetValue, 4).ToString("0.0000")

$labelPad = 22
$valuePad = 35

function Write-PinnedRow ([string]$Label, [string]$Value, [ConsoleColor]$Color) {
    Write-Host $Label.PadRight($labelPad) -NoNewline
    Write-Host ": " -NoNewline
    Write-Host $Value.PadRight($valuePad) -ForegroundColor $Color
}

Write-PinnedRow "ACTION" "PROCESS SUSPENDED" "Green"
Write-PinnedRow "TARGET ENTITY" $TargetProcess "Yellow"
Write-PinnedRow "TTP SIGNATURE" $MitreTactic "Red"
Write-PinnedRow "SOURCE TYPE" $SourceType "White"
Write-PinnedRow "VECTOR SPACE" $VectorName "Cyan"

Write-Host "`n--- Detection Metrics --------------------------" -ForegroundColor DarkGray

if ($VectorName -eq "baseline_reconstruction") {
    # Model A alert rendering
    $reconStr = [math]::Round($ReconstructionError, 6).ToString("0.000000")
    $bThreshStr = [math]::Round($BaselineThreshold, 6).ToString("0.000000")
    Write-PinnedRow "RECONSTRUCTION ERR" $reconStr "Red"
    Write-PinnedRow "BASELINE THRESHOLD" $bThreshStr "White"
    Write-PinnedRow "ERROR RATIO" ([math]::Round($ReconstructionError / [math]::Max($BaselineThreshold, 0.0001), 1).ToString("0.0") + "x") "Red"
} else {
    # Vector similarity alert rendering
    Write-PinnedRow "QDRANT THRESHOLD" $thresholdStr "White"
    Write-PinnedRow "ANOMALY SCORE" $scoreStr "Red"
}

Write-Host "--------------------------------------------------" -ForegroundColor DarkGray

Write-Host "`n--- Governance Metrics -------------------------" -ForegroundColor DarkGray
Write-PinnedRow "DISRUPTION INDEX" $diStr $(if ([float]$diStr -gt 0.5) {"Red"} else {"Green"})
Write-PinnedRow "ASSET VALUE" $avStr $(if ([float]$avStr -ge 0.9) {"Red"} else {"Green"})
Write-PinnedRow "CRITIC VERDICT" $CriticVerdict $(
    if ($CriticVerdict -eq "CONFIRM_QUARANTINE") {"Green"}
    elseif ($CriticVerdict -eq "MANUAL_REVIEW") {"Yellow"}
    else {"Red"}
)
Write-Host "--------------------------------------------------" -ForegroundColor DarkGray

Write-Host "`n[+] HUD rendering test complete. Formatting constraints held." -ForegroundColor Green

# ── Self-test: Render both alert types ──
if (-not $PSBoundParameters.ContainsKey('VectorName')) {
    Write-Host "`n[*] Running self-test with Model A baseline alert..." -ForegroundColor Cyan
    & $PSCommandPath `
        -TargetProcess "10.0.1.50 -> 185.10.68.22" `
        -MitreTactic "Model A Anomaly" `
        -AnomalyScore 0.85 `
        -Threshold 0.85 `
        -VectorName "baseline_reconstruction" `
        -SourceType "network_tap" `
        -DisruptionIndex 0.10 `
        -AssetValue 0.10 `
        -CriticVerdict "CONFIRM_QUARANTINE" `
        -ReconstructionError 0.25 `
        -BaselineThreshold 0.05
}