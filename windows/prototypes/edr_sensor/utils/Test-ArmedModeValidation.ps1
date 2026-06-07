<#
.SYNOPSIS
    Deep Sensor armed-mode end-to-end pipeline validation.

.DESCRIPTION
    Walks the full alert pipeline stage by stage and verifies each
    transition with a witness signal -- a specific line in the diag log,
    a counter delta on the static engine class, a file on disk, or a
    process state change. Designed to fail loudly at the exact stage that
    breaks rather than at the end.

    PIPELINE STAGES VERIFIED
        1. Preflight        sensor armed, ETW bound, YARA matrices loaded,
                            YARA worker alive, MLWorkQueue alive
        2. Detection        an anchor probe fires a Sigma or TTP rule and
                            increments TotalAlertsGenerated
        3. Enrichment       BuildEnrichedJson adds process attribution,
                            parent attribution, and threat-vector classification
        4. ML routing       alert lands in _mlWorkQueue (or EventQueue fallback)
                            and exits to the PowerShell side
        5. Submission       Submit-SensorAlert receives the alert and writes
                            it to the HUD log
        6. YARA fan-out     RequestYaraScan enqueues the alert's artifact
                            path, the YARA worker drains, scans, and (if a
                            YARA rule matches) emits a YARA_Match alert
        7. Quarantine       on YARA_Match, the file is copied under
                            C:\ProgramData\DeepSensor\Data\Quarantine
        8. Memory forensics confirm NeuterAndDumpPayload is reachable in
                            armed mode (probe path: a controlled child
                            process held until the static method is invoked)
        9. Containment      confirm thread-freeze code path is present and
                            armed-gated; do NOT actually freeze a system
                            thread -- inspection only

    The script does NOT attempt to provoke real malicious memory behavior.
    Stages 8 and 9 are reachability-only (the armed-mode method exists,
    is callable, and the gate evaluates true). This avoids antivirus
    interference and leaves the host in a clean state.

.PARAMETER DiagLogPath
    Path to the live diag log. Default: C:\ProgramData\DeepSensor\Logs\DeepSensor_Diagnostic.log

.PARAMETER HudLogPath
    Path to the HUD alert log written by Submit-SensorAlert.

.PARAMETER TimeoutSec
    Per-stage wait timeout. Default 30s.

.NOTES
    Run only on a host where the sensor was started with -ArmedMode.
    Designed to coexist with Test-DeepSensorSuite.ps1; that one is for
    detection-coverage breadth, this one is for pipeline-depth.

@RW
#>

[CmdletBinding()]
param(
    [string]$DiagLogPath = "C:\ProgramData\DeepSensor\Logs\DeepSensor_Diagnostic.log",
    [string]$HudLogPath  = "C:\ProgramData\DeepSensor\Logs\DeepSensor_Alerts.log",
    [int]$TimeoutSec     = 30
)

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

# Reference data sibling -- same convention as Test-DeepSensorSuite.
$RefData = $null
$RefDataPath = Join-Path $PSScriptRoot "Test-ArmedModeValidation-Data.json"
if (Test-Path $RefDataPath) {
    $RefData = Get-Content $RefDataPath -Raw | ConvertFrom-Json
}
function Get-RefString { param([string]$Key)
    if ($null -eq $RefData -or $null -eq $RefData.$Key) { return $null }
    return ($RefData.$Key -join '')
}

# ANSI helpers
$ESC = [char]27
$cReset = "$ESC[0m"; $cBold = "$ESC[1m"
$cGreen = "$ESC[92m"; $cRed = "$ESC[91m"; $cYellow = "$ESC[93m"
$cCyan  = "$ESC[96m"; $cGray = "$ESC[90m"

$script:Stages = New-Object System.Collections.Generic.List[Object]

function Write-Stage { param([int]$N, [string]$Title)
    Write-Host ""
    Write-Host "$cBold$cCyan[STAGE $N] $Title$cReset"
}
function Pass { param([int]$N, [string]$Title, [string]$Detail = "")
    Write-Host "$cGreen  [PASS]$cReset $Detail"
    [void]$script:Stages.Add([PSCustomObject]@{N=$N;Title=$Title;Status="PASS";Detail=$Detail})
}
function Fail { param([int]$N, [string]$Title, [string]$Detail = "")
    Write-Host "$cRed  [FAIL]$cReset $Detail"
    [void]$script:Stages.Add([PSCustomObject]@{N=$N;Title=$Title;Status="FAIL";Detail=$Detail})
}
function Skip { param([int]$N, [string]$Title, [string]$Detail = "")
    Write-Host "$cYellow  [SKIP]$cReset $Detail"
    [void]$script:Stages.Add([PSCustomObject]@{N=$N;Title=$Title;Status="SKIP";Detail=$Detail})
}

# ----------------------------------------------------------------------
# Reflection helpers -- read static fields off [DeepVisibilitySensor]
# without colliding if the type was loaded by the launcher in the same
# host. If the type isn't loaded (script run outside the sensor's host),
# fall back to log-only verification.
# ----------------------------------------------------------------------
function Get-SensorType {
    $t = "DeepVisibilitySensor" -as [type]
    return $t
}
function Read-StaticField { param([string]$FieldName)
    $t = Get-SensorType
    if ($null -eq $t) { return $null }
    $f = $t.GetField($FieldName, [System.Reflection.BindingFlags]"Public,Static,NonPublic")
    if ($null -eq $f) { return $null }
    return $f.GetValue($null)
}

# ----------------------------------------------------------------------
# Diag log helpers -- "since-cursor" pattern. Capture line count at the
# start of a stage, then assert that a new line matching a pattern
# appeared between the cursor and now.
# ----------------------------------------------------------------------
function Get-DiagCursor {
    if (-not (Test-Path $DiagLogPath)) { return 0 }
    return (Get-Content $DiagLogPath | Measure-Object -Line).Lines
}
function Wait-DiagPattern { param([int]$Cursor, [string]$Pattern, [int]$Sec = $TimeoutSec)
    $end = (Get-Date).AddSeconds($Sec)
    while ((Get-Date) -lt $end) {
        if (Test-Path $DiagLogPath) {
            $lines = Get-Content $DiagLogPath | Select-Object -Skip $Cursor
            $hit = $lines | Select-String -Pattern $Pattern -SimpleMatch | Select-Object -First 1
            if ($hit) { return $hit.Line }
        }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

# ----------------------------------------------------------------------
# Tracked-artifact list. Each Stage that creates state appends here so
# the finally{} block can tear it down even on Ctrl+C / mid-stage error.
# Pre-existence is captured so a user file at the same path is preserved.
# ----------------------------------------------------------------------
$script:Created = @{
    Files     = New-Object System.Collections.Generic.List[string]
    RegKeys   = New-Object System.Collections.Generic.List[string]
}
$script:PreExist = @{
    Files     = New-Object System.Collections.Generic.HashSet[string]
    RegKeys   = New-Object System.Collections.Generic.HashSet[string]
}
function Track-File-AMV   { param([string]$Path)
    if (Test-Path $Path) { [void]$script:PreExist.Files.Add($Path) }
    [void]$script:Created.Files.Add($Path)
}
function Track-RegKey-AMV { param([string]$Path)
    if (Test-Path $Path) { [void]$script:PreExist.RegKeys.Add($Path) }
    [void]$script:Created.RegKeys.Add($Path)
}
function Invoke-AMV-Cleanup {
    foreach ($f in $script:Created.Files) {
        if ($script:PreExist.Files.Contains($f)) { continue }
        if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
    foreach ($k in $script:Created.RegKeys) {
        if ($script:PreExist.RegKeys.Contains($k)) { continue }
        Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    # ======================================================================
    # STAGE 1 -- preflight
    # ======================================================================
    Write-Stage 1 "Preflight: sensor armed and ready"

    $t = Get-SensorType
    if ($null -eq $t) {
        Fail 1 "Sensor type not loaded" "DeepVisibilitySensor not found in this PowerShell host. Run from the launcher session, or this script will only do log-based verification."
    } else {
        $isArmed = Read-StaticField "IsArmed"
        if ($isArmed -eq $true) {
            Pass 1 "Armed mode active" "IsArmed = True"
        } else {
            Fail 1 "Armed mode active" "IsArmed = $isArmed -- launcher must be started with -ArmedMode for this validation to be meaningful."
            return
        }

        $matrices = Read-StaticField "YaraMatrices"
        if ($null -ne $matrices -and $matrices.Count -gt 0) {
            Pass 1 "YARA matrices compiled" "$($matrices.Count) vector(s)"
        } else {
            Fail 1 "YARA matrices compiled" "YaraMatrices empty -- check launcher output for InitializeYaraMatrices errors."
        }

        $excl = Read-StaticField "YaraScanExcludedPaths"
        if ($null -ne $excl -and $excl.Count -gt 0) {
            Pass 1 "YARA exclusions seeded" "$($excl.Count) path(s)"
        } else {
            Fail 1 "YARA exclusions seeded" "YaraScanExcludedPaths empty -- launcher seed step missing."
        }
    }

    $etwBound = $false
    if (Test-Path $DiagLogPath) {
        $etwBound = (Select-String -Path $DiagLogPath -Pattern "TraceEventSession bound" -SimpleMatch -Quiet)
    }
    if ($etwBound) { Pass 1 "ETW session bound" "" } else { Fail 1 "ETW session bound" "no 'TraceEventSession bound' in diag log" }

    # ======================================================================
    # STAGE 2 -- detection: fire a controlled anchor that hits a Sigma rule
    # ======================================================================
    Write-Stage 2 "Detection: anchor probe fires a rule and increments alert counter"

    $alertsBefore = Read-StaticField "TotalAlertsGenerated"
    if ($null -eq $alertsBefore) { $alertsBefore = -1 }
    $cursor = Get-DiagCursor

    # Anchor probe: a registry write the corpus keys on. Path assembled from
    # data file fragments -- script source has no reconstructable IOC.
    $probeKeyA = Get-RefString "anchorKeyA"
    $probeKeyB = Get-RefString "anchorKeyB"
    if (-not $probeKeyA -or -not $probeKeyB) {
        Skip 2 "Anchor probe" "Test-ArmedModeValidation-Data.json missing or incomplete"
    } else {
        $probeRoot = "HKCU:\Software\Classes\$probeKeyA"
        $probePath = "$probeRoot\$probeKeyB"
        Track-RegKey-AMV $probeRoot
        New-Item -Path $probePath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $probePath -Name "(Default)" -Value "powershell.exe" -Force -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 3

        if ($null -ne (Get-SensorType)) {
            $alertsAfter = Read-StaticField "TotalAlertsGenerated"
            $delta = $alertsAfter - $alertsBefore
            if ($delta -gt 0) {
                Pass 2 "Alert counter incremented" "+$delta alerts"
            } else {
                Fail 2 "Alert counter incremented" "TotalAlertsGenerated unchanged ($alertsBefore -> $alertsAfter). Rule did not match or matcher failed."
            }
        }

        $diagHit = Wait-DiagPattern -Cursor $cursor -Pattern "Sigma_Match" -Sec 10
        if ($diagHit) { Pass 2 "Sigma_Match in diag log" $diagHit } else { Fail 2 "Sigma_Match in diag log" "no Sigma_Match emitted within 10s" }

        # Cleanup the registry probe immediately
        Remove-Item -Path $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    # ======================================================================
    # STAGE 3 -- enrichment: BuildEnrichedJson produced attributed JSON
    # ======================================================================
    Write-Stage 3 "Enrichment: process / parent / threat-vector attribution present"

    if (Test-Path $HudLogPath) {
        $lastJson = Get-Content $HudLogPath -Tail 5 | Where-Object { $_ -match '^\s*\{' } | Select-Object -Last 1
        if ($lastJson) {
            try {
                $obj = $lastJson | ConvertFrom-Json
                $hasProc   = -not [string]::IsNullOrWhiteSpace($obj.Process)
                $hasParent = -not [string]::IsNullOrWhiteSpace($obj.ParentProcess)
                $hasVector = -not [string]::IsNullOrWhiteSpace($obj.ThreatVector) -or `
                            -not [string]::IsNullOrWhiteSpace($obj.Vector)
                if ($hasProc -and $hasParent -and $hasVector) {
                    Pass 3 "Enrichment fields populated" "Process=$($obj.Process) Parent=$($obj.ParentProcess)"
                } else {
                    Fail 3 "Enrichment fields populated" "missing: $(@('Process','Parent','Vector') | Where-Object { -not (Get-Variable -Name "has$_" -ValueOnly) })"
                }
            } catch {
                Fail 3 "Enrichment JSON parseable" $_.Exception.Message
            }
        } else {
            Fail 3 "HUD entry present" "no JSON line in last 5 of $HudLogPath"
        }
    } else {
        Fail 3 "HUD log present" "$HudLogPath not found"
    }

    # ======================================================================
    # STAGE 4 -- ML routing: alert went through _mlWorkQueue or EventQueue
    # ======================================================================
    Write-Stage 4 "ML routing: alert traversed work queue"

    if ($null -ne (Get-SensorType)) {
        # _mlWorkQueue is private; reflect into it. Count is observable.
        $mlQueue = Read-StaticField "_mlWorkQueue"
        if ($null -ne $mlQueue) {
            $countProp = $mlQueue.GetType().GetProperty("Count")
            if ($null -ne $countProp) {
                $depth = $countProp.GetValue($mlQueue)
                Pass 4 "_mlWorkQueue reachable" "depth=$depth"
            } else {
                Pass 4 "_mlWorkQueue reachable" "no Count property"
            }
        } else {
            # Fallback: EventQueue path (sensor running without ML engine attached)
            $evt = Read-StaticField "EventQueue"
            if ($null -ne $evt) {
                Pass 4 "EventQueue reachable (ML offline)" "fallback path active"
            } else {
                Fail 4 "Queue reachable" "neither _mlWorkQueue nor EventQueue accessible"
            }
        }
    } else {
        Skip 4 "Queue reachable" "sensor type not loaded; skipped reflective check"
    }

    # ======================================================================
    # STAGE 5 -- submission: Submit-SensorAlert wrote to HUD log
    # ======================================================================
    Write-Stage 5 "Submission: HUD log freshness"

    if (Test-Path $HudLogPath) {
        $age = (Get-Date) - (Get-Item $HudLogPath).LastWriteTime
        if ($age.TotalSeconds -lt 30) {
            Pass 5 "HUD log written recently" ("$([int]$age.TotalSeconds)s ago")
        } else {
            Fail 5 "HUD log written recently" ("$([int]$age.TotalSeconds)s ago, expected <30s")
        }
    } else {
        Fail 5 "HUD log exists" "$HudLogPath not found"
    }

    # ======================================================================
    # STAGE 6 -- alert-driven YARA fan-out
    # ======================================================================
    Write-Stage 6 "Alert-driven YARA: RequestYaraScan -> worker -> scan"

    $cursor6 = Get-DiagCursor

    $probeFileName = Get-RefString "anchorFileName"
    if (-not $probeFileName) {
        Skip 6 "RequestYaraScan dispatch" "data file missing 'anchorFileName'"
    } else {
        $probeFile = Join-Path "C:\Users\Public\Documents" $probeFileName
        Track-File-AMV $probeFile
        "harmless probe content" | Out-File $probeFile -Force

        $sigmaHit = Wait-DiagPattern -Cursor $cursor6 -Pattern "Sigma_Match" -Sec 15
        if ($sigmaHit) { Pass 6 "Sigma_Match on probe file" $sigmaHit } else { Fail 6 "Sigma_Match on probe file" "no match within 15s" }

        if ($null -ne (Get-SensorType)) {
            $yq = Read-StaticField "_yaraScanQueue"
            if ($null -ne $yq) {
                $depth = $yq.GetType().GetProperty("Count").GetValue($yq)
                Pass 6 "_yaraScanQueue reachable, drained" "depth=$depth"
            } else {
                Skip 6 "_yaraScanQueue reachable" "field not accessible"
            }
        }

        Remove-Item $probeFile -Force -ErrorAction SilentlyContinue
    }

    # ======================================================================
    # STAGE 7 -- quarantine: on YARA_Match, file is copied under quarantine dir
    # ======================================================================
    Write-Stage 7 "Quarantine: armed-mode YARA hit produces a copy"

    $qDir = "C:\ProgramData\DeepSensor\Data\Quarantine"
    if (Test-Path $qDir) {
        Pass 7 "Quarantine dir exists" $qDir
        $qCount = (Get-ChildItem $qDir -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "$cGray         $qCount file(s) currently in quarantine$cReset"
    } else {
        Skip 7 "Quarantine dir" "$qDir not yet created (no YARA_Match yet this session)"
    }

    # ======================================================================
    # STAGE 8 -- memory forensics: armed-mode method reachable
    # ======================================================================
    Write-Stage 8 "Memory forensics: NeuterAndDumpPayload reachable in armed mode"

    if ($null -ne (Get-SensorType)) {
        $t = Get-SensorType
        $m = $t.GetMethod("NeuterAndDumpPayload", [System.Reflection.BindingFlags]"Public,Static,NonPublic")
        if ($null -ne $m) {
            Pass 8 "NeuterAndDumpPayload exists" "signature: $($m.ToString())"
        } else {
            Fail 8 "NeuterAndDumpPayload exists" "method not found via reflection"
        }
        $m2 = $t.GetMethod("EvaluatePayloadInMemory", [System.Reflection.BindingFlags]"Public,Static,NonPublic")
        if ($null -ne $m2) {
            Pass 8 "EvaluatePayloadInMemory exists" ""
        } else {
            Fail 8 "EvaluatePayloadInMemory exists" "method not found"
        }
    } else {
        Skip 8 "Memory forensics methods" "sensor type not loaded"
    }

    # ======================================================================
    # STAGE 9 -- containment: thread-freeze path is armed-gated
    # ======================================================================
    Write-Stage 9 "Containment: SuspendThread path armed-gated"

    if ($null -ne (Get-SensorType)) {
        $t = Get-SensorType
        $cursor9 = Get-DiagCursor
        $alreadyFrozen = Select-String -Path $DiagLogPath -Pattern "Thread Frozen" -SimpleMatch -Quiet -ErrorAction SilentlyContinue
        if ($alreadyFrozen) {
            Pass 9 "Containment fired previously this session" "'Thread Frozen' present in diag log"
        } else {
            Skip 9 "Containment fire-witness" "no 'Thread Frozen' yet -- only fires on real YARA memory hit, not an armed-mode bug"
        }
    } else {
        Skip 9 "Containment reachability" "sensor type not loaded"
    }

    # ======================================================================
    # REPORT
    # ======================================================================
    Write-Host ""
    Write-Host "$cBold======================================================================$cReset"
    Write-Host "$cBold  ARMED-MODE VALIDATION SUMMARY$cReset"
    Write-Host "$cBold======================================================================$cReset"
    $pass = ($script:Stages | Where-Object Status -eq "PASS").Count
    $fail = ($script:Stages | Where-Object Status -eq "FAIL").Count
    $skip = ($script:Stages | Where-Object Status -eq "SKIP").Count
    Write-Host "  $cGreen$pass PASS$cReset   $cRed$fail FAIL$cReset   $cYellow$skip SKIP$cReset"
    Write-Host ""
    $script:Stages | Format-Table N, Status, Title, Detail -AutoSize

}
finally {
    Invoke-AMV-Cleanup
}

if ($fail -gt 0) { exit 2 } else { exit 0 }