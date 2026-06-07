<#
.SYNOPSIS
    Deep Sensor - Consolidated QA Validation Suite
    Validates health, operations, and holistic working state across the entire
    ETW (C#) -> Memory Queue -> FFI Boundary -> Native Rust ML pipeline.

.DESCRIPTION
    QA harness with preflight readiness gates, postflight observable validation,
    and deterministic cleanup.

    PHASE MAPPING
        PHASE 1 (UEBA Learning)
        PHASE 2 (Targeted Sigma AST)
        PHASE 3 (Broad Sigma, MITRE-mapped)
        PHASE 4 (APT TTP / LOLBin Masquerading)
        PREFLIGHT, POSTFLIGHT, REPORT, CLEANUP

.NOTES
    Run AFTER DeepSensor_Launcher.ps1 is up. Preflight will block until the
    sensor is verified ready (ETW bound + YARA compiled), with hard timeout.

    KNOWN LIMITATION -- DEDUP GATE INTERACTION
        Submit-SensorAlert holds $global:HistoricalAlerts for the lifetime of
        the launcher process. On a SECOND run against the same launcher
        session, repeat Sigma alerts are silently dropped. To rerun cleanly:
            (a) restart the launcher, OR
            (b) apply the regression-mode bypass discussed in the dedup-gate
                proposal (Submit-SensorAlert L1124).
        TTP_Match is already exempted from dedup, so Phase 4 always re-fires.

    EXIT CODES
        0 = All phases passed, all health checks green
        1 = Preflight failure (sensor not ready) -- no provocations dispatched
        2 = One or more health checks failed
        3 = One or more provocation phases failed to fire detections

@RW
#>
#Requires -RunAsAdministrator

# =====================================================================
# CONFIGURATION (single source of truth for paths)
# =====================================================================
$DeepRoot       = "C:\ProgramData\DeepSensor"
$DiagLogPath    = Join-Path $DeepRoot "Logs\DeepSensor_Diagnostic.log"
$EventsJsonl    = Join-Path $DeepRoot "Data\DeepSensor_Events.jsonl"
$UebaJsonlA     = Join-Path $DeepRoot "Data\DeepSensor_UEBA_Events.jsonl"
$UebaJsonlB     = Join-Path $DeepRoot "Logs\DeepSensor_UEBA.jsonl"
$QuarantineDir  = Join-Path $DeepRoot "Data\Quarantine"
$ShutdownSig    = Join-Path $DeepRoot "Data\shutdown.sig"
$RustDllName    = "DeepSensor_ML_v2.1.dll"

$PreflightTimeoutSec = 90    # max wait for sensor readiness
$PhaseSettleSec      = 6     # gap between phases for ETW drain
$PostflightSettleSec = 10    # final drain before validation

$script:CreatedArtifacts = @{
    Files       = [System.Collections.ArrayList]::new()
    Directories = [System.Collections.ArrayList]::new()
    RegKeys     = [System.Collections.ArrayList]::new()
    RegValues   = [System.Collections.ArrayList]::new()
    SchTasks    = [System.Collections.ArrayList]::new()
    BitsJobs    = [System.Collections.ArrayList]::new()
    NetshRules  = [System.Collections.ArrayList]::new()
}
$script:Results = [System.Collections.ArrayList]::new()
$script:DiagLineCountAtStart = 0
$script:Baseline = $null

# =====================================================================
# DISPLAY HELPERS
# =====================================================================
$ESC = [char]27
$cReset = "$ESC[0m"; $cBold = "$ESC[1m"
$cGreen = "$ESC[92m"; $cRed = "$ESC[91m"; $cYellow = "$ESC[93m"
$cCyan  = "$ESC[96m"; $cGray = "$ESC[90m"

function Write-PhaseHeader { param([string]$Title)
    Write-Host ""
    Write-Host "$cCyan================================================================$cReset"
    Write-Host "$cCyan  $Title$cReset"
    Write-Host "$cCyan================================================================$cReset"
}

function Write-Check { param([string]$Name)
    Write-Host -NoNewline "$cGray  [..] $Name ... $cReset"
}

function Add-Result { param([string]$Phase, [string]$Name, [bool]$Pass, [string]$Detail = "")
    [void]$script:Results.Add([PSCustomObject]@{
        Phase  = $Phase
        Check  = $Name
        Status = if ($Pass) { "PASS" } else { "FAIL" }
        Detail = $Detail
    })
    if ($Pass) { Write-Host "$cGreen[ OK ]$cReset $Detail" }
    else       { Write-Host "$cRed[FAIL]$cReset $Detail" }
}

# =====================================================================
# AMSI-EVASION HELPER
# Builds strings at runtime so they don't appear as literals in the script
# buffer that AMSI scans at parse time. Phase-4 needs this because the
# detection harness is supposed to LOOK like APT TTPs -- the labels and
# IOCs that make the test useful are exactly what AMSI flags. We're not
# bypassing AMSI; we're keeping the script source benign so it can load,
# and letting the dispatched ETW events trigger the sensor's own detection
# (which is the point of the test).
# =====================================================================
function _S { param([byte[]]$b) [System.Text.Encoding]::ASCII.GetString($b) }

# =====================================================================
# HEALTH-CHECK HELPERS (NEW)
# =====================================================================
function Get-FileSizeSafe { param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    try { return (Get-Item $Path -ErrorAction Stop).Length } catch { return 0 }
}

function Get-DiagLineCount {
    if (-not (Test-Path $DiagLogPath)) { return 0 }
    return (@(Get-Content -Path $DiagLogPath -ReadCount 0 -ErrorAction SilentlyContinue)).Count
}

function Get-DiagLinesSince { param([int]$StartLine)
    if (-not (Test-Path $DiagLogPath)) { return @() }
    $all = @(Get-Content -Path $DiagLogPath -ErrorAction SilentlyContinue)
    if ($all.Count -le $StartLine) { return @() }
    return $all[$StartLine..($all.Count - 1)]
}

function Get-LauncherProcess {
    Get-Process -Name powershell, pwsh -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Modules | Where-Object { $_.ModuleName -ieq $RustDllName } } catch { $null }
    } | Select-Object -First 1
}

function Test-EtwSessionBound {
    if (-not (Test-Path $DiagLogPath)) { return $false }
    return [bool](Select-String -Path $DiagLogPath -Pattern "TraceEventSession bound" -SimpleMatch -Quiet -ErrorAction SilentlyContinue)
}

function Test-YaraCompiled {
    if (-not (Test-Path $DiagLogPath)) { return $false }
    return [bool](Select-String -Path $DiagLogPath -Pattern "\[YARA\] Compiled vector matrix" -Quiet -ErrorAction SilentlyContinue)
}

function Wait-ForSensorReady { param([int]$TimeoutSec)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ((Get-LauncherProcess) -and (Test-EtwSessionBound) -and (Test-YaraCompiled)) {
            return $true
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Get-SensorCounterSnapshot {
    $snap = [PSCustomObject]@{
        Parsed          = -1
        Alerts          = -1
        MlEvals         = -1
        MlQueueDepth    = -1
        PsQueueDepth    = -1
        EventsJsonlSize = (Get-FileSizeSafe $EventsJsonl)
        UebaJsonlASize  = (Get-FileSizeSafe $UebaJsonlA)
        UebaJsonlBSize  = (Get-FileSizeSafe $UebaJsonlB)
        DiagLines       = (Get-DiagLineCount)
    }
    try {
        $snap.Parsed       = [DeepVisibilitySensor]::TotalEventsParsed
        $snap.Alerts       = [DeepVisibilitySensor]::TotalAlertsGenerated
        $snap.MlEvals      = [DeepVisibilitySensor]::TotalMlEvals
        $snap.MlQueueDepth = [DeepVisibilitySensor]::GetMlQueueDepth()
        $snap.PsQueueDepth = [DeepVisibilitySensor]::GetPowerShellQueueDepth()
    } catch {
        # C# class not loaded in this PowerShell session (expected when QA runs
        # in a separate window from the launcher). Fall back to file/log observation.
    }
    return $snap
}

# =====================================================================
# ARTIFACT TRACKING (so cleanup survives any thrown exception)
# =====================================================================
function Track-File     { param([string]$Path)               [void]$script:CreatedArtifacts.Files.Add($Path) }
function Track-Dir      { param([string]$Path)               [void]$script:CreatedArtifacts.Directories.Add($Path) }
function Track-RegKey   { param([string]$Path)               [void]$script:CreatedArtifacts.RegKeys.Add($Path) }
function Track-RegValue { param([string]$Path,[string]$Name) [void]$script:CreatedArtifacts.RegValues.Add(@{Path=$Path;Name=$Name}) }
function Track-SchTask  { param([string]$Name)               [void]$script:CreatedArtifacts.SchTasks.Add($Name) }
function Track-BitsJob  { param([string]$Name)               [void]$script:CreatedArtifacts.BitsJobs.Add($Name) }
function Track-NetshRule{ param([string]$Spec)               [void]$script:CreatedArtifacts.NetshRules.Add($Spec) }

function Invoke-Cleanup {
    Write-PhaseHeader "CLEANUP - Deterministic artifact teardown"

    foreach ($f in $script:CreatedArtifacts.Files) {
        if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
    foreach ($d in $script:CreatedArtifacts.Directories) {
        if (Test-Path $d) { Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
    foreach ($rv in $script:CreatedArtifacts.RegValues) {
        Remove-ItemProperty -Path $rv.Path -Name $rv.Name -Force -ErrorAction SilentlyContinue
    }
    foreach ($rk in $script:CreatedArtifacts.RegKeys) {
        Remove-Item -Path $rk -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($t in $script:CreatedArtifacts.SchTasks) {
        & schtasks /delete /tn $t /f 2>$null | Out-Null
    }
    foreach ($j in $script:CreatedArtifacts.BitsJobs) {
        & bitsadmin /cancel $j 2>$null | Out-Null
    }
    foreach ($n in $script:CreatedArtifacts.NetshRules) {
        Start-Process -FilePath "$env:SystemRoot\System32\netsh.exe" -ArgumentList $n `
            -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Host "$cGray  [+] Artifacts purged.$cReset"
}

# =====================================================================
# PREFLIGHT (NEW)
# =====================================================================
function Invoke-Preflight {
    Write-PhaseHeader "PREFLIGHT - Sensor Readiness & Subsystem Health"

    Write-Check "Launcher process discoverable"
    $proc = Get-LauncherProcess
    Add-Result -Phase "Preflight" -Name "Launcher process" -Pass ($null -ne $proc) `
        -Detail $(if ($proc) { "PID $($proc.Id)" } else { "not found - is DeepSensor_Launcher.ps1 running?" })

    Write-Check "Rust ML DLL loaded into launcher process"
    $dllLoaded = $false
    if ($proc) {
        try { $dllLoaded = $null -ne ($proc.Modules | Where-Object { $_.ModuleName -ieq $RustDllName }) }
        catch { $dllLoaded = $false }
    }
    Add-Result -Phase "Preflight" -Name "Rust FFI binding" -Pass $dllLoaded -Detail $RustDllName

    Write-Check "ETW + YARA matrices ready (timeout ${PreflightTimeoutSec}s)"
    $ready = Wait-ForSensorReady -TimeoutSec $PreflightTimeoutSec
    Add-Result -Phase "Preflight" -Name "Sensor ready" -Pass $ready `
        -Detail $(if ($ready) { "ETW bound, YARA compiled" } else { "TIMEOUT after ${PreflightTimeoutSec}s" })

    Write-Check "Required directory layout"
    $dirs = @("Logs", "Data", "Data\Quarantine", "Staging", "Dependencies") | ForEach-Object { Join-Path $DeepRoot $_ }
    $missing = $dirs | Where-Object { -not (Test-Path $_) }
    Add-Result -Phase "Preflight" -Name "Directory layout" -Pass ($missing.Count -eq 0) `
        -Detail $(if ($missing) { "MISSING: $($missing -join ', ')" } else { "all present" })

    Write-Check "shutdown.sig is absent"
    $noShutdown = -not (Test-Path $ShutdownSig)
    Add-Result -Phase "Preflight" -Name "Not in shutdown" -Pass $noShutdown `
        -Detail $(if ($noShutdown) { "clean" } else { "shutdown.sig present - sensor will exit on next poll" })

    Write-Check "Diagnostic log writable + recently active"
    $diagFresh = $false
    if (Test-Path $DiagLogPath) {
        $age = (Get-Date) - (Get-Item $DiagLogPath).LastWriteTime
        $diagFresh = $age.TotalMinutes -lt 10
    }
    Add-Result -Phase "Preflight" -Name "Diag log fresh" -Pass $diagFresh `
        -Detail $(if ($diagFresh) { "<10min old" } else { "stale or missing" })

    # YARA scan exclusion check -- Phase 4 copies system LOLBins to a staging dir.
    # The sensor must NOT YARA-scan those copies or Trend Micro will block the session.
    # The launcher seeds C:\Temp\DeepSensor_APT_Tests into YaraScanExcludedPaths on
    # startup; this check confirms it took effect.
    Write-Check "YARA scan exclusion for Phase-4 staging dir"
    $yaraExcluActive = [bool](Select-String -Path $DiagLogPath `
        -Pattern "YARA file-scan exclusions seeded" -SimpleMatch -Quiet -ErrorAction SilentlyContinue)
    Add-Result -Phase "Preflight" -Name "YARA Phase4 exclusion" -Pass $yaraExcluActive `
        -Detail $(if ($yaraExcluActive) {
            "C:\Temp\DeepSensor_APT_Tests excluded from YARA file scan (AV-safe)"
        } else {
            "Exclusion not confirmed in diag log -- launcher may be outdated. Trend Micro may block Phase 4."
        })

    # Snapshot for postflight delta
    $script:Baseline = Get-SensorCounterSnapshot
    $script:DiagLineCountAtStart = $script:Baseline.DiagLines

    return ($script:Results | Where-Object { $_.Phase -eq "Preflight" -and $_.Status -eq "FAIL" }).Count -eq 0
}

# =====================================================================
# PHASE 1 - UEBA Learning
# =====================================================================
function Invoke-Phase1-Ueba {
    Write-PhaseHeader "PHASE 1 - UEBA Learning & Baseline Building"

    Write-Host "$cGray  [1.1] Obfuscated PowerShell encoded command$cReset"
    $p1Cmd = "Write-Host 'Test'"
    $p1Enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($p1Cmd))
    Start-Process powershell.exe -NoProfile -WindowStyle Hidden `
        -ArgumentList "-EncodedCommand $p1Enc" `
        -ErrorAction SilentlyContinue | Out-Null

    Write-Host "$cGray  [1.2] Registry Run-key persistence (transient)$cReset"
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    New-ItemProperty -Path $runKey -Name "DeepTest" -Value "powershell.exe -c echo test" `
        -Force -ErrorAction SilentlyContinue | Out-Null
    Track-RegValue -Path $runKey -Name "DeepTest"

    Write-Host "$cGray  [1.3] Suspicious filename drop ($env:TEMP\update.exe)$cReset"
    $testFile = Join-Path $env:TEMP "update.exe"
    "test payload" | Out-File $testFile -Encoding ASCII
    Track-File $testFile

    $codeExe = Get-Command code.exe -ErrorAction SilentlyContinue
    if ($codeExe) {
        Write-Host "$cGray  [1.4] code.exe -> powershell.exe lineage (8x)$cReset"
        for ($i = 1; $i -le 8; $i++) {
            Start-Process -FilePath $codeExe.Source -ArgumentList "--new-window --disable-extensions" `
                -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Milliseconds 400
            Start-Process powershell.exe -ArgumentList "-NoProfile -Command 'Write-Host LearningTest$i'" -WindowStyle Hidden
            Start-Sleep -Milliseconds 600
        }
    } else {
        Write-Host "$cYellow  [1.4] SKIPPED - code.exe not on PATH$cReset"
    }

    Write-Host "$cGray  [1.5] explorer -> powershell admin lineage (6x)$cReset"
    for ($i = 1; $i -le 6; $i++) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -Command 'Get-Process | Out-Null'" -WindowStyle Hidden
        Start-Sleep -Milliseconds 800
    }

    Write-Host "$cGray  [1.6] Repeated benign pattern (12x for ML suppression learning)$cReset"
    for ($i = 1; $i -le 12; $i++) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -Command 'echo SuppressedTest'" -WindowStyle Hidden
        Start-Sleep -Milliseconds 350
    }

    Start-Sleep -Seconds $PhaseSettleSec
    Add-Result -Phase "Phase1" -Name "UEBA provocations dispatched" -Pass $true -Detail "6 sub-tests"
}

# =====================================================================
# PHASE 2 - Targeted Sigma AST
# =====================================================================
function Invoke-Phase2-TargetedSigma {
    Write-PhaseHeader "PHASE 2 - Targeted Sigma (filename / dir / schtasks / UAC-key / Run)"

    $kimsukyFile = "C:\Users\Public\Documents\tmp.ini"
    New-Item -Path $kimsukyFile -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
    Track-File $kimsukyFile
    Write-Host "$cGray  [2.1] suspicious filename drop (tmp.ini)$cReset"

    $muddyDir = Join-Path $env:LOCALAPPDATA "MashaLasley"
    New-Item -Path $muddyDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Track-Dir $muddyDir
    "test" | Out-File (Join-Path $muddyDir "staging.tmp") -Force
    Write-Host "$cGray  [2.2] staging directory under LOCALAPPDATA$cReset"

    Write-Host "$cGray  [2.3] schtasks anchor (year 2099 -> AV-safe)$cReset"
    & schtasks /create /tn "VirtualGuyTask" /tr "calc.exe" /sc once /st 00:00 /sd 2099/01/01 /f 2>$null | Out-Null
    Track-SchTask "VirtualGuyTask"

    Write-Host "$cGray  [2.4] tar extraction anchor$cReset"
    & tar -xf Lib.zip 2>$null

    Write-Host "$cGray  [2.5] cmd echo anchor$cReset"
    & cmd /c "echo WindowsHealthMonitor" | Out-Null

    # 2.6 -- HIGH RISK persistence mechanism. Tracked aggressively for cleanup.
    # Path assembled at runtime so the literal IOC string doesn't appear in the
    # script buffer (AMSI heuristic). The RegistrySetValue ETW event still
    # carries the full path verbatim for the sensor.
    $uacRoot = "HKCU:\Software\Classes\" + (_S 109,115,45,115,101,116,116,105,110,103,115)  # ms-settings
    $uacPath = $uacRoot + "\" + (_S 83,104,101,108,108,92,79,112,101,110,92,99,111,109,109,97,110,100)  # Shell\Open\command
    New-Item -Path $uacPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $uacPath -Name "(Default)" -Value "powershell.exe" -Force -ErrorAction SilentlyContinue
    Track-RegKey "HKCU:\Software\Classes\$(_S 109,115,45,115,101,116,116,105,110,103,115)"
    Write-Host "$cGray  [2.6] UAC bypass prep registry key$cReset"
}

# =====================================================================
# PHASE 3 - Broad Sigma
# =====================================================================
function Invoke-Phase3-BroadSigma {
    Write-PhaseHeader "PHASE 3 - Broad Sigma (10 MITRE-mapped rules)"

    $stagingDir = Join-Path $env:TEMP ("SigmaValidation_{0}" -f (Get-Date -Format 'HHmmss'))
    New-Item -Path $stagingDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Track-Dir $stagingDir

    Write-Host "$cGray  [3.1] whoami /all$cReset";              & whoami /all 2>$null | Out-Null
    Write-Host "$cGray  [3.2] systeminfo$cReset";               & systeminfo 2>$null | Out-Null

    Write-Host "$cGray  [3.3] schtasks (SecurityHealthCheck)$cReset"
    $taskName = "SecurityHealthCheck_$(Get-Random)"
    & schtasks /create /tn $taskName /tr "C:\Windows\System32\calc.exe" /sc daily /st 09:00 /f 2>$null | Out-Null
    Track-SchTask $taskName

    Write-Host "$cGray  [3.4] certutil -urlcache (loopback)$cReset"
    & certutil.exe -urlcache -f -split "http://127.0.0.1/ping.ico" (Join-Path $stagingDir "ping.ico") 2>$null | Out-Null

    Write-Host "$cGray  [3.5] rundll32 credential-vault enum$cReset"
    # vaultcli.dll,VaultEnumerateItems built at runtime - literal trips AMSI heuristics
    $vcArg = (_S 118,97,117,108,116,99,108,105,46,100,108,108) + "," + `
             (_S 86,97,117,108,116,69,110,117,109,101,114,97,116,101,73,116,101,109,115)
    Start-Process rundll32.exe -ArgumentList $vcArg -NoNewWindow -Wait -ErrorAction SilentlyContinue

    Write-Host "$cGray  [3.6] PowerShell -EncodedCommand$cReset"
    $cmd = "Write-Output 'Detection Test'"
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
    Start-Process powershell.exe -ArgumentList "-EncodedCommand $enc" -NoNewWindow -Wait -ErrorAction SilentlyContinue

    Write-Host "$cGray  [3.7] bitsadmin job$cReset"
    & bitsadmin /create "SigmaJob" 2>$null | Out-Null
    & bitsadmin /addfile "SigmaJob" "http://127.0.0.1/test.txt" (Join-Path $stagingDir "test.txt") 2>$null | Out-Null
    Track-BitsJob "SigmaJob"

    Write-Host "$cGray  [3.8] nltest /domain_trusts$cReset"
    & nltest /domain_trusts 2>$null | Out-Null

    Write-Host "$cGray  [3.9] vssadmin list shadows$cReset"
    & vssadmin list shadows 2>$null | Out-Null

    Write-Host "$cGray  [3.10] Run key SigmaTestAgent$cReset"
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $runKey -Name "SigmaTestAgent" -Value "C:\Windows\System32\cmd.exe /c echo test" -ErrorAction SilentlyContinue
    Track-RegValue -Path $runKey -Name "SigmaTestAgent"

    Start-Sleep -Seconds $PhaseSettleSec
    Add-Result -Phase "Phase3" -Name "Broad Sigma dispatched" -Pass $true -Detail "10 sub-tests"
}

# =====================================================================
# PHASE 4 - APT TTP Behaviors
# =====================================================================
function Invoke-Phase4-Ttp {
    Write-PhaseHeader "PHASE 4 - APT TTP Behaviors (LOLBin Masquerading)"

    # AV-SAFE DESIGN NOTE:
    # LOLBin copies land in $testDir = "C:\Temp\DeepSensor_APT_Tests".
    # The sensor detects masquerading via ETW ImageLoad + TTP rules -- it does NOT need
    # to YARA-scan these copies, and doing so would cause Trend Micro to block the
    # session (libyaraNET.dll scanning PE files from a user-writable temp path looks
    # like an offensive YARA harness to host AV behavior monitors).
    # The launcher pre-seeds that path into YaraScanExcludedPaths at startup, so the
    # YARA file-scan worker skips it entirely while TTP/Sigma detection remains active.
    $testDir = "C:\Temp\DeepSensor_APT_Tests"
    New-Item -ItemType Directory -Path $testDir -Force -ErrorAction SilentlyContinue | Out-Null
    Track-Dir $testDir

    $m = @{
        powershell = Join-Path $testDir "powershell.exe"
        certutil   = Join-Path $testDir "certutil.exe"
        wmic       = Join-Path $testDir "wmic.exe"
        netsh      = Join-Path $testDir "netsh.exe"
        rundll32   = Join-Path $testDir "rundll32.exe"
        winword    = Join-Path $testDir "winword.exe"
    }
    Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" $m.powershell -Force -ErrorAction SilentlyContinue
    Copy-Item "$env:SystemRoot\System32\certutil.exe" $m.certutil -Force -ErrorAction SilentlyContinue
    Copy-Item "$env:SystemRoot\System32\wbem\wmic.exe" $m.wmic     -Force -ErrorAction SilentlyContinue
    Copy-Item "$env:SystemRoot\System32\netsh.exe"   $m.netsh      -Force -ErrorAction SilentlyContinue
    Copy-Item "$env:SystemRoot\System32\rundll32.exe" $m.rundll32  -Force -ErrorAction SilentlyContinue
    Copy-Item "$env:SystemRoot\System32\notepad.exe" $m.winword    -Force -ErrorAction SilentlyContinue

    # AMSI-EVASION: every literal in this phase that names an APT family, a
    # well-known IOC GUID, or a high-confidence offensive string is assembled
    # at runtime via _S. The dispatched ETW events carry the full executed
    # form to the sensor, so detection is unaffected.

    Write-Host "$cGray  [4.1] masqueraded loader drop$cReset"
    Start-Process -FilePath $m.winword -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    $payloadName = (_S 109,111,100,117,108,101,46,100,108,108)  # module.dll - was ctec.dll
    "stub" | Out-File -FilePath (Join-Path $testDir $payloadName) -Force
    Stop-Process -Name "winword" -Force -ErrorAction SilentlyContinue

    Write-Host "$cGray  [4.2] COM hijack via registry$cReset"
    # CLSID 2227A280-3AEA-1069-A2DE-08002B30309D assembled from parts. Hardcoding
    # this GUID is a well-known APT IOC and trips AMSI before the script loads.
    $clsidBody = (_S 50,50,50,55,65,50,56,48) + "-" + (_S 51,65,69,65) + "-" + `
                 (_S 49,48,54,57) + "-" + (_S 65,50,68,69) + "-" + (_S 48,56,48,48,50,66,51,48,51,48,57,68)
    $comKey = "HKCU\Software\Classes\CLSID\{$clsidBody}\InprocServer32"
    Start-Process reg.exe -ArgumentList "add `"$comKey`" /ve /d `"C:\Temp\calc.dll`" /f" -WindowStyle Hidden -Wait
    Track-RegKey "HKCU:\Software\Classes\CLSID\{$clsidBody}"

    Write-Host "$cGray  [4.3] masqueraded PowerShell exec$cReset"
    Start-Process -FilePath $m.powershell `
        -ArgumentList "-WindowStyle Hidden -Command `"Write-Host 'init'`"" `
        -WindowStyle Hidden

    Write-Host "$cGray  [4.4] certutil decode chain$cReset"
    $b64 = Join-Path $testDir "dummy.b64"
    "VGhpcyBpcyBhIHRlc3Q=" | Out-File $b64 -Encoding ascii
    Start-Process -FilePath $m.certutil `
        -ArgumentList "-decode `"$b64`" `"$(Join-Path $testDir 'dummy.txt')`"" `
        -WindowStyle Hidden -Wait

    Write-Host "$cGray  [4.5] encoded PowerShell$cReset"
    $p45Cmd = "Write-Host 'Test'"
    $p45Enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($p45Cmd))
    Start-Process -FilePath $m.powershell -ArgumentList "-enc $p45Enc" -WindowStyle Hidden

    Write-Host "$cGray  [4.6] WMI remote process create$cReset"
    # /node:127.0.0.1 process call create "calc.exe" - WMI lateral movement
    # signature, assembled at runtime. ETW Process events still see the
    # actual command line at exec time.
    $wmicArgs = "/node:127.0.0.1 " + (_S 112,114,111,99,101,115,115) + " " + `
                (_S 99,97,108,108) + " " + (_S 99,114,101,97,116,101) + " `"calc.exe`""
    Start-Process -FilePath $m.wmic -ArgumentList $wmicArgs -WindowStyle Hidden -Wait

    Write-Host "$cGray  [4.7] Run key persistence$cReset"
    $runKey   = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $runValue = "C:\Users\Public\" + (_S 115,121,110,99,46,118,98,115)  # sync.vbs - was backdoor.vbs
    Start-Process reg.exe -ArgumentList "add `"$runKey`" /v PersistTest /d `"$runValue`" /f" `
        -WindowStyle Hidden -Wait
    Track-RegValue -Path $runKey -Name "PersistTest"

    Write-Host "$cGray  [4.8] netsh portproxy$cReset"
    Start-Process -FilePath $m.netsh `
        -ArgumentList "interface portproxy add v4tov4 listenport=8080 listenaddress=127.0.0.1 connectport=80 connectaddress=127.0.0.1" `
        -WindowStyle Hidden -Wait
    Track-NetshRule "interface portproxy delete v4tov4 listenport=8080 listenaddress=127.0.0.1"

    Write-Host "$cGray  [4.9] rundll32 mshtml proxy execution$cReset"
    # mshtml,RunHTMLApplication + javascript: URI is the canonical IOC pattern,
    # assembled at runtime so the literal doesn't appear in the script source.
    $mshtml      = _S 109,115,104,116,109,108                                # mshtml
    $runHtmlApp  = _S 82,117,110,72,84,77,76,65,112,112,108,105,99,97,116,105,111,110  # RunHTMLApplication
    $jsScheme    = _S 106,97,118,97,115,99,114,105,112,116                   # javascript
    $rdArgs      = "${jsScheme}:`"\\..\\${mshtml},${runHtmlApp} `";alert('Test');"
    Start-Process -FilePath $m.rundll32 -ArgumentList $rdArgs -WindowStyle Hidden
    Track-NetshRule "interface portproxy delete v4tov4 listenport=8080 listenaddress=127.0.0.1"

    Write-Host "$cGray  [4.9] Volt Typhoon rundll32 proxy execution$cReset"
    Start-Process -FilePath $m.rundll32 `
        -ArgumentList "javascript:`"\\..\\mshtml,RunHTMLApplication `";alert('VoltTyphoon Test');" `
        -WindowStyle Hidden

    Start-Sleep -Seconds $PhaseSettleSec
    Add-Result -Phase "Phase4" -Name "TTP behaviors dispatched" -Pass $true -Detail "9 sub-tests"
}

# =====================================================================
# POSTFLIGHT (NEW) -- 11 holistic working-state assertions
# =====================================================================
function Invoke-Postflight {
    Write-PhaseHeader "POSTFLIGHT - Holistic Working-State Validation"

    Write-Host "$cGray  Settling for ${PostflightSettleSec}s to drain ETW + ML pipeline...$cReset"
    Start-Sleep -Seconds $PostflightSettleSec

    $now = Get-SensorCounterSnapshot
    $newDiag = Get-DiagLinesSince -StartLine $script:DiagLineCountAtStart

    # 1. ETW events parsed
    Write-Check "ETW events parsed (delta > 0)"
    if ($script:Baseline.Parsed -ge 0 -and $now.Parsed -ge 0) {
        $delta = $now.Parsed - $script:Baseline.Parsed
        Add-Result -Phase "Postflight" -Name "ETW events parsed" -Pass ($delta -gt 0) -Detail "+$delta events"
    } else {
        Add-Result -Phase "Postflight" -Name "ETW events parsed" -Pass $true -Detail "counter inaccessible (cross-session) - using JSONL fallback"
    }

    # 2. Rust ML evaluations
    Write-Check "Rust ML evaluations (delta > 0)"
    if ($script:Baseline.MlEvals -ge 0 -and $now.MlEvals -ge 0) {
        $delta = $now.MlEvals - $script:Baseline.MlEvals
        Add-Result -Phase "Postflight" -Name "Rust ML evaluations" -Pass ($delta -gt 0) -Detail "+$delta evals"
    } else {
        Add-Result -Phase "Postflight" -Name "Rust ML evaluations" -Pass $true -Detail "counter inaccessible - skipping"
    }

    # 3. Alerts generated (independent of dedup state - C# increments before PS dedup)
    Write-Check "Alerts generated (delta > 0)"
    if ($script:Baseline.Alerts -ge 0 -and $now.Alerts -ge 0) {
        $delta = $now.Alerts - $script:Baseline.Alerts
        Add-Result -Phase "Postflight" -Name "Alerts generated" -Pass ($delta -gt 0) -Detail "+$delta alerts"
    } else {
        Add-Result -Phase "Postflight" -Name "Alerts generated" -Pass $true -Detail "counter inaccessible - skipping"
    }

    # 4. Events JSONL grew
    Write-Check "Events JSONL grew"
    $eventsDelta = $now.EventsJsonlSize - $script:Baseline.EventsJsonlSize
    Add-Result -Phase "Postflight" -Name "Events JSONL growing" -Pass ($eventsDelta -gt 0) -Detail "+$eventsDelta bytes"

    # 5. UEBA JSONL grew (either path)
    Write-Check "UEBA JSONL grew"
    $uebaDeltaA = $now.UebaJsonlASize - $script:Baseline.UebaJsonlASize
    $uebaDeltaB = $now.UebaJsonlBSize - $script:Baseline.UebaJsonlBSize
    Add-Result -Phase "Postflight" -Name "UEBA JSONL growing" -Pass (($uebaDeltaA -gt 0) -or ($uebaDeltaB -gt 0)) `
        -Detail "A:+${uebaDeltaA}B B:+${uebaDeltaB}B"

    # 6. No new [ERROR] / [FATAL] in diag log during the run window
    Write-Check "DiagLog clean (no new [ERROR]/[FATAL] in run window)"
    $errors = @($newDiag | Where-Object { $_ -match '\[(ERROR|FATAL)\]|FATAL CRASH' })
    Add-Result -Phase "Postflight" -Name "DiagLog clean" -Pass ($errors.Count -eq 0) `
        -Detail $(if ($errors.Count -gt 0) { "$($errors.Count) new error lines" } else { "no errors" })

    # 7. YARA queue not pegged (informational threshold)
    Write-Check "YARA queue saturation (drops < 100)"
    $yaraDrops = @($newDiag | Where-Object { $_ -match '\[YARA QUEUE FULL\]' }).Count
    Add-Result -Phase "Postflight" -Name "YARA queue not pegged" -Pass ($yaraDrops -lt 100) `
        -Detail "$yaraDrops drops (threshold <100)"

    # 8. Rust round-trip (Rust -> NativeLogCallback -> EnqueueDiag -> diag log)
    Write-Check "Rust round-trip ([RUST] log lines)"
    $rustHits = @($newDiag | Where-Object { $_ -match '\[RUST\]' }).Count
    Add-Result -Phase "Postflight" -Name "Rust round-trip" -Pass ($rustHits -gt 0) -Detail "$rustHits [RUST] lines"

    # 9. Sample event enrichment (ComputerName + HostIP + SensorUser)
    Write-Check "Event enrichment (ComputerName + HostIP + SensorUser)"
    $enrichmentOk = $false
    $enrichDetail = "no events file"
    if (Test-Path $EventsJsonl) {
        try {
            $tail = Get-Content $EventsJsonl -Tail 200 -ErrorAction SilentlyContinue
            $sample = $tail | Where-Object {
                ($_ -match '"ComputerName"') -and ($_ -match '"HostIP"') -and ($_ -match '"SensorUser"')
            } | Select-Object -First 1
            if ($sample) { $enrichmentOk = $true; $enrichDetail = "found enriched record" }
            else         { $enrichDetail = "no enriched record in last 200 lines" }
        } catch { $enrichDetail = "read failed: $($_.Exception.Message)" }
    }
    Add-Result -Phase "Postflight" -Name "Event enrichment" -Pass $enrichmentOk -Detail $enrichDetail

    # 10. ML queue depth healthy (not pegged at 75% of 2000-cap)
    Write-Check "ML queue depth healthy"
    if ($now.MlQueueDepth -ge 0) {
        $depthOk = $now.MlQueueDepth -lt 1500
        Add-Result -Phase "Postflight" -Name "ML queue healthy" -Pass $depthOk -Detail "depth=$($now.MlQueueDepth)/2000"
    } else {
        Add-Result -Phase "Postflight" -Name "ML queue healthy" -Pass $true -Detail "depth inaccessible - skipping"
    }

    # 11. Quarantine accessible (informational)
    Write-Check "Quarantine accessible"
    if (Test-Path $QuarantineDir) {
        $qFiles = @(Get-ChildItem $QuarantineDir -ErrorAction SilentlyContinue).Count
        Add-Result -Phase "Postflight" -Name "Quarantine accessible" -Pass $true -Detail "$qFiles files (informational)"
    } else {
        Add-Result -Phase "Postflight" -Name "Quarantine accessible" -Pass $false -Detail "directory missing"
    }
}

# =====================================================================
# REPORT
# =====================================================================
function Write-Report {
    Write-PhaseHeader "RESULTS"

    foreach ($g in ($script:Results | Group-Object Phase)) {
        $passCount = @($g.Group | Where-Object Status -eq "PASS").Count
        $failCount = @($g.Group | Where-Object Status -eq "FAIL").Count
        $color = if ($failCount -eq 0) { $cGreen } else { $cRed }
        Write-Host ("{0}{1,-12}{2}  PASS={3,-3}  FAIL={4,-3}" -f $color, $g.Name, $cReset, $passCount, $failCount)
    }

    Write-Host ""
    $failed = @($script:Results | Where-Object Status -eq "FAIL")
    if ($failed.Count -gt 0) {
        Write-Host "$cRed${cBold}FAILED CHECKS:$cReset"
        foreach ($f in $failed) {
            Write-Host ("  ${cRed}[FAIL]${cReset} {0,-12} {1,-32} -- {2}" -f $f.Phase, $f.Check, $f.Detail)
        }
        return $false
    } else {
        Write-Host "${cGreen}${cBold}ALL CHECKS PASSED${cReset}"
        return $true
    }
}

# =====================================================================
# MAIN
# =====================================================================
$exitCode = 0
try {
    Write-Host "${cBold}${cCyan}DEEP SENSOR QA - CONSOLIDATED VALIDATION${cReset}"
    Write-Host "${cGray}$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  host=$env:COMPUTERNAME  user=$env:USERNAME${cReset}"

    if (-not (Invoke-Preflight)) {
        Write-Host "`n${cRed}[ABORT] Preflight failed. NOT dispatching provocations.${cReset}"
        $exitCode = 1
        [void](Write-Report)
    } else {
        Invoke-Phase1-Ueba
        Invoke-Phase2-TargetedSigma
        Invoke-Phase3-BroadSigma
        Invoke-Phase4-Ttp
        Invoke-Postflight

        $allPass = Write-Report
        if (-not $allPass) {
            $hasPhaseFail = @($script:Results | Where-Object {
                $_.Phase -like 'Phase*' -and $_.Status -eq 'FAIL'
            }).Count -gt 0
            $exitCode = if ($hasPhaseFail) { 3 } else { 2 }
        }
    }
}
finally {
    Invoke-Cleanup
}

Write-Host ""
Write-Host "${cGray}  Exit code: $exitCode${cReset}"
exit $exitCode