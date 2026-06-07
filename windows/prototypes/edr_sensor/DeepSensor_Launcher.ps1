<#
.SYNOPSIS
    Deep Visibility Sensor v2.1 - OS Behavioral Orchestrator & Active Defense HUD

.DESCRIPTION
    The central nervous system of the Deep Visibility EDR toolkit. This script is
    responsible for bootstrapping the environment, bridging the unmanaged C# ETW
    engine natively with the Rust ML DLL, and rendering the mathematically pinned
    diagnostic HUD.

    It operates completely independently of network-based C2 tracking, focusing
    strictly on deep operating system hooks and persistence mechanisms.
    Additionally, it acts as a dynamic Threat Intelligence compiler, natively parsing
    and executing Sigma rules and BYOVD driver lists directly within the kernel event loop.

.ARCHITECTURE_FLOW
    1. Environment Pre-Flight: Validates the presence of the compiled Rust ML DLL.
    2. Threat Intel Compiler: Recursively parses the local 'sigma/' directory, auto-corrects
       YAML syntax, and fetches live BYOVD (LOLDrivers) intelligence to build O(1) arrays.
    3. Dynamic Compilation: Embeds the OsSensor.cs payload directly
       into the PowerShell RAM space, linking the TraceEvent libraries on the fly.
    4. Matrix Initialization: Maps critical PIDs (Sensor) and injects the compiled
       Sigma and Threat Intel arrays directly into the unmanaged C# memory space.
    5. Native FFI Pipeline: C# natively invokes the Rust ML engine (DeepSensor_ML_v2.1.dll)
       directly within its own memory space, bypassing all IPC pipe latency.
    6. Security Lockdown: Utilizes icacls and sdset to restrict file and service access.
    7. Telemetry Triage: Continuously drains the C# ConcurrentQueue. Static, high-
       fidelity alerts and native ML anomalies are actioned instantly.
    8. Active Defense: If ArmedMode is enabled, native SuspendThread / Quarantine (Surgical) and memory
       neutralization (PAGE_NOACCESS) are issued the millisecond an exploit chain is verified.

.PARAMETERS
    ArmedMode           - Enables autonomous surgical thread suspension (Quarantine),
                          memory permission stripping, and forensic payload extraction
                          for critical alerts.
    Background          - Executes the sensor headlessly by hiding the console window to
                          minimize CPU overhead. Relies on the 'shutdown.sig' file-based
                          kill switch for graceful termination.
    PolicyUpdateUrl     - URL to fetch centralized Sigma rules during policy sync.
    SiemEndpoint        - REST API endpoint for Splunk HEC or Azure Log Analytics.
    SiemToken           - Authorization token for the SIEM endpoint.
    MlBinaryName        - The filename of the compiled Rust ML engine.
    MlRepoUrl           - URL to fetch the compiled Rust binary if missing.
    LogPath             - Destination for the rolling JSONL SIEM forwarder cache.
    TraceEventDllPath   - Path to the Microsoft.Diagnostics.Tracing.TraceEvent.dll.

.NOTES
    If running in background mode, to gracefully terminate the process:

        New-Item -Path "C:\ProgramData\DeepSensor\Data\shutdown.sig" -ItemType File -Force

    If unexpected shutdown to unlock project directory:

        icacls "C:\path\to\project\dir" /reset /T /C /Q

    Author: Robert Weber
#>
#Requires -RunAsAdministrator

# ======================================================================
# 1. PARAMETERS
# ======================================================================

param (
    [switch]$ArmedMode,
    [switch]$Background,
    [string]$PolicyUpdateUrl = "",
    [string]$SiemEndpoint = "",
    [string]$SiemToken = "",
    [string]$OfflineRepoPath = "",
    [string]$MlBinaryName = "DeepSensor_ML_v2.1.dll",
    [string]$LogPath = "C:\ProgramData\DeepSensor\Data\DeepSensor_Events.jsonl",
    [string]$TraceEventDllPath = "C:\ProgramData\DeepSensor\Dependencies\TE\lib\net45\Microsoft.Diagnostics.Tracing.TraceEvent.dll"
)

# --- Clear Trace ---
logman stop "NT Kernel Logger" -ets >$null 2>&1

<#
# --- Global Failsafe ---
Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    try {
        if ([DeepVisibilitySensor]::IsSessionHealthy()) {
            [DeepVisibilitySensor]::StopSession()
            [DeepVisibilitySensor]::TeardownEngine()
        }
    } catch {}
}
#>

# --- Headless State Exec ---
if ($Background) {
    $HideCode = @"
    using System;
    using System.Runtime.InteropServices;
    public class ConsoleInterop {
        [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }
"@
    Add-Type -TypeDefinition $HideCode
}

# ======================================================================
# 2. GLOBAL CONSTANTS & PATHS
# ======================================================================

$Global:ProgData = if ($env:ProgramData) { $env:ProgramData } else { "C:\ProgramData" }
$activeRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
if ($activeRoute) {
    $IpAddress = (Get-NetIPAddress -InterfaceIndex $activeRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
}
if (-not $IpAddress) { $IpAddress = "Unknown" }
$OsContext = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption -replace 'Microsoft ', ''
$userStr = "$env:USERDOMAIN\$env:USERNAME".Replace("\", "\\")
$global:EnrichmentPrefix = "`"ComputerName`":`"$env:COMPUTERNAME`", `"IP`":`"$IpAddress`", `"OS`":`"$OsContext`", `"SensorUser`":`"$userStr`", "
$global:cycleAlerts = [System.Collections.Generic.Dictionary[string, object]]::new()
$global:dataBatch = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:IsArmed = $ArmedMode
if ($ArmedMode) {
    Write-Host "`n[!] SENSOR BOOTING IN ARMED MODE: ACTIVE DEFENSE ENABLED" -ForegroundColor Red
} else {
    Write-Host "`n[*] SENSOR BOOTING IN AUDIT MODE: OBSERVATION ONLY" -ForegroundColor Yellow
}
$global:RecentAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:StartupLogs = [System.Collections.Generic.List[string]]::new()
$global:TotalMitigations = 0

$script:logBatch = [System.Collections.Generic.List[string]]::new()
# Dedicated UEBA JSONL pipeline
$script:uebaBatch = [System.Collections.Generic.List[string]]::new()
$UebaLogPath = $LogPath -replace "DeepSensor_Events.jsonl", "DeepSensor_UEBA_Events.jsonl"

# Cache for historical alerts
$global:HistoricalAlerts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$global:HistoricalSuppressions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$global:HistoricalAlertsPath = Join-Path "C:\ProgramData\DeepSensor\Data" "HistoricalAlerts.cache"

$ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptDir)) {
    if ($PSCommandPath) { $ScriptDir = Split-Path $PSCommandPath -Parent }
    else { $ScriptDir = $PWD.Path }
}

$LogDir = Join-Path $env:ProgramData "DeepSensor\Logs"
$DiagLogPath = Join-Path $LogDir "DeepSensor_Diagnostic.log"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

if (Test-Path $DiagLogPath) {
    Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue
}

$global:TerminateSwitchPath = "C:\ProgramData\DeepSensor\Data\shutdown.sig"

if (Test-Path $global:TerminateSwitchPath) {
    Write-Diag "[BOOT] Stale shutdown signal detected and cleared to prevent immediate termination." "INFO"
    Remove-Item -Path $global:TerminateSwitchPath -Force -ErrorAction SilentlyContinue
}

$global:SecureStaging = "C:\ProgramData\DeepSensor\Staging"
if (-not (Test-Path $global:SecureStaging)) { New-Item -ItemType Directory -Path $global:SecureStaging -Force | Out-Null }
# ======================================================================
# 3. HELPER FUNCTIONS
# ======================================================================

function Write-Diag([string]$Message, [string]$Level = "INFO") {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    try {
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        Add-Content -Path $DiagLogPath -Value "[$ts] [$Level] $Message" -Encoding UTF8
    } catch {}

    if ($Level -eq "STARTUP") {
        $global:StartupLogs.Add($Message)
        Draw-StartupWindow
    }
}

function Write-RawJsonl {
    param([string]$Path, [string[]]$Lines)
    if ($Lines.Count -eq 0) { return $true }

    # 100MB Log Rotation to prevent Disk Exhaustion
    if (Test-Path $Path) {
        $fileInfo = Get-Item $Path
        if ($fileInfo.Length -gt 100MB) {
            $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
            $newName = $fileInfo.Name -replace "\.jsonl$", "_$stamp.jsonl"

            $retryCount = 0
            $renamed = $false
            while ($retryCount -lt 5 -and -not $renamed) {
                try {
                    Rename-Item -Path $Path -NewName $newName -ErrorAction Stop
                    $renamed = $true
                } catch {
                    $retryCount++
                    Start-Sleep -Milliseconds 200
                }
            }

            if ($renamed) {
                $baseName = $fileInfo.Name -replace "\.jsonl$", "_*.jsonl"
                Get-ChildItem -Path (Split-Path $Path) -Filter $baseName |
                    Sort-Object CreationTime -Descending |
                    Select-Object -Skip 3 | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $clean = $Lines | ForEach-Object { if ($_) { ($_ -replace "`r`n", " " -replace "`r", " " -replace "`n", " ").Trim() } }
    $content = ($clean -join "`r`n") + "`r`n"

    $retry = 0
    while ($retry -lt 5) {
        try {
            $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            $sw = [System.IO.StreamWriter]::new($fs, [System.Text.Encoding]::UTF8)

            $sw.AutoFlush = $true

            $sw.Write($content)
            $sw.Close()
            $fs.Close()
            return $true
        } catch {
            $retry++
            $DiagMsg = "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'))] [CRITICAL] IO ERROR Writing to $Path : $($_.Exception.Message) (Retry $retry/5)"
            Add-Content -Path $DiagLogPath -Value $DiagMsg -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 100
        }
    }

    $FatalMsg = "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'))] [FATAL] Dropped $($Lines.Count) events. Could not obtain file lock on $Path."
    Add-Content -Path $DiagLogPath -Value $FatalMsg -ErrorAction SilentlyContinue
    return $false
}

function Optimize-Cmdline {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return "" }

    $Cmd = $Cmd -replace '\\\\', '\'
    $Cmd = $Cmd -replace '\\"', '"'
    $Cmd = $Cmd -replace "`r`n|`n|`r", " "

    $Cmd = $Cmd -replace "^\\\?\?\\", ""
    $Cmd = $Cmd -replace "^\\\\\?\?\\\\", ""

    if ($Cmd -match "^`"?([A-Za-z]:\\[^`"]+\\([^\\]+\.(exe|dll)))`"?\s*(.*)") {
        $Cmd = "$($matches[2]) $($matches[4])"
    }

    if ($Cmd -match "(?i)(-enc|-encodedcommand|-e|decode)\s+([A-Za-z0-9+/]{60,}=*)") {
        $b64 = $matches[2]
        $truncated = $b64.Substring(0, 30) + "...[B64_TRUNCATED]"
        $Cmd = $Cmd.Replace($b64, $truncated)
    }

    return $Cmd.Trim('"', ' ', '\')
}

function Assert-ServiceStability {
    $TrackerPath = "C:\ProgramData\DeepSensor\Data\CrashTracker.log"
    $Threshold = (Get-Date).AddMinutes(-60)
    $RecentStarts = @()

    if (Test-Path $TrackerPath) {
        $RawText = Get-Content $TrackerPath -Raw -ErrorAction SilentlyContinue
        if ($RawText) {
            $Lines = $RawText -split '(?<=\d{2}:\d{2}:\d{2}.*?)(?=\d{4}-\d{2}-\d{2})'
            foreach ($line in $Lines) {
                try {
                    $trimmed = $line.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                        if ([datetime]$trimmed -gt $Threshold) { $RecentStarts += [datetime]$trimmed }
                    }
                } catch { }
            }
        }
    }

    if ($RecentStarts.Count -ge 10) {
        Write-Diag "CIRCUIT BREAKER TRIPPED: Sensor failed 10 times within 60 minutes. Halting to protect OS." "CRITICAL"
        if (Get-Service -Name "DeepSensorService" -ErrorAction Ignore) {
            Set-Service -Name "DeepSensorService" -StartupType Disabled -ErrorAction Ignore
        }
        Exit 0
    }

    $RecentStarts += (Get-Date).ToString("o")
    $RecentStarts | Out-File -FilePath $TrackerPath -Force
}

# ======================================================================
# 4. HUD / UI RENDERING
# ======================================================================

# Disable Windows QuickEdit Mode to prevent accidental process freezing
$QuickEditCode = @"
using System;
using System.Runtime.InteropServices;
public class ConsoleConfig {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    public static void DisableQuickEdit() {
        IntPtr consoleHandle = GetStdHandle(-10); // STD_INPUT_HANDLE
        if (GetConsoleMode(consoleHandle, out uint consoleMode)) {
            consoleMode &= ~0x0040U; // Strip ENABLE_QUICK_EDIT_MODE
            SetConsoleMode(consoleHandle, consoleMode);
        }
    }
}
"@
Add-Type -TypeDefinition $QuickEditCode
[ConsoleConfig]::DisableQuickEdit()

# ====================== HUD DASHBOARD RENDERING ======================
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
Clear-Host

$ESC      = [char]27
# 24-bit TrueColor Neon Palette (R;G;B)
$cCyan    = "$ESC[38;2;0;255;255m"
$cGreen   = "$ESC[38;2;57;255;20m"
$cOrange  = "$ESC[38;2;255;103;0m"
$cGold    = "$ESC[38;2;255;215;0m"
$cYellow  = "$ESC[38;2;255;255;51m"
$cRed     = "$ESC[38;2;255;49;49m"
$cWhite   = "$ESC[38;2;255;255;255m"
$cDark    = "$ESC[38;2;80;80;80m"
$cReset   = "$ESC[0m$ESC[40m"

try {
    $ui = $Host.UI.RawUI
    $buffer = $ui.BufferSize
    $buffer.Width = 160
    $buffer.Height = 3000
    $ui.BufferSize = $buffer
    $size = $ui.WindowSize
    $size.Width = 160

    $size.Height = 55
    $ui.WindowSize = $size
} catch {}

[Console]::SetCursorPosition(0, 9)

function Add-AlertMessage([string]$Message, [string]$ColorCode) {
    $Message = $Message -replace "`t", " " -replace "`r", "" -replace "`n", " "

    $ts = (Get-Date).ToString("HH:mm:ss"); $prefix = "[$ts] "
    $maxLen = 98 - $prefix.Length
    if ($Message.Length -gt $maxLen) { $Message = $Message.Substring(0, $maxLen - 3) + "..." }
    $global:RecentAlerts.Add([PSCustomObject]@{ Text = "$prefix$Message"; Color = $ColorCode })

    if ($global:RecentAlerts.Count -gt 20) { $global:RecentAlerts.RemoveAt(0) }

    Draw-AlertWindow
}

function Draw-Dashboard([long]$Events, [long]$MlEvals, [int]$Alerts, [string]$EtwHealth, [int]$MlQueue, [int]$PsQueue) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    $mitreTags = @()
    foreach ($alert in $global:RecentAlerts) {
        if ($alert.Text -match "\[(T\d{4}(?:\.\d{3})?)\]") { $mitreTags += $matches[1] }
    }
    $uniqueMitre = if ($mitreTags.Count -gt 0) { ($mitreTags | Select-Object -Unique) -join ", " } else { "None" }
    if ($uniqueMitre.Length -gt 25) { $uniqueMitre = $uniqueMitre.Substring(0, 22) + "..." }

    $lastAction = "None"
    for ($i = $script:logBatch.Count - 1; $i -ge 0; $i--) {
        if ($script:logBatch[$i] -match "`"Action`":`"(.*?Quarantined.*?)`"") {
            $lastAction = $matches[1]; break
        }
    }
    if ($lastAction.Length -gt 25) { $lastAction = $lastAction.Substring(0, 22) + "..." }

    $evPad       = $Events.ToString().PadRight(15)
    $mlPad       = $MlEvals.ToString().PadRight(15)
    $alertPad    = $Alerts.ToString().PadRight(15)
    $defFiredPad = $global:TotalMitigations.ToString().PadRight(15)

    $EtwState = if ($EtwHealth -eq "Good") { "ONLINE" } else { "DEGRADED" }
    $LogHealthStr = if ($MlQueue -gt 1500 -or $PsQueue -gt 5000) { "SATURATED" } elseif ($MlQueue -gt 500 -or $PsQueue -gt 1000) { "BACKLOGGED" } else { "HEALTHY" }

    $L0_Plain = "  ██ Deep Sensor | System Status Dashboard"
    $L1_Plain = "  [ ENGINE STATUS ]"
    $L2_Plain = "  Sensor Status : $EtwState"
    $L3_Plain = "  Pipeline Load : $LogHealthStr (ML: $MlQueue | PS: $PsQueue)"
    $L4_Plain = "  Total Events  : $Events"
    $L5_Plain = "  ML/UEBA Evals : $MlEvals"

    $lastActionPad = $lastAction.PadRight(22)
    $vectorsPad = $uniqueMitre.PadRight(22)
    $defFiredPad = $global:TotalMitigations.ToString().PadRight(22)
    $alertPad = $Alerts.ToString().PadRight(22)

    $R1_Plain = "  [ ACTIVE DEFENSE ]".PadRight(39)
    $R2_Plain = "  Defenses Engaged : $defFiredPad"
    $R3_Plain = "  Total Alerts     : $alertPad"
    $R4_Plain = "  Last Action      : $lastActionPad"
    $R5_Plain = "  Vectors          : $vectorsPad"

    $UIWidth = 100
    $Pad0 = " " * [math]::Max(0, ($UIWidth - $L0_Plain.Length - 1))
    $Pad1 = " " * [math]::Max(0, ($UIWidth - $L1_Plain.Length - $R1_Plain.Length - 4))
    $Pad2 = " " * [math]::Max(0, ($UIWidth - $L2_Plain.Length - $R2_Plain.Length + 2))
    $Pad3 = " " * [math]::Max(0, ($UIWidth - $L3_Plain.Length - $R3_Plain.Length + 2))
    $Pad4 = " " * [math]::Max(0, ($UIWidth - $L4_Plain.Length - $R4_Plain.Length + 2))
    $Pad5 = " " * [math]::Max(0, ($UIWidth - $L5_Plain.Length - $R5_Plain.Length + 2))

    $cGreen  = "$([char]27)[38;2;57;255;20m"
    $cGold    = "$([char]27)[38;2;255;215;0m"
    $cOrange = "$([char]27)[38;2;255;165;0m"
    $cCyan   = "$([char]27)[38;2;0;255;255m"
    $cRed     = "$([char]27)[38;2;255;49;49m"
    $cWhite   = "$([char]27)[38;2;255;255;255m"
    $cDark    = "$([char]27)[38;2;80;80;80m"
    $cReset  = "$([char]27)[0m$([char]27)[40m"

    $EColor = if ($EtwHealth -eq "Good") { $cGreen } else { $cRed }
    $LColor = if ($LogHealthStr -eq "HEALTHY") { $cGreen } else { $cRed }

    $L0_Color = "  $cGold██ Deep Sensor $cReset | System Status Dashboard"
    $L1_Color = "  $cOrange[ ENGINE STATUS ]$cReset"
    $L2_Color = "  Sensor Status : $EColor$EtwState$cReset"
    $L3_Color = "  Pipeline Load : $LColor$LogHealthStr$cReset (ML: $cWhite$MlQueue$cReset | PS: $cWhite$PsQueue$cReset)"
    $L4_Color = "  Total Events  : $cWhite$Events$cReset"
    $L5_Color = "  ML/UEBA Evals : $cGold$MlEvals$cReset"

    $R1_TitlePad = " " * 25
    $R1_Color = "$cOrange[ ACTIVE DEFENSE ]$cReset$R1_TitlePad"
    $R2_Color = "Defenses Engaged : $cRed$defFiredPad$cReset"
    $R3_Color = "Total Alerts     : $cOrange$alertPad$cReset"
    $R4_Color = "Last Action      : $cWhite$lastActionPad$cReset"
    $R5_Color = "Vectors          : $cDark$vectorsPad$cReset"

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset$L0_Color$Pad0$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset$L1_Color$Pad1$R1_Color$cCyan║$cReset"
    Write-Host "$cCyan║$cReset$L2_Color$Pad2$R2_Color$cCyan║$cReset"
    Write-Host "$cCyan║$cReset$L3_Color$Pad3$R3_Color$cCyan║$cReset"
    Write-Host "$cCyan║$cReset$L4_Color$Pad4$R4_Color$cCyan║$cReset"
    Write-Host "$cCyan║$cReset$L5_Color$Pad5$R5_Color$cCyan║$cReset"
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    if ($curTop -lt 10) { $curTop = 10 }
    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Draw-AlertWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    $UIWidth = 100

    # Moved up to slot perfectly under the Dashboard
    [Console]::SetCursorPosition(0, 10)

    $cGreen = "$([char]27)[38;2;57;255;20m"
    $headerPlain = "  [ LIVE THREAT TELEMETRY ]"
    $padHeader = " " * [math]::Max(0, ($UIWidth - $headerPlain.Length))

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cGreen[ LIVE THREAT TELEMETRY ]$cReset$padHeader$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    for ($i = 0; $i -lt 20; $i++) {
        if ($i -lt $global:RecentAlerts.Count) {
            $item = $global:RecentAlerts[$i]
            # Strip ANSI codes from length calculation to preserve original right-side padding math
            $cleanText = $item.Text -replace "`e\[[0-9;]*m",""
            $pad = " " * [math]::Max(0, (98 - $cleanText.Length))
            Write-Host "$cCyan║$cReset  $($item.Color)$($item.Text)$cReset$pad$cCyan║$cReset"
        } else {
            Write-Host "$cCyan║$cReset                                                                                                    $cCyan║$cReset"
        }
    }

    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    $ControlsPlain = "  [ I ] UPDATE SIGMA  |  [ R ] ROLLBACK DEFENSE  |  [ CTRL + C ] TEARDOWN SEQUENCE"
    $PadControls   = " " * [math]::Max(0, ($UIWidth - $ControlsPlain.Length))
    Write-Host "$cCyan║$cReset$cWhite$ControlsPlain$cReset$PadControls$cCyan║$cReset"
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    [Console]::SetCursorPosition(0, 36)
    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Draw-StartupWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    $UIWidth = 100

    [Console]::SetCursorPosition(0, 37)

    $cGreen = "$([char]27)[38;2;57;255;20m"
    $HeaderPlain = "  [ SENSOR INITIALIZATION ]"
    $PadHeader = " " * [math]::Max(0, ($UIWidth - $HeaderPlain.Length))

    Write-Host "$cCyan╔════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset$cGreen$HeaderPlain$cReset$PadHeader$cCyan║$cReset"
    Write-Host "$cCyan╠════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    $recent = if ($global:StartupLogs.Count -gt 10) { $global:StartupLogs.GetRange($global:StartupLogs.Count - 10, 10) } else { $global:StartupLogs }

    for ($i = 0; $i -lt 10; $i++) {
        if ($i -lt $recent.Count) {
            $logLine = "    $($recent[$i])"
            if ($logLine.Length -gt ($UIWidth - 1)) { $logLine = $logLine.Substring(0, $UIWidth - 4) + "..." }
            $pad = " " * [math]::Max(0, ($UIWidth - $logLine.Length))
            Write-Host "$cCyan║$cReset$logLine$pad$cCyan║$cReset"
        } else {
            $pad = " " * $UIWidth
            Write-Host "$cCyan║$cReset$pad$cCyan║$cReset"
        }
    }
    Write-Host "$cCyan╚════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Start-DeepSensorHUD {
    param(
        [bool]$Background = $false,
        [string]$EvtPath,
        [string]$UbaPath
    )

    Write-Diag "    [*] Initializing Live Browser HUD Bridge (Port Hunting)..." "STARTUP"

    $HtmlPayload = @'
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self';">
        <title>Deep Sensor | Live Workbench</title>
        <style>
            :root { --bg-main: #0a0e14; --bg-card: #0d1117; --bg-hover: #161b22; --text-main: #c9d1d9; --text-muted: #8b949e; --neon-green: #39FF14; --neon-orange: #FF5F1F; --red: #ff4b4b; --blue: #58a6ff; --border: #30363d; }
            * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
            body { background: var(--bg-main); color: var(--text-main); margin: 0; padding: 20px; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

            .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 15px; border-bottom: 1px solid var(--border); }
            .header h1 { margin: 0; font-size: 1.5rem; color: #fff; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
            .header h1 span { color: var(--neon-green); }

            .btn-group { display: flex; gap: 10px; align-items: center; }
            input[type="file"] { display: none; }
            .custom-file-upload { background: var(--bg-card); color: var(--neon-green); border: 1px solid var(--neon-green); padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; transition: all 0.2s; }
            .custom-file-upload:hover { background: rgba(57, 255, 20, 0.1); }
            .btn { background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border); padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; transition: all 0.2s; }
            .btn:hover { border-color: var(--neon-orange); color: var(--neon-orange); }

            .live-indicator { display: flex; align-items: center; gap: 8px; color: var(--neon-green); font-weight: bold; font-family: 'Consolas', monospace; text-transform: uppercase; border: 1px solid var(--neon-green); padding: 5px 12px; border-radius: 4px; background: rgba(57, 255, 20, 0.05); }
            .pulse { width: 8px; height: 8px; background-color: var(--neon-green); border-radius: 50%; box-shadow: 0 0 8px var(--neon-green); animation: throb 1.5s infinite; }
            @keyframes throb { 0% { transform: scale(0.8); opacity: 1; } 50% { transform: scale(1.3); opacity: 0.5; } 100% { transform: scale(0.8); opacity: 1; } }

            .toolbar { display: flex; justify-content: space-between; align-items: center; margin: 15px 0; }
            .search-box { width: 400px; padding: 10px 15px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 4px; color: var(--neon-green); outline: none; font-family: 'Consolas', monospace; }
            .search-box:focus { border-color: var(--neon-green); box-shadow: 0 0 5px rgba(57, 255, 20, 0.2); }

            .tabs { display: flex; gap: 5px; }
            .tab { padding: 8px 20px; background: transparent; border: none; color: var(--text-muted); cursor: pointer; font-weight: 600; border-bottom: 2px solid transparent; text-transform: uppercase; }
            .tab.active { color: var(--neon-green); border-bottom: 2px solid var(--neon-green); }

            .workspace { display: flex; flex: 1; overflow: hidden; position: relative; gap: 15px; }
            .table-container { flex: 1; overflow: auto; background: var(--bg-card); border: 1px solid var(--border); }
            table { width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left; }
            th { background: #161b22; padding: 12px 15px; position: sticky; top: 0; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); z-index: 10; text-transform: uppercase; }
            td { padding: 12px 15px; border-bottom: 1px solid var(--border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px; }
            tr { cursor: pointer; transition: background 0.1s; }
            tr:hover { background: var(--bg-hover); }
            tr.selected { background: rgba(57, 255, 20, 0.05); box-shadow: inset 3px 0 0 var(--neon-green); }

            .tag { padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase; }
            .tag-crit { background: rgba(255, 75, 75, 0.1); color: var(--red); border: 1px solid rgba(255, 75, 75, 0.3); }
            .tag-high { background: rgba(255, 95, 31, 0.1); color: var(--neon-orange); border: 1px solid rgba(255, 95, 31, 0.3); }
            .tag-info { background: rgba(57, 255, 20, 0.1); color: var(--neon-green); border: 1px solid rgba(57, 255, 20, 0.3); }
            .tag-suppressed { background: rgba(255, 95, 31, 0.1); color: var(--neon-orange); border: 1px solid rgba(255, 95, 31, 0.3); font-style: italic; }
            .mono { font-family: 'Consolas', monospace; color: var(--text-muted); }

            .inspector { width: 450px; background: var(--bg-card); border: 1px solid var(--neon-green); display: flex; flex-direction: column; transform: translateX(120%); transition: transform 0.3s ease; position: absolute; right: 0; top: 0; bottom: 0; z-index: 20; box-shadow: -5px 0 25px rgba(0,0,0,0.8); }
            .inspector.open { transform: translateX(0); }
            .ins-header { padding: 15px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #161b22; }
            .ins-header h3 { margin: 0; font-size: 1rem; color: var(--neon-green); text-transform: uppercase; }
            .close-btn { background: transparent; border: none; color: var(--text-muted); cursor: pointer; font-size: 1.5rem; font-weight: bold; }
            .close-btn:hover { color: var(--red); }
            .ins-body { padding: 15px; overflow-y: auto; flex: 1; }
            .kv-pair { margin-bottom: 15px; border-bottom: 1px solid #161b22; padding-bottom: 5px; }
            .kv-key { display: block; font-size: 0.75rem; color: var(--neon-orange); text-transform: uppercase; font-weight: 600; margin-bottom: 4px; }
            .kv-val { font-family: 'Consolas', monospace; font-size: 0.85rem; color: var(--text-main); word-break: break-all; white-space: pre-wrap; }
        </style>
    </head>
    <body>
        <div id="app-container" style="display:flex; flex-direction:column; height:100%;">
            <div class="header">
                <div style="display: flex; flex-direction: column;">
                    <h1>Deep Sensor <span>HUD</span></h1>
                    <span style="font-family: 'Consolas', monospace; font-size: 0.75rem; color: var(--neon-orange); text-transform: uppercase; margin-top: 5px;">
                        [!] Only the last 500 events are rendered | Session auto-terminates after 120s of inactivity [!]
                    </span>
                </div>
                <div class="btn-group">
                    <div class="live-indicator" id="apiStatus"><div class="pulse"></div> Auto-Tailing API</div>
                    <label class="custom-file-upload">
                        <input type="file" id="fileUploader" accept=".jsonl" multiple />
                        Manual Load
                    </label>
                    <button class="btn" onclick="exportCSV()">Export CSV</button>
                </div>
            </div>

            <div class="toolbar">
                <div class="tabs">
                    <button class="tab active" id="tab-core" onclick="setTab('core')">Security Events (<span id="count-core">0</span>)</button>
                    <button class="tab" id="tab-ueba" onclick="setTab('ueba')">UEBA Audit (<span id="count-ueba">0</span>)</button>
                </div>
                <input type="text" class="search-box" id="search" placeholder="Search processes, tags, or signatures...">
            </div>

            <div class="workspace">
                <div class="table-container">
                    <table>
                        <thead id="table-head"></thead>
                        <tbody id="table-body"></tbody>
                    </table>
                </div>
                <div class="inspector" id="inspector">
                    <div class="ins-header">
                        <h3>Event Detail Inspector</h3>
                        <button class="close-btn" onclick="closeInspector()">&times;</button>
                    </div>
                    <div class="ins-body" id="inspector-content"></div>
                </div>
            </div>
        </div>

        <script>
            let coreData = [];
            let uebaData = [];
            let currentTab = 'core';
            let totalCount = 0;
            let isManualMode = false;
            let failCount = 0;

            document.getElementById('fileUploader').addEventListener('change', function(e) {
                const files = e.target.files;
                if (files.length === 0) return;

                isManualMode = true;
                document.getElementById('apiStatus').innerHTML = "<span style='color:var(--neon-orange)'>Manual Mode Active</span>";

                let filesProcessed = 0;
                coreData = []; uebaData = [];

                for (let i = 0; i < files.length; i++) {
                    const reader = new FileReader();
                    reader.onload = function(event) {
                        const lines = event.target.result.split('\n');
                        lines.forEach(line => {
                            if (line.trim().startsWith('{')) {
                                try {
                                    const parsed = JSON.parse(line);
                                    if (parsed.Category === 'UEBA_Audit' || parsed.Category === 'AggregatedUEBA') {
                                        uebaData.push(parsed);
                                    } else {
                                        coreData.push(parsed);
                                    }
                                } catch (err) { }
                            }
                        });

                        filesProcessed++;
                        if (filesProcessed === files.length) {
                            document.getElementById('count-core').innerText = coreData.length;
                            document.getElementById('count-ueba').innerText = uebaData.length;
                            renderTable();
                        }
                    };
                    reader.readAsText(files[i]);
                }
            });

            function setTab(tab) {
                currentTab = tab;
                document.getElementById('tab-core').classList.toggle('active', tab === 'core');
                document.getElementById('tab-ueba').classList.toggle('active', tab === 'ueba');
                closeInspector();
                renderTable();
            }

            function closeInspector() {
                document.getElementById('inspector').classList.remove('open');
                document.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
            }

            function openInspector(dataItem, rowElement) {
                document.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
                rowElement.classList.add('selected');
                const content = document.getElementById('inspector-content');
                content.innerHTML = '';
                for (const [key, value] of Object.entries(dataItem)) {
                    if (value === "" || value === null || value === undefined) continue;
                    const valStr = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);

                    const pairDiv = document.createElement('div');
                    pairDiv.className = 'kv-pair';

                    const keySpan = document.createElement('span');
                    keySpan.className = 'kv-key';
                    keySpan.textContent = key.replace(/_/g, ' ');

                    const valDiv = document.createElement('div');
                    valDiv.className = 'kv-val';
                    valDiv.textContent = valStr; // XSS Mitigation: Strict textContent insertion

                    pairDiv.appendChild(keySpan);
                    pairDiv.appendChild(valDiv);
                    content.appendChild(pairDiv);
                }
                document.getElementById('inspector').classList.add('open');
            }

            function renderTable() {
                const term = document.getElementById('search').value.toLowerCase();
                const data = currentTab === 'core' ? coreData : uebaData;
                const thead = document.getElementById('table-head');
                const tbody = document.getElementById('table-body');

                tbody.innerHTML = '';
                thead.innerHTML = currentTab === 'core'
                    ? '<tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Process</th><th>Signature</th><th>Context (Cmd/Path)</th></tr>'
                    : '<tr><th>Timestamp</th><th>State</th><th>Process</th><th>Audit Action</th><th>Context</th></tr>';

                for (let i = data.length - 1; i >= 0; i--) {
                    const item = data[i];
                    if (JSON.stringify(item).toLowerCase().indexOf(term) === -1) continue;

                    const tr = document.createElement('tr');
                    // XSS Mitigation: Convert via textContent DOM node
                    const sanitize = (str) => {
                        const div = document.createElement('div');
                        div.textContent = str || '';
                        return div.innerHTML || 'N/A';
                    };

                    if (currentTab === 'core') {
                        const sev = (item.Severity || '').toLowerCase();
                        const tagClass = sev === 'critical' ? 'tag-crit' : (sev === 'high' ? 'tag-high' : 'tag-info');
                        tr.innerHTML = `
                            <td>${sanitize(item.Timestamp_Local ? item.Timestamp_Local.split('.')[0] : '')}</td>
                            <td style='color:var(--blue)'>${sanitize(item.EventType)}</td>
                            <td><span class='tag ${tagClass}'>${sanitize(item.Severity || 'INFO')}</span></td>
                            <td style='font-weight:600; color:var(--neon-green)'>${sanitize(item.Image)}</td>
                            <td>${sanitize(item.SignatureName)}</td>
                            <td class='mono'>${sanitize(item.CommandLine || item.Path)}</td>`;
                    } else {
                        const isSuppressed = item.Type === 'Suppressed';
                        const stateClass = isSuppressed ? 'tag-suppressed' : 'tag-info';
                        tr.innerHTML = `
                            <td>${sanitize(item.Timestamp_Local ? item.Timestamp_Local.split('.')[0] : '')}</td>
                            <td><span class='tag ${stateClass}'>${sanitize(item.Type)}</span></td>
                            <td style='font-weight:600; color:var(--neon-green)'>${sanitize(item.Process)}</td>
                            <td>${sanitize(item.Details)}</td>
                            <td class='mono'>${sanitize(item.Cmd || item.MatchedIndicator)}</td>`;
                    }
                    tr.onclick = () => openInspector(item, tr);
                    tbody.appendChild(tr);
                }
            }

            function exportCSV() {
                const data = currentTab === 'core' ? coreData : uebaData;
                if (data.length === 0) return alert('No data to export.');
                const headersSet = new Set();
                data.forEach(item => Object.keys(item).forEach(k => headersSet.add(k)));
                const headers = Array.from(headersSet);
                let csv = headers.join(',') + '\n';
                data.forEach(item => {
                    const rowArray = headers.map(h => {
                        let val = item[h];
                        val = (val === null || val === undefined) ? '' : val.toString();
                        return '"' + val.replace(/"/g, '""') + '"';
                    });
                    csv += rowArray.join(',') + '\n';
                });
                const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `DeepSensor_${currentTab.toUpperCase()}_Export.csv`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            }

            async function fetchTelemetry() {
                if (isManualMode) return;
                try {
                    const response = await fetch('./api/data');
                    if (!response.ok) throw new Error('API Offline');

                    failCount = 0;
                    const json = await response.json();
                    const newTotal = json.core.length + json.ueba.length;

                    const latestEventStr = newTotal > 0 ? JSON.stringify(json.core[json.core.length - 1] || json.ueba[json.ueba.length - 1]) : "";

                    if (newTotal !== totalCount || latestEventStr !== window.lastItemTracker) {
                        coreData = json.core; uebaData = json.ueba;
                        totalCount = newTotal;
                        window.lastItemTracker = latestEventStr;

                        document.getElementById('count-core').innerText = coreData.length >= 200 ? '200+' : coreData.length;
                        document.getElementById('count-ueba').innerText = uebaData.length >= 200 ? '200+' : uebaData.length;
                        renderTable();
                    }
                } catch (err) {
                    failCount++;
                    if (failCount >= 3) {
                        document.body.innerHTML = `
                            <div style='display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;background:#0a0e14;color:#c9d1d9;font-family:sans-serif;'>
                                <h1 style='color:#ff4b4b;font-size:2.5rem;margin-bottom:10px;text-transform:uppercase;'>Sensor Offline</h1>
                                <p style='font-size:1.1rem;'>The Deep Sensor Orchestrator has been terminated.</p>
                                <p style='color:#8b949e; margin-top:20px; font-style:italic;'>Closing tab...</p>
                            </div>
                        `;
                        setTimeout(() => {
                            window.opener = null;
                            window.open('', '_self');
                            window.close();
                        }, 2000);
                    }
                }
            }

            document.getElementById('search').addEventListener('input', renderTable);
            fetchTelemetry();
            setInterval(fetchTelemetry, 2000);
        </script>
    </body>
    </html>
'@

    $RunspaceCode = {
        param($HtmlStr, $EvtLogPath, $UbaLogPath, $RunInBackground)

        $EphPort = Get-Random -Minimum 49152 -Maximum 65535
        $OtpToken = [guid]::NewGuid().ToString("N")
        $BaseUrl = "http://127.0.0.1:$EphPort/"
        $SecureUrl = "$($BaseUrl)$OtpToken/"

        $Listener = New-Object System.Net.HttpListener
        $Listener.Prefixes.Add($BaseUrl)
        $Listener.Start()

        if (-not $RunInBackground) {
            Start-Process $SecureUrl
        }

        $LastHit = Get-Date
        while ($Listener.IsListening) {
            $ContextAsync = $Listener.BeginGetContext($null, $null)
            $WaitResult = $false

            while (-not $WaitResult) {
                $WaitResult = $ContextAsync.AsyncWaitHandle.WaitOne(2000)
                if (-not $WaitResult -and ((Get-Date) - $LastHit).TotalSeconds -gt 120) {
                    $Listener.Stop()
                    return # Auto-terminate: Browser tab was closed
                }
            }

            $Context = $Listener.EndGetContext($ContextAsync)
            $LastHit = Get-Date

            $Req = $Context.Request
            $Res = $Context.Response

            if (-not $Req.Url.LocalPath.StartsWith("/$OtpToken")) {
                $Res.StatusCode = 403; $Res.Close(); continue
            }

            $ReqPath = $Req.Url.LocalPath.Replace("/$OtpToken", "")
            if ($ReqPath -eq "") { $ReqPath = "/" }

            $Res.Headers.Add("X-Frame-Options", "DENY")
            $Res.Headers.Add("X-Content-Type-Options", "nosniff")
            $Res.Headers.Add("Cache-Control", "no-store, max-age=0")

            if ($ReqPath -eq "/") {
                $Buffer = [System.Text.Encoding]::UTF8.GetBytes($HtmlStr)
                $Res.ContentType = "text/html; charset=utf-8"
                $Res.ContentLength64 = $Buffer.Length
                $Res.OutputStream.Write($Buffer, 0, $Buffer.Length)
            }
            elseif ($ReqPath -eq "/api/data") {
                $Payload = @{
                    Core = [System.Collections.Generic.List[string]]::new()
                    Ueba = [System.Collections.Generic.List[string]]::new()
                }
                foreach ($Log in @{Core=$EvtLogPath; Ueba=$UbaLogPath}.GetEnumerator()) {
                    if (Test-Path $Log.Value) {
                        $fs = $null; $sr = $null
                        try {
                            $fs = New-Object System.IO.FileStream($Log.Value, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                            $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)

                            $tempLines = [System.Collections.Generic.List[string]]::new()
                            while (-not $sr.EndOfStream) {
                                $line = $sr.ReadLine()
                                if ($line.Trim().StartsWith("{")) { $tempLines.Add($line) }
                            }

                            $startIndex = [math]::Max(0, $tempLines.Count - 500)
                            for ($i = $startIndex; $i -lt $tempLines.Count; $i++) {
                                $Payload[$Log.Key].Add($tempLines[$i])
                            }
                        } catch {
                        } finally {
                            if ($null -ne $sr) { $sr.Dispose() }
                            if ($null -ne $fs) { $fs.Dispose() }
                        }
                    }
                }
                $JsonData = "{ `"core`": [" + ($Payload.Core -join ",") + "], `"ueba`": [" + ($Payload.Ueba -join ",") + "] }"
                $Buffer = [System.Text.Encoding]::UTF8.GetBytes($JsonData)
                $Res.ContentType = "application/json"
                $Res.ContentLength64 = $Buffer.Length
                $Res.OutputStream.Write($Buffer, 0, $Buffer.Length)
            }
            else { $Res.StatusCode = 404 }
            $Res.Close()
        }
    }

    $PS = [powershell]::Create().AddScript($RunspaceCode).AddArgument($HtmlPayload).AddArgument($EvtPath).AddArgument($UbaPath).AddArgument($Background)
    $global:HudRunspace = $PS
    $PS.BeginInvoke() | Out-Null
}

# ======================================================================
# 5. ACTIVE DEFENSE & RESPONSE FUNCTIONS
# ======================================================================
function Invoke-ActiveDefense([string]$ProcName, [int]$PID_Id, [int]$TID_Id, [string]$TargetType, [string]$Reason) {
    if (-not $global:IsArmed -or $ProcName -match "Unknown|System|Idle") { return }

    # 1. THE ANTI-BSOD & BUSINESS CONTINUITY GATEKEEPER
    $BSOD_Risks = @("csrss.exe", "lsass.exe", "smss.exe", "services.exe", "wininit.exe", "winlogon.exe", "svchost.exe", "dwm.exe", "explorer.exe")
    if ($BSOD_Risks -contains $ProcName.ToLower()) {
        Write-Diag "[ACTIVE DEFENSE] Skipped termination of $ProcName to prevent OS BSOD." "WARNING"
        Add-AlertMessage "DEFENSE ABORTED: OS Critical Process ($ProcName)" "$([char]27)[95;40m"
        return
    }

    $containmentStatus = "Failed"
    $forensicArtifact = "None"

    # 2. FORENSIC PRESERVATION
    $dumpPath = [DeepVisibilitySensor]::PreserveForensics($PID_Id, $ProcName)
    if ($dumpPath -ne "Failed" -and $dumpPath -ne "AccessDenied" -and $dumpPath -ne "Bypassed") {
        $forensicArtifact = $dumpPath
    }

    # 3. CONTAINMENT EXECUTION (Prefer Thread Quarantine for safe rollback)
    if ($TargetType -eq "Thread" -and $TID_Id -gt 0) {
        $res = [DeepVisibilitySensor]::QuarantineNativeThread($TID_Id, $PID_Id)
        if ($res) {
            $containmentStatus = "Thread ($TID_Id) Quarantined"
            $global:TotalMitigations++
        }
    }
    else {
        Stop-Process -Id $PID_Id -Force -ErrorAction SilentlyContinue
        if (-not (Get-Process -Id $PID_Id -ErrorAction SilentlyContinue)) {
            $containmentStatus = "Process ($PID_Id) Terminated"
            $global:TotalMitigations++
        }
    }

    # 4. INCIDENT REPORTING
    $ReportDir = "C:\ProgramData\DeepSensor\Data\Reports"
    if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
    $ReportId = [guid]::NewGuid().ToString().Substring(0,8)

    $IncidentReport = @{
        IncidentID = $ReportId
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Process = $ProcName
        PID = $PID_Id
        TID = $TID_Id
        TriggerReason = $Reason
        ActionTaken = $containmentStatus
        ForensicsSavedAt = $forensicArtifact
    }
    $IncidentReport | ConvertTo-Json -Depth 4 | Out-File "$ReportDir\Incident_${ReportId}.json"

    $audit = "{$global:EnrichmentPrefix`"Category`":`"AuditTrail`", `"Action`":`"$containmentStatus`", `"TargetProcess`":`"$ProcName`", `"PID`":$PID_Id, `"TID`":$TID_Id, `"Reason`":`"$Reason`", `"ReportID`":`"$ReportId`"}"
    $script:logBatch.Add($audit)

    Add-AlertMessage "DEFENSE: $containmentStatus ($ProcName)" "$([char]27)[93;40m"
}

function Invoke-DefenseRollback {
    Write-Host "`n[!] INITIATING ACTIVE DEFENSE ROLLBACK..." -ForegroundColor Cyan

    # 1. Lift Host Isolation (Firewall)
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction NotConfigured -DefaultOutboundAction NotConfigured -ErrorAction Stop
        Remove-NetFirewallRule -DisplayName "DeepSensor_Safe_Uplink" -ErrorAction SilentlyContinue
        Write-Diag "[ROLLBACK] Network Host Isolation lifted." "INFO"
        Add-AlertMessage "ROLLBACK: Network Isolation Lifted" "$([char]27)[96;40m"
    } catch { Write-Diag "[ROLLBACK] Network restore failed: $($_.Exception.Message)" "ERROR" }

    # 2. Look for recently suspended threads in our audit log and resume them
    # Note: In a full enterprise UI, you would select the specific TID. Here we use a safe heuristic for the last action.
    $LastSuspendedTid = 0
    # Search backwards through the log batch for the last quarantined thread
    for ($i = $script:logBatch.Count - 1; $i -ge 0; $i--) {
        if ($script:logBatch[$i] -match "`"Action`":`"Thread \((\d+)\) Quarantined`"") {
            $LastSuspendedTid = [int]$matches[1]
            break
        }
    }

    if ($LastSuspendedTid -gt 0) {
        $res = [DeepVisibilitySensor]::ResumeNativeThread($LastSuspendedTid)
        if ($res) {
            Write-Diag "[ROLLBACK] Successfully resumed Native Thread $LastSuspendedTid." "INFO"
            Add-AlertMessage "ROLLBACK: Thread $LastSuspendedTid Resumed" "$([char]27)[96;40m"
        }
    } else {
        Add-AlertMessage "ROLLBACK: No suspended threads found in active queue." "$([char]27)[90;40m"
    }
    Start-Sleep -Seconds 2
}

function Invoke-HostIsolation {
    param([string]$Reason, [string]$TriggeringProcess)

    if (-not $ArmedMode) {
        Write-Diag "[AUDIT MODE] Host Isolation bypassed for: $Reason ($TriggeringProcess)" "CRITICAL"
        return
    }

    Write-Host "`n[!] CRITICAL THREAT DETECTED: INITIATING HOST ISOLATION" -ForegroundColor Red
    Write-Host "    Reason: $Reason ($TriggeringProcess)" -ForegroundColor Yellow

    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop
        New-NetFirewallRule -DisplayName "DeepSensor_Safe_Uplink" -Direction Outbound -Action Allow -RemoteAddress "10.0.0.50" -ErrorAction SilentlyContinue | Out-Null
        Write-Diag "[ACTIVE DEFENSE] Host isolated from network via Firewall. Safe Uplink preserved." "CRITICAL"
    } catch {
        Write-Diag "[ACTIVE DEFENSE ERROR] Failed to enforce firewall quarantine: $($_.Exception.Message)" "CRITICAL"
    }
}

function Write-RotatedJsonl {
    param (
        [string]$FilePath,
        [string]$JsonPayload
    )
    try {
        [System.IO.File]::AppendAllText($FilePath, $JsonPayload + "`r`n")

        # 2. Ephemeral HUD Check (Hard Cap at 10MB to prevent I/O burn)
        $fileInfo = New-Object System.IO.FileInfo($FilePath)
        if ($fileInfo.Length -gt 10485760) {
            # Keep only the last 2000 lines for the Web UI, truncate the rest.
            # History is perfectly safe in the Rust SQLite Ledger.
            $tail = Get-Content $FilePath -Tail 2000
            [System.IO.File]::WriteAllLines($FilePath, $tail)
            Write-Diag "Rotated ephemeral HUD log: $FilePath (Exceeded 10MB threshold)" "INFO"
        }
    } catch { }
}

function Submit-UebaAudit {
    param([PSCustomObject]$AuditObj)

    $payload = $AuditObj | ConvertTo-Json -Compress

    # PERMANENT STORAGE: Push to the ultra-compressed Rust SQLite WAL Database
    try { [DeepVisibilitySensor]::RouteUebaToSqlite($payload) } catch {}

    # EPHEMERAL HUD: Write to JSONL with strict 10MB rotation
    $UebaLogPath = Join-Path "C:\ProgramData\DeepSensor\Logs" "DeepSensor_UEBA.jsonl"
    Write-RotatedJsonl -FilePath $UebaLogPath -JsonPayload $payload
}

function Submit-SensorAlert {
    param(
        [string]$Type, [string]$TargetObject, [string]$Image, [string]$Flags,
        [int]$Confidence, [int]$PID_Id = 0, [int]$TID_Id = 0, [string]$AttckMapping = "N/A",
        [string]$EventId = ([guid]::NewGuid().ToString()), [string]$RawJson = $null,
        [int]$LearningHit = 0, [string]$CommandLine = "Unknown", [switch]$IsSuppressed,
        [string]$MatchedIndicator = ""
    )

    # 1. Deduplication Logic
    $dedupKey = "$($Type)_$($TargetObject)_$($Flags)_$($Image)"

    if ($null -eq $global:HistoricalAlerts) {
        $global:HistoricalAlerts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }

    # TTP_Match always re-fires. Sigma re-fires only when regression mode is active.
    $bypassDedup = ($Type -eq "TTP_Match") -or
                ($global:RegressionTestMode -eq $true -and $Type -eq "Sigma_Match")

    if (-not $bypassDedup -and -not $global:HistoricalAlerts.Add($dedupKey)) {
        return
    }

    $isNewAlert = -not $global:cycleAlerts.ContainsKey($dedupKey)

    if (-not $isNewAlert) {
        $global:cycleAlerts[$dedupKey].Count++
        return
    }

    # 2. Standardized PSCustomObject (Dynamically maps Rust or C# fields)
    $parsedJson = $null
    if ($RawJson) { $parsedJson = try { $RawJson | ConvertFrom-Json } catch { $null } }

    $alertObj = [PSCustomObject][ordered]@{
        EventID = $EventId; Count = 1
        Timestamp_Local = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
        Timestamp_UTC   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        ComputerName = $env:COMPUTERNAME; HostIP = $IpAddress; SensorUser = $userStr
        EventType = $Type; Destination = $TargetObject; Image = $Image; CommandLine = $CommandLine
        SuspiciousFlags = $Flags; MatchedIndicator = $MatchedIndicator; ATTCKMappings = $AttckMapping; Confidence = $Confidence
        SignatureName = if ($parsedJson -and $parsedJson.SignatureName) { $parsedJson.SignatureName } elseif ($parsedJson -and $parsedJson.signature_name) { $parsedJson.signature_name } else { "" }
        Tactic        = if ($parsedJson -and $parsedJson.Tactic) { $parsedJson.Tactic } elseif ($parsedJson -and $parsedJson.tactic) { $parsedJson.tactic } else { "" }
        Technique     = if ($parsedJson -and $parsedJson.Technique) { $parsedJson.Technique } elseif ($parsedJson -and $parsedJson.technique) { $parsedJson.technique } else { "" }
        Procedure     = if ($parsedJson -and $parsedJson.Procedure) { $parsedJson.Procedure } elseif ($parsedJson -and $parsedJson.procedure) { $parsedJson.procedure } else { "" }
        Severity      = if ($parsedJson -and $parsedJson.Severity) { $parsedJson.Severity } elseif ($parsedJson -and $parsedJson.severity) { $parsedJson.severity } else { "Medium" }
        Action = if ($IsSuppressed) { "Suppressed" } elseif ($global:IsArmed -and $Confidence -ge 95) { "Mitigated" } else { "Logged" }
    }

    $global:cycleAlerts[$dedupKey] = $alertObj

    if (-not $IsSuppressed) {
        try {
            $GatewayPayload = $alertObj | ConvertTo-Json -Compress
            [DeepVisibilitySensor]::TransmitAlertToGateway($GatewayPayload)
        } catch {
            Write-Diag "Failed to bridge orchestrator alert to FFI transmission gateway: $($_.Exception.Message)" "WARN"
        }
    }

    # 3. Instant HUD Rendering & Defense Routing
    if ($IsSuppressed) { return }

    $cRed = "$([char]27)[38;2;255;49;49m"; $cOrange = "$([char]27)[38;2;255;103;0m"
    $cGold = "$([char]27)[38;2;255;215;0m"; $cWhite = "$([char]27)[38;2;255;255;255m"

    if ($alertObj.Action -eq "Mitigated" -or $Confidence -ge 100) {
        Add-AlertMessage "$Flags ($Image)" $cRed
    } elseif ($Confidence -ge 90) {
        Add-AlertMessage "$Flags ($Image) [Conf:$Confidence]" $cOrange
    } elseif ($LearningHit -gt 0) {
        Add-AlertMessage "LEARNING: $Flags ($Image) [Hit:$LearningHit]" $cGold
    } else {
        Add-AlertMessage "STATIC: $Flags ($Image)" $cWhite
    }

    if ($alertObj.Action -eq "Mitigated") {
        Invoke-ActiveDefense -ProcName $Image -PID_Id $PID_Id -TID_Id $TID_Id -TargetType "Process" -Reason $Flags
        Invoke-HostIsolation -Reason $Flags -TriggeringProcess $Image
    }
}

# ======================================================================
# 6. ENVIRONMENT & BOOTSTRAP FUNCTIONS
# ======================================================================

function Unlock-PolicySyncPaths {
    $PathsToUnlock = @($ScriptDir, $global:SecureStaging)
    foreach ($p in $PathsToUnlock) {
        if (Test-Path $p) {
            $null = icacls $p /reset /T /C /Q *>$null
        }
    }
}

function Protect-SensorEnvironment {
    Write-Diag "[*] Hardening Sensor Ecosystem (DACLs & Registry)..." "STARTUP"

    $DataDir = "C:\ProgramData\DeepSensor\Data"
    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }

    $PathsToLock = @($ScriptDir, $global:SecureStaging)
    foreach ($p in $PathsToLock) {
        if (Test-Path $p) {
            $null = icacls $p /inheritance:r /q
                $null = icacls $p /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q
                $null = icacls $p /grant "BUILTIN\Administrators:(OI)(CI)F" /q
                $null = icacls $p /deny "BUILTIN\Users:(OI)(CI)W" /q
        }
    }

    if (Test-Path $DataDir) {
        $currentUser = "$env:USERDOMAIN\$env:USERNAME"

        icacls $DataDir /inheritance:d /q *>$null
        icacls $DataDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q *>$null
        icacls $DataDir /grant "BUILTIN\Administrators:(OI)(CI)F" /q *>$null
        icacls $DataDir /grant "${currentUser}:(OI)(CI)M" /q *>$null

        if ($null -ne $ReadAccessAccounts) {
            foreach ($account in $ReadAccessAccounts) {
                if (-not [string]::IsNullOrWhiteSpace($account)) {
                    icacls $DataDir /grant "${account}:(OI)(CI)RX" /q *>$null
                }
            }
        }
        icacls $DataDir /remove "BUILTIN\Users" /q 2>$null *>$null
    }

    Write-Diag "    [+] Discretionary Access Control Lists (DACLs) locked down." "STARTUP"

    $ServiceName = "DeepSensorService"
    $serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($serviceExists) {
        $secureSddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
        $null = & sc.exe sdset $ServiceName $secureSddl
        # The PowerShell 'Assert-ServiceStability' function handles the 10-try limit.
        $null = & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000
        Write-Diag "    [+] Windows Service configuration secured." "STARTUP"
    }
}

function Initialize-Environment {
    Write-Diag "[*] Hardening Binary Environment & Cryptographic Validation..." "STARTUP"

    $BaseDataDir = "C:\ProgramData\DeepSensor"
    $BinDir = Join-Path $BaseDataDir "bin"
    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }

    $MlBinaryPath = Join-Path $BinDir $MlBinaryName
    $HashPath     = $MlBinaryPath -replace "\.dll$", ".sha256"
    $binaryReady  = $false

    $ProjectDll  = Join-Path $ScriptDir $MlBinaryName
    $ProjectHash = Join-Path $ScriptDir ($MlBinaryName -replace "\.dll$", ".sha256")

    if ((Test-Path $ProjectDll) -and (Test-Path $ProjectHash)) {
        Write-Diag "    [*] New build artifacts detected in project directory. Preparing secure update..." "STARTUP"

        Write-Diag "    [*] Temporarily unlocking bin directory for update..." "STARTUP"
        $null = icacls $BinDir /inheritance:e /q
        $null = icacls $BinDir /remove "BUILTIN\Users" /q 2>$null

        if (Test-Path $MlBinaryPath) { Remove-Item $MlBinaryPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $HashPath)     { Remove-Item $HashPath     -Force -ErrorAction SilentlyContinue }

        $ExpectedHash = (Get-Content $ProjectHash -Raw).Trim()
        $ActualHash   = (Get-FileHash $ProjectDll -Algorithm SHA256).Hash

        if ($ExpectedHash -eq $ActualHash) {
            Move-Item -Path $ProjectDll  -Destination $MlBinaryPath -Force
            Move-Item -Path $ProjectHash -Destination $HashPath     -Force
            $binaryReady = $true
            Write-Diag "    [+] Hash verified → New DLL and hash successfully moved to secure bin" "STARTUP"
        }
        else {
            Write-Diag "    [!] Hash mismatch on build artifacts in project directory!" "ERROR"
        }

        Write-Diag "    [*] Re-locking bin directory..." "STARTUP"
        $null = icacls $BinDir /inheritance:d /q
        $null = icacls $BinDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q
        $null = icacls $BinDir /grant "BUILTIN\Administrators:(OI)(CI)F" /q
        $null = icacls $BinDir /deny "BUILTIN\Users:(W)" /q
    }

    if (-not $binaryReady -and (Test-Path $MlBinaryPath) -and (Test-Path $HashPath)) {
        $ExpectedHash = (Get-Content $HashPath -Raw).Trim()
        $ActualHash   = (Get-FileHash $MlBinaryPath -Algorithm SHA256).Hash

        if ($ExpectedHash -eq $ActualHash) {
            $binaryReady = $true
            Write-Diag "    [+] Cryptographic Integrity Verified: $MlBinaryName" "STARTUP"
        } else {
            Write-Diag "    [!] CRITICAL: Hash Mismatch. Possible DLL Hijacking detected." "ERROR"
        }
    }

    if (-not $binaryReady) {
        Write-Diag "    [-] Provisioning verified binary from repository..." "STARTUP"
        try {
            if ($OfflineRepoPath) {
                Copy-Item (Join-Path $OfflineRepoPath $MlBinaryName) -Destination $MlBinaryPath -Force
                Copy-Item (Join-Path $OfflineRepoPath ($MlBinaryName -replace "\.dll$", ".sha256")) -Destination $HashPath -Force
            }

            if ((Test-Path $MlBinaryPath) -and (Test-Path $HashPath)) {
                $ExpectedHash = (Get-Content $HashPath -Raw).Trim()
                $ActualHash   = (Get-FileHash $MlBinaryPath -Algorithm SHA256).Hash
                if ($ExpectedHash -eq $ActualHash) {
                    $binaryReady = $true
                    Write-Diag "    [+] Binary successfully provisioned and verified." "STARTUP"
                }
            }
        } catch {
            Write-Diag "    [!] Acquisition failed: $($_.Exception.Message)" "ERROR"
        }
    }

    if (-not $binaryReady) {
        throw "CRITICAL: Engine initialization aborted due to missing verified artifacts."
    }

    $null = icacls $BinDir /inheritance:d /q
    $null = icacls $BinDir /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /q
    $null = icacls $BinDir /grant "BUILTIN\Administrators:(OI)(CI)F" /q
    $null = icacls $BinDir /deny "BUILTIN\Users:(W)" /q

    return $MlBinaryPath
}

function Initialize-TraceEventDependency {
    param([string]$ExtractBase = "C:\ProgramData\DeepSensor\Dependencies")

    Write-Diag "Validating C# ETW Dependencies..." "STARTUP"
    $ExpectedDllName = "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

    $ExistingDll = Get-ChildItem -Path $ExtractBase -Filter $ExpectedDllName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($ExistingDll) {
        $DllDir = Split-Path $ExistingDll.FullName -Parent
        $FastSerPath = Join-Path $DllDir "Microsoft.Diagnostics.FastSerialization.dll"
        $YaraPath = Join-Path $DllDir "libyara.NET.dll"

        # Flatten unmanaged DLLs on fast-restart
        $Amd64Dir = Join-Path $DllDir "amd64"
        if (Test-Path $Amd64Dir) {
            $UnmanagedToFlatten = @("KernelTraceControl.dll", "msdia140.dll", "yara.dll")
            foreach ($lib in $UnmanagedToFlatten) {
                $src = Join-Path $Amd64Dir $lib
                $dst = Join-Path $DllDir $lib
                if ((Test-Path $src) -and -not (Test-Path $dst)) {
                    Copy-Item -Path $src -Destination $dst -Force
                }
            }
        }

        if ((Test-Path $FastSerPath) -and (Test-Path $YaraPath)) {
            Write-Diag "[+] TraceEvent and Context-Aware YARA libraries validated." "STARTUP"
            return $ExistingDll.FullName
        }
    }

    Write-Diag "[-] TraceEvent library absent. Initiating silent deployment..." "STARTUP"
    try {
        if (Test-Path $ExtractBase) { Remove-Item $ExtractBase -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $ExtractBase -Force | Out-Null

        $SecureStaging = "C:\ProgramData\DeepSensor\Staging"
        if (-not (Test-Path $SecureStaging)) {
            New-Item -ItemType Directory -Path $SecureStaging -Force | Out-Null
        }

        $null = icacls $SecureStaging /reset /T /C /Q *>$null

        $TE_Zip = "$SecureStaging\TE.zip"
        $UN_Zip = "$SecureStaging\UN.zip"

        if ($OfflineRepoPath) {
            Copy-Item (Join-Path $OfflineRepoPath "traceevent.nupkg") -Destination $TE_Zip -Force
            Copy-Item (Join-Path $OfflineRepoPath "unsafe.nupkg") -Destination $UN_Zip -Force
        } else {
            $TE_Url = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.2.2"
            $UN_Url = "https://www.nuget.org/api/v2/package/System.Runtime.CompilerServices.Unsafe/6.1.0"
            Invoke-WebRequest -Uri $TE_Url -OutFile $TE_Zip -UseBasicParsing
            Invoke-WebRequest -Uri $UN_Url -OutFile $UN_Zip -UseBasicParsing
        }

        Expand-Archive -Path $TE_Zip -DestinationPath "$ExtractBase\TE" -Force
        Expand-Archive -Path $UN_Zip -DestinationPath "$ExtractBase\UN" -Force
        Remove-Item $TE_Zip, $UN_Zip -Force -ErrorAction SilentlyContinue

        $YARA_Zip = "$SecureStaging\YARA.zip"
        if ($OfflineRepoPath) {
            Copy-Item (Join-Path $OfflineRepoPath "libyaranet.nupkg") -Destination $YARA_Zip -Force
        } else {
            Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/Microsoft.O365.Security.Native.libyara.NET/4.5.5" -OutFile $YARA_Zip -UseBasicParsing
        }
        Expand-Archive -Path $YARA_Zip -DestinationPath "$ExtractBase\YARA" -Force
        Remove-Item $YARA_Zip -Force -ErrorAction SilentlyContinue

        $FoundDll = Get-ChildItem -Path "$ExtractBase\TE" -Filter $ExpectedDllName -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -match "net462|netstandard|net45" } | Select-Object -First 1

        if ($FoundDll) {
            $DllDir = Split-Path $FoundDll.FullName -Parent
            $UnsafeDll = Get-ChildItem -Path "$ExtractBase\UN" -Filter "System.Runtime.CompilerServices.Unsafe.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "net45|netstandard|net46" } | Select-Object -First 1
            if ($UnsafeDll) { Copy-Item -Path $UnsafeDll.FullName -Destination $DllDir -Force }

            $Amd64Dir = Join-Path $DllDir "amd64"
            if (-not (Test-Path $Amd64Dir)) { New-Item -ItemType Directory -Path $Amd64Dir -Force | Out-Null }

            $NativeHelpers = @(
                (Get-ChildItem -Path "$ExtractBase\TE" -Filter "KernelTraceControl.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "amd64" } | Select-Object -First 1),
                (Get-ChildItem -Path "$ExtractBase\TE" -Filter "msdia140.dll" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "amd64" } | Select-Object -First 1)
            )

            foreach ($h in $NativeHelpers) {
                if ($h) {
                    Copy-Item -Path $h.FullName -Destination $Amd64Dir -Force
                    Copy-Item -Path $h.FullName -Destination $DllDir -Force
                }
            }

            $ProcArch = if ([Environment]::Is64BitProcess) {
                if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'x64' }
            } else { 'x86' }

            $ManagedYara = Get-ChildItem -Path "$ExtractBase\YARA" -Filter "libyara.NET.dll" -Recurse |
                           Where-Object { $_.FullName -match "[\\/]$ProcArch[\\/]" } |
                           Select-Object -First 1
            if (-not $ManagedYara) {
                $ManagedYara = Get-ChildItem -Path "$ExtractBase\YARA" -Filter "libyara.NET.dll" -Recurse |
                               Where-Object { $_.FullName -notmatch "[\\/](x86|x64|arm64)[\\/]" } |
                               Select-Object -First 1
            }
            if (-not $ManagedYara) {
                throw "libyara.NET.dll not found for architecture '$ProcArch' under $ExtractBase\YARA"
            }

            $UnmanagedYara = Get-ChildItem -Path "$ExtractBase\YARA" -Filter "yara.dll" -Recurse |
                             Where-Object { $_.FullName -match "win-$ProcArch" } |
                             Select-Object -First 1

            Write-Diag "    [+] Selected libyara.NET.dll ($ProcArch): $($ManagedYara.FullName)" "STARTUP"
            if ($ManagedYara) { Copy-Item -Path $ManagedYara.FullName -Destination $DllDir -Force }
            if ($UnmanagedYara) {
                Copy-Item -Path $UnmanagedYara.FullName -Destination $Amd64Dir -Force
                Copy-Item -Path $UnmanagedYara.FullName -Destination $DllDir -Force
            }

            Write-Diag "[+] TraceEvent library deployed successfully." "STARTUP"
            return $FoundDll.FullName
        } else {
            throw "DLL not found within extracted package structure."
        }
    } catch {
        Write-Diag "[!] TraceEvent deployment failed: $($_.Exception.Message)" "STARTUP"
        return $null
    }
}

function Invoke-EnvironmentalAudit {
    Write-Diag "    [*] Initializing Environmental Audit..." "STARTUP"
    Write-Diag "        [*] Executing Proactive Posture & WMI Sweep..." "STARTUP"

    $lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if (-not $lsa -or $lsa.RunAsPPL -ne 1) {
        Write-Diag "[POSTURE] Vulnerability: LSASS is not running as a Protected Process Light (PPL)." "AUDIT"
    }

    $rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($rdp -and $rdp.fDenyTSConnections -eq 0) {
        Write-Diag "[POSTURE] Vulnerability: RDP is currently enabled and exposed." "AUDIT"
    }

    try {
        $consumers = Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -ErrorAction Stop
        foreach ($c in $consumers) {
            if ($c.CommandLineTemplate -match "powershell|cmd|wscript|cscript") {
                Write-Diag "[THREAT HUNT] Suspicious WMI Event Consumer Found: $($c.Name) -> $($c.CommandLineTemplate)" "CRITICAL"
            }
        }
    } catch { }
}

# ======================================================================
# 7. THREAT INTELLIGENCE & COMPILER FUNCTIONS
# ======================================================================

function Sync-YaraIntelligence {
    Write-Diag "Syncing YARA Intelligence (Elastic & ReversingLabs)..." "STARTUP"

    $YaraBaseDir = Join-Path $global:SecureStaging "yara"
    $VectorDir = if ($OfflineRepoPath) { Join-Path $OfflineRepoPath "yara_rules" } else { Join-Path $global:SecureStaging "yara_rules" }
    $CacheMarker = Join-Path $global:SecureStaging "yara.cache"
    $needsDownload = $true

    if (Test-Path $CacheMarker) {
        if (((Get-Date) - (Get-Item $CacheMarker).LastWriteTime).TotalHours -lt 24) {
            $needsDownload = $false
            Write-Diag "    [*] Using cached YARA Intelligence (< 24h old). Skipping download." "STARTUP"
        }
    }

    if (-not (Test-Path $YaraBaseDir)) { New-Item -ItemType Directory -Path $YaraBaseDir -Force | Out-Null }

    if ($needsDownload) {
        $Sources = @(
            @{ Name = "ElasticLabs"; Url = "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip"; SubPath = "protections-artifacts-main/yara" },
            @{ Name = "ReversingLabs"; Url = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip"; SubPath = "reversinglabs-yara-rules-develop/yara" },
            @{ Name = "SignatureBase_Neo23x0"; Url = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"; SubPath = "signature-base-master/yara" }
        )

        $SecureStaging = "C:\ProgramData\DeepSensor\Staging"
        if (-not (Test-Path $SecureStaging)) { New-Item -ItemType Directory -Path $SecureStaging -Force | Out-Null }
        $null = icacls $SecureStaging /reset /T /C /Q *>$null

        foreach ($src in $Sources) {
            $TempZip = "$SecureStaging\$($src.Name).zip"
            $TempExt = "$SecureStaging\$($src.Name)_extract"

            try {
                if ($OfflineRepoPath) {
                    $OfflineZip = Join-Path $OfflineRepoPath "$($src.Name).zip"
                    if (Test-Path $OfflineZip) { Copy-Item $OfflineZip -Destination $TempZip -Force }
                } else {
                    Write-Diag "    [*] Downloading $($src.Name) ruleset..." "STARTUP"
                    Invoke-WebRequest -Uri $src.Url -OutFile $TempZip -UseBasicParsing -ErrorAction Stop
                }

                if (Test-Path $TempZip) {
                    Expand-Archive -Path $TempZip -DestinationPath $TempExt -Force
                    $SourceRules = Join-Path $TempExt $src.SubPath
                    Copy-Item -Path "$SourceRules\*" -Destination $YaraBaseDir -Recurse -Force
                    Write-Diag "    [+] $($src.Name) staged to local yara/ directory." "STARTUP"
                }
            } catch {
                Write-Diag "    [-] Failed to sync $($src.Name): $($_.Exception.Message)" "STARTUP"
            } finally {
                if (Test-Path $TempZip) { Remove-Item $TempZip -Force }
                if (Test-Path $TempExt) { Remove-Item $TempExt -Recurse -Force }
            }
        }
        New-Item -Path $CacheMarker -ItemType File -Force | Out-Null
    }

    $LocalRules = Get-ChildItem -Path $YaraBaseDir -Filter "*.yar" -Recurse
    Write-Diag "    [*] Sorting $($LocalRules.Count) rules into context-aware vectors..." "STARTUP"

    $Vectors = @("WebInfrastructure", "SystemExploits", "LotL", "MacroPayloads", "BinaryProxy", "SystemPersistence", "InfostealerTargets", "RemoteAdmin", "DevOpsSupplyChain", "Core_C2")
    foreach ($v in $Vectors) {
        $vPath = Join-Path $VectorDir $v
        if (-not (Test-Path $vPath)) { New-Item -ItemType Directory -Path $vPath -Force | Out-Null }
    }

    foreach ($rule in $LocalRules) {
        try {
            # GATEKEEPER: Test-compile the rule in memory before committing to a vector
            if (-not [DeepVisibilitySensor]::IsYaraRuleValid($rule.FullName)) {
                continue # Skip this file and move to the next
            }

            $content = [System.IO.File]::ReadAllText($rule.FullName)
            $target = "Core_C2"

            if ($content -match "webshell|aspx?|php|iis|nginx|tomcat") { $target = "WebInfrastructure" }
            elseif ($content -match "exploit|cve|lsass|spoolsv|privesc") { $target = "SystemExploits" }
            elseif ($content -match "powershell|cmd|wscript|cscript|encoded") { $target = "LotL" }
            elseif ($content -match "vba|macro|office|doc|xls") { $target = "MacroPayloads" }
            elseif ($content -match "rundll32|regsvr32|mshta|dll_loading|sideload") { $target = "BinaryProxy" }
            elseif ($content -match "com_hijack|persistence|registry_run|startup") { $target = "SystemPersistence" }
            elseif ($content -match "cookie|infostealer|stealer|credential|browser") { $target = "InfostealerTargets" }
            elseif ($content -match "remotemanagement|rmm|vnc|rdp|tunnel") { $target = "RemoteAdmin" }
            elseif ($content -match "reverse_shell|supply_chain|container|escape") { $target = "DevOpsSupplyChain" }

            [System.IO.File]::Copy($rule.FullName, (Join-Path $VectorDir "$target\$($rule.Name)"), $true)
        }
        catch { continue }
    }
    Write-Diag "    [+] YARA Intelligence sorted and ready for compilation." "STARTUP"
}

function Compile-SigmaRulesToBase64 {
    $StagingSigmaDir = Join-Path $global:SecureStaging "sigma"
    $CustomSigmaDir  = Join-Path $ScriptDir "sigma"

    $SigmaFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    # Ingest the dynamically downloaded SigmaHQ rules from the secure staging area
    if (Test-Path $StagingSigmaDir) {
        Get-ChildItem -Path $StagingSigmaDir -Include "*.yml", "*.yaml" -Recurse | ForEach-Object { $SigmaFiles.Add($_) }
    }

    # Ingest custom rules from the project directory
    if (Test-Path $CustomSigmaDir) {
        $customCount = 0
        Get-ChildItem -Path $CustomSigmaDir -Include "*.yml", "*.yaml" -Recurse | ForEach-Object {
            $SigmaFiles.Add($_)
            $customCount++
        }
        if ($customCount -gt 0) {
            Write-Diag "    [+] Integrated $customCount custom Sigma rules from project root." "STARTUP"
        }
    }

    if ($SigmaFiles.Count -eq 0) { return "" }

    $RuleStrings = [System.Collections.Generic.List[string]]::new()
    $ParsedCount = 0

    Write-Diag "    [*] Compiling $($SigmaFiles.Count) total Sigma rules into Boolean AST Matrices..." "STARTUP"

    foreach ($file in $SigmaFiles) {
        $lines = Get-Content $file.FullName
        $content = $lines -join "`n"

        if ($content -notmatch "product:\s*windows") { continue }

        $title = "Unknown Rule"; if ($content -match "(?im)^\s*title:\s*(.+)") { $title = $matches[1].Trim(" '`"") }
        $id = [guid]::NewGuid().ToString(); if ($content -match "(?im)^\s*id:\s*(.+)") { $id = $matches[1].Trim(" '`"") }
        $severity = "high"; if ($content -match "(?im)^\s*level:\s*(.+)") { $severity = $matches[1].Trim(" '`"") }

        $tags = "N/A"; if ($content -match '(?ms)^\s*tags:\s*\r?\n((?:\s*-\s*.*?\r?\n?)+)') {
            $tags = ($matches[1] -split "\r?\n" | ForEach-Object { $_.Trim(" -`t'`"") } | Where-Object { $_ }) -join ","
        }

        $category = "process_creation"
        if ($content -match "(?im)^\s*category:\s*registry") { $category = "registry_event" }
        elseif ($content -match "(?im)^\s*category:\s*file") { $category = "file_event" }
        elseif ($content -match "(?im)^\s*category:\s*image") { $category = "image_load" }
        elseif ($content -match "(?im)^\s*category:\s*network_connection") { $category = "network_connection" }

        $condition = ""
        if ($content -match "(?im)^\s*condition:\s*(.+)") { $condition = $matches[1].Trim() }

        if ([string]::IsNullOrWhiteSpace($condition)) { continue }

        # 1. EXTRACT BLOCKS AND FIELDS (State-Aware)
        $blocks = @{}
        $currentBlockName = ""
        $currentField = ""
        $inDetection = $false

        foreach ($line in $lines) {
            if ($line -match "^\s*detection:\s*$") { $inDetection = $true; continue }
            if ($line -match "^\s*falsepositives:\s*$") { $inDetection = $false; continue }

            if (-not $inDetection) { continue }

            if ($line -match "^\s*([a-zA-Z0-9_]+):\s*$") {
                $possibleBlock = $matches[1]
                if ($possibleBlock -eq "condition") { continue }
                $currentBlockName = $possibleBlock
                $blocks[$currentBlockName] = @{}
                $currentField = ""
                continue
            }

            if ($currentBlockName -and $line -match "^\s*(?:-\s+)?([a-zA-Z0-9_\|]+):\s*(.*)$") {
                $currentField = $matches[1]
                $val = $matches[2].Trim(" '`"")

                if (-not $blocks[$currentBlockName].ContainsKey($currentField)) {
                    $blocks[$currentBlockName][$currentField] = [System.Collections.Generic.List[string]]::new()
                }
                if ($val) { $blocks[$currentBlockName][$currentField].Add($val) }
                continue
            }

            if ($currentBlockName -and $currentField -and $line -match "^\s*-\s*(.+)") {
                $val = $matches[1].Trim(" '`"")
                $blocks[$currentBlockName][$currentField].Add($val)
            }
        }

        # 2. RESOLVE CONDITION WILDCARDS
        if ($condition -match "1 of them") {
            $expanded = "(" + ($blocks.Keys -join " OR ") + ")"
            $condition = $condition -replace "1 of them", $expanded
        }
        if ($condition -match "all of them") {
            $expanded = "(" + ($blocks.Keys -join " AND ") + ")"
            $condition = $condition -replace "all of them", $expanded
        }

        if ($condition -match "all of ([a-zA-Z0-9_]+)\*") {
            $prefix = $matches[1]
            $matchedKeys = $blocks.Keys | Where-Object { $_ -like "$prefix*" }
            if ($matchedKeys) {
                $expanded = "(" + ($matchedKeys -join " AND ") + ")"
                $condition = $condition -replace "all of $prefix\*", $expanded
            }
        }
        if ($condition -match "1 of ([a-zA-Z0-9_]+)\*") {
            $prefix = $matches[1]
            $matchedKeys = $blocks.Keys | Where-Object { $_ -like "$prefix*" }
            if ($matchedKeys) {
                $expanded = "(" + ($matchedKeys -join " OR ") + ")"
                $condition = $condition -replace "1 of $prefix\*", $expanded
            }
        }

        # 3. SHUNTING-YARD ALGORITHM TO POSTFIX AST
        $condition = $condition -replace '\(', ' ( ' -replace '\)', ' ) '
        $tokens = $condition -split '\s+' | Where-Object { $_ }

        $outputQueue = [System.Collections.Generic.List[string]]::new()
        $opStack = [System.Collections.Generic.List[string]]::new()
        $precedence = @{ "NOT" = 3; "AND" = 2; "OR" = 1; "(" = 0 }

        foreach ($token in $tokens) {
            $uToken = $token.ToUpper()
            if ($uToken -match "^(AND|OR|NOT)$") {
                while ($opStack.Count -gt 0 -and $precedence[$opStack[$opStack.Count - 1]] -ge $precedence[$uToken]) {
                    $outputQueue.Add($opStack[$opStack.Count - 1]); $opStack.RemoveAt($opStack.Count - 1)
                }
                $opStack.Add($uToken)
            } elseif ($token -eq "(") {
                $opStack.Add("(")
            } elseif ($token -eq ")") {
                while ($opStack.Count -gt 0 -and $opStack[$opStack.Count - 1] -ne "(") {
                    $outputQueue.Add($opStack[$opStack.Count - 1]); $opStack.RemoveAt($opStack.Count - 1)
                }
                if ($opStack.Count -gt 0) { $opStack.RemoveAt($opStack.Count - 1) }
            } else {
                $outputQueue.Add($token)
            }
        }
        while ($opStack.Count -gt 0) { $outputQueue.Add($opStack[$opStack.Count - 1]); $opStack.RemoveAt($opStack.Count - 1) }
        $postfixStr = $outputQueue -join ","

        # 4. SERIALIZE BLOCKS FOR C# CONSUMPTION
        $serializedBlocks = [System.Collections.Generic.List[string]]::new()
        foreach ($bName in $blocks.Keys) {
            $fields = [System.Collections.Generic.List[string]]::new()
            foreach ($fName in $blocks[$bName].Keys) {
                $cleanField = $fName -replace "\|.*", ""
                $baseMatchType = "Exact"
                if ($fName -match "(?i)\|endswith") { $baseMatchType = "EndsWith" }
                elseif ($fName -match "(?i)\|startswith") { $baseMatchType = "StartsWith" }
                elseif ($fName -match "(?i)\|contains") { $baseMatchType = "Contains" }

                $matchAll = if ($fName -match "(?i)\|all") { "true" } else { "false" }

                $parsedVals = [System.Collections.Generic.List[string]]::new()
                foreach ($val in $blocks[$bName][$fName]) {
                    $finalType = $baseMatchType
                    if ($baseMatchType -eq "Exact") {
                        # Translate Sigma asterisks into explicit C# matching logic
                        if ($val -match "^\*(.*)\*$") { $finalType = "Contains"; $val = $matches[1] }
                        elseif ($val -match "^\*(.*)$") { $finalType = "EndsWith"; $val = $matches[1] }
                        elseif ($val -match "^(.*)\*$") { $finalType = "StartsWith"; $val = $matches[1] }
                    } else {
                        # If a modifier was explicitly declared, just strip the wildcards
                        $val = $val -replace "^\*", "" -replace "\*$", ""
                    }
                    $parsedVals.Add(("{0}={1}" -f $finalType, $val))
                }

                if ($parsedVals.Count -eq 0) { continue }

                # Group by the dominant match type to satisfy the C# struct
                $grouped = $parsedVals | Group-Object { ($_ -split "=")[0] }
                foreach ($grp in $grouped) {
                    $grpType = $grp.Name
                    $grpVals = ($grp.Group | ForEach-Object { ($_ -split "=", 2)[1] }) -join "`t"
                    if ([string]::IsNullOrWhiteSpace($grpVals)) { continue }
                    $fields.Add(("{0}:{1}:{2}:{3}" -f $cleanField, $grpType, $matchAll, $grpVals))
                }
            }
            if ($fields.Count -gt 0) {
                $serializedBlocks.Add(("{0}>{1}" -f $bName, ($fields -join "^")))
            }
        }

        $blockStr = $serializedBlocks -join "~"

        if ([string]::IsNullOrWhiteSpace($blockStr) -or [string]::IsNullOrWhiteSpace($postfixStr)) { continue }

        $RuleStrings.Add(("{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f $category, $title, $id, $severity, $tags, $postfixStr, $blockStr))
        $ParsedCount++
    }

    $BuiltInCmds = @("sekurlsa::logonpasswords", "lsadump::", "privilege::debug", "Invoke-BloodHound", "procdump -ma lsass", "vssadmin delete shadows")
    foreach ($c in $BuiltInCmds) {
        $builtInId = [guid]::NewGuid().ToString()
        $RuleStrings.Add(("{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f "process_creation", "Built-in Core TI Signature", $builtInId, "high", "N/A", "b1", ("b1>CommandLine:Contains:false:" + $c)))
    }

    Write-Diag "    [+] Sigma Compilation Complete: $ParsedCount rules natively mapped to AST." "STARTUP"

    $Payload = $RuleStrings -join "[NEXT]"
    if ($Payload) { return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Payload)) } else { return "" }
}

function Compile-TtpSignaturesToBase64 {
    $TtpDir = Join-Path $ScriptDir "ttp_signatures"
    if (-not (Test-Path $TtpDir)) {
        Write-Diag "    [-] TTP Directory not found. Skipping High-Fidelity signatures." "STARTUP"
        return ""
    }

    $TtpFiles = Get-ChildItem -Path $TtpDir -Include "*.yml", "*.yaml", "*.ttp" -Recurse
    $ruleStrings = [System.Collections.Generic.List[string]]::new()
    $seenNames = @{}
    $ParsedCount = 0

    Write-Diag "    [*] Compiling high-fidelity TTP Signatures..." "STARTUP"

    function Extract-YamlField {
        param([string]$Block, [string]$Key)
        if ($Block -match "(?im)^[ \t]*$Key\s*:\s*\n((?:[ \t]*-\s*.*?\n?)+)") {
            $lines = $matches[1] -split '\r?\n'
            $items = foreach ($line in $lines) {
                if ($line -match '-\s*(.*)') { $matches[1].Trim(" `t`"\'") }
            }
            return ($items | Where-Object { $_ } | Join-String -Separator ',')
        }
        elseif ($Block -match "(?im)^[ \t]*$Key\s*:\s*`"?(.*?)`"?\s*$") {
            return $matches[1].Trim(" `t`"\'")
        }
        return ""
    }

    foreach ($file in $TtpFiles) {
        $content = Get-Content $file.FullName -Raw

        $blocks = $content -split '(?im)^-\s*ttp_signature:'

        foreach ($block in $blocks) {
            if ([string]::IsNullOrWhiteSpace($block)) { continue }

            $name = Extract-YamlField -Block $block -Key "name"
            $targetRaw = Extract-YamlField -Block $block -Key "target"
            if (-not $name -or -not $targetRaw) { continue }

            $targetList = $targetRaw -split ','

            if ($seenNames.ContainsKey($name)) {
                Write-Diag "    [DEDUP] Skipping duplicate rule: $name" "STARTUP"
                continue
            }
            $seenNames[$name] = $true

            $severity  = Extract-YamlField -Block $block -Key "severity"; if (-not $severity) { $severity = "High" }
            $tactic    = Extract-YamlField -Block $block -Key "tactic"; if (-not $tactic) { $tactic = "N/A" }
            $technique = Extract-YamlField -Block $block -Key "technique"; if (-not $technique) { $technique = "N/A" }
            $procedure = Extract-YamlField -Block $block -Key "procedure"; if (-not $procedure) { $procedure = "N/A" }
            $actor     = Extract-YamlField -Block $block -Key "actor"; if (-not $actor) { $actor = "**" }
            $type      = Extract-YamlField -Block $block -Key "type"; if (-not $type) { $type = "PROCESS_START" }
            $target    = Extract-YamlField -Block $block -Key "target"

            if (-not $target) { continue }

            $excludePath       = Extract-YamlField -Block $block -Key "exclude_path"
            $excludeTarget     = Extract-YamlField -Block $block -Key "exclude_target"
            $excludeTargetVal  = Extract-YamlField -Block $block -Key "exclude_target_value"
            $excludeActorCmd   = Extract-YamlField -Block $block -Key "exclude_actor_cmd"
            $excludeActor      = Extract-YamlField -Block $block -Key "exclude_actor"

            $category = "process_creation"
            if ($type -match "FILE") { $category = "file_event" }
            elseif ($type -match "REGISTRY") { $category = "registry_event" }
            elseif ($type -match "MODULE") { $category = "image_load" }
            elseif ($type -match "NETWORK") { $category = "network_connection" }

            $b64Trigger          = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($target))
            $b64Exclusion        = if ($excludePath)       { [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($excludePath)) } else { "" }
            $b64ExcludePath      = if ($excludePath)       { [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($excludePath)) } else { "" }
            $b64ExcludeTarget    = if ($excludeTarget)     { [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($excludeTarget)) } else { "" }
            $b64ExcludeTargetVal = if ($excludeTargetVal)  { [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($excludeTargetVal)) } else { "" }
            $b64ExcludeActorCmd  = if ($excludeActorCmd)   { [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($excludeActorCmd)) } else { "" }
            $b64ExcludeActor     = if ($excludeActor)      { [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($excludeActor)) } else { "" }

            $ruleStrings.Add("$category|$name|$severity|$tactic|$technique|$procedure|$actor|Contains|$b64Trigger|$b64Exclusion|$b64ExcludePath|$b64ExcludeTarget|$b64ExcludeTargetVal|$b64ExcludeActorCmd|$b64ExcludeActor")
            $ParsedCount++
        }
    }

    if ($ParsedCount -gt 0) {
        Write-Diag "    [+] TTP Compilation Complete: $ParsedCount custom signatures loaded." "STARTUP"
    }

    $Payload = $ruleStrings -join "[NEXT]"
    if ($Payload) {
        return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Payload))
    } else {
        return ""
    }
}

function Invoke-StagingInjection {
    $StagingDir = "$ScriptDir\sigma_staging"
    $SigmaDir = Join-Path $global:SecureStaging "sigma"

    if (-not (Test-Path $StagingDir)) {
        Write-Diag "`n[*] Staging directory '\sigma_staging' has no rules. Skipping." "STARTUP"
        Start-Sleep -Seconds 1
        return
    }

    try {
        $StagedFiles = Get-ChildItem -Path $StagingDir -Filter "*.yaml" -ErrorAction Stop
        if ($StagedFiles.Count -gt 0) {
            Write-Diag "`n[!] HOT RELOAD INITIATED: Injecting $($StagedFiles.Count) rules from staging..." "STARTUP"

            if (-not (Test-Path $SigmaDir)) { New-Item -ItemType Directory -Path $SigmaDir | Out-Null }
            Move-Item -Path "$StagingDir\*.yaml" -Destination $SigmaDir -Force -ErrorAction Stop

            $NewBase64Rules = Compile-SigmaRulesToBase64
            if (-not [string]::IsNullOrEmpty($NewBase64Rules)) {
                [DeepVisibilitySensor]::UpdateSigmaRules($NewBase64Rules)
            }
            Add-AlertMessage "HOT RELOAD SUCCESSFUL" "$([char]27)[92;40m"
            Start-Sleep -Seconds 2
        } else {
            Write-Diag "`n[*] Staging directory is empty. No rules to inject." "STARTUP"
            Start-Sleep -Seconds 1
        }
    } catch {
        Write-Diag "`n[-] HOT RELOAD FAILED: $($_.Exception.Message)" "STARTUP"
        Start-Sleep -Seconds 2
    }
}

function Initialize-SigmaEngine {
    Write-Diag "Initializing Sigma Compiler & Threat Intelligence Matrices..." "STARTUP"

    $LocalSigmaDir = Join-Path $global:SecureStaging "sigma"
    if (-not (Test-Path $LocalSigmaDir)) { New-Item -ItemType Directory -Path $LocalSigmaDir -Force | Out-Null }

    $SigmaCacheMarker = Join-Path $global:SecureStaging "sigma.cache"
    $needsSigmaDownload = $true

    if (Test-Path $SigmaCacheMarker) {
        if (((Get-Date) - (Get-Item $SigmaCacheMarker).LastWriteTime).TotalHours -lt 24) {
            $needsSigmaDownload = $false
            Write-Diag "    [*] Using cached Sigma HQ Rules (< 24h old). Skipping download." "STARTUP"
        }
    }

    if ($needsSigmaDownload) {
        $SecureStaging = "C:\ProgramData\DeepSensor\Staging"
        if (-not (Test-Path $SecureStaging)) { New-Item -ItemType Directory -Path $SecureStaging -Force | Out-Null }

        $TempZipPath = "$SecureStaging\sigma_master.zip"
        $ExtractPath = "$SecureStaging\sigma_extract"

        try {
            if ($OfflineRepoPath) {
                Write-Diag "    [*] Fetching Sigma rules from offline repository..." "STARTUP"
                Copy-Item (Join-Path $OfflineRepoPath "sigma_master.zip") -Destination $TempZipPath -Force -ErrorAction Stop
            } else {
                Write-Diag "    [*] Fetching latest Sigma rules from SigmaHQ GitHub..." "STARTUP"
                $SigmaZipUrl = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
                Invoke-WebRequest -Uri $SigmaZipUrl -OutFile $TempZipPath -UseBasicParsing -ErrorAction Stop
            }
            Expand-Archive -Path $TempZipPath -DestinationPath $ExtractPath -Force -ErrorAction Stop

            $RuleCategories = @(
                "process_creation", "file_event", "registry_event", "wmi_event", "pipe_created",
                "ps_module", "ps_script", "ps_classic_start", "ps_classic_provider",
                "driver_load", "image_load", "network_connection", "dns", "firewall",
                "webserver", "sysmon", "powershell", "security", "application",
                "threat_hunting", "emerging_threats"
            )

            foreach ($cat in $RuleCategories) {
                $RulesPath = Join-Path $ExtractPath "sigma-master\rules\windows\$cat\*"
                if (Test-Path (Split-Path $RulesPath)) {
                    Copy-Item -Path $RulesPath -Destination $LocalSigmaDir -Recurse -Force
                }
            }
            New-Item -Path $SigmaCacheMarker -ItemType File -Force | Out-Null
            Write-Diag "    [+] Successfully updated local Sigma repository with Advanced Detection vectors." "STARTUP"
        } catch {
            Write-Diag "    [-] GitHub pull failed (Network/Firewall). Proceeding with local cache." "STARTUP"
        } finally {
            if (Test-Path $TempZipPath) { Remove-Item $TempZipPath -Force -ErrorAction SilentlyContinue }
            if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # 1. Compile the local YAML files using the new consolidated fast/slow path parser
    $Base64Sigma = Compile-SigmaRulesToBase64
    $Base64TTP   = Compile-TtpSignaturesToBase64

    # 2. Sync LOLDrivers (BYOVD) Threat Intel
    $TiDriverSignatures = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $OfflineDrivers = @("capcom.sys", "iqvw64.sys", "RTCore64.sys", "gdrv.sys", "AsrDrv.sys", "procexp.sys")
    foreach ($d in $OfflineDrivers) { [void]$TiDriverSignatures.Add($d) }

    $LolDriversCache = Join-Path $global:SecureStaging "loldrivers.json"
    $needsDriverDownload = $true
    if (Test-Path $LolDriversCache) {
        if (((Get-Date) - (Get-Item $LolDriversCache).LastWriteTime).TotalHours -lt 24) { $needsDriverDownload = $false }
    }

    try {
        $jsonString = ""
        if ($OfflineRepoPath) {
            Write-Diag "[*] Loading LOLDrivers Threat Intel from offline repository..." "STARTUP"
            $jsonString = Get-Content (Join-Path $OfflineRepoPath "drivers.json") -Raw
        } elseif ($needsDriverDownload) {
            Write-Diag "[*] Fetching live LOLDrivers.io Threat Intel..." "STARTUP"
            $response = Invoke-WebRequest -Uri "https://www.loldrivers.io/api/drivers.json" -UseBasicParsing -ErrorAction Stop
            $jsonString = $response.Content
            $jsonString | Out-File -FilePath $LolDriversCache -Encoding UTF8 -Force
        } else {
            Write-Diag "[*] Loading cached LOLDrivers.io Threat Intel (< 24h old)..." "STARTUP"
            $jsonString = Get-Content $LolDriversCache -Raw
        }

        $jsonString = $jsonString -replace '"INIT"', '"init"'
        $apiDrivers = $jsonString | ConvertFrom-Json -AsHashtable

        $liveCount = 0
        foreach ($entry in $apiDrivers) {
            if ($entry.KnownVulnerableSamples) {
                foreach ($sample in $entry.KnownVulnerableSamples) {
                    if (-not [string]::IsNullOrWhiteSpace($sample.Filename)) {
                        if ($TiDriverSignatures.Add($sample.Filename)) {
                            $liveCount++
                        }
                    }
                }
            }
        }
        Write-Diag "[+] Integrated $liveCount live BYOVD signatures." "STARTUP"
    } catch {
        Write-Diag "[-] LOLDrivers API parsing failed: $($_.Exception.Message)" "STARTUP"
    }

    # 3. Return the compiled objects to be injected into C#
    return @{
        Base64Sigma = $Base64Sigma
        Base64TTP   = $Base64TTP
        Drivers = [string[]]($TiDriverSignatures | Select-Object)
    }
}

function Get-IniContent([string]$filePath) {
    $ini = @{}
    $currentSection = "Default"
    $ini[$currentSection] = @{}

    $lines = Get-Content $filePath -ErrorAction Stop
    $i = 0

    while ($i -lt $lines.Count) {
        $line = $lines[$i].Trim()
        $i++

        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) { continue }

        if ($line -match "^\[(.*)\]$") {
            $currentSection = $matches[1].Trim()
            if (-not $ini.ContainsKey($currentSection)) { $ini[$currentSection] = @{} }
            continue
        }

        if ($line -match "^([^=]+)=(.*)$") {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()

            while ($i -lt $lines.Count) {
                $nextLine = $lines[$i].Trim()
                if ($nextLine.StartsWith("#") -or [string]::IsNullOrWhiteSpace($nextLine)) {
                    $i++; continue
                }
                if ($nextLine -match "^[^=]+=") { break }
                if ($val -match ",$") {
                    $val += " " + $nextLine
                    $i++
                } else {
                    break
                }
            }

            $ini[$currentSection][$key] = $val
        }
    }
    return $ini
}

# ======================================================================
# 8. MAIN EXECUTION FLOW
# ======================================================================

# Execute the stability check before allocating heavy memory
Assert-ServiceStability

$ConfigPath = Join-Path $ScriptDir "DeepSensor_Config.ini"
if (-not (Test-Path $ConfigPath)) { throw "CRITICAL: Missing DeepSensor_Config.ini." }

Write-Diag "[*] Loading external process and registry exclusions..." "STARTUP"
$IniConfig = Get-IniContent $ConfigPath

if (-not $IniConfig.ContainsKey("ProcessExclusions")) { $IniConfig["ProcessExclusions"] = @{} }
if (-not $IniConfig.ContainsKey("RegistryExclusions")) { $IniConfig["RegistryExclusions"] = @{} }

$BenignADSProcs = ($IniConfig["ProcessExclusions"]["BenignADSProcs"]) -split ",\s*"
$TrustedNoise   = ($IniConfig["ProcessExclusions"]["TrustedNoise"]) -split ",\s*"
$BenignExplorerValues = ($IniConfig["RegistryExclusions"]["BenignExplorerValues"]) -split ",\s*"
$ExtraBenignLineages = if ($IniConfig["ProcessExclusions"]["ExtraBenignLineages"]) {
    $IniConfig["ProcessExclusions"]["ExtraBenignLineages"] -split ",\s*"
} else { @() }

$ExtraSuppressedRules = if ($IniConfig["ProcessExclusions"]["ExtraSuppressedRules"]) {
    $IniConfig["ProcessExclusions"]["ExtraSuppressedRules"] -split ",\s*"
} else { @() }

# Merge everything
$CombinedProcessExclusions = $BenignADSProcs + $TrustedNoise

$ValidMlBinaryPath = Initialize-Environment

$ActualDllPath = Initialize-TraceEventDependency -ExtractBase "C:\ProgramData\DeepSensor\Dependencies"
if (-not $ActualDllPath) {
    Write-Host "`n[!] CRITICAL: TraceEvent dependency missing. Cannot start ETW sensor. Exiting." -ForegroundColor Red
    Exit
}
$TraceEventDllPath = $ActualDllPath
Write-Diag "    [+] Environment Bootstrap Complete." "STARTUP"

Invoke-EnvironmentalAudit

$CompiledTI = Initialize-SigmaEngine

Write-Diag "Initializing Core Engine..." "STARTUP"

# 1. Compile C# Sensor into RAM
try {
    $DllDir = Split-Path $ActualDllPath -Parent
    $SiblingDlls = Get-ChildItem -Path $DllDir -Filter "*.dll" | Where-Object { $_.Name -notmatch "KernelTraceControl|msdia140|yara(?!\.NET)" }

    $global:DeepSensor_DepDir = $DllDir
    if (-not $global:DeepSensor_AssemblyResolveBound) {
        $global:DeepSensor_AssemblyResolveHandler = [System.ResolveEventHandler] {
            param($sender, $eventArgs)
            try {
                $simpleName = (New-Object System.Reflection.AssemblyName($eventArgs.Name)).Name
                $candidate  = Join-Path $global:DeepSensor_DepDir "$simpleName.dll"
                if (Test-Path $candidate) {
                    return [System.Reflection.Assembly]::LoadFrom($candidate)
                }
            } catch { }
            return $null
        }
        [System.AppDomain]::CurrentDomain.add_AssemblyResolve($global:DeepSensor_AssemblyResolveHandler)
        $global:DeepSensor_AssemblyResolveBound = $true
        Write-Diag "    [+] AssemblyResolve handler bound for $DllDir" "STARTUP"
    }

    foreach ($dll in $SiblingDlls) {
        try { [System.Reflection.Assembly]::LoadFrom($dll.FullName) | Out-Null } catch {}
    }

    $RefAssemblies = @(
        "mscorlib", "System.Management",
        "System", "System.Core", "System.Collections",
        "System.Collections.Concurrent", "System.Runtime", "System.Diagnostics.Process",
        "System.Linq", "System.Linq.Expressions", "System.ComponentModel", "System.ComponentModel.Primitives", "netstandard",
        "System.Threading", "System.Threading.Thread", "System.Net.Primitives"
    )

    if ($SiblingDlls) {
        foreach ($dll in $SiblingDlls) { $RefAssemblies += $dll.FullName }
    }

    if (-not ("DeepVisibilitySensor" -as [type])) {
        Add-Type -TypeDefinition (Get-Content (Join-Path $ScriptDir "OsSensor.cs") -Raw) `
                 -ReferencedAssemblies $RefAssemblies `
                 -ErrorAction Stop
    }

    Write-Diag "    [*] Bootstrapping unmanaged memory structures..." "STARTUP"

    [DeepVisibilitySensor]::ToolkitDirectory = $ScriptDir

    $FixedYaraExclusions = @(
        "C:\ProgramData\DeepSensor\Dependencies",
        "C:\Temp\DeepSensor_APT_Tests"
    )
    $ConfigYaraExclusions = if ($IniConfig.ContainsKey("YaraExclusions") -and
                                $IniConfig["YaraExclusions"]["ScanExcludePaths"]) {
        $IniConfig["YaraExclusions"]["ScanExcludePaths"] -split ",\s*" |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    } else { @() }
    foreach ($p in ($FixedYaraExclusions + $ConfigYaraExclusions)) {
        [void][DeepVisibilitySensor]::YaraScanExcludedPaths.TryAdd($p.Trim(), [byte]0)
    }
    Write-Diag ("    [+] YARA file-scan exclusions seeded: {0} path(s)." -f `
        ([DeepVisibilitySensor]::YaraScanExcludedPaths.Count)) "STARTUP"

    # ----------------------------------------------------------------------
    # Seed armed-mode response tiering from [ArmedMode] config.
    # ----------------------------------------------------------------------
    if ($IniConfig.ContainsKey("ArmedMode")) {
        $am = $IniConfig["ArmedMode"]

        if ($am["Tier1Threshold"]) { [DeepVisibilitySensor]::Tier1Threshold = [int]$am["Tier1Threshold"] }
        if ($am["Tier2Threshold"]) { [DeepVisibilitySensor]::Tier2Threshold = [int]$am["Tier2Threshold"] }
        if ($am["Tier3Threshold"]) { [DeepVisibilitySensor]::Tier3Threshold = [int]$am["Tier3Threshold"] }

        if ($am["TrustBenignDelta"])         { [DeepVisibilitySensor]::TrustBenignDelta         = [int]$am["TrustBenignDelta"] }
        if ($am["TrustTrustedDelta"])        { [DeepVisibilitySensor]::TrustTrustedDelta        = [int]$am["TrustTrustedDelta"] }
        if ($am["TrustUnknownDelta"])        { [DeepVisibilitySensor]::TrustUnknownDelta        = [int]$am["TrustUnknownDelta"] }
        if ($am["TrustHostileDelta"])        { [DeepVisibilitySensor]::TrustHostileDelta        = [int]$am["TrustHostileDelta"] }
        if ($am["LineageBenignDelta"])       { [DeepVisibilitySensor]::LineageBenignDelta       = [int]$am["LineageBenignDelta"] }
        if ($am["YaraHitDelta"])             { [DeepVisibilitySensor]::YaraHitDelta             = [int]$am["YaraHitDelta"] }
        if ($am["RepeatActorPerAlertDelta"]) { [DeepVisibilitySensor]::RepeatActorPerAlertDelta = [int]$am["RepeatActorPerAlertDelta"] }
        if ($am["MaxRepeatAlertsConsidered"]){ [DeepVisibilitySensor]::MaxRepeatAlertsConsidered = [int]$am["MaxRepeatAlertsConsidered"] }

        # Severity weights map: "critical=100, high=70, medium=40, low=15, informational=0"
        if ($am["SeverityWeights"]) {
            foreach ($pair in ($am["SeverityWeights"] -split ",\s*")) {
                $kv = $pair -split "="
                if ($kv.Count -eq 2 -and $kv[1] -match '^-?\d+$') {
                    [void][DeepVisibilitySensor]::SeverityWeights.TryAdd($kv[0].Trim(), [int]$kv[1].Trim())
                }
            }
        }
    }

    if ($IniConfig.ContainsKey("ProcessExclusions")) {
        $pe = $IniConfig["ProcessExclusions"]
        foreach ($p in (($pe["BenignADSProcs"] -split ",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            [void][DeepVisibilitySensor]::ProcessTrustClass.TryAdd($p, 3)
        }
        foreach ($p in (($pe["TrustedNoise"] -split ",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            [void][DeepVisibilitySensor]::ProcessTrustClass.TryAdd($p, 2)
        }
        foreach ($p in (($pe["CriticalSystemProcesses"] -split ",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            [void][DeepVisibilitySensor]::CriticalSystemProcesses.TryAdd($p, [byte]0)
        }
        foreach ($p in (($pe["JitRuntimeProcesses"] -split ",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            [void][DeepVisibilitySensor]::JitRuntimeProcesses.TryAdd($p, [byte]0)
        }
    }

    Write-Diag ("    [+] Armed-mode tiering: T1={0} T2={1} T3={2}, {3} trust class(es), {4} lineage(s), {5} severity weight(s)." -f `
        ([DeepVisibilitySensor]::Tier1Threshold), `
        ([DeepVisibilitySensor]::Tier2Threshold), `
        ([DeepVisibilitySensor]::Tier3Threshold), `
        ([DeepVisibilitySensor]::ProcessTrustClass.Count), `
        ([DeepVisibilitySensor]::BenignLineages.Count), `
        ([DeepVisibilitySensor]::SeverityWeights.Count)) "STARTUP"
    Write-Diag ("    [+] Anti-BSOD lists: {0} critical system process(es), {1} JIT runtime(s)." -f `
        ([DeepVisibilitySensor]::CriticalSystemProcesses.Count), `
        ([DeepVisibilitySensor]::JitRuntimeProcesses.Count)) "STARTUP"

    # Map the DLL path for the C# DllImport dynamically
    $SecureBinDir = Split-Path $ValidMlBinaryPath -Parent
    [DeepVisibilitySensor]::SetLibraryPath($SecureBinDir)

    # Inject dynamic Engine tunings from INI
    if ($IniConfig.ContainsKey("ENGINE") -and $null -ne $IniConfig["ENGINE"]["MaxSigmaQueueSize"]) {
        [DeepVisibilitySensor]::MaxSigmaQueueSize = [int]$IniConfig["ENGINE"]["MaxSigmaQueueSize"]
    }

    # Initialize the C# Engine with the 5 required core parameters
    [DeepVisibilitySensor]::Initialize(
        $ActualDllPath,
        $PID,
        $CompiledTI.Drivers,
        $BenignExplorerValues,
        $CombinedProcessExclusions
    )

    [DeepVisibilitySensor]::HostComputerName = $env:COMPUTERNAME
    [DeepVisibilitySensor]::HostIP           = $IpAddress
    [DeepVisibilitySensor]::HostOS           = $OsContext
    [DeepVisibilitySensor]::SensorUser       = $userStr

    Write-Diag "[ENRICHMENT] Host metadata injected - IP: $IpAddress | OS: $OsContext | User: $userStr" "STARTUP"

    foreach ($lineage in $ExtraBenignLineages) {
        if (-not [string]::IsNullOrWhiteSpace($lineage)) {
            [DeepVisibilitySensor]::AddBenignLineage($lineage.Trim())
        }
    }

    if ($ExtraSuppressedRules.Count -gt 0) {
        [DeepVisibilitySensor]::SuppressRulesFromConfig($ExtraSuppressedRules)
        Write-Diag "    [+] Applied $($ExtraSuppressedRules.Count) extra rule suppressions from config.ini" "STARTUP"
    }

    # Inject the startup Sigma JSON Matrix
    if (-not [string]::IsNullOrEmpty($CompiledTI.Base64Sigma)) {
        [DeepVisibilitySensor]::UpdateSigmaRules($CompiledTI.Base64Sigma)
    } else {
        Write-Diag "    [!] Warning: No valid Sigma rules parsed on startup." "STARTUP"
        $EmptyJson = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("[]"))
        [DeepVisibilitySensor]::UpdateSigmaRules($EmptyJson)
    }

    # Inject High-Fidelity TTP Matrix into isolated C# memory
    if (-not [string]::IsNullOrEmpty($CompiledTI.Base64TTP)) {
        [DeepVisibilitySensor]::UpdateTtpRules($CompiledTI.Base64TTP)
    }

    Sync-YaraIntelligence
    $YaraRulesPath = if ($OfflineRepoPath) { Join-Path $OfflineRepoPath "yara_rules" } else { Join-Path $global:SecureStaging "yara_rules" }
    [DeepVisibilitySensor]::IsArmed = $ArmedMode.IsPresent

    [DeepVisibilitySensor]::StartUserResolverWorker()
    Write-Diag "    [*] User resolver worker started (deferred WMI off ETW thread)." "STARTUP"

    if ($ArmedMode.IsPresent) {
        Write-Diag "    [*] Armed Mode Active: Compiling YARA matrices and starting alert-driven scanner..." "STARTUP"
        [DeepVisibilitySensor]::InitializeYaraMatrices($YaraRulesPath)
        [DeepVisibilitySensor]::StartYaraWorkerAsync()
    } else {
        Write-Diag "    [*] Passive Mode: YARA matrices not compiled, worker not started." "STARTUP"
    }

    # === APPLY MEMORY HARDENING IF ARMED ===
    if ($ArmedMode) {
        Write-Diag "    [*] Armed Mode Detected: Applying Process Mitigations (Anti-Injection)..." "STARTUP"
        try { [DeepVisibilitySensor+SensorSelfDefense]::LockProcessMemory() } catch {}
    }
} catch {
    Write-Diag "CRITICAL: Engine Compilation Failed. Check OsSensor.cs syntax." "ERROR"
    Write-Diag "Error Detail: $($_.Exception.Message)" "ERROR"
    throw $_
}

Protect-SensorEnvironment

# ==============================================================================
Write-Diag "Initiating 20-second JIT compilation and RAM stabilization phase..." "STARTUP"
Write-Diag "    [*] Initializing Math Engine and pre-compiling native FFI pointers..." "STARTUP"
Write-Host "[*] Stabilizing memory footprint (20-second cooldown)..." -ForegroundColor Cyan

$ESC = [char]27
$cGreen     = "$ESC[38;2;57;255;20m"
$cDarkGreen = "$ESC[38;2;15;90;10m"
$cReset     = "$ESC[0m"

$cursor = "█"

foreach ($char in "Call trans opt: received. 2-19-98 13:24:18 REC:Loc".ToCharArray()) {
    Write-Host "$cGreen$char" -NoNewline
    Write-Host "$cDarkGreen$cursor" -NoNewline
    Start-Sleep -Milliseconds 60
    Write-Host "`b `b" -NoNewline
}
Write-Host ""
Start-Sleep -Milliseconds 1200

foreach ($char in "Trace program: running".ToCharArray()) {
    Write-Host "$cGreen$char" -NoNewline
    Write-Host "$cDarkGreen$cursor" -NoNewline
    Start-Sleep -Milliseconds 60
    Write-Host "`b `b" -NoNewline
}
Write-Host "`n"
Start-Sleep -Milliseconds 2400

[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

$matrixStart = Get-Date
$width = [Console]::WindowWidth - 2
$floorY = 35
$startY = [Console]::CursorTop + 1

if ($startY -ge $floorY - 5) { $startY = 15 }

$columns = @(0) * $width
Write-Host "$ESC[?25l" -NoNewline

while (((Get-Date) - $matrixStart).TotalSeconds -lt 20) {
    for ($i = 0; $i -lt $width; $i++) {
        if ($columns[$i] -eq 0 -and (Get-Random -Maximum 100) -gt 97) {
            $columns[$i] = 1
        }

        if ($columns[$i] -gt 0) {
            $y = $startY + $columns[$i]

            if ($y -lt $floorY) {
                [Console]::SetCursorPosition($i, $y)
                Write-Host "$cGreen$([char](Get-Random -Minimum 33 -Maximum 126))" -NoNewline

                if ($y -gt $startY + 1) {
                    [Console]::SetCursorPosition($i, $y - 1)
                    Write-Host "$cDarkGreen$([char](Get-Random -Minimum 33 -Maximum 126))" -NoNewline
                }

                if ($y -gt $startY + 6) {
                    [Console]::SetCursorPosition($i, $y - 6)
                    Write-Host " " -NoNewline
                }
                $columns[$i]++
            } else {
                for ($t = 0; $t -lt 7; $t++) {
                    $tailY = $y - $t
                    if ($tailY -ge $startY -and $tailY -lt $floorY) {
                        [Console]::SetCursorPosition($i, $tailY)
                        Write-Host " " -NoNewline
                    }
                }
                $columns[$i] = 0
            }
        }
    }
    Start-Sleep -Milliseconds 40
}

# --- CLEANUP VIEWPORT ---
for ($y = 0; $y -lt 36; $y++) {
    [Console]::SetCursorPosition(0, $y)
    Write-Host (" " * $width) -NoNewline
}

Write-Host "$ESC[?25h$cReset" -NoNewline
[Console]::SetCursorPosition(0, 0)

Write-Diag "Stabilization complete. Memory optimized. Transitioning to HUD..." "STARTUP"
# ==============================================================================

if ($Background) {
    $ESC = [char]27
    $cNeonGreen = "$ESC[38;2;57;255;20m"
    $cDarkGray  = "$ESC[38;2;40;40;40m"
    $cReset     = "$ESC[0m"

    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host " [!] INITIALIZATION COMPLETE - TRANSITIONING TO HEADLESS " -ForegroundColor Cyan
    Write-Host "================================================================`n" -ForegroundColor Cyan

    Write-Host " [*] LOG FILE LOCATIONS:" -ForegroundColor Yellow
    Write-Host "     - Telemetry & Alerts:  C:\ProgramData\DeepSensor\Data\"
    Write-Host "     - Engine Diagnostics:  C:\ProgramData\DeepSensor\Logs\DeepSensor_Diagnostic.log`n"

    Write-Host " [*] HOW TO GRACEFULLY TERMINATE THIS SENSOR:" -ForegroundColor Red
    Write-Host "     This runs headlessly. DO NOT use Task Manager to terminate it."
    Write-Host "     To safely flush the database and detach the kernel, run this command from any prompt:`n"
    Write-Host "     New-Item -Path `"$global:TerminateSwitchPath`" -ItemType File -Force`n"

    Write-Host " [*] Detaching console window in:`n" -ForegroundColor Gray

    $totalSeconds = 60
    $barWidth = 60
    $cursorTop = [Console]::CursorTop
    $cursorLeft = 0

    for ($i = $totalSeconds; $i -gt 0; $i--) {
        [Console]::SetCursorPosition($cursorLeft, $cursorTop)

        $progress = $totalSeconds - $i
        $filledBlocks = [math]::Floor(($progress / $totalSeconds) * $barWidth)
        $emptyBlocks = $barWidth - $filledBlocks

        $filledString = "█" * $filledBlocks
        $emptyString  = "█" * $emptyBlocks

        Write-Host "     [" -NoNewline -ForegroundColor Gray
        Write-Host "$cNeonGreen$filledString$cReset$cDarkGray$emptyString$cReset" -NoNewline -BackgroundColor Black
        Write-Host "] " -NoNewline -ForegroundColor Gray
        Write-Host "$($i.ToString().PadLeft(2)) sec remaining...  " -NoNewline -ForegroundColor Cyan

        Start-Sleep -Seconds 1
    }

    [Console]::SetCursorPosition($cursorLeft, $cursorTop)
    $fullString = "█" * $barWidth
    Write-Host "     [" -NoNewline -ForegroundColor Gray
    Write-Host "$cNeonGreen$fullString$cReset" -NoNewline -BackgroundColor Black
    Write-Host "] " -NoNewline -ForegroundColor Gray
    Write-Host "00 sec remaining...   " -ForegroundColor Cyan

    Write-Host "`n`n[*] Vanishing... Deep Sensor v2 is now active in the background." -ForegroundColor Green
    Start-Sleep -Seconds 1

    $hwnd = [ConsoleInterop]::GetConsoleWindow()
    [ConsoleInterop]::ShowWindow($hwnd, 0) # 0 = SW_HIDE
} else {
    # Standard Interactive Mode
    Start-Sleep -Seconds 3
    Clear-Host
}

$startupRef = $null
while ([DeepVisibilitySensor]::EventQueue.TryDequeue([ref]$startupRef)) {
    $startupEvt = try { $startupRef | ConvertFrom-Json } catch { $null }
    if ($null -ne $startupEvt -and $startupEvt.Provider -eq "DiagLog") {
        Write-Diag $startupEvt.Message "ENGINE"
    }
}

Write-Diag "Binding Kernel ETW Trace Session..." "INFO"
[DeepVisibilitySensor]::StartSession()
Start-Sleep -Seconds 1

$SensorBlinded = $false
$LastPolicySync = Get-Date
$lastLightGC = Get-Date
$lastUebaCleanup = Get-Date

if (-not $Background) {
    Draw-Dashboard -Events 0 -MlEvals 0 -Alerts 0 -EtwHealth "ONLINE" -MlHealth "Native DLL"
    Draw-AlertWindow
    Draw-StartupWindow
    Start-DeepSensorHUD -Background $false -EvtPath $LogPath -UbaPath $UebaLogPath
} else {
    Start-DeepSensorHUD -Background $true -EvtPath $LogPath -UbaPath $UebaLogPath
}

# ====================== MAIN ORCHESTRATOR LOOP ======================
try {
    try { [console]::TreatControlCAsInput = $true } catch {}

    if (-not $Background) {
        Write-Diag "[+] Deep Visibility Sensor is monitoring the situation." "INFO"
        Write-Diag "    [*] Press 'Ctrl+C' or 'Q' to gracefully terminate the sensor." "STARTUP"
    }

    $dashboardDirty = $true
    $totalEvents = 0
    $totalAlerts = 0
    $eventCount = 0
    $LastHeartbeat = Get-Date
    $LastEventReceived = Get-Date
    $LastHeartbeatWrite = Get-Date

    while ($true) {
        $now = Get-Date

        # === SHUTDOWN & INTERACTION LOGIC ===

        if (Test-Path $global:TerminateSwitchPath) {
            Write-Diag "[*] Headless shutdown signal detected. Initiating graceful exit..." "INFO"
            if (-not $Background) { Write-Host "`n[!] Shutdown signal received..." -ForegroundColor Yellow }

            Remove-Item -Path $global:TerminateSwitchPath -Force -ErrorAction SilentlyContinue

            if (Get-Service -Name "DeepSensorService" -ErrorAction Ignore) {
                Set-Service -Name "DeepSensorService" -StartupType Disabled -ErrorAction Ignore
            }
            break
        }

        if (-not $Background -and [console]::KeyAvailable) {
            $keyInput = [console]::ReadKey($true)

            if ($keyInput.Key -eq 'Q' -or ($keyInput.Key -eq 'C' -and $keyInput.Modifiers -match 'Control')) {
                Write-Host "`n[!] Graceful shutdown initiated by user..." -ForegroundColor Yellow
                break
            }
            if ($keyInput.KeyChar -eq 'i' -or $keyInput.KeyChar -eq 'I') { Invoke-StagingInjection }
            if ($keyInput.KeyChar -eq 'r' -or $keyInput.KeyChar -eq 'R') { Invoke-DefenseRollback }
        }

        if (($now - $LastPolicySync).TotalMinutes -ge 60) {
            $LastPolicySync = $now
            $syncStatus = "POLICY SYNC COMPLETE"
            $syncColor  = $cGreen

            try {
                Unlock-PolicySyncPaths

                $EngineData = Initialize-SigmaEngine

                if (-not [string]::IsNullOrEmpty($EngineData.Base64Sigma)) {
                    [DeepVisibilitySensor]::UpdateSigmaRules($EngineData.Base64Sigma)
                } else {
                    Write-Diag "    [!] Policy sync produced empty Sigma corpus; retaining previously-loaded rule matrix." "STARTUP"
                    $syncStatus = "POLICY SYNC: EMPTY CORPUS, RETAINED PRIOR RULES"
                    $syncColor  = $cYellow
                }

                if ($null -ne $EngineData -and $null -ne $EngineData.Drivers) {
                    [DeepVisibilitySensor]::UpdateThreatIntel($EngineData.Drivers)
                }
            }
            catch {
                Write-Diag "    [-] Policy sync error: $($_.Exception.Message). Prior rules retained." "STARTUP"
                $syncStatus = "POLICY SYNC FAILED -- PRIOR RULES RETAINED"
                $syncColor  = $cRed
            }
            finally {
                Protect-SensorEnvironment
            }

            Add-AlertMessage $syncStatus $syncColor
        }

        $maxDequeue = 500
        $jsonStr = ""

        while (($maxDequeue-- -gt 0) -and [DeepVisibilitySensor]::EventQueue.TryDequeue([ref]$jsonStr)) {
            $LastEventReceived = $now
            $eventCount++
            try {
                if ([string]::IsNullOrWhiteSpace($jsonStr)) { continue }

                # INTERCEPT NATIVE RUST ML ALERTS FROM C# FFI
                if ($jsonStr.StartsWith("[ML_ALERTS]")) {
                    $mlPayload = $jsonStr.Substring(11).TrimStart('[').TrimEnd(']').Trim()
                    $mlResponse = try { $mlPayload | ConvertFrom-Json } catch { $null }

                    if ($mlResponse -and $mlResponse.alerts) {
                        foreach ($alert in $mlResponse.alerts) {
                            if ($alert.reason -eq "HEALTH_OK") { continue }

                            # Route raw commands through the SIEM Optimizer
                            $safeCmd = if ($alert.cmd) { Optimize-Cmdline -Cmd $alert.cmd } else { "" }

                            # --------------------------------------------------------------
                            # ENRICHED UEBA_AUDIT & ML_ANOMALY ESCALATION
                            # --------------------------------------------------------------
                            $LocalTS = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")

                            if ($null -eq $global:HistoricalSuppressions) {
                                $global:HistoricalSuppressions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                            }

                            # 1. MAIN SIEM (HOT INDEX) + HUD ESCALATION
                            if ($alert.score -ge 0.8) {
                                [DeepVisibilitySensor]::TotalAlertsGenerated++

                                $type = "ML_Anomaly"
                                if ($alert.reason -match "\[FIRST ALERT\] \[TTP\]" -or $alert.reason -match "^\[TTP\]") { $type = "TTP_Match" }
                                elseif ($alert.reason -match "\[FIRST ALERT\] \[SIGMA\]" -or $alert.reason -match "^\[SIGMA\]") { $type = "Sigma_Match" }

                                $MitreTag = if ($alert.reason -match "\[(T\d{4}(?:\.\d{3})?)\]") { $matches[1] } else { "N/A" }
                                $conf = if ($alert.score -ge 10.0) { 100 } elseif ($alert.score -ge 1.0) { 95 } else { 85 }

                                Submit-SensorAlert -Type $type `
                                    -TargetObject $alert.destination `
                                    -Image $alert.process `
                                    -Flags $alert.reason `
                                    -Confidence $conf `
                                    -PID_Id $alert.pid `
                                    -TID_Id $alert.tid `
                                    -AttckMapping $MitreTag `
                                    -CommandLine $safeCmd `
                                    -RawJson ($alert | ConvertTo-Json -Compress) `
                                    -MatchedIndicator $alert.matched_indicator

                                continue
                            }

                            # 2. SECURED BASELINE: UEBA SIEM (COLD INDEX) + HUD NOTICE
                            if ($alert.score -eq -1.0) {
                                # TTP matches must always surface -- never route to UEBA-only
                                if ($alert.reason -match "\[TTP\]") {
                                    Submit-SensorAlert -Type "TTP_Match" `
                                        -TargetObject $alert.destination `
                                        -Image $alert.process `
                                        -Flags $alert.reason `
                                        -Confidence 100 `
                                        -PID_Id $alert.pid `
                                        -TID_Id $alert.tid `
                                        -AttckMapping "N/A" `
                                        -CommandLine $safeCmd `
                                        -RawJson ($alert | ConvertTo-Json -Compress) `
                                        -MatchedIndicator $alert.matched_indicator
                                    continue
                                }

                                $suppressionKey = "PROC_$($alert.process)_$($alert.reason)"

                                if ($global:HistoricalSuppressions.Add($suppressionKey)) {
                                    Add-AlertMessage $alert.reason $cDark
                                    try { [DeepVisibilitySensor]::SuppressProcessRule($alert.process, $alert.reason) } catch {}

                                    $logObj = [ordered]@{
                                        Timestamp_Local = $LocalTS
                                        Category = "UEBA_Audit"
                                        Type = "Secured"
                                        Process = $alert.process
                                        Details = $alert.reason
                                        SignatureName = $alert.signature_name
                                        Tactic = $alert.tactic
                                        Technique = $alert.technique
                                        MatchedIndicator = $alert.matched_indicator
                                        Cmd = $safeCmd
                                        EventUser = [DeepVisibilitySensor]::SensorUser
                                        ComputerName = [DeepVisibilitySensor]::HostComputerName
                                        IP = [DeepVisibilitySensor]::HostIP
                                        OS = $OsContext
                                    }
                                    $script:uebaBatch.Add(($logObj | ConvertTo-Json -Compress))
                                }
                                continue
                            }

                            # 3. GLOBAL SUPPRESSION: UEBA SIEM (COLD INDEX) ONLY
                            if ($alert.score -eq -2.0) {
                                # TTP matches are never globally suppressed
                                if ($alert.reason -match "\[TTP\]") {
                                    Submit-SensorAlert -Type "TTP_Match" `
                                        -TargetObject $alert.destination `
                                        -Image $alert.process `
                                        -Flags $alert.reason `
                                        -Confidence 100 `
                                        -PID_Id $alert.pid `
                                        -TID_Id $alert.tid `
                                        -AttckMapping "N/A" `
                                        -CommandLine $safeCmd `
                                        -RawJson ($alert | ConvertTo-Json -Compress) `
                                        -MatchedIndicator $alert.matched_indicator
                                    continue
                                }

                                $suppressionKey = "SIGMA_$($alert.reason)"

                                if ($global:HistoricalSuppressions.Add($suppressionKey)) {
                                    try { [DeepVisibilitySensor]::SuppressSigmaRule($alert.reason) } catch {}

                                    $logObj = [ordered]@{
                                        Timestamp_Local = $LocalTS
                                        Category = "UEBA_Audit"
                                        Type = "Suppressed"
                                        Process = $alert.process
                                        Details = $alert.reason
                                        SignatureName = $alert.signature_name
                                        Tactic = $alert.tactic
                                        Technique = $alert.technique
                                        MatchedIndicator = $alert.matched_indicator
                                        Cmd = $safeCmd
                                        EventUser = [DeepVisibilitySensor]::SensorUser
                                        ComputerName = [DeepVisibilitySensor]::HostComputerName
                                        IP = [DeepVisibilitySensor]::HostIP
                                        OS = $OsContext
                                    }
                                    $script:uebaBatch.Add(($logObj | ConvertTo-Json -Compress))
                                }
                                continue
                            }

                            # 4. SILENT ROLLUP HEARTBEAT: UEBA SIEM (COLD INDEX) ONLY
                            if ($alert.score -eq -3.0) {
                                $logObj = [ordered]@{
                                    Timestamp_Local = $LocalTS
                                    Category = "UEBA_Audit"
                                    Type = "Rollup"
                                    Process = $alert.process
                                    Details = $alert.reason
                                    SignatureName = $alert.signature_name
                                    Tactic = $alert.tactic
                                    Technique = $alert.technique
                                    MatchedIndicator = $alert.matched_indicator
                                    Cmd = $safeCmd
                                    EventUser = [DeepVisibilitySensor]::SensorUser
                                    ComputerName = [DeepVisibilitySensor]::HostComputerName
                                    IP = [DeepVisibilitySensor]::HostIP
                                    OS = $OsContext
                                }
                                $script:uebaBatch.Add(($logObj | ConvertTo-Json -Compress))
                                continue
                            }

                            # 5. SILENT LEARNING AUDIT: UEBA SIEM (COLD INDEX) ONLY
                            if ($alert.score -eq -4.0) {
                                $logObj = [ordered]@{
                                    Timestamp_Local = $LocalTS
                                    Category = "UEBA_Audit"
                                    Type = "Learning"
                                    Process = $alert.process
                                    Details = $alert.reason
                                    SignatureName = $alert.signature_name
                                    Tactic = $alert.tactic
                                    Technique = $alert.technique
                                    MatchedIndicator = $alert.matched_indicator
                                    Cmd = $safeCmd
                                    EventUser = [DeepVisibilitySensor]::SensorUser
                                    ComputerName = [DeepVisibilitySensor]::HostComputerName
                                    IP = [DeepVisibilitySensor]::HostIP
                                    OS = $OsContext
                                }
                                $script:uebaBatch.Add(($logObj | ConvertTo-Json -Compress))
                                continue
                            }
                        }
                    }
                    continue
                }

                # STANDARD C# ETW ALERTS
                $evt = try { $jsonStr | ConvertFrom-Json } catch { $null }
                if ($null -eq $evt) { continue }

                if ($evt.Provider -eq "DiagLog") {
                    # Route engine diagnostics directly to the log file and HUD initialization window
                    Write-Diag $evt.Message "ENGINE"
                    continue
                }
                if ($evt.Provider -eq "HealthCheck") { $LastHeartbeat = $now; continue }
                if ($evt.Provider -eq "Error") { Add-AlertMessage "CORE ENGINE CRASH: $($evt.Message)" $cRed; continue }

                # Catch ALL native C# alerts (Sigma_Match, T1055, StaticAlert)
                if ($evt.Category -and $evt.Category -notmatch "RawEvent|UEBA") {
                    [DeepVisibilitySensor]::TotalAlertsGenerated++

                    $conf = if ($evt.Category -eq "TTP_Match" -or $evt.Type -match "SensorTampering|ProcessHollowing|PendingRename|UnbackedModule|EncodedCommand|ThreatIntel_Driver") { 100 } else { 85 }
                    $pidExtract = 0; if ($evt.Process -match "PID:(\d+)") { $pidExtract = [int]$matches[1] } else { $pidExtract = $evt.PID }

                    # Map the Mitre tag if the C# engine provided one in the Category
                    $mitre = if ($evt.Category -match "^T\d{4}") { $evt.Category } else { "N/A" }

                    # Extract the alert text depending on which C# constructor sent it
                    $alertText = if ($evt.Details) { $evt.Details } elseif ($evt.Reason) { $evt.Reason } else { "Suspicious Activity" }

                    $staticSafeCmd = if ($evt.Cmd) { Optimize-Cmdline -Cmd $evt.Cmd } else { "" }

                    Submit-SensorAlert -Type "Static_Detection" `
                        -TargetObject $evt.Type `
                        -Image $evt.Process `
                        -Flags $alertText `
                        -Confidence $conf `
                        -PID_Id $pidExtract `
                        -TID_Id $evt.TID `
                        -AttckMapping $mitre `
                        -CommandLine $staticSafeCmd `
                        -RawJson $jsonStr `
                        -MatchedIndicator $evt.MatchedIndicator
                }
            } catch {
                Write-Diag "DEQUEUE ERROR: $($_.Exception.Message)" "ERROR"
            }
        }

        # Transfer Deduplicated Alerts into the SIEM Batch Array
        foreach ($alert in $global:cycleAlerts.Values) {
            $global:dataBatch.Add($alert)
        }
        $global:cycleAlerts.Clear()

        # BATCH SIEM FORWARDING (Actionable Alerts & Active Defense)
        if ($global:dataBatch.Count -gt 0) {
            $batchPayload = ($global:dataBatch | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join "`r`n"
            Write-RotatedJsonl -FilePath $LogPath -JsonPayload $batchPayload
            $global:dataBatch.Clear()
        }

        if ($script:logBatch.Count -gt 0) {
            $logPayload = $script:logBatch -join "`r`n"
            Write-RotatedJsonl -FilePath $LogPath -JsonPayload $logPayload
            $script:logBatch.Clear()
        }

        # BATCH UEBA FORWARDING (Learning & Suppressions)
        if ($script:uebaBatch.Count -gt 0) {
            $uebaPayload = $script:uebaBatch -join "`r`n"
            Write-RotatedJsonl -FilePath $UebaLogPath -JsonPayload $uebaPayload
            $script:uebaBatch.Clear()
        }

        # === DEEP MEMORY RECLAMATION: LOH COMPACTION (every 60 seconds) ===
        if (($now - $lastLightGC).TotalSeconds -ge 60) {

            # Prevent Gatekeeper Memory Exhaustion (Cap at 50,000 tracked signatures)
            if ($null -ne $global:HistoricalAlerts) {
                if ($global:HistoricalAlerts.Count -gt 50000) {
                    Write-Diag "[MAINTENANCE] Historical Alerts matrix reached capacity. Flushing state." "INFO"
                    $global:HistoricalAlerts.Clear()
                    # Only write on flush/clear to avoid constant 60s I/O churn
                    try { $global:HistoricalAlerts | Out-File -FilePath $global:HistoricalAlertsPath -Encoding UTF8 -Force -ErrorAction Stop } catch {}
                }
            }
            if ($null -ne $global:HistoricalSuppressions -and $global:HistoricalSuppressions.Count -gt 50000) {
                Write-Diag "[MAINTENANCE] Historical Suppressions matrix reached capacity. Flushing state." "INFO"
                $global:HistoricalSuppressions.Clear()
            }

            [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = [System.Runtime.GCLargeObjectHeapCompactionMode]::CompactOnce
            [System.GC]::Collect(2, [System.GCCollectionMode]::Forced, $true, $true)
            [System.GC]::WaitForPendingFinalizers()
            $lastLightGC = $now
        }

        # ETW HEALTH CANARY & WATCHDOG EVALUATION + METRICS EMIT
        if (($now - $LastHeartbeatWrite).TotalSeconds -ge 60) {
            $LastHeartbeatWrite = $now
            $CanaryPath = Join-Path "C:\ProgramData\DeepSensor\Data" "deepsensor_canary.tmp"
            $null = New-Item -ItemType File -Path $CanaryPath -Force
            Remove-Item -Path $CanaryPath -Force -ErrorAction SilentlyContinue

            try { [DeepVisibilitySensor]::EmitMetricsLine() } catch {}
        }

        $tamperStatus = "Good"

        # 1. Did the background Watchdog flag a buffer exhaustion?
        if ($jsonStr -match "SENSOR_BLINDING_DETECTED:(\d+)") {
            $tamperStatus = "BAD"
            $droppedCount = $matches[1]
            Submit-SensorAlert -Type "Telemetry_Gap" -TargetObject "ETW_Buffer" -Image "System" -Flags "Sensor blinded due to kernel buffer exhaustion. Dropped $droppedCount events." -Confidence 100 -IsSuppressed:$false
        }

        # 2. Is the C# session still alive and responding to canaries?
        if (-not [DeepVisibilitySensor]::IsSessionHealthy() -or (($now - $LastHeartbeat).TotalSeconds -gt 120)) { $tamperStatus = "BAD" }

        # 3. Have we been starved of events?
        if (($now - $LastEventReceived).TotalMinutes -gt 3) { $tamperStatus = "BAD" }

        $currentTotalEvents = [DeepVisibilitySensor]::TotalEventsParsed
        $currentTotalAlerts = [DeepVisibilitySensor]::TotalAlertsGenerated

        # Query the C# memory depths
        $currentMlQueue = [DeepVisibilitySensor]::GetMlQueueDepth()
        $currentPsQueue = [DeepVisibilitySensor]::GetPowerShellQueueDepth()

        # Only burn CPU to redraw the HUD if we are not in background mode
        if (-not $Background -and ($dashboardDirty -or $currentTotalEvents -ne $totalEvents -or $currentTotalAlerts -ne $totalAlerts -or $tamperStatus -eq "BAD" -or ($currentTotalEvents % 10 -eq 0))) {
            $totalEvents = $currentTotalEvents
            $totalAlerts = $currentTotalAlerts

            Draw-Dashboard -Events $totalEvents -MlEvals ([DeepVisibilitySensor]::TotalMlEvals) -Alerts $totalAlerts -EtwHealth $tamperStatus -MlQueue $currentMlQueue -PsQueue $currentPsQueue
            $dashboardDirty = $false
            $eventCount = 0
        }

        if ($tamperStatus -eq "BAD") {
            $script:RecoveryAttempts = if ($null -ne $script:RecoveryAttempts) { $script:RecoveryAttempts + 1 } else { 1 }
            $script:RecoveryMaxAttempts = 3

            if ($script:RecoveryAttempts -gt $script:RecoveryMaxAttempts) {
                Write-Diag "AUTO-RECOVERY ABANDONED after $script:RecoveryMaxAttempts consecutive failures. Underlying cause likely permanent (kernel ETW disabled, GPO change, driver conflict). Exiting orchestrator -- restart sensor manually after addressing host state." "CRITICAL"
                $global:FatalCrashMsg = "Auto-recovery exhausted ($script:RecoveryMaxAttempts attempts)."
                break
            }

            Write-Diag "SENSOR BLINDED: ETW thread unresponsive. Auto-recovery attempt $script:RecoveryAttempts of $script:RecoveryMaxAttempts." "ERROR"
            Write-Diag "Auto-Recovery: Tearing down dead ETW session..." "INFO"
            try { [DeepVisibilitySensor]::StopSession() } catch {}

            Start-Sleep -Seconds 2

            Write-Diag "Auto-Recovery: Re-building memory pointers & initializing native ETW session..." "INFO"
            $recoveryOk = $false
            try {
                [DeepVisibilitySensor]::StartSession()
                Start-Sleep -Seconds 1
                $recoveryOk = $true
            } catch {
                Write-Diag "Auto-Recovery FAILED: $($_.Exception.Message)" "CRITICAL"
            }

            if ($recoveryOk) {
                $script:RecoveryAttempts = 0
            }

            $LastHeartbeat = Get-Date
            $LastEventReceived = Get-Date
            $LastHeartbeatWrite = Get-Date
            $tamperStatus = "Good"
        }

        if ($maxDequeue -gt 0) {
            Start-Sleep -Milliseconds 250
        }
    }
} catch {
    $crashMsg = $_.Exception.Message
    Write-Host "`n[!] ORCHESTRATOR FATAL CRASH: $crashMsg" -ForegroundColor Red
    "[$((Get-Date).ToString('HH:mm:ss'))] ORCHESTRATOR FATAL CRASH: $crashMsg" | Out-File -FilePath "$env:ProgramData\DeepSensor\Logs\DeepSensor_Diagnostic.log" -Append

    $global:FatalCrashMsg = $crashMsg
} finally {
    Clear-Host

    if ($global:FatalCrashMsg) {
        Write-Host "`n[!] ORCHESTRATOR CRASHED: $($global:FatalCrashMsg)`n" -ForegroundColor Red
    }

    Write-Host "[*] Initiating Graceful Shutdown..." -ForegroundColor Cyan
    try { [console]::TreatControlCAsInput = $false } catch {}

    Write-Host "    [*] Terminating Web HUD Runspace..." -ForegroundColor Gray
    try {
        if ($global:HudRunspace) {
            $global:HudRunspace.BeginStop($null, $null) | Out-Null
            $global:HudRunspace.Dispose()
        }
    } catch { Write-Host "        [-] HUD Teardown Error: $($_.Exception.Message)" -ForegroundColor DarkRed }

    Write-Host "    [*] Finalizing Kernel Telemetry & ML Database..." -ForegroundColor Gray
    try {
        if ($null -ne $global:dataBatch -and $global:dataBatch.Count -gt 0 -and $null -ne $LogPath) {
            $batchOutput = ($global:dataBatch | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join "`r`n"
            try { [System.IO.File]::AppendAllText($LogPath, $batchOutput + "`r`n") } catch { }
        }

        [DeepVisibilitySensor]::StopSession()
        [DeepVisibilitySensor]::TeardownEngine()
    } catch {
        Write-Diag "StopSession error (non-fatal): $($_.Exception.Message)" "WARN"
    }
    Write-Diag "C# TraceEvent Session halted and Rust FFI pointer freed." "INFO"

    if ($global:DeepSensor_AssemblyResolveBound) {
        try {
            [System.AppDomain]::CurrentDomain.remove_AssemblyResolve($global:DeepSensor_AssemblyResolveHandler)
            $global:DeepSensor_AssemblyResolveBound = $false
            Write-Diag "AssemblyResolve handler unbound." "INFO"
        } catch { }
    }

    Write-Host "    [*] Unlocking project directory permissions..." -ForegroundColor Gray
    try {
        $PathsToUnlock = @(
            $ScriptDir,
            "C:\ProgramData\DeepSensor\Staging",
            "C:\ProgramData\DeepSensor\Dependencies"
        )

        foreach ($path in $PathsToUnlock) {
            if ($null -ne $path -and (Test-Path $path)) {
                $null = icacls $path /reset /T /C /Q *>$null
            }
        }
    } catch { Write-Host "        [-] DACL Reset Error: $($_.Exception.Message)" -ForegroundColor DarkRed }

    Write-Host "    [*] Cleaning up centralized library dependencies..." -ForegroundColor Gray
    try {
        $StagingPath = "C:\ProgramData\DeepSensor\Staging"
        if ($null -ne $StagingPath -and (Test-Path $StagingPath)) {
            Remove-Item -Path "$StagingPath\*.zip" -Force -ErrorAction Stop
        }
    } catch { Write-Host "        [-] File Cleanup Error: $($_.Exception.Message)" -ForegroundColor DarkRed }

    Write-Host "`n[+] Sensor Teardown Complete. Log artifacts preserved in C:\ProgramData\DeepSensor\Logs & \Data." -ForegroundColor Green

    if (-not $Background) {
        $RealErrors = $Error | Where-Object {
            $_.Exception.Message -notmatch "DeepSensorService|Cannot find path"
        }

        if ($RealErrors.Count -gt 0 -and -not $global:FatalCrashMsg) {
            Write-Host "`n[!] UNHANDLED PIPELINE ERROR DETECTED:`n$($RealErrors[0].Exception.Message)" -ForegroundColor Red
        }

        Write-Host "`n[!] Teardown complete or fatal error encountered." -ForegroundColor Yellow
        Write-Host "Press any key to close the console..." -ForegroundColor Yellow

        try {
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        } catch {
            $null = Read-Host
        }
    }
    [System.Environment]::Exit(0)
}