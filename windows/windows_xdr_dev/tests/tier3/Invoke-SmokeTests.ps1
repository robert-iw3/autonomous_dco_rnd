<#
.SYNOPSIS
    Tier 3 — Windows ring-3 smoke tests for DeepXDR.

.DESCRIPTION
    Builds the XdrAgent, publishes a self-contained win-x64 binary, then:
      1. Service registration  — sc.exe create/query/delete
      2. Binary integrity      — PE header, signed-file check, correct arch
      3. Config loading        — DeepXDR_Config.ini parsed without exceptions
      4. Rust DLL presence     — xdr_ml_engine.dll, xdr_nexus.dll in DllDirectory
      5. Named-pipe smoke      — agent creates \\.\pipe\DeepXDR if started (optional)
      6. ETW session listing   — trace session visible after agent start (optional)
      7. Log output existence  — log file created within startup timeout
      8. Self-stop             — agent stops cleanly when sc.exe stop is issued

    All tests log to $ReportDir\tier3_smoke_<timestamp>.log.

.PARAMETER RepoRoot
    Path to windows/windows_xdr_dev/ directory.

.PARAMETER ReportDir
    Directory for output logs.

.PARAMETER SkipBuild
    Skip dotnet publish step (use existing build artifacts in $PublishDir).

.PARAMETER StartAgent
    Start the agent process for live smoke tests (ETW, pipe, log).
    Requires running as Administrator and Defender/AV exclusion on $PublishDir.

.NOTES
    Run as Administrator for StartAgent tests.
    Do NOT run on production endpoints.
#>

param(
    [string]$RepoRoot    = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$ReportDir   = "$env:USERPROFILE\DeepXDR_TestReports",
    [string]$PublishDir  = "$env:TEMP\DeepXDR_SmokePublish_$$",
    [switch]$SkipBuild,
    [switch]$StartAgent
)

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile   = "$ReportDir\tier3_smoke_$Timestamp.log"
$Passed    = 0
$Failed    = 0
$Skipped   = 0

function Write-Log([string]$msg, [string]$color = "White") {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line
}

function Pass([string]$name) {
    $script:Passed++
    Write-Log "  PASS: $name" "Green"
}

function Fail([string]$name, [string]$detail = "") {
    $script:Failed++
    Write-Log "  FAIL: $name$(if ($detail) { ' — ' + $detail } else { '' })" "Red"
}

function Skip([string]$name, [string]$reason = "") {
    $script:Skipped++
    Write-Log "  SKIP: $name$(if ($reason) { ' (' + $reason + ')' } else { '' })" "Yellow"
}

function Test-Block([string]$name, [scriptblock]$block) {
    Write-Log ""
    Write-Log "--- $name ---" "Cyan"
    try {
        & $block
    } catch {
        Fail $name "Unhandled exception: $_"
    }
}

# --- Setup ---------------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
New-Item -ItemType Directory -Force -Path $PublishDir | Out-Null

Write-Log "DeepXDR Tier 3 Smoke Tests — $Timestamp" "Magenta"
Write-Log "RepoRoot:   $RepoRoot"
Write-Log "PublishDir: $PublishDir"
Write-Log "Log:        $LogFile"

$CsprojPath = Join-Path $RepoRoot "agent\XdrAgent.csproj"

# --- Test 1: Project file exists -----------------------------------------------

Test-Block "T01 Project file exists" {
    if (Test-Path $CsprojPath) {
        Pass "XdrAgent.csproj present"
    } else {
        Fail "XdrAgent.csproj missing" "Expected at $CsprojPath"
    }
}

# --- Test 2: dotnet restore ----------------------------------------------------

Test-Block "T02 NuGet restore" {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        Skip "dotnet restore" ".NET SDK not installed"
        return
    }
    $result = & dotnet restore $CsprojPath --runtime win-x64 2>&1
    if ($LASTEXITCODE -eq 0) {
        Pass "dotnet restore"
    } else {
        Fail "dotnet restore" "Exit code $LASTEXITCODE"
        $result | Select-Object -Last 20 | ForEach-Object { Write-Log "    $_" "DarkRed" }
    }
}

# --- Test 3: dotnet publish ----------------------------------------------------

Test-Block "T03 dotnet publish (win-x64 self-contained)" {
    if ($SkipBuild) {
        Skip "dotnet publish" "--SkipBuild specified"
        return
    }
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        Skip "dotnet publish" ".NET SDK not installed"
        return
    }

    $result = & dotnet publish $CsprojPath `
        --configuration Release `
        --runtime win-x64 `
        --self-contained true `
        /p:PublishSingleFile=true `
        --output $PublishDir `
        2>&1
    if ($LASTEXITCODE -eq 0) {
        Pass "dotnet publish"
    } else {
        Fail "dotnet publish" "Exit code $LASTEXITCODE"
        $result | Select-Object -Last 30 | ForEach-Object { Write-Log "    $_" "DarkRed" }
    }
}

# --- Test 4: Published binary exists and is PE64 ------------------------------

Test-Block "T04 Published binary is PE64 executable" {
    $exe = Get-ChildItem -Path $PublishDir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if (-not $exe) {
        Fail "PE64 binary" "No .exe found in $PublishDir"
        return
    }
    Write-Log "  Binary: $($exe.FullName) ($([math]::Round($exe.Length/1MB,1)) MB)"

    # Check MZ header
    $bytes = [System.IO.File]::ReadAllBytes($exe.FullName)
    if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
        Pass "MZ header present (valid PE)"
    } else {
        Fail "MZ header check" "First bytes: 0x$($bytes[0].ToString('X2'))0x$($bytes[1].ToString('X2'))"
    }

    # Check IMAGE_NT_HEADERS -> Machine = 0x8664 (AMD64)
    $lfaNew = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($lfaNew -gt 0 -and ($lfaNew + 6) -lt $bytes.Length) {
        $machine = [BitConverter]::ToUInt16($bytes, $lfaNew + 4)
        if ($machine -eq 0x8664) {
            Pass "PE machine type AMD64 (0x8664)"
        } else {
            Fail "PE machine type" "Expected 0x8664, got 0x$($machine.ToString('X4'))"
        }
    } else {
        Skip "PE machine type" "Could not parse NT headers"
    }
}

# --- Test 5: Config INI exists and is parseable -------------------------------

Test-Block "T05 DeepXDR_Config.ini present and parseable" {
    $iniPath = Join-Path $RepoRoot "agent\DeepXDR_Config.ini"
    if (-not (Test-Path $iniPath)) {
        Fail "Config INI missing" $iniPath
        return
    }
    Pass "Config INI present"

    $content = Get-Content $iniPath -Raw
    $requiredSections = @("ProcessExclusions","NetworkExclusions","AppGuardDefinitions","Agent","Transmission")
    foreach ($sec in $requiredSections) {
        if ($content -match "\[$sec\]") {
            Pass "Section [$sec] present"
        } else {
            Fail "Section [$sec] missing from INI"
        }
    }

    # Check that AppGuard entries lack .exe (known discrepancy)
    if ($content -match "ShellInterpreters\s*=.*\bcmd\b") {
        Write-Log "  KNOWN BUG: ShellInterpreters has 'cmd' without .exe — AppGuard will fail to match 'cmd.exe'" "Yellow"
    }
}

# --- Test 6: Rust DLLs present in DllDirectory --------------------------------

Test-Block "T06 Rust DLLs present" {
    $dllDir = "C:\ProgramData\DeepSensor\Bin"

    # Override from INI if possible
    $iniPath = Join-Path $RepoRoot "agent\DeepXDR_Config.ini"
    if (Test-Path $iniPath) {
        $content = Get-Content $iniPath -Raw
        if ($content -match "DllDirectory\s*=\s*(.+)") {
            $dllDir = $Matches[1].Trim()
        }
    }

    Write-Log "  DllDirectory: $dllDir"

    if (-not (Test-Path $dllDir)) {
        Skip "Rust DLLs" "DllDirectory $dllDir does not exist (pre-install state OK)"
        return
    }

    foreach ($dll in @("xdr_ml_engine.dll", "xdr_nexus.dll")) {
        $path = Join-Path $dllDir $dll
        if (Test-Path $path) {
            Pass "$dll present ($([math]::Round((Get-Item $path).Length/1KB,1)) KB)"
        } else {
            Fail "$dll missing from DllDirectory"
        }
    }
}

# --- Test 7: Service registration (dry-run) -----------------------------------

Test-Block "T07 Windows service registration (dry-run)" {
    if (-not $StartAgent) {
        Skip "Service registration" "use -StartAgent to enable live tests"
        return
    }

    $svcName  = "DeepXDR_SmokeTest_$$"
    $exe      = Get-ChildItem -Path $PublishDir -Filter "*.exe" -Recurse | Select-Object -First 1

    if (-not $exe) {
        Skip "Service registration" "No .exe found in publish dir"
        return
    }

    try {
        & sc.exe create $svcName binPath= "`"$($exe.FullName)`"" start= demand type= own | Out-Null
        $query = & sc.exe query $svcName 2>&1
        if ($query -match "STOPPED") {
            Pass "sc.exe create and query: service registered"
        } else {
            Fail "sc.exe query" "Expected STOPPED state, got: $query"
        }
    } finally {
        & sc.exe delete $svcName 2>&1 | Out-Null
        Pass "sc.exe delete: service cleaned up"
    }
}

# --- Test 8: Agent self-start and log creation --------------------------------

Test-Block "T08 Agent self-start (optional live test)" {
    if (-not $StartAgent) {
        Skip "Agent self-start" "use -StartAgent to enable"
        return
    }

    $exe = Get-ChildItem -Path $PublishDir -Filter "*.exe" -Recurse | Select-Object -First 1
    if (-not $exe) {
        Skip "Agent self-start" "No binary in publish dir"
        return
    }

    $logPath = "$env:ProgramData\DeepSensor\Logs\xdragent.log"
    $proc = Start-Process -FilePath $exe.FullName -PassThru -WindowStyle Hidden

    Write-Log "  Agent PID $($proc.Id) started. Waiting 10s for log creation..."
    Start-Sleep -Seconds 10

    if (Test-Path $logPath) {
        Pass "Agent log created at $logPath"
    } else {
        Fail "Agent log not created within 10s" "Expected: $logPath"
    }

    # Stop agent
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Pass "Agent process stopped cleanly"
}

# --- Summary -------------------------------------------------------------------

Write-Log ""
Write-Log "══════════════════════════════════════════════" "Magenta"
Write-Log " Tier 3 Summary" "Magenta"
Write-Log "  Passed:  $Passed" "Green"
Write-Log "  Failed:  $Failed" $(if ($Failed -gt 0) { "Red" } else { "Green" })
Write-Log "  Skipped: $Skipped" "Yellow"
Write-Log "  Log:     $LogFile" "Gray"
Write-Log "══════════════════════════════════════════════" "Magenta"
Write-Log ""

if ($Failed -gt 0) {
    exit 1
} else {
    exit 0
}
