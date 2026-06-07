<#
.SYNOPSIS
    C2 Beacon Sensor -- Rust Workspace Compiler Pipeline

.DESCRIPTION
    Compiles the C2Sensor Rust workspace into a native C-compatible DLL
    (c2sensor_ml.dll) for direct FFI integration with the C# ETW orchestrator.

    The workspace contains two crates:
      • ml_engine    -- The behavioral ML engine (cdylib → c2sensor_ml.dll)
      • transmission -- Async telemetry pusher to the sensor middleware gateway

    Pipeline:
      1. Validates MSVC Desktop C++ Workload & Windows SDK (UCRT).
      2. Validates the Rust stable toolchain (x86_64-pc-windows-msvc).
      3. Initialises vcvars64 and runs `cargo build --release --workspace`.
      4. Validates the compiled DLL, computes SHA-256, stages to project root.

.PARAMETER Clean
    When specified, runs `cargo clean` before building.

.PARAMETER SkipToolchainCheck
    Skips MSVC and Rust toolchain validation (for pre-provisioned CI images).

.NOTES
    Author : Robert Weber
    Must be run as Administrator (MSVC installer requires elevation).
#>
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$SkipToolchainCheck
)

$ErrorActionPreference = 'Stop'

# -- Paths ----------------------------------------------------------------------
$WorkingDir       = $PSScriptRoot   # Script lives in the workspace root
$BinDir           = Join-Path $WorkingDir "target\release"
$FinalBinaryName  = "c2sensor_ml.dll"
$FinalDest        = Join-Path $WorkingDir $FinalBinaryName

# -- ANSI Colors ---------------------------------------------------------------
$ESC    = [char]27
$cRed   = "$ESC[91m"
$cGreen = "$ESC[92m"
$cYellow= "$ESC[93m"
$cCyan  = "$ESC[96m"
$cGray  = "$ESC[90m"
$cBold  = "$ESC[1m"
$cReset = "$ESC[0m"

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Detail = "")
    $stamp = "[{0:HH:mm:ss}]" -f (Get-Date)
    Write-Host "$cCyan$stamp$cReset $cYellow[$Phase]$cReset $Message"
    if ($Detail) { Write-Host "           $cGray$Detail$cReset" }
}

Write-Host ""
Write-Host "$cCyan$cBold╔══════════════════════════════════════════════════════════════╗$cReset"
Write-Host "$cCyan$cBold║   C2 BEACON SENSOR -- RUST WORKSPACE COMPILER PIPELINE       ║$cReset"
Write-Host "$cCyan$cBold╚══════════════════════════════════════════════════════════════╝$cReset"
Write-Host ""

# -- Verify workspace structure ------------------------------------------------
$wsCargoToml = Join-Path $WorkingDir "Cargo.toml"
$mlEngineSrc = Join-Path $WorkingDir "ml_engine\src\lib.rs"
$txSrc       = Join-Path $WorkingDir "transmission\src\lib.rs"

if (-not (Test-Path $wsCargoToml)) {
    Write-Host "$cRed[!] CRITICAL: Workspace Cargo.toml not found at $wsCargoToml$cReset"
    Write-Host "    The build script must be run from the C2Sensor workspace root."
    Exit 1
}

foreach ($required in @($mlEngineSrc, $txSrc)) {
    if (-not (Test-Path $required)) {
        Write-Host "$cRed[!] CRITICAL: Missing source file: $required$cReset"
        Exit 1
    }
}
Write-Step "VERIFY" "Workspace structure validated" "ml_engine + transmission"

# ═══════════════════════════════════════════════════════════════════════════════
# 1.  MSVC BUILD TOOLS VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
$vsInstallPath = $null

if (-not $SkipToolchainCheck) {
    Write-Step "MSVC" "Verifying MSVC Desktop Workload & Universal C Runtime..."

    $vsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWherePath) {
        $paths = & $vsWherePath -latest -products * -property installationPath
        if ($paths) {
            $vsInstallPath = if ($paths -is [array]) { $paths[0] } else { $paths }
        }
    }

    if ([string]::IsNullOrWhiteSpace($vsInstallPath)) {
        foreach ($fp in @(
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise"
        )) {
            if (Test-Path (Join-Path $fp "VC\Auxiliary\Build\vcvars64.bat")) {
                $vsInstallPath = $fp; break
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($vsInstallPath) -and (Test-Path $vsInstallPath)) {
        Write-Host "  $cGreen[+]$cReset Visual Studio environment: $vsInstallPath"
    } else {
        Write-Host "`n$cRed[!] CRITICAL: MSVC Build Tools not found. Install the C++ Desktop Workload.$cReset"
        Exit 1
    }
} else {
    Write-Step "MSVC" "Skipped (SkipToolchainCheck)"
    foreach ($fp in @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise"
    )) {
        if (Test-Path (Join-Path $fp "VC\Auxiliary\Build\vcvars64.bat")) {
            $vsInstallPath = $fp; break
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# 2.  RUST TOOLCHAIN VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $SkipToolchainCheck) {
    Write-Step "RUST" "Verifying Rust toolchain (cargo)..."
    try {
        $null = Get-Command cargo -ErrorAction Stop
        $rustVer = (& cargo --version 2>&1) -join ''
        Write-Host "  $cGreen[+]$cReset $rustVer"
    } catch {
        Write-Host "`n$cRed[!] CRITICAL: Rust toolchain (cargo) not found in PATH.$cReset"
        Exit 1
    }
} else {
    Write-Step "RUST" "Skipped (SkipToolchainCheck)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 3.  NATIVE VCVARS COMPILATION
# ═══════════════════════════════════════════════════════════════════════════════
Write-Step "BUILD" "Constructing native MSVC compilation context..."

$VcvarsPath = $null
if (-not [string]::IsNullOrWhiteSpace($vsInstallPath)) {
    $VcvarsPath = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvars64.bat"
}

$CleanLine = ""
if ($Clean) { $CleanLine = "cargo clean" }

$CompileWrapper = Join-Path $WorkingDir "_build_temp.cmd"
if ($VcvarsPath -and (Test-Path $VcvarsPath)) {
    $WrapperLogic = @"
@echo off
echo     [*] Initializing MSVC x64 linkers and Windows SDK...
call "$VcvarsPath" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo     [!] CRITICAL: vcvars64.bat failed.
    exit /b %ERRORLEVEL%
)
echo     [*] MSVC environment mapped.
cd /d "$WorkingDir"
$CleanLine
echo     [*] Executing cargo build --release --workspace...
cargo build --release --workspace
exit /b %ERRORLEVEL%
"@
} else {
    Write-Host "  $cYellow[!]$cReset vcvars64.bat not found; building without MSVC env."
    $WrapperLogic = @"
@echo off
cd /d "$WorkingDir"
$CleanLine
echo     [*] Executing cargo build --release --workspace...
cargo build --release --workspace
exit /b %ERRORLEVEL%
"@
}

Set-Content -Path $CompileWrapper -Value $WrapperLogic

$buildStart = Get-Date
& cmd.exe /c $CompileWrapper
$buildElapsed = (Get-Date) - $buildStart

Remove-Item $CompileWrapper -Force -ErrorAction SilentlyContinue

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n$cRed[!] COMPILATION FAILED: cargo returned exit code $LASTEXITCODE$cReset"
    Exit 1
}

Write-Step "BUILD" "Compilation succeeded" "Elapsed: $($buildElapsed.ToString('mm\:ss'))"

# ═══════════════════════════════════════════════════════════════════════════════
# 4.  BINARY VALIDATION & STAGING
# ═══════════════════════════════════════════════════════════════════════════════
Write-Step "VERIFY" "Validating compiled binary..."

$CompiledDll = Join-Path $BinDir $FinalBinaryName

if (-not (Test-Path $CompiledDll)) {
    Write-Host "$cRed[!] CRITICAL: Expected DLL not found at $CompiledDll$cReset"
    Write-Host "    Check that ml_engine/Cargo.toml [lib] name = 'c2sensor_ml' and crate-type = ['cdylib']"
    Exit 1
}

Copy-Item -Path $CompiledDll -Destination $FinalDest -Force

$HashVal = (Get-FileHash $FinalDest -Algorithm SHA256).Hash
$HashFile = Join-Path $WorkingDir ($FinalBinaryName -replace "\.dll$", ".sha256")
$HashVal | Out-File -FilePath $HashFile -Encoding ascii -NoNewline

$SizeMB = [math]::Round(((Get-Item $FinalDest).Length / 1MB), 2)

# ═══════════════════════════════════════════════════════════════════════════════
# 5.  BUILD ARTIFACT CLEANUP
$TargetDir = Join-Path $WorkingDir "target"
if (Test-Path $TargetDir) {
    Write-Step "CLEANUP" "Removing build artifacts" $TargetDir
    Remove-Item $TargetDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "$cCyan$cBold╔══════════════════════════════════════════════════════════════╗$cReset"
Write-Host "$cCyan║$cReset $cGreen SUCCESS: C2 Sensor ML Engine Compiled$cReset"
Write-Host "$cCyan║$cReset"
Write-Host "$cCyan║$cReset   Binary  : $FinalBinaryName"
Write-Host "$cCyan║$cReset   Size    : $SizeMB MB"
Write-Host "$cCyan║$cReset   SHA-256 : $HashVal"
Write-Host "$cCyan║$cReset   Staged  : $FinalDest"
Write-Host "$cCyan║$cReset   Hash    : $HashFile"
Write-Host "$cCyan║$cReset   Elapsed : $($buildElapsed.ToString('mm\:ss'))"
Write-Host "$cCyan$cBold╚══════════════════════════════════════════════════════════════╝$cReset"
Write-Host ""