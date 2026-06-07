<#
.SYNOPSIS
    Tier 3 — Windows VM test environment installer.
    Run once on the Windows 11 test VM before Invoke-SmokeTests.ps1.

.DESCRIPTION
    Installs prerequisites needed to build and run DeepXDR on Windows 11:
      - .NET 10 SDK
      - Rust (nightly) + cargo
      - WinGet (if missing)
      - Python 3.12 + pip (for Tier 0 on Windows if needed)
      - Creates test output directory

.NOTES
    Run as Administrator. Reboot may be required after first install.
    Expected on: Windows 11, version 22H2+, x64.
#>

#Requires -RunAsAdministrator

param(
    [switch]$SkipDotNet,
    [switch]$SkipRust,
    [switch]$SkipPython,
    [string]$ReportDir = "$env:USERPROFILE\DeepXDR_TestReports"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

function Write-Step([string]$msg) {
    Write-Host "`n[STEP] $msg" -ForegroundColor Cyan
}

function Write-OK([string]$msg) {
    Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "  [WARN] $msg" -ForegroundColor Yellow
}

function Write-Fail([string]$msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
}

# --- Preflight -----------------------------------------------------------------

Write-Host ""
Write-Host "  DeepXDR Tier 3 — Environment Installer" -ForegroundColor Magenta
Write-Host "  Windows: $([System.Environment]::OSVersion.VersionString)" -ForegroundColor Gray
Write-Host "  User:    $env:USERNAME@$env:COMPUTERNAME" -ForegroundColor Gray
Write-Host ""

# Windows 11 check
$buildNum = [System.Environment]::OSVersion.Version.Build
if ($buildNum -lt 22000) {
    Write-Warn "Windows build $buildNum detected. DeepXDR targets Windows 11 (22000+)."
}

# Arch check
if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    Write-Fail "DeepXDR requires x64 architecture. Got: $env:PROCESSOR_ARCHITECTURE"
    exit 1
}

# --- WinGet --------------------------------------------------------------------

Write-Step "WinGet availability"
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-OK "winget found: $(winget --version)"
} else {
    Write-Warn "winget not found. Install from Microsoft Store (App Installer) and re-run."
}

# --- .NET 10 SDK ---------------------------------------------------------------

if (-not $SkipDotNet) {
    Write-Step ".NET 10 SDK"
    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($dotnet) {
        $ver = & dotnet --version 2>&1
        if ($ver -match "^10\.") {
            Write-OK ".NET $ver already installed."
        } else {
            Write-Warn "Installed: $ver. Installing .NET 10 SDK..."
            winget install Microsoft.DotNet.SDK.10 --silent --accept-package-agreements --accept-source-agreements
            Write-OK ".NET 10 SDK installed."
        }
    } else {
        Write-Host "  Installing .NET 10 SDK via winget..." -ForegroundColor Yellow
        winget install Microsoft.DotNet.SDK.10 --silent --accept-package-agreements --accept-source-agreements
        Write-OK ".NET 10 SDK installed."
    }
}

# --- Rust (nightly) ------------------------------------------------------------

if (-not $SkipRust) {
    Write-Step "Rust nightly toolchain"
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if ($cargo) {
        Write-OK "Rust found. Updating to nightly..."
        & rustup toolchain install nightly --profile minimal 2>&1 | Write-Host
        & rustup default nightly 2>&1 | Write-Host
        Write-OK "Rust nightly ready: $(& rustc --version)"
    } else {
        Write-Host "  Downloading rustup-init.exe..." -ForegroundColor Yellow
        $rustupUrl = "https://win.rustup.rs/x86_64"
        $rustupExe = "$env:TEMP\rustup-init.exe"
        Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupExe -UseBasicParsing
        & $rustupExe -y --default-toolchain nightly --profile minimal
        $env:PATH += ";$env:USERPROFILE\.cargo\bin"
        Write-OK "Rust installed: $(& rustc --version)"
    }
}

# --- Python 3.12 ---------------------------------------------------------------

if (-not $SkipPython) {
    Write-Step "Python 3.12"
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        $pyVer = & python --version 2>&1
        Write-OK "Python found: $pyVer"
    } else {
        winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        Write-OK "Python 3.12 installed."
    }

    Write-Host "  Installing Python test requirements..." -ForegroundColor Yellow
    $reqPath = "$PSScriptRoot\..\requirements.txt"
    if (Test-Path $reqPath) {
        & python -m pip install -r $reqPath --quiet
        Write-OK "Python requirements installed."
    } else {
        Write-Warn "requirements.txt not found at $reqPath"
    }
}

# --- Test output directory -----------------------------------------------------

Write-Step "Test output directory"
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir | Out-Null
}
Write-OK "Report directory: $ReportDir"

# --- Summary -------------------------------------------------------------------

Write-Host ""
Write-Host "  Environment setup complete." -ForegroundColor Green
Write-Host "  Next: run Invoke-SmokeTests.ps1 as a standard user (not admin)." -ForegroundColor Gray
Write-Host ""
