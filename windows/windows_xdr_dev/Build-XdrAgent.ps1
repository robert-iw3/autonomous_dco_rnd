<#
.SYNOPSIS
    DeepXDR Unified Build & Deployment Script
.DESCRIPTION
    Builds all Rust crates and the .NET 10 agent, then deploys as a hardened
    Windows Service.

    Build order:
        1. Rust workspace  (xdr_ml_engine.dll + xdr_nexus.dll)
        2. Ring-0 driver   (endpoint_monitor_driver.sys)  -- requires WDK + nightly Rust
        3. .NET 10 agent   (XdrAgent.exe -- self-contained, single-file)
        4. Secure install  (directory hardening, service registration, SDDL)

.PARAMETER BuildDriver
    Also compile the ring-0 kernel driver. Requires:
      - Windows Driver Kit (WDK) installed
      - Rust nightly toolchain  (rustup toolchain install nightly)
      - cargo-make              (cargo install cargo-make)

.PARAMETER SkipService
    Build and copy artifacts but do NOT register or start the Windows Service.
    Useful for local dev/test cycles.

.PARAMETER Configuration
    "Release" (default) or "Debug". Debug builds include symbols and skip strip.

.PARAMETER SignDriver
    Code-sign the compiled .sys file. Requires signtool.exe on PATH and an
    EV certificate installed in the current user's certificate store.
    Required for Secure Boot + HVCI environments. Skip for lab/test only.

.EXAMPLE
    # Standard production deploy (no driver)
    .\Build-XdrAgent.ps1

    # Include kernel driver compilation
    .\Build-XdrAgent.ps1 -BuildDriver

    # Sign and include driver
    .\Build-XdrAgent.ps1 -BuildDriver -SignDriver

    # Dev cycle -- build only, no service registration
    .\Build-XdrAgent.ps1 -SkipService
#>

#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $BuildDriver,
    [switch] $SkipService,
    [switch] $SignDriver,
    [ValidateSet("Release","Debug")]
    [string] $Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Paths ──────────────────────────────────────────────────────────────────────
$AgentRoot   = $PSScriptRoot                                      # windows_xdr_dev/
$AgentDir    = Join-Path $AgentRoot "agent"                       # XdrAgent.csproj + C# source
$DriverRoot  = Join-Path $AgentRoot "ring0_driver"
$RustTarget  = Join-Path $AgentRoot "target\$($Configuration.ToLower())"

$InstallDir  = "C:\ProgramData\DeepSensor\Bin"
$DataDir     = "C:\ProgramData\DeepSensor\Data"
$LogDir      = "C:\ProgramData\DeepSensor\Logs"
$YaraDir     = "C:\ProgramData\DeepSensor\YaraRules"
$SigmaDir    = "C:\ProgramData\DeepSensor\SigmaRules"

$ServiceName = "DeepXDR_Service"
$ServiceExe  = Join-Path $InstallDir "XdrAgent.exe"

$CargoFlags  = if ($Configuration -eq "Release") { @("--release") } else { @() }

# Color helpers
function Info  ($m) { Write-Host "  [INF] $m" -ForegroundColor Cyan    }
function Ok    ($m) { Write-Host "  [OK]  $m" -ForegroundColor Green   }
function Warn  ($m) { Write-Host "  [WRN] $m" -ForegroundColor Yellow  }
function Fatal ($m) { Write-Host "  [ERR] $m" -ForegroundColor Red; exit 1 }

function Invoke-Step ([string]$Label, [scriptblock]$Body) {
    Write-Host "`n━━━ $Label " -ForegroundColor Magenta -NoNewline
    Write-Host ("━" * [math]::Max(0, 60 - $Label.Length)) -ForegroundColor DarkGray
    & $Body
}

# ── Pre-flight checks ──────────────────────────────────────────────────────────
Invoke-Step "Pre-flight checks" {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Fatal "cargo not found. Install Rust: https://rustup.rs"
    }
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        Fatal "dotnet not found. Install .NET 10 SDK: https://dot.net"
    }

    $dotnetVer = (dotnet --version)
    if (-not ($dotnetVer -match "^10\.")) {
        Warn ".NET SDK version is $dotnetVer -- expected 10.x. Build may fail."
    }

    if ($BuildDriver) {
        if (-not (Get-Command cargo-make -ErrorAction SilentlyContinue)) {
            Fatal "-BuildDriver requires cargo-make: cargo install cargo-make"
        }
        $nightly = rustup toolchain list | Select-String "nightly"
        if (-not $nightly) {
            Fatal "-BuildDriver requires Rust nightly: rustup toolchain install nightly"
        }
        if ($SignDriver -and -not (Get-Command signtool.exe -ErrorAction SilentlyContinue)) {
            Fatal "-SignDriver requires signtool.exe on PATH (part of Windows SDK)"
        }
    }

    Info "Cargo  : $(cargo --version)"
    Info "Dotnet : $(dotnet --version)"
    Info "Config : $Configuration"
    Info "Driver : $BuildDriver"
}

# ── Step 1: Rust workspace ─────────────────────────────────────────────────────
Invoke-Step "Rust workspace  (xdr_ml_engine.dll + xdr_nexus.dll)" {
    Push-Location $AgentRoot
    try {
        $args = @("build") + $CargoFlags + @(
            "--workspace",
            "--features", "ml_ueba/with-transmission"  # optional nexus link
        )

        Info "Running: cargo $($args -join ' ')"
        & cargo @args
        if ($LASTEXITCODE -ne 0) { Fatal "Rust workspace build failed (exit $LASTEXITCODE)" }

        # Verify expected outputs
        $mlDll    = Join-Path $RustTarget "xdr_ml_engine.dll"
        $nexusDll = Join-Path $RustTarget "xdr_nexus.dll"
        if (-not (Test-Path $mlDll))    { Fatal "Expected output not found: $mlDll" }
        if (-not (Test-Path $nexusDll)) { Fatal "Expected output not found: $nexusDll" }

        Ok "xdr_ml_engine.dll  →  $mlDll"
        Ok "xdr_nexus.dll      →  $nexusDll"
    } finally { Pop-Location }
}

# ── Step 2: Ring-0 kernel driver (optional) ────────────────────────────────────
if ($BuildDriver) {
    Invoke-Step "Ring-0 kernel driver  (endpoint_monitor_driver.sys)" {
        Push-Location $DriverRoot
        try {
            $driverArgs = @("build", "--release",
                "--features=registry,threads,objects,network")

            Info "Running: cargo +nightly $($driverArgs -join ' ')"
            & cargo +nightly @driverArgs
            if ($LASTEXITCODE -ne 0) { Fatal "Driver build failed (exit $LASTEXITCODE)" }

            $sysPath = Join-Path $DriverRoot "target\release\endpoint_monitor_driver.dll"
            $sysOut  = Join-Path $DriverRoot "target\release\endpoint_monitor_driver.sys"

            # Cargo produces a .dll for a cdylib; rename to .sys for kernel loading
            if (Test-Path $sysPath) {
                Move-Item -Force $sysPath $sysOut
                Ok "Driver compiled → $sysOut"
            } elseif (Test-Path $sysOut) {
                Ok "Driver compiled → $sysOut"
            } else {
                Fatal "Driver output not found after build"
            }

            if ($SignDriver) {
                Info "Signing driver with signtool..."
                & signtool.exe sign /fd SHA256 `
                    /tr http://timestamp.digicert.com /td SHA256 `
                    $sysOut
                if ($LASTEXITCODE -ne 0) { Fatal "signtool failed (exit $LASTEXITCODE)" }
                Ok "Driver signed"
            } else {
                Warn "Driver NOT signed -- only suitable for test signing / HVCI-disabled environments"
            }
        } finally { Pop-Location }
    }
}

# ── Step 3: .NET 10 agent ──────────────────────────────────────────────────────
Invoke-Step ".NET 10 agent  (XdrAgent.exe -- self-contained, win-x64)" {
    # Copy DLLs into the agent project directory so dotnet publish bundles them
    $mlDll    = Join-Path $RustTarget "xdr_ml_engine.dll"
    $nexusDll = Join-Path $RustTarget "xdr_nexus.dll"

    Copy-Item -Force $mlDll    (Join-Path $AgentDir "xdr_ml_engine.dll")
    Copy-Item -Force $nexusDll (Join-Path $AgentDir "xdr_nexus.dll")
    Info "Copied DLLs to agent/ for bundling"

    $publishArgs = @(
        "publish",
        (Join-Path $AgentDir "XdrAgent.csproj"),
        "-c", $Configuration,
        "-r", "win-x64",
        "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-o", $InstallDir
    )

    Info "Running: dotnet $($publishArgs -join ' ')"
    & dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) { Fatal ".NET publish failed (exit $LASTEXITCODE)" }
    Ok "XdrAgent.exe published → $InstallDir"
}

# ── Step 4: Secure install directories ────────────────────────────────────────
Invoke-Step "Secure install directories" {
    foreach ($dir in @($InstallDir, $DataDir, $LogDir, $YaraDir, $SigmaDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Ok "Created $dir"
        }
    }

    # Copy config file (preserve existing if already deployed -- don't overwrite secrets)
    $configDst = Join-Path $InstallDir "DeepXDR_Config.ini"
    $configSrc = Join-Path $AgentDir   "DeepXDR_Config.ini"
    if (-not (Test-Path $configDst)) {
        Copy-Item -Force $configSrc $configDst
        Ok "Config deployed → $configDst"
    } else {
        Warn "Config already exists at $configDst -- NOT overwritten (rotate secrets manually)"
    }

    # Copy driver artifacts if built
    if ($BuildDriver) {
        $sysOut  = Join-Path $DriverRoot "target\release\endpoint_monitor_driver.sys"
        $infSrc  = Join-Path $DriverRoot "driver.inf"
        if (Test-Path $sysOut) {
            Copy-Item -Force $sysOut (Join-Path $InstallDir "endpoint_monitor_driver.sys")
            Copy-Item -Force $infSrc (Join-Path $InstallDir "driver.inf")
            Ok "Driver artifacts copied → $InstallDir"
        }
    }

    # Lock down Bin directory -- only SYSTEM and Admins can write; deny world read
    # This prevents DLL hijacking of xdr_ml_engine.dll / xdr_nexus.dll
    Info "Applying DACL to $InstallDir..."
    $acl = Get-Acl $InstallDir
    $acl.SetAccessRuleProtection($true, $false)  # break inheritance, no copy

    $system = [System.Security.Principal.NTAccount]"NT AUTHORITY\SYSTEM"
    $admins = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"

    foreach ($principal in @($system, $admins)) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $InstallDir -AclObject $acl
    Ok "DACL applied -- world access denied to $InstallDir"
}

# ── Step 5: Windows Service registration ──────────────────────────────────────
if (-not $SkipService) {
    Invoke-Step "Windows Service  ($ServiceName)" {
        # Stop and remove existing instance before reinstalling
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne "Stopped") {
                Info "Stopping existing service..."
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }
            Info "Removing existing service..."
            & sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 2
        }

        # Register new service running as LocalSystem
        Info "Creating service: $ServiceName"
        & sc.exe create $ServiceName `
            binPath= "`"$ServiceExe`"" `
            start=   auto `
            obj=     LocalSystem `
            DisplayName= "DeepXDR Unified Endpoint Detection & Response" `
            | Out-Null

        if ($LASTEXITCODE -ne 0) { Fatal "sc.exe create failed (exit $LASTEXITCODE)" }

        & sc.exe description $ServiceName `
            "Unified XDR agent: EDR/DLP/C2/IDPS detection, ring-0 enforcement, Nexus forwarding." `
            | Out-Null

        # Service SDDL -- SYSTEM + Admins: full control; Users: query only
        # Prevents malware from stopping/modifying the service without SYSTEM privs
        $sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)"
        & sc.exe sdset $ServiceName $sddl | Out-Null
        Ok "Service SDDL applied"

        # Configure failure recovery: restart on first 3 failures, 60-s delay
        & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
        Ok "Failure recovery configured (restart × 3, 60 s delay)"

        Info "Starting $ServiceName..."
        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 3

        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq "Running") {
            Ok "$ServiceName is RUNNING"
        } else {
            Fatal "$ServiceName failed to start -- status: $($svc.Status). Check Event Viewer."
        }
    }
}

# ── Summary ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Magenta
Write-Host "  DeepXDR build complete" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Install dir  :  $InstallDir"
Write-Host "  Config       :  $(Join-Path $InstallDir 'DeepXDR_Config.ini')"
Write-Host "  Service      :  $ServiceName  $(if ($SkipService) { '(not registered)' } else { '(running)' })"
Write-Host "  ML engine    :  xdr_ml_engine.dll  ($Configuration)"
Write-Host "  Nexus        :  xdr_nexus.dll      ($Configuration)"
if ($BuildDriver) {
    $sigTag = if ($SignDriver) { "(signed)" } else { "(unsigned -- test only)" }
    Write-Host "  Driver       :  endpoint_monitor_driver.sys  $sigTag"
    Write-Host ""
    Write-Host "  To install the driver:" -ForegroundColor Yellow
    Write-Host "    devcon install `"$InstallDir\driver.inf`" endpoint_monitor_driver" -ForegroundColor Yellow
    Write-Host "  Then set EnableKernelDriver = true in DeepXDR_Config.ini" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  To enable Nexus transmission, set in DeepXDR_Config.ini:" -ForegroundColor Cyan
Write-Host "    [Agent]  EnableNexusTransmission = true" -ForegroundColor Cyan
Write-Host "    [Transmission]  Endpoint = https://<nexus-host>:8443/api/v1/telemetry" -ForegroundColor Cyan
Write-Host "                    AuthToken = <rotate-this>" -ForegroundColor Cyan
Write-Host "                    IntegritySecret = <rotate-this>" -ForegroundColor Cyan
Write-Host "                    EnableSync = true" -ForegroundColor Cyan
Write-Host ""
