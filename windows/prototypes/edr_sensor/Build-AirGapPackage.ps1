<#
.SYNOPSIS
    Deep Sensor v2.1 - Air-Gap Package Builder (Rust & Native AOT)

.DESCRIPTION
    Executes on an internet-connected staging system to gather all required dependencies,
    threat intelligence files, and the pre-compiled binaries (Rust ML Engine & .NET Native AOT Forwarder).
    Stages the files into a structured directory and compresses them into a portable ZIP archive.
#>

param(
    [string]$StagingDir = "C:\Temp\DeepSensor_AirGap_Staging",
    [string]$OutFile = "C:\Temp\DeepSensor_AirGap_Package.zip"
)

Write-Host "[*] Initializing Air-Gap Staging Directory at $StagingDir..." -ForegroundColor Cyan
if (Test-Path $StagingDir) { Remove-Item -Path $StagingDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path $StagingDir -Force

$TransitManifest = @{}

function Register-FileHash([string]$FilePath, [string]$LogicalName) {
    if (Test-Path $FilePath) {
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        $TransitManifest[$LogicalName] = $hash
        Write-Host "    [+] Hashed $LogicalName : $hash" -ForegroundColor DarkGray
    }
}

# ============================================================================
# 1. C# ETW DEPENDENCIES
# ============================================================================
Write-Host "`n[*] Downloading C# TraceEvent & Unsafe NuGet Packages (v3.2.2)..." -ForegroundColor Gray
$TeUrl = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.2.2"
$UnUrl = "https://www.nuget.org/api/v2/package/System.Runtime.CompilerServices.Unsafe/5.0.0"
$TeOut = Join-Path $StagingDir "traceevent.nupkg"
$UnOut = Join-Path $StagingDir "unsafe.nupkg"

Invoke-WebRequest -Uri $TeUrl -OutFile $TeOut
Invoke-WebRequest -Uri $UnUrl -OutFile $UnOut
Register-FileHash -FilePath $TeOut -LogicalName "TraceEvent_NuGet"
Register-FileHash -FilePath $UnOut -LogicalName "Unsafe_NuGet"

# ============================================================================
# 2. CONTEXT-AWARE YARA DEPENDENCIES
# ============================================================================
Write-Host "`n[*] Downloading C# libyara.NET NuGet Package (v3.5.2)..." -ForegroundColor Gray
$YaraUrl = "https://www.nuget.org/api/v2/package/libyara.NET/3.5.2"
$YaraOut = Join-Path $StagingDir "libyaranet.nupkg"

Invoke-WebRequest -Uri $YaraUrl -OutFile $YaraOut
Register-FileHash -FilePath $YaraOut -LogicalName "LibYara_NuGet"

Write-Host "    [*] Generating Category Folders for Context-Aware Routing..." -ForegroundColor DarkGray
$YaraRuleDir = Join-Path $StagingDir "yara_rules"
$null = New-Item -ItemType Directory -Path $YaraRuleDir -Force
$Vectors = @("WebInfrastructure", "SystemExploits", "LotL", "MacroPayloads", "BinaryProxy", "SystemPersistence", "InfostealerTargets", "RemoteAdmin", "DevOpsSupplyChain", "Core_C2")
foreach ($v in $Vectors) {
    New-Item -ItemType Directory -Path (Join-Path $YaraRuleDir $v) -Force | Out-Null
}

# ============================================================================
# 3. THREAT INTELLIGENCE (SIGMA & LOLDrivers)
# ============================================================================
Write-Host "`n[*] Fetching Latest LOLDrivers Database..." -ForegroundColor Gray
$LolUrl = "https://loldrivers.io/api/drivers.json"
$LOLout = Join-Path $StagingDir "drivers.json"
Invoke-WebRequest -Uri $LolUrl -OutFile $LOLout
Register-FileHash -FilePath $LOLout -LogicalName "LOLDriver_DB"

Write-Host "`n[*] Fetching SigmaHQ Ruleset..." -ForegroundColor Gray
$SigmaUrl = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
$SigmaOut = Join-Path $StagingDir "sigma_master.zip"
Invoke-WebRequest -Uri $SigmaUrl -OutFile $SigmaOut
Register-FileHash -FilePath $SigmaOut -LogicalName "Sigma_Rules"

Write-Host "`n[*] Fetching YARA Intelligence (Elastic & ReversingLabs)..." -ForegroundColor Gray
$YaraSources = @(
    @{ Name = "ElasticLabs"; Url = "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip" },
    @{ Name = "ReversingLabs"; Url = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip" }
)

foreach ($src in $YaraSources) {
    $outPath = Join-Path $StagingDir "$($src.Name).zip"
    Invoke-WebRequest -Uri $src.Url -OutFile $outPath
    Register-FileHash -FilePath $outPath -LogicalName "$($src.Name)_Rules"
}

# ============================================================================
# 4. CORE SENSOR PAYLOADS & TRANSMISSION LAYER
# ============================================================================
Write-Host "`n[*] Copying Core Sensor & Transmission Payloads from Local Workspace..." -ForegroundColor Gray
$Payloads = @(
    "DeepSensor_Launcher.ps1",
    "OsSensor.cs",
    "DeepSensor_ML_v2.1.dll",
    "DeepSensor_ML_v2.1.sha256",
    "DeepSensor_Config.ini",
    "Deployment_Orchestrator.ps1",
    "TelemetryForwarder.cs",
    "TelemetryForwarder.csproj",
    "Program.cs",
    "TelemetryForwarder.exe" # Crucial: Pre-compiled AOT binary to prevent compiling on endpoints
)

foreach ($p in $Payloads) {
    if (Test-Path $p) {
        Copy-Item -Path $p -Destination $StagingDir -Force
        Write-Host "    [+] Staged: $p" -ForegroundColor Green
    } else {
        Write-Host "    [!] WARNING: $p not found in current directory." -ForegroundColor Yellow
    }
}

# ============================================================================
# 5. COMPRESSION & CLEANUP
# ============================================================================
Write-Host "`n[*] Generating Transit Manifest..." -ForegroundColor Gray
$ManifestPath = Join-Path $StagingDir "AirGap_Manifest.json"
$TransitManifest | ConvertTo-Json | Out-File -FilePath $ManifestPath -Encoding UTF8

Write-Host "[*] Compressing Air-Gap Package to $OutFile..." -ForegroundColor Cyan
if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
Compress-Archive -Path "$StagingDir\*" -DestinationPath $OutFile -Force

$FinalZipHash = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash

Write-Host "`n[+] Build Complete. Portable Deployment Archive: $OutFile" -ForegroundColor Green
Write-Host "[+] PACKAGE SHA256: $FinalZipHash" -ForegroundColor Yellow