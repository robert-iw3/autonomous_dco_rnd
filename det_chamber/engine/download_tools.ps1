# download_tools.ps1
# Downloads tools required for malware_sandbox into E:\Tools\Windows and E:\Tools\Windows\inetsim
# Logs to C:\Logs\download_tools.log
# Licensed tools (MagnetRESPONSE.exe, malw.pmc) must be manually placed by the user

# Configure logging
$LogDir = "C:\Logs"
$LogFile = "$LogDir\download_tools.log"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogMessage = { param($Level, $Message) Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message" }
& $LogMessage "INFO" "Starting tool download script"

# Create directories
$ToolsDir = "E:\Tools\Windows"
$INetSimDir = "$ToolsDir\inetsim"
if (-not (Test-Path $ToolsDir)) {
    New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
    & $LogMessage "INFO" "Created directory: $ToolsDir"
}
if (-not (Test-Path $INetSimDir)) {
    New-Item -ItemType Directory -Path $INetSimDir -Force | Out-Null
    & $LogMessage "INFO" "Created directory: $INetSimDir"
}

# Download tools
$Tools = @(
    @{
        Name = "Procmon.exe"
        Url = "https://download.sysinternals.com/files/ProcessMonitor.zip"
        Dest = "$ToolsDir\Procmon.exe"
        Zip = "$ToolsDir\ProcessMonitor.zip"
    },
    @{
        Name = "etl2pcapng.exe"
        Url = "https://github.com/microsoft/etl2pcapng/releases/download/v1.8.0/etl2pcapng.zip"
        Dest = "$ToolsDir\etl2pcapng.exe"
        Zip = "$ToolsDir\etl2pcapng.zip"
    },
    @{
        Name = "vol.exe"
        Url = "https://github.com/volatilityfoundation/volatility3/releases/download/v2.5.0/volatility3-2.5.0-Windows-x64.zip"
        Dest = "$ToolsDir\vol.exe"
        Zip = "$ToolsDir\volatility3.zip"
    },
    @{
        Name = "capa.exe"
        Url = "https://github.com/mandiant/capa/releases/download/v6.1.0/capa-v6.1.0-windows-x64.exe"
        Dest = "$ToolsDir\capa.exe"
    },
    @{
        Name = "yara64.exe"
        Url = "https://github.com/VirusTotal/yara/releases/download/v4.5.1/yara-v4.5.1-win64.zip"
        Dest = "$ToolsDir\yara64.exe"
        Zip = "$ToolsDir\yara.zip"
    },
    @{
        Name = "inetsim.exe"
        Url = "http://www.inetsim.org/downloads/inetsim-1.3.2-win32.zip"
        Dest = "$INetSimDir\inetsim.exe"
        Zip = "$INetSimDir\inetsim.zip"
    },
    @{
        Name = "inetsim.conf"
        Url = "http://www.inetsim.org/downloads/inetsim-1.3.2-win32.zip"
        Dest = "$INetSimDir\inetsim.conf"
        Zip = "$INetSimDir\inetsim.zip"
    }
)

foreach ($Tool in $Tools) {
    try {
        & $LogMessage "INFO" "Downloading $($Tool.Name) from $($Tool.Url)"
        Invoke-WebRequest -Uri $Tool.Url -OutFile $Tool.Zip -ErrorAction Stop
        if ($Tool.Zip -and (Test-Path $Tool.Zip)) {
            Expand-Archive -Path $Tool.Zip -DestinationPath (Split-Path $Tool.Dest -Parent) -Force
            & $LogMessage "INFO" "Extracted $($Tool.Name) to $($Tool.Dest)"
            Remove-Item $Tool.Zip -Force
            & $LogMessage "INFO" "Cleaned up $($Tool.Zip)"
        } else {
            Move-Item -Path $Tool.Zip -Destination $Tool.Dest -Force
            & $LogMessage "INFO" "Moved $($Tool.Name) to $($Tool.Dest)"
        }
    } catch {
        & $LogMessage "ERROR" "Failed to download or extract $($Tool.Name): $_"
    }
}

# Warn about licensed tools
$LicensedTools = @("MagnetRESPONSE.exe", "malw.pmc")
foreach ($Tool in $LicensedTools) {
    if (-not (Test-Path "$ToolsDir\$Tool")) {
        & $LogMessage "WARNING" "$Tool requires a license. Please manually place it in $ToolsDir"
    } else {
        & $LogMessage "INFO" "Found $Tool in $ToolsDir"
    }
}

& $LogMessage "INFO" "Tool download script completed"