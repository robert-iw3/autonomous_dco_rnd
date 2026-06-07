<#
.SYNOPSIS
    Deep Sensor - Targeted Sigma Validation Suite (AST Test)
    Validates the specific YAML rules for Kimsuky, MuddyWater, Russian CTRL, and TrustConnect.
#>
#Requires -RunAsAdministrator

$ESC = [char]27
$cGreen = "$ESC[92m"; $cCyan = "$ESC[96m"; $cYellow = "$ESC[93m"; $cReset = "$ESC[0m"

Write-Host "`n$cCyan [!] STARTING TARGETED SIGMA VALIDATION (AST) $cReset`n"

# =====================================================================
# FILE EVENTS: Kimsuky & MuddyWater
# =====================================================================
Write-Host "$cYellow [*] Testing File Event Rules...$cReset"

# 1. Kimsuky Python Backdoor Staging
$kimsukyFile = "C:\Users\Public\Documents\tmp.ini"
New-Item -Path $kimsukyFile -ItemType File -Force | Out-Null
Write-Host "    [+] Created: $kimsukyFile"

# 2. MuddyWater CastleRAT Staging
$muddyDir = "$env:LOCALAPPDATA\MashaLasley"
New-Item -Path $muddyDir -ItemType Directory -Force | Out-Null
$muddyFile = Join-Path $muddyDir "staging.tmp"
"test" | Out-File $muddyFile -Force
Write-Host "    [+] Created: $muddyFile"

# =====================================================================
# PROCESS EVENTS: MuddyWater & NICKEL ALLEY
# =====================================================================
Write-Host "`n$cYellow [*] Testing Process Creation Rules...$cReset"

# 3. MuddyWater ChainShell (schtasks logic)
# AV Safe: Creating a task for 'calc' that runs once in the year 2099
Write-Host "    [+] Running schtasks anchor for Virtual Guy..."
schtasks /create /tn "VirtualGuyTask" /tr "calc.exe" /sc once /st 00:00 /sd 2099/01/01 /f | Out-Null

# 4. NICKEL ALLEY PyLangGhost (tar extraction logic)
# Note: The command line is sufficient to trigger; Lib.zip doesn't need to exist.
Write-Host "    [+] Executing tar extraction anchor..."
tar -xf Lib.zip 2>$null

# 5. Russian CTRL .NET Toolkit (CommandLine anchor)
Write-Host "    [+] Executing CTRL toolkit anchor..."
cmd /c "echo WindowsHealthMonitor" | Out-Null

# =====================================================================
# REGISTRY EVENTS: Russian CTRL & TrustConnect
# =====================================================================
Write-Host "`n$cYellow [*] Testing Registry Tampering Rules...$cReset"

# 6. Russian CTRL UAC Bypass Prep
$uacPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
New-Item -Path $uacPath -Force | Out-Null
Set-ItemProperty -Path $uacPath -Name "(Default)" -Value "powershell.exe" -Force
Write-Host "    [+] Set Registry: $uacPath"

# 7. TrustConnect Campaign Persistence
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $runKey -Name "TrustConnectAgent" -Value "C:\temp\agent.exe" -Force
Write-Host "    [+] Set Registry: TrustConnectAgent"

# =====================================================================
# CLEANUP (Wait for Sensor to Process)
# =====================================================================
Write-Host "`n$cGreen [*] Test actions complete. Waiting 5s for HUD updates...$cReset"
Start-Sleep -Seconds 5

Remove-Item $kimsukyFile -Force -ErrorAction SilentlyContinue
Remove-Item $muddyDir -Recurse -Force -ErrorAction SilentlyContinue
schtasks /delete /tn "VirtualGuyTask" /f 2>$null
Remove-Item $uacPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $runKey -Name "TrustConnectAgent" -Force -ErrorAction SilentlyContinue

Write-Host "`n$cCyan [+] Cleanup Complete. Check your Deep Sensor HUD for detections. $cReset"