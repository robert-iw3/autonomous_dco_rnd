<#
.SYNOPSIS
    Deep Sensor - High-Fidelity APT TTP Validation Suite
.DESCRIPTION
    Safely simulates APT behaviors derived from YAML signatures.
    Simulates "LOLBin Copying/Masquerading" to validate strict path-exclusion rules.
#>
#Requires -RunAsAdministrator

$ESC = [char]27
$cGreen = "$ESC[92m"; $cCyan = "$ESC[96m"; $cYellow = "$ESC[93m"; $cDark = "$ESC[90m"; $cReset = "$ESC[0m"

$TestDir = "C:\Temp\DeepSensor_APT_Tests"
if (-not (Test-Path $TestDir)) { New-Item -ItemType Directory -Path $TestDir -Force | Out-Null }

Write-Host "$cCyan=================================================================$cReset"
Write-Host "$cCyan   HIGH-FIDELITY TTP SIGNATURE VALIDATION SUITE (AV-SAFE) $cReset"
Write-Host "$cCyan=================================================================`n$cReset"

# --- STAGE ADVERSARY TOOLS (Simulate LOLBin Masquerading) ---
Write-Host "$cDark[*] Staging native Windows binaries into user-writable directories...$cReset"
$FakePoSh = Join-Path $TestDir "powershell.exe"
$FakeCert = Join-Path $TestDir "certutil.exe"
$FakeWmic = Join-Path $TestDir "wmic.exe"
$FakeNetsh = Join-Path $TestDir "netsh.exe"
$FakeRunDll = Join-Path $TestDir "rundll32.exe"

Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" $FakePoSh -Force
Copy-Item "$env:SystemRoot\System32\certutil.exe" $FakeCert -Force
Copy-Item "$env:SystemRoot\System32\wbem\wmic.exe" $FakeWmic -Force
Copy-Item "$env:SystemRoot\System32\netsh.exe" $FakeNetsh -Force
Copy-Item "$env:SystemRoot\System32\rundll32.exe" $FakeRunDll -Force

# =====================================================================
# 1. APT28 (Fancy Bear) Tests
# =====================================================================
Write-Host "`n$cDark--- PHASE 1: APT28 Behaviors ---$cReset"

Write-Host "$cGreen[+] Testing: APT28 Covenant Loader Drop (FILE_EVENT)$cReset"
$FakeWinWord = Join-Path $TestDir "winword.exe"
$TargetFile = Join-Path $TestDir "ctec.dll"
Copy-Item "$env:SystemRoot\System32\notepad.exe" $FakeWinWord -Force
Start-Process -FilePath $FakeWinWord -WindowStyle Hidden
Start-Sleep -Seconds 1
"Simulated Covenant Payload" | Out-File -FilePath $TargetFile -Force
Stop-Process -Name "winword" -Force -ErrorAction SilentlyContinue

Write-Host "$cGreen[+] Testing: APT28 COM Hijacking via Registry (REGISTRY_EVENT)$cReset"
$RegKey = "HKCU\Software\Classes\CLSID\{2227A280-3AEA-1069-A2DE-08002B30309D}\InprocServer32"
Start-Process -FilePath "reg.exe" -ArgumentList "add `"$RegKey`" /ve /d `"C:\Temp\calc.dll`" /f" -WindowStyle Hidden -Wait

# =====================================================================
# 2. APT37 (Reaper) Tests
# =====================================================================
Write-Host "`n$cDark--- PHASE 2: APT37 Behaviors ---$cReset"

Write-Host "$cGreen[+] Testing: APT37 Rust Backdoor Execution (PROCESS_START)$cReset"
Start-Process -FilePath $FakePoSh -ArgumentList "-WindowStyle Hidden -Command `"Write-Host 'Loading rust module...'`"" -WindowStyle Hidden

Write-Host "$cGreen[+] Testing: APT37 Certutil + Python Chain (PROCESS_START)$cReset"
$DummyBase64 = Join-Path $TestDir "dummy.b64"
$DummyOut = Join-Path $TestDir "dummy.txt"
"VGhpcyBpcyBhIHRlc3Q=" | Out-File $DummyBase64 -Encoding ascii
Start-Process -FilePath $FakeCert -ArgumentList "-decode `"$DummyBase64`" `"$DummyOut`"" -WindowStyle Hidden -Wait

# =====================================================================
# 3. APT41 / SilverFox Tests
# =====================================================================
Write-Host "`n$cDark--- PHASE 3: APT41 / SilverFox Behaviors ---$cReset"

Write-Host "$cGreen[+] Testing: SilverFox RAT Execution via Encoded PowerShell (PROCESS_START)$cReset"
Start-Process -FilePath $FakePoSh -ArgumentList "-enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABlAHMAdAAgAFMAaQBsAHYAZQByAEYAbwB4ACc=" -WindowStyle Hidden

Write-Host "$cGreen[+] Testing: SilverFox WMI Lateral Movement Create Process (PROCESS_START)$cReset"
Start-Process -FilePath $FakeWmic -ArgumentList "/node:127.0.0.1 process call create `"calc.exe`"" -WindowStyle Hidden -Wait

# =====================================================================
# 4. Kimsuky Tests
# =====================================================================
Write-Host "`n$cDark--- PHASE 4: Kimsuky Behaviors ---$cReset"

Write-Host "$cGreen[+] Testing: Kimsuky Registry Run Key Persistence (REGISTRY_EVENT)$cReset"
$RunKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
Start-Process -FilePath "reg.exe" -ArgumentList "add `"$RunKey`" /v `"KimsukyTest`" /d `"C:\Users\Public\backdoor.vbs`" /f" -WindowStyle Hidden -Wait

# =====================================================================
# 5. Volt Typhoon Tests
# =====================================================================
Write-Host "`n$cDark--- PHASE 5: Volt Typhoon Behaviors ---$cReset"

Write-Host "$cGreen[+] Testing: Volt Typhoon Netsh Portproxy Abuse (PROCESS_START)$cReset"
Start-Process -FilePath $FakeNetsh -ArgumentList "interface portproxy add v4tov4 listenport=8080 listenaddress=127.0.0.1 connectport=80 connectaddress=127.0.0.1" -WindowStyle Hidden -Wait

Write-Host "$cGreen[+] Testing: Volt Typhoon Rundll32 Proxy Execution (PROCESS_START)$cReset"
Start-Process -FilePath $FakeRunDll -ArgumentList "javascript:`"\\..\\mshtml,RunHTMLApplication `";alert('VoltTyphoon Test');" -WindowStyle Hidden


# =====================================================================
# CLEANUP PHASE
# =====================================================================
Write-Host "`n$cCyan[*] Tests dispatched. Waiting 5 seconds for sensor ingestion...$cReset"
Start-Sleep -Seconds 5

Write-Host "$cDark[*] Initiating Cleanup & Artifact Removal...$cReset"
if (Test-Path $TestDir) { Remove-Item -Path $TestDir -Recurse -Force -ErrorAction SilentlyContinue }
Start-Process -FilePath "reg.exe" -ArgumentList "delete `"HKCU\Software\Classes\CLSID\{2227A280-3AEA-1069-A2DE-08002B30309D}`" /f" -WindowStyle Hidden -Wait
Start-Process -FilePath "reg.exe" -ArgumentList "delete `"$RunKey`" /v `"KimsukyTest`" /f" -WindowStyle Hidden -Wait
Start-Process -FilePath "$env:SystemRoot\System32\netsh.exe" -ArgumentList "interface portproxy delete v4tov4 listenport=8080 listenaddress=127.0.0.1" -WindowStyle Hidden -Wait

Write-Host "$cGreen[+] Cleanup complete. Check your DeepSensor HUD for Critical/High TTP Alerts!$cReset"