<#
.SYNOPSIS
    Contextual information gathering from Deep Sensor jsonl logs.
.DESCRIPTION
    Supports one-time scans (-Scan) or continuous monitoring (-Watch).
#>

param(
    [Parameter(ParameterSetName="Scan")][switch]$Scan,
    [Parameter(ParameterSetName="Watch")][switch]$Watch,
    [string]$OutputPath = "C:\ProgramData\DeepSensor\Data\Forensic_Triage_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
)

$AlertLog = "C:\ProgramData\DeepSensor\Data\DeepSensor_Events.jsonl"
$UebaLog  = "C:\ProgramData\DeepSensor\Data\DeepSensor_UEBA_Events.jsonl"

$ESC = [char]27
$cRed = "$ESC[91m"; $cYellow = "$ESC[93m"; $cGreen = "$ESC[92m"; $cCyan = "$ESC[96m"; $cReset = "$ESC[0m"

function Analyze-HolisticContext {
    param([PSCustomObject]$evt)

    $TargetPID = $evt.PID
    $ProcessPath = if ($evt.Image) { $evt.Image } else { ($evt.Cmd -split ' ')[0].Replace('"', '').Replace('\\??\\', '') }
    $Detection = if ($evt.SignatureName) { $evt.SignatureName } elseif ($evt.Details -match "(TTP|Sigma)_Match: (.*?)( \()") { $matches[2] } else { $evt.Details }

    $ParentCmd = "N/A"; $Grandparent = "N/A"; $GrandparentCmd = "N/A"; $NetState = "None"
    $Hash = "N/A"; $OrigName = "N/A"; $FileAge = "N/A"; $Risk = 0

    if ($TargetPID -gt 0) {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $TargetPID" -ErrorAction SilentlyContinue
        if ($proc) {
            $pProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.ParentProcessId)" -ErrorAction SilentlyContinue
            if ($pProc) {
                $ParentCmd = $pProc.CommandLine
                $gpProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($pProc.ParentProcessId)" -ErrorAction SilentlyContinue
                if ($gpProc) {
                    $Grandparent = $gpProc.Name
                    $GrandparentCmd = $gpProc.CommandLine
                }
            }
        }
        if ($ParentCmd -eq "N/A") {
            try { $ParentCmd = (Get-Process -Id $TargetPID -ErrorAction SilentlyContinue).Parent.Name } catch {}
        }
        $conns = Get-NetTCPConnection -ProcessId $TargetPID -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Established' }
        if ($conns) { $NetState = ($conns | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" }) -join " | " }
    }

    if (Test-Path $ProcessPath) {
        $fInfo = Get-Item $ProcessPath
        $Hash = (Get-FileHash $ProcessPath -Algorithm SHA256).Hash
        $OrigName = $fInfo.VersionInfo.OriginalFilename
        $FileAge = "$([math]::Round(((Get-Date) - $fInfo.CreationTime).TotalDays)) Days"
    }

    if ($NetState -ne "None") { $Risk += 2 }
    if ($FileAge -match "^0 Days") { $Risk += 2 }

    $CleanOrigName = $OrigName -replace '\.MUI$', ''
    if ($OrigName -and $evt.Process -notmatch [regex]::Escape($CleanOrigName)) {
        $Risk += 3
    }

    return [PSCustomObject]@{
        Timestamp       = if ($evt.Timestamp_Local) { $evt.Timestamp_Local } else { (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff") }
        Detection       = $Detection
        RiskLevel       = if ($Risk -ge 3) { "CRITICAL" } elseif ($Risk -ge 1) { "SUSPICIOUS" } else { "LOW" }
        Process         = $evt.Process
        PID             = $TargetPID
        CommandLine     = $evt.Cmd
        ParentCmd       = $ParentCmd
        Grandparent     = "$Grandparent ($GrandparentCmd)"
        SHA256          = $Hash
        OriginalName    = $OrigName
        FileAge         = $FileAge
        ActiveNetwork   = $NetState
        Tactic          = if ($evt.Tactic) { $evt.Tactic } else { "UEBA_Baseline" }
        Technique       = if ($evt.Technique) { $evt.Technique } else { "UEBA_Baseline" }
        LearningStatus  = if ($evt.Details -match "\(Learning: (\d+/\d+)\)") { $matches[1] } else { "Confirmed" }
    }
}

function Process-Telemetry {
    param($Line)
    $evt = try { $Line | ConvertFrom-Json } catch { $null }
    if ($null -eq $evt -or $evt.Category -eq "RawEvent") { return }

    $Forensics = Analyze-HolisticContext -evt $evt
    $Forensics | Export-Csv -Path $OutputPath -Append -NoTypeInformation

    $Color = if ($Forensics.RiskLevel -eq "CRITICAL") { $cRed } elseif ($Forensics.RiskLevel -eq "SUSPICIOUS") { $cYellow } else { $cGreen }
    Write-Host "[$($evt.Timestamp_Local)] $Color$($Forensics.RiskLevel):$cReset $($Forensics.Detection) ($($Forensics.Process))"
}

$Found = @(); if (Test-Path $AlertLog) { $Found += $AlertLog }; if (Test-Path $UebaLog) { $Found += $UebaLog }
if ($Found.Count -eq 0) { Write-Error "Logs not found."; exit }

if ($Scan) {
    Write-Host "$cCyan[*] Performing Holistic Forensic Scan...$cReset"
    Get-Content -Path $Found | ForEach-Object { Process-Telemetry -Line $_ }
    Write-Host "`n$cGreen[+] Holistic Report Generated: $OutputPath$cReset"
}
if ($Watch) {
    Write-Host "$cCyan[*] Watching telemetry streams...$cReset"
    Get-Content -Path $Found -Wait -Tail 0 | ForEach-Object { Process-Telemetry -Line $_ }
}