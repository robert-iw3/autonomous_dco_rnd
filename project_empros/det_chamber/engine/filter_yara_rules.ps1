# filter_yara_rules.ps1
     param (
         [string]$SourceDir = "E:\YARA\Rules",
         [string]$OutputFile = "E:\YARA\windows_x64_rules.yar"
     )

     # Regex pattern for Windows 10, 11, Server 2016, 2019, 2022, 2025 x64
     $pattern = "Windows (10|11)|Server(2016|2019|2022|2025)|x64|pe|dll|exe"
     try {
         $ruleFiles = Get-ChildItem -Path $SourceDir -Recurse -Include *.yar,*.yara -ErrorAction Stop
         if (-not $ruleFiles) {
             Write-Error "No YARA rule files found in $SourceDir"
             exit 1
         }

         # Initialize output
         $filteredRules = @()

         foreach ($file in $ruleFiles) {
             $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
             if ($content -match $pattern -or ($content -match 'meta:.*platform\s*=\s*["'']?windows x64["'']?')) {
                 $filteredRules += $content
                 Write-Host "Included rule: $($file.FullName)"
             }
         }

         if (-not $filteredRules) {
             Write-Error "No rules matched Windows x64 criteria"
             exit 1
         }

         # Write to output file
         $filteredRules | Out-File -FilePath $OutputFile -Encoding UTF8 -ErrorAction Stop
         Write-Host "Compiled YARA rules to $OutputFile"
     } catch {
         Write-Error "Error filtering YARA rules: $_"
         exit 1
     }