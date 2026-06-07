# LOTL -- Living Off the Land Behavioral Training Corpus

**Category:** 6_LOTL (Living Off the Land Binaries & Scripts)
**Sensor Target:** `sysmon_sensor` / `windows_deepsensor`
**Vector Space:** `windows_math` (4D)
**Script:** `mlops/scripts/stage_lotl_behavioral.py`
**Output:** `mlops/data/staging/lotl_behavioral_v1.jsonl`
**Records (default):** 24 classes × (10 TP + 2 FP) = **288 records**

---

## Detection Philosophy

LOLBAS detection is fundamentally about **behavioral context**, not binary names.
A renamed `mshta.exe` still executes JavaScript. A renamed `certutil.exe` still downloads
files. The model learns **what the binary is doing** -- not which binary is doing it.

Every technique has a legitimate administrative use case that produces similar-looking
telemetry. The FP variants are as important as the TP variants: they teach the model
the discriminating factors (UNC path vs local path, signed vs unsigned, authorized
vs unauthorized parent process).

---

## Tool Classes

| # | Class | MITRE | Key Discriminator |
|---|-------|-------|-------------------|
| 1 | `BinaryProxyMshta` | T1218.005 | mshta.exe spawning cmd/PS (vs signed HTA in Program Files) |
| 2 | `BinaryProxyRegsvr32` | T1218.010 | `/s /n /u /i:<URL> scrobj.dll` vs signed DLL registration |
| 3 | `BinaryProxyRundll32` | T1218.011, T1003.001 | `javascript:` protocol or comsvcs MiniDump vs system functions |
| 4 | `CertutilLOLBin` | T1105, T1140 | `-urlcache` HTTP download to %TEMP% vs `-verify` on .crt |
| 5 | `BITSJobAbuse` | T1197 | User-created BITS job to external IP vs SYSTEM wuauserv to MSFT CDN |
| 6 | `InstallUtilBypass` | T1218.004 | `/U` flag + unsigned temp DLL vs MsiExec + signed vendor DLL |
| 7 | `MSBuildInlineTask` | T1127.001 | CodeTaskFactory + temp .csproj + shell child vs devenv + solution dir |
| 8 | `DnsAdminsDLLAbuse` | T1547.013 | `ServerLevelPluginDll` UNC attacker share vs signed local plugin |
| 9 | `RegistryFilelessLOL` | T1620, T1112, T1547.001 | REG_BINARY DLL blob + null-byte Run key vs small REG_SZ config |
| 10 | `WSHScriptletProxy` | T1059.005 | Script from temp + Office parent + shell child vs NETLOGON GPO script |
| 11 | `OfficeDDEExecution` | T1559.002 | Office spawning cmd.exe (no macro) vs Excel→Excel DDE data link |
| 12 | `PowerShellNetworkC2` | T1059.001, T1071.001 | TcpClient/WebClient C2 beacon vs WinRM on port 5985 corp IP |
| 13 | `WmicProxyExecution` | T1047 | `process call create` + WmiPrvSE.exe child vs read-only wmic inventory |
| 14 | `CmstpBypass` | T1218.003 | `/au` + temp INF + shell child vs signed VPN profile from Program Files |
| 15 | `MsiexecRemoteInstall` | T1218.007 | msiexec `/i <URL>` + outbound HTTP vs SCCM pre-cached signed MSI |
| 16 | `OdbcconfDLLLoad` | T1218.008 | `odbcconf /a {REGSVR ...}` + unsigned temp DLL vs signed ODBC driver install |
| 17 | `RegasmComBypass` | T1218.009 | regasm/regsvcs `/u` + unsigned temp DLL vs MsiExec + signed Program Files DLL |
| 18 | `EsentutlStagingCopy` | T1105, T1003.002, T1003.003 | `/vss` targeting ntds.dit/SAM/SYSTEM vs Exchange DB repair |
| 19 | `DiskshadowScriptExec` | T1490, T1006 | `/s` temp .dsh with exec directive + cmd child vs BackupExec snapshot |
| 20 | `WslBashBypass` | T1202 | wsl/bash from non-dev parent + outbound network vs developer build in terminal |
| 21 | `ForfilesCmdProxy` | T1202 | forfiles `/c "cmd..."` + notepad.exe match trick vs scheduled log delete |
| 22 | `MpCmdRunDownload` | T1105 | MpCmdRun `-DownloadFile` to non-Microsoft IP vs `-SignatureUpdate` from wuauserv |
| 23 | `NTDSUtilIFMDump` | T1003.003 | ntdsutil `ifm create` to temp by non-backup user vs dcpromo IFM to backup share |
| 24 | `VssadminShadowDelete` | T1490 | vssadmin delete shadows `/all /quiet` + ransomware context vs `/oldest` by BackupExec |

---

## Chain-of-Thought Structure

Each record uses 3-axis CoT reasoning:

```
[AXIS 1] Benign Alternative Assessment
  -- What does legitimate use of this binary look like?
  -- Why doesn't this event match that pattern?

[AXIS 2] Behavioral Proof Assessment
  -- What specific indicators confirm malicious LOLBAS use?
  -- Flags, child processes, network connections, registry modifications

[AXIS 3] Entity Coverage
  -- Host, user, technique chain, scope of compromise

[CONCLUSION] Technique name + recommended containment action
TRUE POSITIVE / FALSE POSITIVE
RECOMMENDED_ACTION: contain | dismiss
```

---

## S3 Query Index

Each tool class includes a DuckDB S3 query template for live telemetry correlation.
Full index: `mlops/data/staging/lotl_query_index.json`

```sql
-- BinaryProxyMshta: Sysmon EventID 1 -- mshta child shell
WHERE sysmon_event_id = 1
  AND ParentImage LIKE '%mshta%'
  AND (Image LIKE '%cmd%' OR Image LIKE '%powershell%')

-- BinaryProxyRegsvr32: Sysmon EventID 3 -- regsvr32 outbound
WHERE sysmon_event_id = 3
  AND Image LIKE '%regsvr32%'
  AND Initiated = 'true' AND DestinationPort IN (80,443)

-- CertutilLOLBin: Sysmon EventID 3 -- certutil outbound
WHERE sysmon_event_id = 3
  AND Image LIKE '%certutil%'
  AND Initiated = 'true'

-- DnsAdminsDLLAbuse: Sysmon EventID 13 -- ServerLevelPluginDll registry set
WHERE sysmon_event_id = 13
  AND TargetObject LIKE '%DNS%Parameters%ServerLevelPluginDll%'

-- PowerShellNetworkC2: Sysmon EventID 3 -- PS external non-WinRM
WHERE sysmon_event_id = 3
  AND Image LIKE '%powershell%'
  AND is_internal_dst = false
  AND DestinationPort NOT IN (80,443,5985,5986)
```

---

## Validation

Run the standard corpus validator after staging:

```bash
cd mlops/
python3 scripts/validate_pipeline.py --skip-run
```

Expected: all LOTL checks pass (fields, CoT axes, TP/FP balance, sensor tag, MITRE techniques present).

---

## Key LOLBAS Principles for Model Training

1. **Renamed binary, same behavior** -- The behavioral chain (flags + child process + network) is the signal, not the binary filename. The model must generalize to renamed copies.

2. **Admin FP coverage** -- Every technique has a legitimate admin scenario. The model needs to learn the discriminating boundary (signed vs unsigned, temp vs Program Files, known server vs fresh domain, etc.).

3. **Multi-phase chains** -- LOLBAS often involves 2-3 phases (download → decode → execute, or compile → load → spawn). All phases are captured in telemetry.

4. **AppLocker/AppControl bypass** -- InstallUtil, MSBuild, regsvr32 are specifically chosen because they bypass application whitelisting. The model must understand WHY these binaries are high-value for attackers.

5. **No static signatures** -- No CVE IDs, no hash values, no static IOCs in training data. The corpus forces behavioral generalization.
