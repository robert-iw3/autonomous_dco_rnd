# 5_Lateral_Movement -- Adversarial Corpus Manifest

**MITRE Tactic:** TA0008 -- Lateral Movement
**Source tools:** `arcanaeum/offsec/ttps/5_Lateral_Movement/`
**Script:** `stage_lateral_movement_behavioral.py`
**Pipeline target:** `make stage-lateral` / `make data-lateral`

---

## Detection Philosophy

Lateral movement tools exploit the same APIs and protocols used by legitimate remote
administration. The behavioral discriminators are:

1. **Context** -- who initiates it, from what process, at what time. Legitimate admin RPC/WMI
   comes from SCCM service accounts on scheduled cycles; adversarial use comes from interactive
   sessions on compromised hosts at arbitrary times.
2. **Lifecycle** -- adversarial techniques often have a create→execute→cleanup lifecycle
   (service modification reverted, task deleted within seconds) that legitimate deployments never show.
3. **Sequence** -- specific API chains (ChangeServiceConfigA after QueryServiceConfigA followed
   immediately by cleanup; WmiPrvSe.exe spawning cmd.exe; tscon.exe from SYSTEM) are definitional.
4. **Scale** -- credential relay in <3 seconds, SSH chains deeper than 2 hops, subnet sweeps
   at machine-generated timing all indicate automation, not human administration.

---

## Tool Classes

### 1. SCMServiceHijack
**Source:** `SCShell/`, `Invoke-SMBRemoting/`, `SharpLateral/`
**Sensor:** `sysmon_sensor` → `windows_math`
**MITRE:** T1021.002, T1543.003

**Detection teaches:**
- `ChangeServiceConfigA` on an existing service (QueryServiceConfig first = preserved original)
- Binary path replaced with `cmd.exe /c ...`, temp-path binary, or encoded PowerShell
- `StartServiceA` immediately after → execution
- Binary path restored after execution = anti-forensic cleanup
- Sysmon Event 13: `HKLM\...\Services\<svc>\ImagePath` written then restored within seconds

**Admin FP:** SCCM service deployment uses signed binary in C:\Program Files, no cleanup cycle.

---

### 2. WMILateralExec
**Source:** `Amnesiac/Tools/Invoke-WMIRemoting.ps1`, `SharpLateral/Lateral/RedWMI.cs`
**Sensor:** `sysmon_sensor`
**MITRE:** T1047

**Detection teaches:**
- `WmiPrvSe.exe` spawning unexpected child processes (Event ID 4688 / Sysmon Event 1)
- Preceding Event 4624 type-3 logon from attacker IP + Event 4648 explicit creds
- No prior scheduled maintenance context for WMI invocation
- Process lineage: `svchost.exe → WmiPrvSe.exe → cmd.exe` (cross-host RCE)

**Admin FP:** SCCM WMI inventory uses Win32_Service (read-only), no Win32_Process.Create.

---

### 3. ScheduledTaskLateral
**Source:** `SharpLateral/Lateral/RedAtExec.cs`, `Amnesiac/Tools/Suntour.ps1`
**Sensor:** `sysmon_sensor`
**MITRE:** T1053.005, T1021

**Detection teaches:**
- Remote task creation (Event 4698) → immediate exec → deletion (Event 4699) in <30 seconds
- Task action contains Base64-encoded PowerShell or temp-path binary
- Task name randomized or masquerading as system path
- `RunAs=SYSTEM` for task with no admin deployment context
- Trigger = immediate (not time-based) = one-shot execution pattern

**Admin FP:** IT tasks have descriptive names, weekly/daily triggers, persist days, service account.

---

### 4. DCOMHTAExecution
**Source:** `LethalHTA/` (Native, DotNet, CobaltStrike variants)
**Sensor:** `network_tap`
**MITRE:** T1021.003

**Detection teaches:**
- RPC port 135 connection → HTTP GET for .hta URL within 5 seconds = DCOM + HTA pattern
- `mshta.exe` spawned on target with parent `svchost.exe` (DCOM activation context)
- No user interaction on target machine
- CLSID `3050F4D8-98B5-11CF-BB82-00AA00BDCE0B` (HTA file class) requested via CLSCTX_REMOTE_SERVER

**Admin FP:** User-initiated HTA via file share (no DCOM remote activation, user-initiated).

---

### 5. DCOMMMCExecution
**Source:** `SharpLateral/Lateral/DcomExec.cs`, writeup `t1175-distributed-component-object-model.md`
**Sensor:** `sysmon_sensor`
**MITRE:** T1021.003

**Detection teaches:**
- `mmc.exe` spawned with parent `svchost.exe` (DCOM activation) -- not `explorer.exe`
- CLSID `49B2791A-B1AE-4C90-9B8E-E860BA07F889` (MMC20.Application) + `ExecuteShellCommand()`
- RPC 135 connection immediately preceding `mmc.exe` creation
- No user MMC session preceding the spawn

**Admin FP:** User-launched MMC has `explorer.exe` parent (not svchost DCOM activation).

---

### 6. DCOMCOMHijackLateral
**Source:** `BitlockMove/`, `SpeechRuntimeMove/`
**Sensor:** `sysmon_sensor`
**MITRE:** T1021.003, T1574.001

**Detection teaches:**
- Remote registry write to `HKCU\Software\Classes\CLSID\{...}\InProcServer32` (Sysmon Event 13)
- DLL dropped via SMB to AppData/Temp path (Sysmon Event 11)
- DCOM activation triggers `BaaUpdate.exe` or `SpeechRuntime.exe` loading hijacked DLL (Sysmon Event 7)
- 4-step sequence: registry write → DLL drop → DCOM trigger → DLL load
- DLL unsigned, in user-writable path
- Registry key cleaned up post-execution (anti-forensic)

**Admin FP:** Legitimate COM registration writes to HKLM (not HKCU), is local (not remote), signed binary.

---

### 7. MSILateralExecution
**Source:** `msi_lateral_mv/`
**Sensor:** `sysmon_sensor`
**MITRE:** T1021.003

**Detection teaches:**
- `IMsiCustomAction::SQLInstallDriverEx()` invoked via DCOM without preceding `msiexec.exe` parent
- Unsigned ODBC DLL placed in temp/ProgramData path
- ODBC registry key created (`HKLM\SOFTWARE\ODBC\ODBCINST.INI\<attacker_name>`)
- DLL executes as SYSTEM in MSI Server process -- no visible process creation
- No Software Center / change ticket context

**Admin FP:** SCCM uses `msiexec.exe` with signed package, standard ODBC paths, change ticket.

---

### 8. NTLMRelayLateral
**Source:** `lateral-movement-writeups/lateral-movement-via-smb-relaying...`
**Sensor:** `network_tap`
**MITRE:** T1557.001, T1021.002

**Detection teaches:**
- Forced authentication trigger (UNC path, HTML img src, SCF file)
- Same `NTLMv2` credential hash used to authenticate to a second host within 2-3 seconds
- SMB signing disabled on relay target: `NTLMSSP SIGNING_NOT_REQUIRED` flag
- Post-relay action (service creation, file write) on target using relayed identity

**Admin FP:** Monitoring service account authenticates to two hosts but via Kerberos (not NTLM) with >30s gap.

---

### 9. PassTheHashLateral
**Source:** `Amnesiac/Tools/Token-Impersonation.ps1`, SCShell (-hashes), scshell.py
**Sensor:** `sysmon_sensor`
**MITRE:** T1550.002, T1021

**Detection teaches:**
- `LogonUser` with `LOGON32_LOGON_NEW_CREDENTIALS (type 9)`: creates token with hash, no cleartext
- No corresponding `Event 4624` interactive logon for the impersonated account
- `ImpersonateLoggedOnUser` → child process or network auth with different token context
- Event 4648 (explicit credential use) without accompanying password reset/change event

**Admin FP:** PsExec produces type-3 network logon (not type-9), signed tool, change ticket.

---

### 10. LAPSCredentialExtract
**Source:** `DecryptRecoveryLAPS_RPC/`
**Sensor:** `sysmon_sensor`
**MITRE:** T1552.004, T1003

**Detection teaches:**
- Custom RPC service on DC with non-Microsoft UUID (not in standard Windows RPC registry)
- LDAP queries from DC process context for `ms-Mcs-AdmPwd` attribute at scale
- Kerberos S4U2Self requests: machine account token used without interactive logon
- Service binary co-located with legitimate `lapsutil.dll` (masquerade)
- Multiple computer objects queried in sequence (scope suggests bulk extraction)

**Admin FP:** Microsoft LAPS PowerShell: standard LDAP, helpdesk account, single computer, no custom RPC.

---

### 11. TGTPKINITExtract
**Source:** `Amnesiac/Tools/Invoke-GrabTheHash.ps1`, `TGT_Monitor.ps1`
**Sensor:** `sysmon_sensor`
**MITRE:** T1649, T1550.002

**Detection teaches:**
- Certificate request to CA from non-autoenrollment process (certlm.msc is scheduled/policy)
- Kerberos AS-REQ with PKINIT preauth: certificate-based TGT without password
- UnPAC-the-Hash: TGT PAC structure parsed to extract NTLM hash
- Optional: TGT stored in `HKLM\SOFTWARE\MONITOR` registry (attacker persistence)
- LDAP queries to CA for template enumeration preceding cert request

**Admin FP:** Autoenrollment via certlm.msc -- GPO scheduled, no hash extraction, no registry store.

---

### 12. RDPSessionHijack
**Source:** `SessionExec/`, `lateral-movement-writeups/t1076-rdp-hijacking-for-lateral-movement.md`
**Sensor:** `sysmon_sensor`
**MITRE:** T1563.002

**Detection teaches:**
- `tscon.exe` executed with parent in SYSTEM context (not user-initiated)
- `WTSEnumerateSessions` + `WTSQuerySessionInformation` preceding `tscon.exe`
- Event 4779 (victim session disconnected) followed by Event 4778 (session reconnected by different account)
- No user action on victim workstation (no mouse/keyboard events preceding disconnect)

**Admin FP:** User self-reconnect: same account in both 4778/4779, user-initiated, no tscon.exe.

---

### 13. WinRMLateral
**Source:** `lateral-movement-writeups/t1028-winrm-for-lateral-movement.md`, Amnesiac
**Sensor:** `network_tap`
**MITRE:** T1021.006

**Detection teaches:**
- Inbound WinRM (port 5985/5986) from host not in IT admin group
- `wsmprovhost.exe` spawning unexpected child processes on target
- Off-hours connection with no associated change ticket
- Connections from compromised workstations (not known management servers)

**Admin FP:** IT admin from approved management workstation during business hours with change ticket.

---

### 14. NamedPipeShellLateral
**Source:** `Invoke-SMBRemoting/`, `Amnesiac/Tools/Invoke-SMBRemoting.ps1`
**Sensor:** `sysmon_sensor`
**MITRE:** T1021.002, T1059.001

**Detection teaches:**
- Service creation (Event 7045) with binary path = `cmd.exe /c powershell.exe -enc ...`
- Named pipe creation immediately after service start (Sysmon Event 17)
- Pipe name random (not vendor-format like `MSSQL$...`)
- Service terminates after pipe establishment (anti-persistent pattern)
- Pipe connects back to attacker source host

**Admin FP:** SQL Server named pipe -- vendor format (MSSQL$), service account, program files binary.

---

### 15. PassiveNetworkDiscovery
**Source:** `passive_sensor/` (Go -- SSDP, mDNS, DHCP, NetBIOS, WS-Discovery)
**Sensor:** `network_tap`
**MITRE:** T1018, T1040

**Detection teaches:**
- Packet capture on multiple broadcast protocols simultaneously (DHCP/SSDP/mDNS/NetBIOS)
- Zero outbound bytes from sniffer process -- completely passive
- Device fingerprinting: MAC/OUI + hostname + OS hint correlation
- Duration: hours-long sustained passive collection
- No registration in network monitoring CMDB

**Admin FP:** Zabbix/Nagios monitoring registered in CMDB, known source, authorized.

---

### 16. ReachableHostScan
**Source:** `CheckReachableHosts/CheckReachableHosts.ps1`, `NBTScan.txt`
**Sensor:** `network_tap`
**MITRE:** T1018, T1046

**Detection teaches:**
- Fan-out TCP connect to 20+ internal hosts on lateral movement ports: 22, 445, 3389, 5985, 135
- Machine-generated timing (inter-probe CV < 0.08)
- NBTScan: NetBIOS Name Service queries (UDP 137) for hostname resolution
- Source host not in IT asset inventory
- Ports targeted specifically for remote execution (not general scanning)

**Admin FP:** Nessus scanner -- CMDB registered, approved scope, bounded ports, change ticket.

---

### 17. SSHSnakePivoting
**Source:** `ssh-snake/Snake.sh`
**Sensor:** `linux_sentinel`
**MITRE:** T1021.004, T1552.004

**Detection teaches:**
- Recursive SSH chain: each compromised host connects to all hosts in its `known_hosts`
- Script delivered via stdin (`bash <<<...`) -- no file on disk
- Private key discovery and immediate use for pivoting
- `bash` child of `sshd`: fileless script execution within SSH session
- SSH chain depth > 2 hops: no legitimate Ansible/automation does this

**Admin FP:** Ansible uses bounded target group, service account, script on disk, depth=1.

---

### 18. FailoverClusterLateral
**Source:** `fustercluck/fustercluck.py`
**Sensor:** `network_tap`
**MITRE:** T1018, T1078

**Detection teaches:**
- DCERPC bindings to cluster service UUID from non-cluster-admin account
- `ApiGetClusterName` + `ApiCreateEnum` for all resource types (nodes/resources/groups/networks)
- `HKLM\Cluster\ResourceData` registry access for VCO credential extraction
- Kerberos S4U2Self for machine account impersonation
- Source not in cluster admin group

**Admin FP:** Cluster admin using Failover Cluster Manager -- authorized role, maintenance window.

---

### 19. AmnesiacHiveDump
**Source:** `Amnesiac/Tools/HiveDump.ps1`, `Invoke-GrabTheHash.ps1`
**Sensor:** `sysmon_sensor`
**MITRE:** T1003.002

**Detection teaches:**
- `reg save HKLM\SAM + SYSTEM + SECURITY` to temp path = credential triad extraction
- Or shadow copy access + .hiv file copy
- Event 4656: SAM object access
- Parent: PowerShell/wscript (not backup tool)
- Output destination: `%TEMP%` or `C:\Windows\Temp` (staging for exfil)

**Admin FP:** ntbackup.exe under backup operator to network backup share -- signed, service account, ticket.

---

### 20. SMBSigningAbuse
**Source:** `lateral-movement-writeups/lateral-movement-via-smb-relaying-by-abusing-lack-of-smb-signing.md`
**Sensor:** `network_tap`
**MITRE:** T1557.001, T1021.002

**Detection teaches:**
- SMB NTLMSSP negotiation with `SIGNING_NOT_REQUIRED` flag (relay tool downgrade)
- Credential captured from victim relayed to third target in <3 seconds
- SMB signing disabled on target host
- Post-relay action: service creation, file write, registry modification on target with relayed creds

**Admin FP:** SMB signing misconfigured (not disabled by attacker) on legacy host, no active relay.

---

### 21. WormSelfPropagation
**Source:** `Framework-Botnet/NetworkSpreader.cpp`
**Sensor:** `network_tap`
**MITRE:** T1210, T1570

**Detection teaches:**
- **Infected host immediately scans adjacent /24 subnet** after initial compromise -- no legitimate deployment tool scans from its targets
- **Identical payload hash on all compromised hosts** -- each target receives the same binary, confirming self-replication (not a targeted admin push)
- **Latency from compromise to scan** is seconds-to-minutes (fully automated) -- no human operator between generations
- **Gen1 hosts become scanners**: each newly compromised host begins pushing to its own /24 -- exponential fan-out with correlated hashes visible across multiple source IPs
- Observable at the network level as: rapid sequential fan-out to new subnets + cross-subnet payload push (SMB port 445, WMI 135, WinRM 5985, or SSH 22) from hosts that were just targeted

**Admin FP discriminator:** SCCM/Ansible deployments push to a pre-defined CMDB host list -- targets never become scanners, payload is signed, source is always the management server, and a change ticket pre-authorizes the scope.

---

### 22. BloodHoundAttackPath
**Sensor:** `sysmon_sensor` | **MITRE:** T1069.002, T1078.003

SharpHound LDAP burst (200 queries/min on ACL/session/group objects) followed within 120s by automated AD group modification + lateral logins to 3-8 hosts = BloodHound path execution. Human operators take hours; automated exploitation is seconds. FP: authorized read-only AD audit at 3 queries/min with change ticket.

---

### 23. SCMSupplyChainLateral
**Sensor:** `sysmon_sensor` | **MITRE:** T1543.003, T1021.002

Monitoring/security agent (Splunk, Nessus, SolarWinds) loads unsigned DLL from its install directory after DLL replacement, then opens unexpected outbound C2 connection -- lateral via trusted agent's network access. FP: vendor signed DLL in auto-update (signed, vendor service parent, change ticket).

---

### 24. MaliciousOAuthLateral
**Sensor:** `sysmon_sensor` | **MITRE:** T1550.001, T1528

PROCESS_ALL_ACCESS (0x1F0FFF) on Edge/Chrome process → MSAL token cache files read by non-browser process → Microsoft Graph API calls from implant.exe (not the browser) = stolen refresh token replayed for cloud lateral movement without credentials. FP: Token Broker (0x1000) refreshing browser's own tokens.

---

## Training Output

Default run (`--records-per-class 10 --admin-fps-per-class 2`):
- **240 true-positive records** -- lateral movement behavioral patterns
- **48 false-positive records** -- legitimate IT activity that looks similar

Total: **288 SFT training records** across 3 sensor types:
- `sysmon_sensor` (windows_math): 15 classes
- `network_tap` (c2_math): 8 classes
- `linux_sentinel` (sentinel_math): 1 class (SSHSnakePivoting)

### MSSQLLateral *(migrated from tools/)*
**Sensor:** `network_tap` | **MITRE:** T1021.002

dst_port=1433 to internal targets with count > 5 from single src. xp_cmdshell / linked server / CLR assembly abuse. FP: Authorized DBA connection with ticket.

---

### EntraTokenHijack *(migrated from tools/)*
**Sensor:** `azure_entraid` | **MITRE:** T1528, T1021

Refresh/access token reused from different IP across multiple Azure services. S3 query: None (azure_entraid not in SENSOR_COLUMNS). FP: VPN IP change for authorized employee.

---

### PAExecLateral *(migrated from tools/)*
**Sensor:** `network_tap` | **MITRE:** T1021.002, T1543.003

dst_port=445 to internal hosts with high packet count (> 50 packets_src). Service binary written and started via SMB. FP: Authorized SCCM software push with ticket.

---

### SCCMHunterLateral *(migrated from tools/)*
**Sensor:** `network_tap` | **MITRE:** T1072, T1021

HTTP requests to /SMS_MP/ or /AdminService/ endpoints. SCCM management API abuse for lateral movement via trusted management channel. FP: Authorized SCCM admin console traffic.

---

## S3 Query Patterns

Track 6 behavioral filters for live telemetry matching:
- SCMServiceHijack: Event 13 on Services\ImagePath from non-Program Files
- WMILateralExec: Event 1 with WmiPrvSe.exe parent spawning cmd/ps
- ScheduledTaskLateral: Event 1 with schtasks /create + encoded payload
- NTLMRelayLateral: SMB 445 to multiple internal hosts within 3 seconds
- RDPSessionHijack: Event 1 with tscon.exe running as SYSTEM
- WinRMLateral: Inbound WinRM ports 5985/5986
- PassiveNetworkDiscovery: UDP broadcast protocols with zero outbound bytes
- ReachableHostScan: TCP fan-out to 20+ hosts on lateral movement ports
- SSHSnakePivoting: ssh binary child of sshd with -i flag
- AmnesiacHiveDump: Event 1 with reg save targeting SAM/SYSTEM/SECURITY
- WormSelfPropagation: lateral movement ports to 10+ hosts with sessions < 2s avg duration
