# 2_Persistence -- Adversarial Corpus Manifest

**MITRE Tactic:** TA0003 -- Persistence
**Source tools:** `arcanaeum/offsec/ttps/2_Persistence/`
**Script:** `stage_persistence_behavioral.py`
**Pipeline target:** `make stage-persistence` / `make data-persistence`

---

## Detection Philosophy

Persistence mechanisms are characterized by three properties detectable in telemetry:

1. **Location** -- where the mechanism is planted (registry path, file path, service name, cron entry). Adversarial locations are temp directories, non-vendor paths, or system locations accessed by non-installer processes.
2. **Trigger** -- what causes the payload to execute (boot, login, WMI event, cron schedule). Adversarial triggers maximize stealth and coverage.
3. **Lineage** -- what process created the persistence artifact. Adversarial lineage chains (script host → registry write; web worker → file create) don't match legitimate deployment pipelines.

Every tool class includes **admin false-positive variants** defining exactly what makes the same telemetry signal legitimate. The model must learn to distinguish these.

---

## Tool Classes

### 1. RegistryRunKey
**Source:** `windows/AutoRuns/` (enumeration), `windows/ ImageFileExecutionOptions.ps1`, general technique
**Sensor:** `windows_deepsensor` → `windows_math`
**MITRE:** T1547.001

**Detection teaches:**
- **Sysmon Event 13 / Event 4657** at `HKCU\...\Run`, `HKLM\...\Run`, `RunOnce`, `RunServices`
- Parent process is the discriminator: `msiexec.exe` writing to Run = software installer; `powershell.exe`, `wscript.exe`, `WINWORD.EXE` writing to Run = malware
- Value data path: `C:\Program Files\` = legitimate; `%TEMP%\`, `%APPDATA%\`, `C:\ProgramData\` (non-vendor) = adversarial
- Unsigned binary at the Run key destination confirms malicious intent

**Admin FP discriminator:** Vendor installer (msiexec), signed binary, C:\Program Files, change ticket.

---

### 2. IFEODebuggerHijack
**Source:** `windows/ ImageFileExecutionOptions.ps1`
**Sensor:** `windows_deepsensor`
**MITRE:** T1546.012

**Detection teaches:**
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>` with `Debugger` value
- `HKLM\...\SilentProcessExit\<target.exe>` with `ReportingMode=1` + `MonitorProcess` (stealthy variant)
- Special targets: `sethc.exe` (Sticky Keys), `utilman.exe` (Accessibility Menu) → pre-logon SYSTEM access
- Runtime signal: unexpected parent (debugger) spawned before target process

**Admin FP discriminator:** Only the WinDbg binary in Windows SDK path on a developer workstation with a debug ticket is legitimate.

---

### 3. ScheduledTask
**Source:** `windows/techniques/`, general technique
**Sensor:** `windows_deepsensor`
**MITRE:** T1053.005

**Detection teaches:**
- **Event ID 106** (Task Registered), **140** (Task Updated) -- the creation events
- Task action reveals intent: `powershell.exe -EncodedCommand` (obfuscation), `mshta.exe <url>` (remote execution), temp-path batch files
- Task name mimics system tasks (`\Microsoft\Windows\...`) -- camouflage in Task Scheduler
- Trigger = `AtStartup` or `AtLogon` + `RunLevel=Highest` + `Principal=SYSTEM` = adversarial combination
- `Hidden=True` flag deliberately conceals task from Task Scheduler UI

**Admin FP discriminator:** Service account (not SYSTEM), signed binary in Program Files, business-hours trigger, change ticket, visible in Task Scheduler.

---

### 4. StartupFolderLNK
**Source:** `payload-gen/Out-Shortcut.ps1`, `windows/new-shortcut.ps1`
**Sensor:** `windows_deepsensor`
**MITRE:** T1547.001

**Detection teaches:**
- **Sysmon Event 11** (FileCreate) in Startup paths: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` or `C:\ProgramData\Microsoft\...\Startup\`
- **LNK WindowStyle**: `2` (Hidden) or `7` (Minimized) -- adversarial; `1` (Normal) = legitimate
- LNK TargetPath in `%TEMP%\`, `%APPDATA%\`, non-vendor path = adversarial
- Parent process creating the LNK: `wscript.exe`, `mshta.exe`, Office apps = adversarial; `msiexec.exe` = legitimate

**Admin FP discriminator:** Vendor installer, target in C:\Program Files, WindowStyle=Normal, signed binary.

---

### 5. WindowsServiceInstall
**Source:** general Windows technique
**Sensor:** `windows_deepsensor`
**MITRE:** T1543.003

**Detection teaches:**
- **Event ID 7045** (Service Installed) -- log every new service
- `ImagePath` in `%TEMP%`, `%APPDATA%`, `C:\Windows\Temp`, `C:\ProgramData` (non-vendor) = adversarial
- `StartType = 2` (AUTO_START) + `ObjectName = LocalSystem` + unsigned binary = adversarial triple
- `install_source = interactive_user_session` (not SCCM/Ansible/msiexec) = suspicious
- Generic service name mimicking system services for camouflage

**Admin FP discriminator:** SCCM deployment, C:\Program Files path, signed by vendor, LocalService account (not LocalSystem), change ticket.

---

### 6. WMISubscription
**Source:** general Windows technique, `windows/CcmMessagingBackdoor/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1546.003

**Detection teaches:**
- Three-component pattern: `__EventFilter` + `__EventConsumer` + `__FilterToConsumerBinding` in CIM repository
- Consumer type `CommandLineEventConsumer` with PowerShell or cmd.exe command = adversarial
- Consumer type `ActiveScriptEventConsumer` (VBScript execution) = adversarial
- Filter query using `Win32_LocalTime` (timer) or `Win32_Process` creation = common triggers
- **WMI Activity Event IDs 5857, 5858, 5861** -- WMI subscription activity logs
- **Fileless**: no registry Run key, no startup folder -- standard persistence checkers miss this

**Admin FP discriminator:** Documented vendor subscription (Splunk, SCCM) with signed binary in Program Files, referenced in vendor install guide.

---

### 7. DLLSideloading
**Source:** `windows/dll-sideloading/` (version.dll hijack via VEH hook)
**Sensor:** `windows_deepsensor`
**MITRE:** T1574.002

**Detection teaches:**
- **Sysmon Event 7** (ImageLoad): DLL loaded from application directory instead of System32
- Specific targets: `version.dll`, `dbghelp.dll`, `winmm.dll`, `cryptbase.dll` -- commonly sideloaded against OneDrive.exe, Teams.exe, Zoom.exe
- DLL is **unsigned** while the legitimate system DLL is always Microsoft-signed
- DLL exports **forward all functions** to the legitimate DLL (masquerade as real)
- **VEH (Vectored Exception Handler)** registration on `CreateWindowExW` -- function hooking technique from the dll-sideloading source code
- Legitimate process (OneDrive, Teams) making unexpected outbound network connections

**Admin FP discriminator:** Vendor-shipped DLL in application directory is signed by the same vendor as the application and documented in the install manifest.

---

### 8. GPOAbuse
**Source:** `windows/pyGPOAbuse/`
**Sensor:** `azure_entraid` → `cloud_flow`
**MITRE:** T1484.001

**Detection teaches:**
- **LDAP modify** on `gPCFileSysPath`, `gPCMachineExtensionNames`, or `gplink` attributes
- **SMB write** to `\\DC\SYSVOL\Policies\<GPO-GUID>\Machine\Preferences\ScheduledTasks\`
- Scheduled task XML injected in SYSVOL automatically replicates to all domain-joined machines (every 90–120 minutes)
- Task action = encoded PowerShell or temp-path binary = malicious payload
- **Blast radius**: estimated affected machines = all computers in the linked OU or domain

**Admin FP discriminator:** Dedicated GPO admin service account, maintenance window, CISO/change management approval, task XML points to signed binary in Program Files.

---

### 9. IPPrintC2
**Source:** `windows/IPPrintC2/`
**Sensor:** `network_tap` → `c2_math`
**MITRE:** T1071.002, T1505

**Detection teaches:**
- HTTP/HTTPS requests to `/printers/<name>/.printer` on **external IP** -- legitimate print servers are internal
- **Print job names are base64-encoded** -- commands disguised as document names
- **Printer port added** to system -- persistence mechanism for the polling loop
- **Regular polling interval** with low CV -- machine-generated schedule
- **Microsoft-Windows-PrintService/Operational Event ID 300** (printer creation) + **307** (document printed) -- print event logs as C2 log
- Traffic blends into normal enterprise print service communication

**Admin FP discriminator:** Internal destination server (`is_internal_dst=YES`), corp PKI certificate, descriptive human-readable job names, server registered in print CMDB.

---

### 10. WebShellPersist
**Source:** `windows/sharpyshell/` (SharPyShell ASPX webshell)
**Sensor:** `windows_deepsensor`
**MITRE:** T1505.003

**Detection teaches:**
- **File creation in IIS web root** (`C:\inetpub\wwwroot\`) by `w3wp.exe` or `powershell.exe` -- web worker never creates files during normal operation
- **csc.exe spawned from w3wp.exe** -- SharPyShell compiles C# payload at runtime, generating in-memory assembly
- **Child processes from w3wp.exe**: `cmd.exe`, `powershell.exe`, `whoami.exe` -- OS command execution via web shell
- **HTTP POST to non-standard URI** with encrypted body -- web shell command channel
- IIS logs confirm shell invocation via request timestamps

**Admin FP discriminator:** `msdeploy.exe` or CI/CD deployment tool writing files, no child OS processes spawned, deployment pipeline ticket.

---

### 11. CcmBackdoor
**Source:** `windows/CcmMessagingBackdoor/` (RogueCcmEndpoint.cs, wmi_create_rogue_service_endpoint.ps1)
**Sensor:** `windows_deepsensor`
**MITRE:** T1546.015

**Detection teaches:**
- **RegAsm.exe** registering a .NET assembly as a COM server -- creates CLSID in registry
- **WMI service endpoint object created** -- hijacks CCM messaging channel for C2
- **C2 destination is external** (not internal SCCM management point) -- definitional signal
- **Source binary is unsigned and in %TEMP%** -- not a legitimate CCM component
- Persistence via WMI endpoint object survives reboots without Run keys or services -- no standard persistence checkers detect this

**Admin FP discriminator:** Microsoft-signed binary in C:\Program Files\Configuration Manager, registered by CCMSetup.exe.

---

### 12. LinuxCronPersistence
**Source:** `nix/PANIX/` (comprehensive Linux persistence framework)
**Sensor:** `linux_sentinel` → `sentinel_math`
**MITRE:** T1053.003

**Detection teaches:**
- Write to `/etc/cron.d/`, `/var/spool/cron/crontabs/`, or `/etc/cron.hourly/` by non-cron process
- **Cron entry content reveals intent**: `/dev/tcp/<ip>/<port>` redirect = reverse shell; `curl <url> | bash` = download-execute; `/tmp/` or `/var/tmp/` path = malware
- `@reboot` trigger = boot persistence; `*/5 * * * *` = frequent callback; hourly = persistent C2 reconnect
- Written by interactive shell process (`bash`, `python3`) rather than package manager or config management tool

**Admin FP discriminator:** Written by root via SSH session, script in `/usr/sbin/` or `/usr/local/bin/`, documented in runbook, change ticket.

---

### 13. SystemdService
**Source:** `nix/PANIX/`
**Sensor:** `linux_sentinel`
**MITRE:** T1543.002

**Detection teaches:**
- New `.service` unit file in `/etc/systemd/system/` created by non-package-manager process
- **ExecStart path** in `/tmp/`, `/var/tmp/`, `/dev/shm/`, or home directory = adversarial; `/usr/bin/`, `/opt/vendor/` = legitimate
- `Restart=on-failure` -- self-healing persistence that survives `kill`
- `User=root` -- unnecessary for most monitoring agents
- Outbound connection immediately after service start = C2 callback

**Admin FP discriminator:** Ansible/Salt/Chef deployment, binary in `/usr/local/bin/` or `/opt/`, dedicated non-root service account, documented in runbook.

---

### 14. PAMBackdoor
**Source:** `nix/PANIX/`
**Sensor:** `linux_sentinel`
**MITRE:** T1556.003

**Detection teaches:**
- Modification of `/etc/pam.d/sshd`, `/etc/pam.d/login`, `/etc/pam.d/sudo`, `/etc/pam.d/common-auth`
- `pam_exec.so` pointing to `/tmp/` script -- executes arbitrary command at every auth attempt
- `auth sufficient pam_permit.so` -- bypasses all authentication (most dangerous variant)
- Unsigned custom `.so` in `/lib/x86_64-linux-gnu/security/` -- not from package manager
- **Honeypot indicator**: authentication succeeds for a known-invalid username = master backdoor password active

**Admin FP discriminator:** Vendor-signed PAM module (Google Authenticator, Duo), documented in vendor guide, change ticket.

---

### 15. LDPreloadBackdoor
**Source:** `nix/PANIX/`
**Sensor:** `linux_sentinel`
**MITRE:** T1574.006

**Detection teaches:**
- Write to `/etc/ld.so.preload` -- the system-wide library injection mechanism
- Library path in `/tmp/`, `/var/tmp/`, or hidden directory -- not a package-managed path
- Library not found in `dpkg -l` / `rpm -qa` output -- not installed by package manager
- Hooks on `execve`, `connect`, `open` -- credential capture and network redirection
- **Universal injection**: every process on the system loads the malicious library

**Admin FP discriminator:** Package-managed library (gperftools), temporary use (bounded time window), change ticket, library in `/usr/lib/`.

---

### 16. LKMRootkit
**Source:** `nix/linux-rootkits/`, `nix/blackbox-ave/`
**Sensor:** `linux_sentinel`
**MITRE:** T1547.006

**Detection teaches:**
- `insmod` or `modprobe` of `.ko` file from non-standard path (not `/lib/modules/$(uname -r)/`)
- Unsigned kernel module -- legitimate modules are signed with the kernel build key
- **Self-hiding**: module absent from `/proc/modules` and `lsmod` after load -- definitional rootkit
- Process and file hiding via `filldir` VFS hook -- standard userspace tools return false data
- Syscall table hooks on `sys_read`, `sys_getdents`, `sys_kill` -- kernel-level interception
- **Critical**: once a LKM rootkit is confirmed, DO NOT trust userspace forensic tools -- boot from live media

**Admin FP discriminator:** DKMS-managed module in `/lib/modules/`, signed with kernel build certificate, visible in `lsmod`.

---

### 17. EBPFRootkit
**Source:** `nix/TripleCross/` (eBPF rootkit with library injection, execution hijacking, covert backdoor)
**Sensor:** `linux_sentinel`
**MITRE:** T1014, T1056.004

**Detection teaches:**
- `bpf()` syscall invocation for `BPF_PROG_TYPE_TRACEPOINT`, `BPF_PROG_TYPE_KPROBE`, or `BPF_PROG_TYPE_XDP` from unexpected context
- `sys_execve` tracepoint hook -- intercepts all process executions
- **`/proc/<pid>/mem` write** -- GOT (Global Offset Table) patching: redirects function calls in target processes without touching the binary on disk
- **Covert trigger**: crafted TCP packet with specific IP ID field or TCP sequence number activates backdoor without a persistent listener -- inspired by NSA Bvp47 and CIA Hive techniques
- Phantom shell: commands overlaid on existing TCP connections (no new ports opened)

**Admin FP discriminator:** Interactive `bpftrace`/`perf` session, no `/proc/mem` writes, no network covert triggers, bounded time window, change ticket.

---

### 18. AuthorizedKeysBackdoor
**Source:** `nix/PANIX/`, `1_Recon/harvesting/SSH-Stealer`
**Sensor:** `linux_sentinel`
**MITRE:** T1098.004

**Detection teaches:**
- Write to `~/.ssh/authorized_keys` or `/root/.ssh/authorized_keys` by a process that is not an IdM provisioning tool (Vault, Puppet, cfn-init)
- **No corresponding provisioning event in IdM** -- adversarial keys are added directly, bypassing the change management system
- Key comment reveals attacker infrastructure (`root@kali`, `attacker`, random string)
- **Immediate successful SSH login** from external IP within seconds of the write -- key was tested immediately

**Admin FP discriminator:** HashiCorp Vault SSH engine, automated key rotation, IdM event present, time-limited TTL.

---

### 19. TokenImpersonation
**Source:** `privesc/SweetPotato/`, `privesc/rustpotato/`, `privesc/lpe-setcbprivilege/`, `privesc/lpe_via_storsvc/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1134.001

**Detection teaches:**
- API sequence: `OpenProcess` → `OpenProcessToken(TOKEN_ALL_ACCESS)` → `DuplicateTokenEx` → `CreateProcessWithTokenW` -- definitional token theft
- **EventID 4672** (Special Privileges Assigned to New Logon) with logon session type 3 (Network) despite local execution -- session type anomaly
- Triggers: BITS service CLSID, WinRM local auth, EfsRpc CreateFile, PrintSpooler -- known impersonation attack vectors
- Result: SYSTEM token process spawned from user-level parent
- StorSvc variant: `SvcRebootToFlashingMode` RPC call → SprintCSP.dll loaded from writable SYSTEM PATH → SYSTEM shell

**Admin FP discriminator:** PsExec with IT admin service account has a change ticket. No legitimate admin operation requires token duplication from SERVICE context.

---

### 20. ContainerMOTWBypass
**Source:** `payload-gen/packmypayload/` (ISO/VHD/IMG/ZIP MOTW bypass)
**Sensor:** `windows_deepsensor`
**MITRE:** T1553.005

**Detection teaches:**
- **ISO/VHD/IMG file download** with social engineering filename (invoice, contract, resume)
- **Auto-mount event** (Windows 8+): new drive letter assigned automatically on double-click
- **MOTW (Mark-of-the-Web)**: container file has `Zone.Identifier ZoneId=3` (internet), but **inner files have no MOTW** -- Windows does not propagate MOTW into mounted containers
- Result: SmartScreen and Office Protected View are bypassed for all files inside the container
- Executable inside container launches **without SmartScreen check** despite being internet-sourced

**Admin FP discriminator:** Official vendor OS ISO (e.g., Microsoft Windows ISO from microsoft.com) with all inner binaries signed by the vendor.

---

### 21. MacOSLaunchPersistence
**Source:** `macos/KnockKnock/` (LaunchAgent/Daemon location enumeration)
**Sensor:** `macos_sensor`
**MITRE:** T1543.001

**Detection teaches:**
- Plist created in `~/Library/LaunchAgents/` or `/Library/LaunchDaemons/` by a process other than an app installer
- **ProgramArguments path** in `/tmp/`, `/var/folders/`, or hidden user config directory -- not `/Applications/` or `/usr/local/`
- `code_signed=False` -- all legitimate vendor LaunchAgents are signed; unsigned plist targets are malware
- `quarantine_flag=False` -- was never marked as internet-downloaded or flag was stripped (MOTW bypass)
- `RunAtLoad=True` -- executes on every user login
- Network connection after launch = C2 callback

**Admin FP discriminator:** Signed vendor app from `/Applications/`, quarantine flag present, bundle identifier matches developer account.

---

### 22. ExcelAddInPersistence
**Source:** `Macro/Backdoor-ExcelAddIn.ps1`
**Sensor:** `sysmon_sensor`
**MITRE:** T1137.006, T1546

**Detection teaches:**
- **Shell process writes `.xlam` or `.xll` to an XLSTART path** (EventID 11) -- legitimate add-ins are deployed by MSI installers or SCCM to `%ProgramFiles%`, never written to `XLSTART` by cmd/powershell/wscript
- XLSTART paths: `%AppData%\Microsoft\Excel\XLSTART\`, `%LocalAppData%\Microsoft\Excel\XLSTART\`, `C:\ProgramData\Microsoft\Excel\XLSTART\` -- user-writable, no elevation required
- On next Excel launch: EventID 7 (ImageLoaded) shows excel.exe loading the .xlam/.xll from the XLSTART path with `Signed=false` -- all corporate add-ins are signed
- **Execution is automatic and silent** on every Excel open -- no user interaction after initial drop; persistence survives reboots and profile migrations

**Admin FP discriminator:** Corporate Excel add-ins are deployed via MsiExec.exe or CcmExec.exe to `%ProgramFiles%\`, are signed by corporate PKI, and carry a deployment change ticket. The parent process (MsiExec/CcmExec vs. cmd/powershell) is the clearest discriminator.

---

### 23. HotkeyLNKChain
**Source:** `pwsh-scripts/Create-HotKeyLNK.ps1`
**Sensor:** `sysmon_sensor`
**MITRE:** T1547.001, T1037.001

**Detection teaches:**
- **LNK file created by a shell process** (not Explorer) with a non-null `HotKey` field pointing to a shell interpreter (cmd.exe, powershell.exe, rundll32.exe, mshta.exe)
- Placed in an autorun-capable path (Startup folder, `SendTo\`) -- combining two execution triggers: on login AND on keypress matching the registered hotkey
- The critical signal: LNK `HotKey` field is set by the attacker-controlled script, not by a user using the Explorer shortcut dialog -- `Image: powershell.exe` vs. `Image: Explorer.exe` as the FileCreate source
- LNK files in startup paths with non-null hotkeys and shell-interpreter targets are structurally distinct from legitimate application shortcuts (which point to signed %ProgramFiles% binaries)

**Admin FP discriminator:** A user creating a Desktop shortcut with a hotkey via Explorer GUI -- `Image: Explorer.exe`, target is a signed application in `%ProgramFiles%`, placed on Desktop (not in Startup), no encoded arguments.

---

### 24. NetshHelperDLL
**Sensor:** `sysmon_sensor` | **MITRE:** T1546.007

`netsh add helper <dll>` registers DLL in `HKLM\SOFTWARE\Microsoft\NetSh` → loads on every future netsh.exe execution. Unsigned DLL from user-writable path = persistent execution hidden from standard persistence scanners. FP: Windows Update installing signed Microsoft netsh helper to System32.

---

### 25. ScreensaverPersistence
**Sensor:** `sysmon_sensor` | **MITRE:** T1546.002

`HKCU\Control Panel\Desktop\SCRNSAVE.EXE` modified to point to attacker .scr PE in user directory -- executes on idle timeout, appearing as normal screensaver activation. FP: user changing screensaver via Control Panel pointing to System32 screensaver.

---

### 26. OfficeMacroTemplate
**Sensor:** `sysmon_sensor` | **MITRE:** T1137.001

`Normal.dotm` written by non-Word/non-IT process (EventID 11) OR Word connecting to external IP for remote template URL (EventID 3) → macro from downloaded .dotm executes on every Word open. FP: IT deploying corporate template from NETLOGON share via GPO (Word parent, NETLOGON path, no internet).

---

### AzureDevOpsPersistence *(migrated from tools/)*
**Sensor:** `azure_entraid` | **MITRE:** T1098, T1552

Off-hours service_connection_secret_read / pipeline YAML modification / PAT creation from external IP. S3 query: None (azure_entraid not in SENSOR_COLUMNS). FP: Authorized sprint pipeline changes during business hours.

---

### VMkatzHypervisorDump *(migrated from tools/)*
**Sensor:** `linux_sentinel` | **MITRE:** T1003.001, T1550

vCenter API VM memory snapshot targeting specific workstation. target_file LIKE '%lsass%' OR '%.vmem' with uid=0. FP: Veeam scheduled backup snapshot (service account, ticket).

---

### NanodumpLSASS *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1003.001, T1027.012

EventID 10: LSASS access with GrantedAccess including memory-read capability (not just 0x1000/0x1400). Dump written to %TEMP% with non-.dmp extension (MDMP magic hidden). FP: WerFault.exe crash analysis (limited access mask, Windows crash dir).

---

### DPAPISecretExtract *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1555.003, T1552.004

PowerShell invoking DPAPI framework (Invoke-PowerDPAPI / SharpDPAPI) targeting browser/credential stores. DPAPI master key registry access followed immediately by outbound connection. FP: Authorized SCCM service account accessing Credential Manager (no outbound).

---

## Training Output

Default run (`--records-per-class 10 --admin-fps-per-class 2`):
- **260 true-positive records** -- persistence behavioral patterns
- **52 false-positive records** -- legitimate IT activity that looks similar

Total: **312 SFT training records** across 5 sensor types:
- `sysmon_sensor` (windows_math): 17 classes
- `linux_sentinel` (sentinel_math): 7 classes
- `azure_entraid` (cloud_flow): 1 class
- `network_tap` (c2_math): 1 class
- `macos_sensor` (windows_math proxy): 1 class (MacOSLaunchPersistence)

## S3 Query Patterns

Track 6 in `01_spool_datasets.py` uses these behavioral filters for live telemetry matching:
- `RegistryRunKey`: registry_path LIKE Run% AND value NOT in Program Files
- `ScheduledTask`: EventID 106/140 AND action contains powershell/cmd
- `WindowsServiceInstall`: EventID 7045 AND binary outside Program Files
- `WMISubscription`: EventID 5861 AND consumer_type=CommandLineEventConsumer
- `WebShellPersist`: parent=w3wp.exe AND child in (cmd.exe, powershell.exe, csc.exe)
- `LinuxCronPersistence`: write to /etc/cron* by non-cron process
- `SystemdService`: new .service file created by non-package-manager
- `LKMRootkit`: insmod with module path outside /lib/modules/
- `AuthorizedKeysBackdoor`: authorized_keys write with no IdM event
- `IPPrintC2`: HTTP to /printers/*.printer on external destination
- `GPOAbuse`: LDAP modify on Group Policy objects
- `ExcelAddInPersistence`: EventID 11 writing .xlam/.xll to XLSTART by non-installer process
- `HotkeyLNKChain`: EventID 11 writing .lnk to Startup/SendTo path by non-Explorer process

## Extending

When a new persistence technique is added to `arcanaeum/offsec/ttps/2_Persistence/`:
1. Add `_<name>_tp(i)` / `_<name>_fp(i)` functions
2. Add entry to `TOOL_CLASSES` registry
3. Add S3 query to `S3_QUERIES` if telemetry-observable
4. Document in this MANIFEST
5. Run `python stage_persistence_behavioral.py --tool-filter <NewClass>` to validate
