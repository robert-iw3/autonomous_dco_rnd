# 4_Bypass_Detection -- Adversarial Corpus Manifest

**MITRE Tactic:** TA0005 -- Defense Evasion
**Source tools:** `arcanaeum/offsec/ttps/4_Bypass_Detection/`
**Script:** `stage_bypass_behavioral.py`
**Pipeline target:** `make stage-bypass` / `make data-bypass`

---

## Detection Philosophy

Defense evasion tools operate by targeting the security stack itself -- AMSI, EDR sensors, kernel callbacks, and Windows security features. The behavioral evidence they leave falls into three observable layers:

1. **Memory operations** -- `VirtualProtect` sequences on security DLLs, cross-process writes to amsi.dll, kernel structure modifications via vulnerable driver IOCTLs.
2. **API sequences** -- unusual combinations of Windows APIs that have no legitimate analog (PROCESS_ALL_ACCESS + EnumProcessModules on amsi.dll + VirtualProtectEx + WriteProcessMemory).
3. **Security infrastructure state changes** -- EDR processes that stop sending telemetry, WFP filters appearing on security product AppIDs, kernel callback arrays with nulled entries, Defender exclusion registry keys for attacker-controlled paths.

Every class includes admin FP variants teaching the model the exact discriminating factor.

---

## Tool Classes

### AMSI Bypass (3 classes)

---

### 1. AMSIInProcessPatch
**Source:** `amsi_bypass/AMSI.fail/`, `amsi_bypass/EByte-Pattern-AmsiPatch/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001

**Detection teaches:**
- `VirtualProtect` sequence on `amsi.dll` .text section: `PAGE_EXECUTE_READ → PAGE_EXECUTE_READWRITE → PAGE_EXECUTE_READ` -- the write-enable → patch → restore cycle
- Patch bytes written to AmsiScanBuffer: `0x31 0xC0 0xC3` (XOR EAX,EAX; RET), `0xC3` (RET), or conditional jump modifications
- Pattern-based approach (EByte): modifies `cmp eax,0x00` → `cmp eax,0xFF` so AMSI_RESULT_CLEAN is always returned
- Obfuscated bypass snippet executed before main PowerShell commands -- covers detection of the bypass itself
- Actor: `powershell.exe` or `pwsh.exe` (the process being bypassed, also doing the bypass)

**Admin FP discriminator:** Windows Defender reads amsi.dll for scanning but uses `PROCESS_VM_READ` only -- no `VirtualProtect` write sequence, no .text section modification.

---

### 2. AMSIRemotePatch
**Source:** `amsi_bypass/EByte-Remote-AMSI-Bypass/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001

**Detection teaches:**
- `PROCESS_ALL_ACCESS` handle on target process (not just PROCESS_VM_READ)
- `EnumProcessModules` to locate amsi.dll in the remote process address space
- `ReadProcessMemory` to parse the export table and find `AmsiScanBuffer` offset
- `VirtualProtectEx` + `WriteProcessMemory` writing `B8 00 00 00 00 C3` (mov eax,0; ret) -- remotely disabling AMSI in another process
- Targets: another PowerShell instance, wscript.exe, mshta.exe

**Admin FP discriminator:** EDR agents open LSASS with `PROCESS_VM_READ` -- they never write to amsi.dll in remote processes.

---

### 3. AMSIThreadRedirect
**Source:** `amsi_bypass/Ebyte-AMSI-ProxyInjector/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001

**Detection teaches:**
- `NtSuspendThread` on ALL threads in target process (not just one) -- atomic operation to prevent race condition
- `VirtualAllocEx` for proxy function allocation in remote process
- `WriteProcessMemory` writing proxy stub (preserves registers, always returns 0)
- JMP instruction written at start of AmsiScanBuffer redirecting to proxy
- `NtResumeThread` restoring all threads

**Admin FP discriminator:** WinDbg suspends a single thread for a breakpoint -- not all threads, no proxy allocation, no JMP write.

---

### EDR Blinding (5 classes)

---

### 4. WFPEDRNetworkBlock
**Source:** `edrsilencer/`, `silent_but_deadly/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.004, T1562.001

**Detection teaches:**
- `FwpmGetAppIdFromFileName0` called on EDR binary paths (SentinelAgent.exe, MsMpEng.exe, etc.)
- WFP provider + sublayer created with weight `0x7FFF` (maximum -- overrides all other rules)
- Filters added to `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (outbound) and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` (inbound) for each EDR
- EDR outbound telemetry drops to zero immediately after filter addition
- Custom `FwpmGetAppIdFromFileName0` implementation (SilentButDeadly): bypasses EDR's own CreateFileW hook -- attacker aware of countermeasures

**Admin FP discriminator:** Corporate GPO firewall rules target application categories (not security products by binary path), are deployed from domain controllers, and use normal sublayer weights.

---

### 5. EDRProcessSuspend
**Source:** `edr-freeze/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001

**Detection teaches:**
- WerFaultSecure service interaction: attacker creates a crash report job targeting an EDR process PID
- EDR process transitions to SUSPENDED state without BYOVD, without kernel exploit
- User-mode operation on fully patched Windows 11 24H2
- Configurable suspension duration (sleep_time parameter)
- Detection window: EDR is operationally blind for the configured duration

**Admin FP discriminator:** WER crash reports target crashed applications (not healthy security processes), initiated by the crash dialog, non-security targets.

---

### 6. BindFilterDLLRedirect
**Source:** `edr-redir/`, `edr_startup_hinder/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001

**Detection teaches:**
- `bindfltapi.dll!BfSetupFilter` called with `virtual_path = EDR install directory`
- Backing path maps to attacker-controlled fake/corrupt directory
- EDR DLLs silently load from fake location -- functions but with attacker-modified components
- EDRStartupHinder variant: monitors EDR PID in a loop, applies bind link on each start → survives EDR restarts
- No BYOVD required -- bindflt.sys is a legitimate signed Windows driver

**Admin FP discriminator:** Developer sandbox binding non-security application to test environment -- non-security target, development machine, change ticket.

---

### 7. AppLockerEDRDenyRule
**Source:** `EDR-GhostLocker/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001

**Detection teaches:**
- `CreateToolhelp32Snapshot` + `NtQuerySystemInformation(SystemProcessIdInformation)`: resolving full image paths of running EDR processes
- AppLocker deny rules written to `HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\` for resolved EDR paths
- Actor is an interactive session process (cmd.exe, powershell.exe), not GPO management tools
- Effect: EDR executables blocked from starting on next reboot -- persistent sabotage

**Admin FP discriminator:** GPO-deployed AppLocker blocking user AppData executables from management server -- non-security target, GPO-deployed, change ticket.

---

### 8. BYOVDKernelBypass
**Source:** `edrsandblast/`, `sharp-blackout/` (gmer driver)
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001, T1014

**Detection teaches:**
- Known vulnerable driver loaded: `iqvw64e.sys` (Intel NIC, CVE-2015-2291), `gmer.sys`, `RTCore64.sys` (MSI Afterburner), `aswArPot.sys` (Avast, CVE-2022-26522)
- Arbitrary kernel read/write via driver IOCTL -- EDR callbacks located and nulled
- `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine` arrays modified
- `ObRegisterCallbacks` entries removed -- EDR can no longer block handle operations
- ETW Threat Intelligence provider disabled -- process hollowing/APC detection suppressed
- Driver deleted after use to remove evidence

**Admin FP discriminator:** BattlEye/EasyAntiCheat signed drivers not on Microsoft's blocklist and do not modify notification callback arrays.

---

### Kernel Exploitation (3 classes)

---

### 9. UnsignedKernelDriverMap
**Source:** `kurasagi/kdmapper/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1014, T1547.006

**Detection teaches:**
- Two-stage load: (1) known vulnerable signed driver as carrier for kernel r/w, (2) unsigned .sys file in temp/non-standard path
- Code Integrity (DSE) bypassed via kernel write -- driver signature enforcement disabled in kernel memory
- Unsigned driver mapped to kernel address without registration in Services registry
- Not visible in standard driver enumeration (sc query type=kernel, driverquery)

**Admin FP discriminator:** Windows Defender (WdBoot.sys) loaded at boot -- Microsoft-signed, Services-registered, DSE enforced.

---

### 10. KernelNotifyCallbackRemoval
**Source:** `edrsandblast/` (core technique)
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001, T1014

**Detection teaches:**
- Direct kernel memory write to `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine` arrays
- EDR driver callback function pointers nulled -- drivers receive ZERO process/thread/image load events
- Offsets resolved via PDB symbols, ntoskrnl binary scan, or hardcoded values
- ETW TI provider disabled: `Microsoft-Windows-Threat-Intelligence` events suppressed (process hollowing, APC injection detection lost)

**Admin FP discriminator:** Legitimate callback addition uses `PsSetCreateProcessNotifyRoutine` API -- adds entries, never nulls existing ones.

---

### 11. IoUringSyscallEvasion
**Source:** `ringreaper/` (Linux io_uring C2)
**Sensor:** `linux_sentinel`
**MITRE:** T1562.006, T1071

**Detection teaches:**
- `io_uring_setup()` + many `io_uring_enter()` calls replacing `read/recv/send/connect` network syscalls
- Near-zero traditional network syscall count despite active network I/O
- SQPOLL mode: kernel thread polls ring buffer -- zero syscalls for I/O polling
- Standard auditd, seccomp, eBPF tracepoints on network syscalls see nothing
- Unknown binary performing network communication entirely through io_uring ring buffer

**Admin FP discriminator:** nginx io_uring usage -- installed package, known binary, no hidden C2 destination.

---

### Privilege/Trust Bypass (2 classes)

---

### 12. UACRegistryBypass
**Source:** `UAC/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1548.002

**Detection teaches:**
- HKCU registry key written for auto-elevate binary COM handler: `HKCU\Software\Classes\ms-settings\Shell\Open\command`, `mscfile\Shell\Open\command`
- Targets: `fodhelper.exe`, `eventvwr.exe`, `computerdefaults.exe`, `sdclt.exe` (all auto-elevate without UAC dialog)
- Payload in handler value: encoded PowerShell, temp-path binary
- High-integrity process spawned without UAC prompt -- `uac_prompt_displayed=False` is the key signal

**Admin FP discriminator:** Legitimate MSI installer -- UAC dialog IS shown, signed binary, no HKCU COM key hijack.

---

### 13. PPLTokenRace
**Source:** `collection/PPL-0day/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001

**Detection teaches:**
- WMI EventFilter + CommandLineEventConsumer for early-boot SYSTEM execution before svchost
- Target anti-malware service paused during startup (SUSPENDED state)
- `NtOpenProcessToken` + `NtSetInformationToken` on suspended PPL child: token replaced
- Result: anti-malware service resumes with deprivileged token -- PPL bypassed without kernel exploit
- No BYOVD, no kernel debug mode -- user-mode race condition

**Admin FP discriminator:** CreateProcessAsPPL in kernel debug mode for development testing only.

---

### Credential Access via Bypass (2 classes)

---

### 14. LSASSForkDump
**Source:** `collection/Bypass-EDR/` (LSASS forked dump vs CrowdStrike)
**Sensor:** `windows_deepsensor`
**MITRE:** T1003.001

**Detection teaches:**
- `OpenProcess(PROCESS_CREATE_PROCESS)` on lsass -- limited rights, not `PROCESS_ALL_ACCESS`
- `NtCreateProcessEx(ParentProcess=lsass)`: clones lsass to a new PID, inheriting all memory
- `MiniDumpWriteDump` targets the CLONED PID (not lsass PID) -- bypasses EDR rules monitoring `MiniDumpWriteDump(lsass)`
- .dmp file written to public/temp path
- `direct_OpenProcess_on_lsass=NO` -- the key behavioral discriminator

**Admin FP discriminator:** Authorized ProcDump with EDR exception uses direct lsass access, signed binary, IR ticket.

---

### 15. APCQueueInjection
**Source:** `collection/APC-Injection/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1055.004

**Detection teaches:**
- `OpenThread(THREAD_SET_CONTEXT + THREAD_GET_CONTEXT)` on alertable thread in target process
- `VirtualAllocEx(RWX)` + `WriteProcessMemory` planting shellcode
- `NtQueueApcThread(APC_ROUTINE = shellcode_address)` -- shellcode executes when thread calls alertable wait
- Execution appears as the target process (explorer.exe, svchost.exe) -- covers C2 activity

**Admin FP discriminator:** SQL Server async I/O completion uses same-process APCs -- no cross-process `VirtualAllocEx`, no foreign process shellcode.

---

### AV/Shellcode Evasion (3 classes)

---

### 16. ShellcodeRuntimeEncrypt
**Source:** `collection/GenEDRBypass/`, `collection/Shellcode-Mutator/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1027.002, T1027.007

**Detection teaches:**
- Anti-sandbox checks BEFORE decryption: timing check (sleep 5s, verify 5s elapsed), VM artifact check (vmtoolsd.exe), cursor movement check
- Encrypted payload on disk with high entropy (no AV signature match)
- `VirtualAlloc(PAGE_EXECUTE_READWRITE)` + decrypt + execute at runtime
- XOR with rotating key or AES-256-CBC -- per-build key makes every binary unique
- `msfvenom` or similar shellcode generator detected in memory after decryption

**Admin FP discriminator:** DRM-protected game uses code encryption but no anti-sandbox checks, publisher EV cert, no RWX C2 shellcode.

---

### 17. SmartScreenBypass
**Source:** `collection/Bypass-Smartscreen/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1574.002, T1553.005

**Detection teaches:**
- Signed host binary (OneDrive.exe, Teams.exe, Zoom.exe) loading an **unsigned** DLL from AppData
- DLL in application directory exports all functions forwarded to system DLL (masquerades as real)
- Shellcode in DllMain executes at process startup with full trust of host binary
- SmartScreen only validates the launching binary -- does not recursively validate loaded DLLs
- Execution appears as trusted process

**Admin FP discriminator:** AutoCAD resource DLL in C:\Program Files\Autodesk\ -- signed by Autodesk, documented in install manifest.

---

### 18. DefenderExclusionAdd
**Source:** `Defense_Evasion/defender_evasion/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001

**Detection teaches:**
- Registry write to `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\`, `\Processes\`, or `\Extensions\`
- Exclusion target is a temp/writable path (C:\Windows\Temp, C:\Users\Public) or script extension (.hta, .ps1)
- Actor is an interactive session process (cmd.exe, powershell.exe, reg.exe), not GPO management
- Payload already present at excluded path: exclusion added specifically to enable execution
- Effect: Defender stops scanning that location/process permanently

**Admin FP discriminator:** GPO-deployed exclusion for known security scanner false positive -- vendor path (C:\Program Files\), GPO, change ticket.

---

### Linux Evasion (2 classes)

---

### 19. LinuxLibcHookEvasion
**Source:** `collection/Auto-Color/` (Rust rewrite of Auto-Color Linux backdoor)
**Sensor:** `linux_sentinel`
**MITRE:** T1574.006, T1014

**Detection teaches:**
- Library dropped (libcext.so.2 or similar) + `/etc/ld.so.preload` modified
- Hooked libc functions: `open`, `openat`, `fopen`, `stat`, `lstat`, `readdir` -- intercepts file operations
- `/proc/net/tcp` entries filtered: C2 connections invisible to `ss`, `netstat`, `ip addr`
- `/etc/ld.so.preload` self-protected: `unlink/stat/access/rename` on the preload file return errors -- attacker-installed, cannot be removed by standard commands
- Every process on the system loads the hook library (universal injection)

**Admin FP discriminator:** AddressSanitizer LD_PRELOAD -- packaged library, no `/proc/net/tcp` filtering, no self-protection.

---

### 20. RPCInterfaceRace
**Source:** `rpc-racer/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1557.001, T1187

**Detection teaches:**
- Scheduled task or WMI consumer executes at boot before Storage Service starts
- Attacker registers RPC endpoint mimicking `StorSvc` interface (SvcRebootToFlashingMode method)
- Delivery Optimization Service calls the method on attacker's endpoint instead of the real one
- Attacker responds with a UNC path → DoSvc authenticates to the path → machine account NTLMv2 hash captured
- Relay to LDAP: machine account used for RBCD attack or SMB authentication

**Admin FP discriminator:** WinRM registering its own RPC endpoint at service startup -- legitimate service account, no early-boot race.

---

### 21. CallbackShellcodeExecution
**Source:** `code_snippets/CallbackShellcode/` (TimerQueue, EnumChildWindows, CreateFiber, SetWindowsHookEx, CreateThreadpoolWait variants)
**Sensor:** `sysmon_sensor`
**MITRE:** T1055.004, T1027.002

**Detection teaches:**
- `VirtualAlloc(RWX)` in own process with high-entropy content -- shellcode staged before callback registration
- Callback API (`CreateTimerQueueTimer`, `EnumChildWindows`, `SetWindowsHookEx WH_KEYBOARD_LL`, `CreateFiber`, `CreateThreadpoolWait`) registered with callback address inside the RWX alloc region -- not inside any loaded DLL
- **No `CreateRemoteThread` / `WriteProcessMemory`** -- evades API-level injection monitors entirely
- Thread execution originates from within the VirtualAlloc region when the callback fires

**Admin FP discriminator:** Legitimate callbacks (accessibility tools, UI frameworks) register their callback address to a function inside a loaded, signed DLL -- never to an anonymous RWX heap allocation.

---

### 22. DSEDriverSignatureBypass
**Source:** `BYOVD/DSERemover/` (RTCore64/WinRing0 + ci.dll g_CiOptions patch)
**Sensor:** `sysmon_sensor`
**MITRE:** T1562.001, T1014

**Detection teaches:**
- Three-phase sequence: (1) known-vulnerable signed driver loaded (BYOVD stepping stone); (2) IOCTL to that driver patches `ci.dll!g_CiOptions` to `0` in kernel memory -- DSE disabled; (3) **unsigned driver loads successfully** without test-signing boot config
- The diagnostic: `Signed=false` on a driver load that succeeds on a system where `bcdedit /set testsigning on` was never run -- only possible if DSE was patched at runtime
- Distinct from `BYOVDKernelBypass` which targets EDR callbacks: DSE removal enables loading **any** unsigned driver thereafter

**Admin FP discriminator:** Authorized test-signing on a DEV machine shows `TESTSIGNING=On` in bcdedit output, has an IT change ticket, and the unsigned driver is in a development path -- no BYOVD stepping-stone driver in the event chain.

---

### 23. KernelETWTIProviderRemoval
**Source:** `BYOVD/ETwTiRemover/` (kernel EtwThreatIntelProvider array patch)
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.006, T1014

**Detection teaches:**
- BYOVD driver load → IOCTL patching the `EtwThreatIntelProvider` (Microsoft-Windows-Threat-Intelligence) provider array in kernel memory
- Observable consequence: ETW-TI telemetry event rate drops from normal baseline to **zero** within seconds of the IOCTL -- events for ImageLoad, ProcessCreate, NetworkConnect, AllocVM all stop
- Sysmon (user-mode) continues reporting, making host appear monitored while kernel-level EDR hooks are blind
- Distinct from `AMSIInProcessPatch`/`AMSIETWMemPatch` (user-mode): this patches the kernel provider array, affecting all consumers including EDR minifilters

**Admin FP discriminator:** None. Removing ETW threat intelligence providers from kernel memory has no legitimate operational use case.

---

### 24. CredGuardVBSBypass
**Sensor:** `sysmon_sensor` | **MITRE:** T1556.002, T1068

PROCESS_ALL_ACCESS (0x1FFFFF) on `lsaiso.exe` from Medium-IL process -- defeats VBS isolation protecting Credential Guard. FP: SecurityHealthService with 0x1000 (limited query). Lateral: full credential material exposed.

---

### 25. FiberBasedShellcode
**Sensor:** `sysmon_sensor` | **MITRE:** T1055

ConvertThreadToFiber + CreateFiber(RWX shellcode addr) + SwitchToFiber -- executes shellcode without NtCreateThread/EventID 8, evading thread-creation EDR hooks. ETW gap (no thread-start event) + high-entropy RWX region = fingerprint.

---

### 26. PPLKillerPrivesc
**Sensor:** `sysmon_sensor` | **MITRE:** T1562.001, T1068

Known vulnerable LOLDRIVER (RTCore64, gdrv, iqvw64e, cpuz141_x64) with expired signature loaded → PROCESS_ALL_ACCESS on PPL-protected EDR process (MsMpEng, CSFalconService) → EDR terminated → telemetry gap begins. FP: vendor's own signed driver loaded by vendor service.

---

### 27. PatchGuardSubversion
**Sensor:** `sysmon_sensor` | **MITRE:** T1068, T1014

`bcdedit /set testsigning on` (BCD registry modification) precedes unsigned kernel driver load with SSDT hooks (KiSystemServiceUser patch). Production systems never have test signing. FP: isolated dev lab with ITSEC approval.

---

### 28. ETWConsumerKill
**Sensor:** `sysmon_sensor` | **MITRE:** T1562.006

Dual approach: ntdll!EtwEventWrite NOP-patched in-process (silences ETW per-process) + HKLM\\...\\WMI\\Autologger\\EventLog-Security consumer key deleted (system-wide gap). FP: WEF agent (SYSTEM, signed) reconfiguring authorized consumer.

---

### 29. PoolPartyInjection *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1055

Thread pool work item injection via TpAllocWork/SubmitThreadpoolWork into target process. No NtCreateThreadEx visible -- evades standard injection detection. FP: .NET thread pool task dispatching.

---

### 30. EDRLogWipe *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1070.001

wevtutil cl / Clear-EventLog on Security, Sysmon, and Defender event logs. EventIDs 1102/104 generated. FP: Authorized log rotation by SIEM service account with ticket.

---

### 31. ProcessImpersonationEDR *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1036.005

Unsigned AV/EDR binary dropped to %TEMP% with spoofed name (MsMpEng.exe etc.), script-host parent. FP: Legitimate MsMpEng update from C:\Program Files\.

---

### 32. EDRStartupHinder *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1562.001, T1547

IFEO Debugger registry key set for EDR binary redirect to svchost.exe, silently blocking EDR on next boot. FP: SCCM deploying .msi with IFEO for debugging during test window.

---

### 33. SignatureStealer *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1036.001, T1553.002

Authenticode signature cloned from trusted binary onto malicious executable dropped to %TEMP%. FP: MSI installer writing a signed binary to Temp during staging.

---

## Training Output

Default run (`--records-per-class 10 --admin-fps-per-class 2`):
- **280 true-positive records** -- defense evasion behavioral patterns
- **56 false-positive records** -- legitimate admin activity that looks similar

Total: **336 SFT training records** across 3 sensor types:
- `sysmon_sensor` (windows_math): 20 classes
- `windows_deepsensor` (windows_math): 6 classes
- `linux_sentinel` (sentinel_math): 2 classes (IoUringSyscallEvasion, LinuxLibcHookEvasion)

## S3 Query Patterns

- `AMSIInProcessPatch`: VirtualProtect on amsi.dll with RX→RW protection change
- `WFPEDRNetworkBlock`: FwpmFilterAdd0 targeting Defender/Sentinel processes
- `BYOVDKernelBypass`: Known vulnerable driver load events (iqvw64e, gmer, RTCore64)
- `UACRegistryBypass`: HKCU ms-settings or mscfile registry writes
- `LSASSForkDump`: NtCreateProcessEx with lsass.exe as parent process
- `DefenderExclusionAdd`: Defender Exclusions registry write by non-Defender process
- `IoUringSyscallEvasion`: io_uring_enter with near-zero traditional network syscalls
- `LinuxLibcHookEvasion`: Write to /etc/ld.so.preload
- `AppLockerEDRDenyRule`: SrpV2\Exe registry write targeting EDR process names
- `KernelNotifyCallbackRemoval`: Kernel callback array modification events
- `CallbackShellcodeExecution`: VirtualAlloc(RWX) + callback API registration pointing to alloc region
- `DSEDriverSignatureBypass`: Signed=false driver load without TESTSIGNING boot config
- `KernelETWTIProviderRemoval`: ETW provider array modified + ThreatIntel provider removed

## Extending

When a new bypass technique appears in `arcanaeum/offsec/ttps/4_Bypass_Detection/`:
1. Identify which layer it operates at (AMSI, EDR, kernel, UAC, AV)
2. Find the observable behavioral sequence (API calls, registry changes, kernel events)
3. Create `_<name>_tp(i)` / `_<name>_fp(i)` functions
4. Add to `TOOL_CLASSES` and `S3_QUERIES`
5. Document here
