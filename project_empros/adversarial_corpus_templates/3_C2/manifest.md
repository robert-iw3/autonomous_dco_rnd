# 3_C2 -- Adversarial Corpus Manifest

**MITRE Tactic:** TA0011 -- Command and Control
**Source tools:** `arcanaeum/offsec/ttps/3_C2/`
**Script:** `stage_c2_behavioral.py`
**Pipeline target:** `make stage-c2` / `make data-c2`

---

## Detection Philosophy

C2 frameworks leave behavioral evidence across two layers:

1. **Network layer** -- beacon timing, protocol characteristics, destination IP context, TLS attributes, DNS patterns. The key principle: adversarial traffic has machine-generated timing (low CV), destinations on commodity VPS (not enterprise vendor AS), and protocol mimicry that breaks down under destination-IP correlation.

2. **Host layer** -- process injection APIs, memory protection patterns, evasion techniques. The key principle: C2 agents execute OS operations that have no legitimate analog -- allocating RWX memory in remote processes, patching security DLLs, spoofing call stacks.

Every class includes admin FP variants so the model learns the exact factor that converts a suspicious-looking pattern into a confirmed adversarial one.

---

## Tool Classes

### Network Channel Patterns

---

### 1. HTTPSBeaconInterval
**Source frameworks:** Havoc, Adaptix, Gunner, Tempest, Sliver, Drill v3, Viper
**Sensor:** `network_tap` → `c2_math`
**MITRE:** T1071.001, T1573.001

**Detection teaches:**
- `inter_arrival_cv` < 0.12: machine-generated timing (human-driven apps have cv > 0.3)
- Destination on commodity VPS ASN (Vultr, DigitalOcean, OVH) -- not CDN or enterprise vendor
- Self-signed certificate with validity < 90 days (attacker-generated infra)
- Consistent payload size across beacon sessions (structured protocol, not user data)
- Activity at off-hours (03:00–05:00) with no user session = autonomous beacon

**Admin FP discriminator:** APM agent (Datadog, New Relic) -- registered vendor FQDN, CA-signed cert, CDN-hosted (Cloudflare/AWS), higher CV (human scheduling + NTP drift).

---

### 2. MalleableProfileMimicry
**Source:** `cobalt_strike/profile_examples/` (Gmail, Amazon), `havoc/profiles/` (Teams profile)
**Sensor:** `network_tap`
**MITRE:** T1071.001, T1001.003

**Detection teaches:**
- The URI and header combination are correct for the impersonated service -- but the destination IP is wrong
- Teams `/Collector/2.0/settings/` goes to AS8075 (Microsoft) -- not Vultr or DigitalOcean
- Gmail `/mail/u/0/` goes to AS15169 (Google) -- not OVH
- Amazon `/s/ref=...` goes to AS16509 (Amazon) -- not Hostinger
- Self-signed cert: Teams/Gmail/Amazon always use CA-signed vendor PKI
- Missing header returns 404 (strict enforcement = C2 profile validator)
- CV near-zero: legitimate service traffic is user-driven with irregular timing

**Admin FP discriminator:** Destination AS must match the impersonated service. Teams to AS8075 + Microsoft IT TLS CA = legitimate. Teams to AS-CHOOPA + self-signed = adversarial.

---

### 3. DNSSubdomainBeacon
**Source:** agent-loader DoH, any DNS C2 framework
**Sensor:** `network_tap`
**MITRE:** T1071.004, T1048.003

**Detection teaches:**
- Subdomain label entropy > 3.5 bits/char: encoded data (base64/hex), not human-readable hostnames
- Regular interval DNS queries with low CV: automated polling loop
- TXT record queries > 20%: command channel (browsers almost never query TXT records)
- Near-zero TTL (0–30s): prevents caching, ensures fresh commands
- Fresh domain (< 30 days): registered specifically for the campaign
- Subdomain encoding: each query carries 40–200 bytes of exfiltrated data

**Admin FP discriminator:** CDN dynamic subdomains (Cloudflare, Akamai) have deterministic templates (geographic codes, session hashes), NOT high-entropy random base64. CDN TXT queries are DKIM/SPF only.

---

### 4. DoHBeaconChannel
**Source:** `agent/agent-loader/` (5-second hardcoded DoH beacon)
**Sensor:** `network_tap`
**MITRE:** T1071.004, T1090.003

**Detection teaches:**
- HTTPS POST to `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `149.112.112.112` with `Content-Type: application/dns-message`
- Non-browser parent process initiating DoH: `powershell.exe`, `python.exe`, `svchost.exe` -- not `firefox.exe` or `chrome.exe`
- TXT record query percentage > 40%: command channel (browsers query A/AAAA dominant)
- Machine-precision interval (cv < 0.06): hardcoded 5-second loop
- Bypasses all DNS-layer controls (DNS firewall, RPZ, Zeek DNS log) -- traffic appears as normal HTTPS

**Admin FP discriminator:** Browser-native DoH -- `firefox.exe` parent, irregular timing, A/AAAA dominant queries, < 5% TXT.

---

### 5. SMBNamedPipeBeacon
**Source:** `havoc/profiles/` (demon_pipe), `adaptix/` (SMB listener), Cobalt Strike SMB beacon
**Sensor:** `windows_deepsensor`
**MITRE:** T1071.002, T1090

**Detection teaches:**
- Named pipe created by non-pipe-server processes (notepad, powershell, svchost via injection)
- Pipe name pattern: `demon_pipe`, `mojo.NNNN.NNNN`, random strings -- NOT `MSSQL$`, `spoolss`, `PrintDataPort`
- Cross-host pipe access (port 445): lateral C2 -- attacker using one beacon to relay C2 to another
- Machine-generated read/write interval on pipe (cv < 0.10)

**Admin FP discriminator:** SQL Server named pipe `MSSQL$PROD\sql\query` created by `sqlservr.exe` under `NT SERVICE\MSSQLSERVER` -- vendor pipe format, service process, service account.

---

### 6. WebSocketPersistentC2
**Source:** `gunner_c2/` (FastAPI/uvicorn, port 6060), `drill_v3/` (Socket.IO)
**Sensor:** `network_tap`
**MITRE:** T1071.001

**Detection teaches:**
- WebSocket Upgrade from non-browser process: `powershell.exe`, `python.exe`, `unknown.exe`
- Server header: `uvicorn`, `socket.io`, `actix-web` (development frameworks, not commercial services)
- Destination: raw external IP, non-standard port (6060, 8765, 9090) -- not Slack, not Teams
- Session duration > 30 minutes: persistent bidirectional command channel
- Machine-generated message timing (cv < 0.09)

**Admin FP discriminator:** Slack WebSocket -- `Slack.exe` parent, `app.slack.com` destination, DigiCert cert, user session active.

---

### 7. TorHiddenServiceC2
**Source:** `agent/OnionC2/` (Arti Rust Tor implementation)
**Sensor:** `network_tap`
**MITRE:** T1090.003

**Detection teaches:**
- Destination IP appears in Tor consensus list (guard/exit node registry)
- Multiple Tor circuits established: multi-hop routing to hide C2 location
- Tor control port activity (9051): local Tor daemon managing circuits
- Onion service resolution: connecting to `.onion` hidden service (C2 infrastructure not traceable to a clearnet IP)
- Arti library: programmatic Tor from non-browser context (Rust library signatures)

**Admin FP discriminator:** No corporate enterprise use case. Only legitimate exception: isolated research VMs with explicit security team ticket, on a research VLAN.

---

### 8. C2RedirectorPattern
**Source:** `cobalt_strike/cobalt-strike-infrastructure/` (redirector deployment guides)
**Sensor:** `network_tap`
**MITRE:** T1090.002

**Detection teaches:**
- Fresh domain (< 30 days) with Let's Encrypt cert (free, no identity validation)
- Strict URI whitelist: only known C2 paths pass through -- all others return 404
- X-Forwarded-For forwarded to teamserver (hiding backend behind redirector)
- Backend on non-standard port (40056, 50050, 6060) on internal/VPS host
- `nginx` 404 response for non-matching requests (strict whitelisting = C2 profile enforcement)

**Admin FP discriminator:** Corporate reverse proxy -- CMDB-registered, corp PKI certificate, internal destination, years-old stable domain.

---

### Host Injection/Evasion Patterns

---

### 9. RemoteProcessInjectionRWX
**Source:** `havoc/` (NtCreateThreadEx), `agent/agent-loader/`, `tempest/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1055.001, T1055

**Detection teaches:**
- Three-API sequence: `VirtualAllocEx(PAGE_EXECUTE_READWRITE)` → `WriteProcessMemory` → `NtCreateThreadEx`
- `PAGE_EXECUTE_READWRITE` (RWX): memory is writable AND executable immediately -- no legitimate app needs this in a remote process
- Shellcode entropy in allocated region > 3.5: encrypted/encoded payload waiting to execute
- Indirect syscalls: NtCreateThreadEx called without ntdll import table entry (bypasses EDR hooks)
- Injection target is a trusted process (notepad, werfault, RuntimeBroker) for cover

**Admin FP discriminator:** EDR agents (CrowdStrike) read LSASS with `PROCESS_VM_READ` only -- no VirtualAllocEx, no WriteProcessMemory, no thread creation. The presence of the write+exec allocation is the discriminator.

---

### 10. ProcessHollowing
**Source:** `tempest/` (RunPE), `agent/agent-loader/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1055.012

**Detection teaches:**
- Six-API sequence: `CreateProcess(CREATE_SUSPENDED)` → `NtUnmapViewOfSection` → `VirtualAllocEx` → `NtWriteVirtualMemory` → `SetThreadContext` → `ResumeThread`
- `NtUnmapViewOfSection` on the victim process is the unique discriminator -- legitimate apps never unmap a process's own image
- On-disk hash ≠ memory hash: the process name in Task Manager is legitimate, but the code is not
- Parent PID spoofing: attacker hides the actor process in the process tree

**Admin FP discriminator:** JVM loads classes with `VirtualAlloc` for JIT but never calls `NtUnmapViewOfSection` -- original image remains intact. Memory hash matches on-disk hash.

---

### 11. IndirectSyscallStub
**Source:** `havoc/` (SysNtCreateThreadEx), `cobalt_strike/koneko/`, `agent/agent-loader/`
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001, T1055

**Detection teaches:**
- NT functions invoked (NtCreateThreadEx, NtWriteVirtualMemory) without corresponding ntdll.dll import table entries
- Syscall stubs in RWX memory region: custom assembly with hardcoded syscall numbers
- No return address pointing back to ntdll.dll: EDR hook interception bypassed
- Syscall numbers are Windows-version-specific and hardcoded at compile time (Havoc, Koneko)

**Admin FP discriminator:** Game anti-cheat kernel driver using direct syscalls -- EV code-signed, single well-known function (NtQuerySystemInformation), kernel driver context.

---

### 12. SleepMaskingPattern
**Source:** `havoc/` (Ekko/FOLIAGE/Ziliean), `cobalt_strike/koneko/`, `tempest/` (rekkoex)
**Sensor:** `windows_deepsensor`
**MITRE:** T1055, T1562.001

**Detection teaches:**
- Zero `Sleep()` or `WaitForSingleObject` calls in the beaconing process
- Replaced by: `NtCreateEvent` + `NtWaitForSingleObject` (custom sleep implementation)
- Ekko pattern: periodic `VirtualProtect` RW↔RX flips -- heap encrypted to RW during sleep (invisible to memory scanners), decrypted to RX before next beacon
- Heap entropy drops dramatically during sleep (RW=near-uniform encrypted data) and rises during active phase
- This is a pure anti-EDR evasion technique with no legitimate software analog

**Admin FP discriminator:** Chrome GPU sync uses `WaitForSingleObjectEx` but heap entropy is stable (no encryption), no VirtualProtect flips.

---

### 13. AMSIETWMemPatch
**Source:** `havoc/` (AMSIETW_PATCH_HWBP and MEM variants)
**Sensor:** `windows_deepsensor`
**MITRE:** T1562.001

**Detection teaches:**
- Target functions: `amsi.dll!AmsiScanBuffer`, `amsi.dll!AmsiOpenSession`, `ntdll.dll!EtwEventWrite`, `ntdll.dll!NtTraceEvent`
- Memory patch method: `WriteProcessMemory` with `0xC3` (RET), `0x90` (NOP), or `0x31 0xC0` (XOR EAX)
- `VirtualProtect` sequence: RX → RW (to write patch) → RX (restore) -- observable as three consecutive protection changes
- Hardware breakpoint method: `NtSetInformationThread(ThreadHideFromDebugger)` + DR0-DR3 register set, VEH handler intercepts

**Admin FP discriminator:** Windows Update replacing `amsi.dll` on disk via `TrustedInstaller.exe` -- file-level replacement, not runtime memory patch, no `VirtualProtect` sequence on DLL pages.

---

### 14. ReflectiveDLLLoad
**Source:** `agent/agent-loader/`, `havoc/`, most C2 loaders
**Sensor:** `windows_deepsensor`
**MITRE:** T1620

**Detection teaches:**
- MZ/PE header at allocated memory base with no disk-backing file
- `LoadLibrary` not called: custom PE loader inside the shellcode
- Base relocations applied in memory: image base patched at runtime
- IAT (Import Address Table) resolved at runtime: function pointers resolved without Windows loader
- No file on disk: PE was downloaded in-memory or was deleted after loading
- Region entropy high (encrypted payload decoded at runtime before execution)

**Admin FP discriminator:** .NET `Assembly.Load()` -- CLR-managed, disk backing file exists, no manual IAT resolution, CLR reports the assembly path.

---

### 15. TokenDuplicationC2
**Source:** `agent/agent-loader/` (token vault), `havoc/` (token manipulation)
**Sensor:** `windows_deepsensor`
**MITRE:** T1134.001, T1021

**Detection teaches:**
- Four-API chain: `NtOpenProcessToken` → `NtDuplicateToken(TOKEN_ALL_ACCESS)` → `ImpersonateLoggedOnUser` → `CreateProcessWithTokenW`
- Token vault: multiple stolen tokens cached for different users/services -- not a single RunAs operation
- EventID 4674 (attempt to operate on privileged object): confirms token manipulation
- Target accounts: SYSTEM, Domain Admin, Service Accounts -- opportunistic privilege escalation

**Admin FP discriminator:** PsExec with a service account -- single token (not a vault), signed tool, change ticket.

---

### 16. ChromeExtensionC2
**Source:** `chrome-c2-extension/` (extension + loader + server)
**Sensor:** `windows_deepsensor`
**MITRE:** T1176, T1547.001

**Detection teaches:**
- Hidden extension path: `%APPDATA%\.hidden_extension\extension` (not Chrome Web Store path)
- Browser launched with `--load-extension=<hidden_path>`: forces unpacked extension, bypasses Web Store verification
- Polls C2 server every 30 seconds (cv < 0.05): machine-generated command polling
- Startup folder LNK for persistence: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\loader.lnk`
- MetaMask override: original MetaMask extension replaced with modified version for crypto theft

**Admin FP discriminator:** Enterprise extension deployed via Google Admin Console -- appears in `chrome://extensions`, known extension ID from Chrome Web Store, managed deployment.

---

### Infrastructure Signature Patterns

---

### 17. TeamserverExposure
**Source:** `havoc/` (port 40056), `gunner_c2/` (6060), `auxiliary/Villain/` (6501), Cobalt Strike (50050)
**Sensor:** `network_tap`
**MITRE:** T1583.003

**Detection teaches:**
- Known teamserver ports: 40056 (Havoc), 6060 (Gunner), 6501 (Villain), 50050 (CS), 4444/4443 (Metasploit/generic)
- Multiple simultaneous operator connections: teamserver is being actively used
- Self-signed certificate with short validity on commodity VPS
- Authentication challenge-response exchange on initial connection

**Admin FP discriminator:** Internal admin tool on 8443 -- CMDB registered, corp PKI, internal destination, single operator.

---

### 18. BeaconJitterStatistics
**Source:** All frameworks -- this is the c2_math vector analysis class
**Sensor:** `network_tap` → `c2_math` vector
**MITRE:** T1071.001, T1573

**Detection teaches:**
- This class directly trains Model B's c2_math 8-dimensional vector:
  - `inter_arrival_cv` < 0.12 (machine precision)
  - `payload_entropy` > 3.5 (encrypted payload)
  - `packet_size_std` < 20B (consistent frame size)
  - `outbound_ratio` ≈ 0.4-0.5 (symmetric check-in/response)
  - `cmd_entropy` > 3.0 (cryptographic randomness in command structure)
  - `score` > 0.75 (Model A anomaly detected)
- Machine-generated timing + encrypted payload + symmetric ratio = beacon fingerprint

**Admin FP discriminator:** APM agent heartbeat -- cv > 0.2, entropy < 2.5 (structured metrics payload), vendor FQDN destination.

---

### 19. StackCallSpoofing
**Source:** `cobalt_strike/koneko/` (return address spoofing on every API/NTAPI call), `havoc/` (context spoofing)
**Sensor:** `windows_deepsensor`
**MITRE:** T1055, T1562.001

**Detection teaches:**
- Return address on thread stack points to an address in ntdll.dll/kernel32.dll with no corresponding `CALL` instruction at that address
- `RtlCaptureContext` called in the beaconing process: thread context captured for manual modification
- Multiple spoofed frames: entire call chain is fake (attacker constructs synthetic call stack)
- ROP gadget used for indirect execution: `RET` to a gadget in a legitimate DLL for untraceable control flow

**Admin FP discriminator:** SQL Server fiber scheduler has unusual stacks but they are consistent across fiber yields, SQL Server is signed by Microsoft, and the pattern doesn't change per API call.

---

### 20. HavocTeamsMimicry
**Source:** `havoc/profiles/` (Teams profile: x-ms-session-id, x-ms-client-type, x-ms-environment)
**Sensor:** `network_tap`
**MITRE:** T1001.003, T1071.001

**Detection teaches:**
- Complete Havoc Teams profile header set: `x-ms-session-id` (GUID), `x-ms-client-type: desktop`, `x-ms-environment: prod`, Teams version User-Agent
- URI: `/Collector/2.0/settings/` -- the Teams telemetry collection endpoint
- **The discriminator**: destination IP is NOT in AS8075 (Microsoft Corporation)
- Real Teams never uses self-signed certificates (uses Microsoft IT TLS CA)
- Real Teams timing is human-driven (irregular); beacon timing is machine-precision
- This is the most commonly deployed Havoc profile in the wild

**Admin FP discriminator:** Destination `teams.microsoft.com` on AS8075 with Microsoft IT TLS CA -- actual Teams. Any deviation from AS8075 with these headers is adversarial.

---

### 21. SocialPlatformC2
**Source:** `Framework-Botnet/` Telegram/Discord/Slack C2 communication modules
**Sensor:** `network_tap`
**MITRE:** T1102.002, T1071.001

**Detection teaches:**
- Machine-generated POST rate to platform bot/webhook API endpoints (`api.telegram.org/bot*/`, `discord.com/api/webhooks/*/`, `slack.com/api/chat.postMessage`) with inter_arrival_cv < 0.12 -- not event-driven, human-irregular notification traffic
- Base64-encoded or encrypted message body -- legitimate DevOps bots send plain-text status messages
- **Bidirectional command channel**: implant POSTs to receive commands, parses the API response for instructions -- legitimate notification bots never parse responses for execution
- Traffic blends with legitimate platform usage and bypasses domain-based blocklists (these platforms are often on allowlists)

**Admin FP discriminator:** DevOps pipeline notification bots are event-driven (not timed), send plain-text messages, do not parse responses as commands, and have their bot tokens registered in corporate secrets management with a change ticket.

---

### 22. EmailIMAPCommandC2
**Source:** `pwsh-scripts/Send-CommandToAgent.ps1` + Framework-Botnet email C2 module
**Sensor:** `network_tap`
**MITRE:** T1071.003, T1102

**Detection teaches:**
- Periodic IMAP SEARCH for specific command-prefix subjects (`TASK:*`, `CMD:*`, `[agent]*`) at a machine-generated interval with low CV -- human email clients use IMAP IDLE (event-driven), not timed polling
- INBOX-only access: legitimate MUAs sync multiple folders; command-polling implants access only the inbox
- **Immediate SMTP reply** after FETCH: implant sends command results back via SMTP within seconds -- human inbox activity never produces automatic SMTP replies
- No MUA user-agent header: raw IMAP library (paramiko, imaplib, rust-imap) vs. `Outlook/16.0` or `Thunderbird/102.x`
- C2 traffic is encrypted TLS and indistinguishable at the perimeter from normal corporate email

**Admin FP discriminator:** Legitimate email clients use IMAP IDLE, sync multiple folders, carry MUA user-agent headers, have irregular timing, and never send automatic SMTP replies upon fetching a message.

---

### 23. ICMPCovertChannel
**Sensor:** `network_tap` | **MITRE:** T1095

ICMP echo with payload >64 bytes, machine-generated inter-arrival CV <0.08, high data entropy = covert C2 channel. ICMP is frequently allowed through firewalls that block other protocols. FP: standard diagnostic ping (32 bytes, human-timed, short burst).

---

### 24. CloudStorageC2
**Sensor:** `network_tap` | **MITRE:** T1102.002

Regular HTTPS to S3/Azure Blob/GCS with generic HTTP User-Agent (not cloud SDK) + beacon CV <0.09 = implant polling cloud storage for commands. Cloud storage traffic is rarely blocked. FP: authorized backup agent with SDK UA, service role, CMDB.

---

### 25. GitHubGistC2
**Sensor:** `network_tap` | **MITRE:** T1102.001

Fixed Gist ID polled repeatedly via `api.github.com` with generic UA (not git/gh CLI) + hardcoded PAT token not matching user + beacon timing = dead-drop resolver C2. GitHub API traffic almost never blocked. FP: gh CLI, human timing, Engineering group.

---

### 26. BITSTransferC2Persist
**Sensor:** `sysmon_sensor` | **MITRE:** T1197, T1071.001

BITS job with `SetNotifyCmdLine` pointing to payload + external non-Microsoft destination = polling C2 with built-in Windows persistence (job survives reboot). Rarely monitored vs. scheduled tasks. FP: Windows Update BITS job (wuauserv, Microsoft CDN, no SetNotifyCmdLine).

---

### HVNCHiddenDesktop *(migrated from tools/)*
**Sensor:** `network_tap` | **MITRE:** T1021.005

Hidden desktop + screen capture over long-lived external TCP session. Low variance inter-arrival, session > 60s. FP: Authorized TeamViewer session with corporate asset ticket.

---

### HoaxShellWebC2 *(migrated from tools/)*
**Sensor:** `network_tap` | **MITRE:** T1071.001

HTTP GET/POST with session-encoded PowerShell command in URI. Beaconing pattern: > 10 requests from same src_ip. FP: Application health-check polling.

---

### FilelessMemLoader *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1620

EventID 7: clrjit.dll loaded by non-Windows binary (Signed=false). Assembly.Load(bytes) from HTTP. FP: .NET Framework application loading CLR legitimately (signed, Windows path).

---

### DeserializationRCE *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1059.001, T1190

w3wp.exe spawning cmd.exe or powershell.exe (EventID 1). Binary POST to ASP.NET endpoint triggers deserialization chain. FP: SharePoint timer job OWSTIMER (vendor-signed, no cmd spawn).

---

### DarkWidowC2 *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1055.004, T1134.004

EventID 8 (CreateRemoteThread) targeting non-svchost process from %Temp% binary. Parent process impersonation via token duplication. FP: Authorized injection from signed security tooling.

---

## Training Output

Default run (`--records-per-class 10 --admin-fps-per-class 2`):
- **260 true-positive records** -- C2 behavioral patterns
- **52 false-positive records** -- legitimate traffic that looks similar

Total: **312 SFT training records** across 3 sensor types:
- `network_tap` (c2_math): 15 classes (network channel, infrastructure, platform C2)
- `sysmon_sensor` (windows_math): 8 classes (host injection/evasion + BITS C2)
- `windows_deepsensor` (windows_math): 3 classes (sleep masking, syscall, stack spoofing)

## S3 Query Patterns for Track 6

Behavioral filters applied to live S3 telemetry:
- `HTTPSBeaconInterval`: inter_arrival_cv < 0.12 AND self_signed AND external AND session_count > 20
- `DNSSubdomainBeacon`: dns payload_entropy > 3.5 AND cv < 0.10
- `DoHBeaconChannel`: POST to 1.1.1.1/8.8.8.8/9.9.9.9 with dns-message content-type
- `TorHiddenServiceC2`: dst_port 9001/9030 AND external
- `TeamserverExposure`: known teamserver ports AND self-signed AND external
- `ProcessHollowing`: CREATE_SUSPENDED + NtWriteVirtualMemory API sequence
- `AMSIETWMemPatch`: WriteProcessMemory targeting amsi.dll or ntdll.dll
- `ChromeExtensionC2`: --load-extension flag with hidden AppData path
- `SocialPlatformC2`: POST to telegram/discord/slack API with cv < 0.12 AND session_count > 15
- `EmailIMAPCommandC2`: IMAP dst_port 993/143 AND cv < 0.12 AND no MUA user-agent

## Extending

When a new C2 framework appears in `arcanaeum/offsec/ttps/3_C2/`:
1. Identify which network/host pattern category it falls into
2. Extract the unique behavioral differentiator (what makes it distinct from existing classes)
3. If it adds a new pattern class: create `_<name>_tp(i)` / `_<name>_fp(i)` functions
4. If it's a variant of an existing class: add it as an additional payload variant in that class
5. Document in this MANIFEST
