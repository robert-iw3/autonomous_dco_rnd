# 1_Recon -- Adversarial Corpus Manifest

**MITRE Tactic:** TA0043 -- Reconnaissance
**Source tools:** `arcanaeum/offsec/ttps/1_Recon/`
**Script:** `stage_recon_behavioral.py`
**Pipeline target:** `make stage-recon` / `make data-recon`

---

## Detection Philosophy

This corpus teaches the model to detect **behavioral evidence** of recon-phase
tradecraft -- the observable patterns in OS telemetry, network flows, and cloud
audit logs that tools leave behind regardless of their name, version, or
obfuscation.

**What the model must NOT rely on:** script names, file hashes, known IP lists,
static signatures. These are bypassed by any competent attacker.

**What the model learns instead:** ratios, timing, scope anomalies, call
patterns, and context violations -- signals that are difficult to suppress
because they are intrinsic to what the tool *does*.

Each tool class includes **admin false-positive variants** so the model learns
the specific discriminating factors that separate adversarial behavior from
legitimate IT operations performing similar activities.

---

## Tool Classes

### 1. NetworkPortScan
**Source cluster:** `scanners/` (nmap, rustscan, osmedeus)
**Sensor:** `network_tap` → `c2_math` vector
**MITRE:** T1046, T1595.001

**What it teaches:**
- Fan-out pattern: >100 unique destination ports in a single observation window
- SYN-RST signature: connections that never complete a 3-way handshake (session_duration_ms <500, tcp_syn ~100%, tcp_rst >70%)
- Uniform small packet ratio: all frames are 60-byte SYN probes (ratio_small_packets >0.91)
- Zero payload entropy: no application data in any session
- Requires raw socket capability (CAP_NET_RAW / Administrator)

**Admin FP discriminator:** IT asset discovery uses a bounded port list (5–15 well-known ports), completes full TCP handshakes (session_duration_ms >100ms), runs from a known service account during business hours, has a change ticket. The fan-out port count is the clearest signal: adversarial sweeps touch hundreds to thousands of ports; IT inventory touches fewer than 20.

---

### 2. WebFuzzing
**Source cluster:** `web/` (ffuf, dirsearch, nuclei, feroxbuster)
**Sensor:** `network_tap`
**MITRE:** T1595.002

**What it teaches:**
- URI uniqueness ratio: >0.87 means nearly every request targets a unique path (wordlist-driven, not navigation)
- 404 rate: >0.68 (high miss rate confirms brute-force against unknown paths)
- Request velocity: >80 req/s from a single source (machine-generated)
- Automated user-agent strings (Go-http-client, python-httpx, curl, tool-specific strings)

**Admin FP discriminator:** CI/CD DAST scans are rate-limited (<25 rps), target only dev/staging environments, come from known pipeline source IPs, and have a pre-authorized ticket.

---

### 3. WAFEvasionProbe
**Source cluster:** `scanners/gotestwaf`, manual pen test probing
**Sensor:** `network_tap`
**MITRE:** T1595.002, T1190

**What it teaches:**
- Multi-category payload diversity: legitimate scanners don't mix SQL injection, XSS, directory traversal, command injection, and XXE in the same session window
- WAF block percentage: high block rate with continued requests = attacker hunting for bypass, not testing functionality
- Bypass discovery: when a payload category achieves <20% block rate compared to others, that category is being exploited

**Admin FP discriminator:** Authorized pen tests have a ticket, scope limited to 1–2 payload types per job, and stop when blocked rather than iterating for bypasses.

---

### 4. NTLMIntercept
**Source cluster:** `intercept/` (mitmproxy, dnsforge, NTLMRawUnHide scripts)
**Sensor:** `network_tap`
**MITRE:** T1557.001, T1040

**What it teaches:**
- Non-DC host responding to LLMNR (port 5355), NBT-NS (port 137/138), or mDNS (5353) broadcasts
- Net-NTLMv2 hash captures -- credential material extracted without any user interaction
- NTLM relay: poisoned auth forwarded to a third host for authenticated SMB session establishment
- Key signal: `is_domain_controller=NO` on the responding host is definitional

**Admin FP discriminator:** Legacy WINS clients may respond to NBT-NS, but they do not capture hashes and the response count is 1, not sustained. There is NO legitimate admin use case for a workstation to respond to broadcast name-resolution queries.

---

### 5. TunnelInfra
**Source cluster:** `comm/` (ligolo-ng, tor-socks-proxy, rustunnel, bbs)
**Sensor:** `network_tap` → `c2_math` vector
**MITRE:** T1090.003, T1572

**What it teaches:**
- Session duration: >5 minutes persistent connection to a VPS = keepalive tunnel (not a transaction)
- Beacon inter-arrival CV: <0.12 = machine-generated heartbeat, not human or application traffic
- Destination ASN: commodity VPS providers (Vultr, DigitalOcean, OVH, Hostinger) for attacker infrastructure
- Self-signed certificate with short validity (<90 days) = attacker-generated cert
- TUN interface creation on the host (ligolo-ng proxy): OS-level kernel signal requiring CAP_NET_ADMIN
- Non-browser JA3 fingerprint

**Admin FP discriminator:** Corporate VPN terminates at a known gateway in the approved network device list, uses a PKI-signed certificate from the corporate CA, runs on port 500 (IKEv2) or 1194 (OpenVPN), and appears in the CMDB. VPS destination + self-signed cert + non-standard port is not an authorized VPN pattern.

---

### 6. ReverseProxyTunnel
**Source cluster:** `comm/` (frp, socktail, go-routersocks)
**Sensor:** `network_tap`
**MITRE:** T1090.003, T1572

**What it teaches:**
- Direction of initiation: legitimate reverse proxies serve inbound traffic; a tunnel agent initiates an outbound persistent connection to an attacker server
- Multiplexed channels: `frpc` opens multiple virtual circuits through a single TCP connection to relay arbitrary internal ports
- Heartbeat: frp uses a fixed-interval keepalive (configurable, default 30s) with very low CV
- Admin dashboard: frps exposes a web UI on port 7500 (default admin/admin) -- attacker management interface

**Admin FP discriminator:** Corporate reverse proxies (nginx, HAProxy, Traefik) are inbound-facing, registered in the CMDB, use corp PKI certificates, and terminate at known internal hosts. They do not initiate persistent outbound connections to external VPS servers.

---

### 7. WindowsHostEnum
**Source cluster:** `enumeration/windows/` (Host_Recon.ps1, Invoke-ADEnum, portscan.ps1, gomapenum)
**Sensor:** `windows_deepsensor` → `windows_math` vector
**MITRE:** T1082, T1087, T1518

**What it teaches:**
- WMI burst: >15 distinct Win32_* class queries in 60 seconds from a non-service parent process
- Classes queried: Win32_UserAccount, Win32_Share, Win32_NetworkAdapterConfiguration, MSFT_DNSClientCache -- these together map users, shares, network config, and cached DNS (tells the attacker what domains the host talks to)
- Scheduled task enumeration via COM (Schedule.Service interface, not schtasks.exe)
- Security product fingerprinting: process list scan for AV/EDR names
- LAPS check: testing for `%SystemDrive%\Program Files\LAPS\CSE\Admpwd.dll` existence
- Outbound port scan to egress-check hosts (allports.exposed): mapping allowed firewall ports for C2 channel selection
- **Critical**: legitimate tools avoid net.exe, ipconfig, whoami, netstat to evade detection -- the model must not rely on absence of these commands as a benign signal

**Admin FP discriminator:** SCCM/Lansweeper run under dedicated service accounts at scheduled intervals, query 3–8 specific WMI classes, never touch security product processes, and never perform outbound port scans. The parent process for legitimate IT tools is always the agent binary (LsAgent.exe, CcmExec.exe), not an Office application or script host.

---

### 8. ADDomainEnum
**Source cluster:** `enumeration/windows/` (Invoke-ADEnum, enum4linux, viewstalker, badsecrets)
**Sensor:** `windows_deepsensor`
**MITRE:** T1087.002, T1069.002, T1482

**What it teaches:**
- LDAP search scope: SUBTREE from DC= root with filter `(&(objectClass=*)(objectCategory=*))` = full directory dump
- Object count: >500 objects returned signals a bulk enumeration, not a targeted lookup
- Certificate template enumeration: querying `CN=Certificate Templates` = ADCS attack surface mapping (ESC1–ESC8)
- ACL queries: requesting `nTSecurityDescriptor` attribute = BloodHound-style privilege path discovery
- AdminSDHolder queries: identifying accounts protected by SDProp
- Kerberoasting target enumeration: `(servicePrincipalName=*)` filter returns all accounts with SPNs

**Admin FP discriminator:** Helpdesk and application LDAP queries target a specific OU with a precise filter (e.g., `(sAMAccountName=jsmith)`) and return 1–10 objects. They never query certificate templates or ACL descriptors. The discriminator is search scope + base DN + object count.

---

### 9. SMBShareHarvest
**Source cluster:** `harvesting/manspider`
**Sensor:** `network_tap`
**MITRE:** T1039, T1083, T1135

**What it teaches:**
- Fan-out: simultaneous SMB connections to >5 distinct internal hosts = subnet crawl, not targeted access
- Content inspection: opening files (not just listing directories) with credential-targeted extensions (xlsx, docx, config, key, pfx, kdbx)
- Keyword matching: reading file content for password/credential patterns
- Loot download: files transferred to the source host
- Auth method context: NTLM authentication (rather than Kerberos) may indicate pass-the-hash lateral movement

**Admin FP discriminator:** Backup agents (Veeam, Commvault) access a single known backup share, read .bak/.zip files on a schedule, never inspect file content, and never download to an unregistered destination.

---

### 10. CredentialMemoryAccess
**Source cluster:** `harvesting/` (chromekatz, Invoke-RDPThief, RunAs-Stealer)
**Sensor:** `windows_deepsensor`
**MITRE:** T1003, T1555

**What it teaches:**
- PROCESS_VM_READ handle on browser processes (Chrome, Edge) from a non-browser parent = cookie/password extraction
- Cross-user process access: reading another user's browser memory requires SeDebugPrivilege -- highly anomalous
- NtCreateSection + NtMapViewOfSection sequence: injection into target process for in-memory credential reading
- DPAPI master key request outside the owning application context: decrypting stored secrets
- Browser SQLite database access (Cookies/Login Data): file-based credential extraction
- RDP credential theft via API hook injection into mstsc.exe

**Admin FP discriminator:** EDR agents (CrowdStrike, SentinelOne) read lsass memory using signed binaries running as SYSTEM with vendor code-signing certificates. The discriminator is: vendor cert + SYSTEM context vs. unsigned binary + interactive user context.

---

### 11. SCCMRecon
**Source cluster:** `harvesting/SCCMSecrets, sccmsqlclient`
**Sensor:** `windows_deepsensor`
**MITRE:** T1087, T1078

**What it teaches:**
- Direct WMI queries to `SMS_R_System`, `SMS_G_System_*` WMI classes = bypassing SCCM client, reading full managed endpoint inventory
- SCCM admin share access (`\\SERVER\SMS_<SiteCode>$`) = accessing deployment packages and scripts
- MSSQL connection to `CM_<SiteCode>` database = full inventory/policy/credential data
- NAA credential extraction: Network Access Account stored in WMI repository, readable without special privileges

**Admin FP discriminator:** Legitimate SCCM console queries run from `mmc.exe` via a service account, scope to a specific collection, and make 1–4 queries. Raw WMI to SMS_R_System classes outside the SCCM console is not authorized admin behavior.

---

### 12. LinuxPrivescEnum
**Source cluster:** `enumeration/linux/` (linenum.sh, lse, linux-enum.sh)
**Sensor:** `linux_sentinel` → `sentinel_math` vector
**MITRE:** T1083, T1087.001, T1068

**What it teaches:**
- File read volume: >100 files in 120 seconds from a shell process = bulk enumeration script execution
- SUID binary enumeration: checking >10 setuid binaries = mapping privilege escalation vectors
- `/proc/version` read: kernel version extraction for exploit selection
- Shadow file access attempt: credential theft preparation
- Writable directory probes: finding paths for payload staging
- External download: pulling a stage-2 tool after local enumeration completes
- UID context: unprivileged UID running enumeration = post-exploitation before escalation; root UID running enumeration = attacker already has root and is mapping further pivots

**Admin FP discriminator:** Monitoring agents (Nagios, Zabbix) read a bounded set of known metric paths (/proc/meminfo, /proc/loadavg) at regular intervals. They never enumerate SUID binaries, never read /etc/shadow, and run as a dedicated service UID.

---

### 13. SSHKeyHarvest
**Source cluster:** `harvesting/SSH-Stealer`
**Sensor:** `linux_sentinel`
**MITRE:** T1552.004

**What it teaches:**
- Private key file access: reading id_rsa, id_ed25519, id_ecdsa -- especially from multiple user home directories
- Cross-user home directory traversal: requires root or sudo; no legitimate single-user tool accesses other users' ~/.ssh/
- known_hosts read: mapping trusted SSH targets for subsequent pivoting
- authorized_keys read: mapping which keys grant inbound access to this host
- SSH agent socket access: hijacking a live agent for key-free authentication to any session the user has open

**Admin FP discriminator:** SSH key rotation scripts run from a service account, access only managed key paths under `/opt/` or defined service directories, never cross into user home directories, and are scheduled quarterly.

---

### 14. AzureO365Spray
**Source cluster:** `password_sprayers/` (MSOLSpray, teamFiltration, captaincredz, CredMaster)
**Sensor:** `azure_entraid` → `cloud_flow` vector
**MITRE:** T1110.003, T1078.004

**What it teaches:**
- Auth velocity: many UPNs targeted from a single IP in a short window (the defining spray signal)
- Error code diversity: AADSTS50126 (wrong password), AADSTS50053 (locked), AADSTS50057 (disabled), AADSTS50055 (expired) -- this diversity means the attacker is learning account states, not just testing one credential
- MFA-blocked accounts: these are valid accounts -- attacker now has a confirmed valid user list
- Non-browser user-agent: python-requests, Go-http-client, AutodiscoverClient (the real Office clients use rich OAuth flows)
- Seasonal password patterns: "Winter2024!", "Spring2024!" -- spray wordlist entries
- Lockout-aware pacing: requests spaced to stay below Azure Smart Lockout threshold

**Admin FP discriminator:** Password resets and SSO failures affect a single UPN from a known enterprise IP. The unique-UPN count is the primary discriminator -- 1 account = misconfiguration; 20+ accounts = spray.

---

### 15. ADPasswordSpray
**Source cluster:** `password_sprayers/` (DomainPasswordSpray, AD_Sprayer, pySprayer)
**Sensor:** `windows_deepsensor`
**MITRE:** T1110.003, T1078.002

**What it teaches:**
- LDAP bind failure fan-out: N failures across M accounts where N/M < lockout_threshold = spray
- Kerberos AS-REQ failures (KDC_ERR_PREAUTH_FAILED) from a single source to many accounts
- Sub-threshold awareness: 1–2 failures per account with many accounts is impossible to explain as a service account misconfiguration
- Seasonal password vocabulary: spray tools use predictable patterns

**Admin FP discriminator:** Service account misconfiguration produces many failures for exactly one account. The discriminator is `unique_accounts_failed` -- if >5 distinct accounts fail authentication from the same source in a short window with <3 failures each, it is definitionally a spray.

---

### 16. CloudStorageEnum
**Source cluster:** `scanners/s3scanner`, automated cloud asset discovery
**Sensor:** `aws_cloudtrail` → `cloud_flow` vector
**MITRE:** T1619

**What it teaches:**
- Anonymous requests: no Authorization header = unauthenticated enumeration
- Multi-provider scope: probing AWS S3 + GCP Storage + DigitalOcean Spaces simultaneously = systematic cloud asset discovery, not a developer debugging
- GetBucketAcl API calls: mapping access permissions for found buckets
- Anonymous-listable buckets: when a bucket returns 200 to an unauthenticated ListBucket request, it is publicly exposed

**Admin FP discriminator:** Legitimate cloud clients always send signed requests (AWS Signature v4, GCP OAuth2). An authorized audit uses an IAM role with ListBucket/GetBucketAcl permissions, sends authenticated requests, and has an audit ticket. The discriminator is the presence or absence of the Authorization header.

---

### 17. CICDSecretsHarvest
**Source cluster:** `harvesting/nord-stream`
**Sensor:** `aws_cloudtrail`
**MITRE:** T1552.004, T1098

**What it teaches:**
- Secrets API enumeration: GET `/repos/*/actions/secrets` across multiple repositories = harvest, not pipeline execution (pipelines access secrets through the runner runtime, not the REST API)
- Environment secrets enumeration: `/repos/*/environments` = staging/production credential access
- New workflow creation: injecting a malicious job to execute in the pipeline and exfiltrate secrets
- Log deletion after workflow run: covering tracks -- legitimate pipelines never delete their own logs
- OIDC token to external STS: cloud credential exfiltration (e.g., assuming an AWS role via GitHub OIDC)

**Admin FP discriminator:** Legitimate DevSecOps audits use a service account with pre-approved repos, make list API calls only (no workflow creation), and have a ticket. Log deletion is never authorized in a legitimate CI/CD pipeline.

---

### 18. MultiProtocolBrute
**Source cluster:** `password_sprayers/legba` (multi-protocol brute forcer)
**Sensor:** `network_tap`
**MITRE:** T1110.001

**What it teaches:**
- Multi-service fan-out: simultaneously targeting SSH:22, RDP:3389, LDAP:389, WinRM:5985, MSSQL:1433 = credential testing across the entire service portfolio
- Credential pair volume: >50 pairs tested = password list, not human guessing
- Request timing: machine-generated, consistent inter-attempt intervals

**Admin FP discriminator:** IT connectivity checks test a single service on a known host with 1 credential pair and a 5-second timeout. Multi-protocol fan-out has no legitimate operational use case.

---

### 19. OAuthPhishing
**Source cluster:** `social_eng/oauthseeker`
**Sensor:** `azure_entraid`
**MITRE:** T1528

**What it teaches:**
- Unregistered app: `app_registered_in_tenant=NO` -- user consented to an external attacker-controlled application
- Scope greed: requesting Mail.Read + Files.Read.All + User.ReadBasic.All gives email, file, and directory access
- Token persistence: 24h refresh cycle maintains access even after password resets (token does not expire with password change)
- Admin consent flow: attacker crafting an admin consent URL to get tenant-wide access rather than per-user
- Post-consent Graph API calls: immediate data collection after token acquisition

**Admin FP discriminator:** Enterprise OAuth apps are registered in the tenant's app catalog, have a publisher-verified badge, use minimal scopes, and go through IT admin pre-consent. `app_registered_in_tenant=YES` + `publisher_verified=YES` is the discriminator.

---

### 20. PhishingInfra
**Source cluster:** `social_eng/gophish-deploy`, phisherman-lab
**Sensor:** `network_tap`
**MITRE:** T1566, T1598

**What it teaches:**
- Fresh domain: <30 days old -- registered specifically for a campaign
- Let's Encrypt certificate: free, no identity validation -- not used for production corporate services
- Tracking pixel requests: GET requests to a 1x1 pixel endpoint from diverse source IPs = email open tracking
- Credential POST submissions: HTTP POST with username/password fields to a non-corporate domain
- Email sender domain spoofing: From: header claims a trusted brand while DKIM/SPF fail

**Admin FP discriminator:** Authorized corporate phishing simulations use pre-registered domains in corporate DNS, have a security team ticket, and use certificates from the corporate PKI. The domain age + cert issuer combination is the strongest discriminator.

---

### GraphAPIEnumeration *(migrated from tools/)*
**Sensor:** `azure_entraid` | **MITRE:** T1087.004

python-requests UA hitting 5+ Graph API endpoints in bulk. S3 query: None (azure_entraid not in SENSOR_COLUMNS). FP: Authorized Graph API integration with OAuth service account.

---

### MFABypassEnum *(migrated from tools/)*
**Sensor:** `azure_entraid` | **MITRE:** T1078.004, T1110

4+ legacy protocols tested across multiple accounts (IMAP/EWS/ActiveSync/ADFS). S3 query: None (azure_entraid not in SENSOR_COLUMNS). FP: IT testing protocol availability.

---

### ExchangeEmailRecon *(migrated from tools/)*
**Sensor:** `network_tap` | **MITRE:** T1114, T1087

OWA/EWS bulk mailbox access. dst_port IN (443,993,143,25) with Exchange/ews URIs from single src. FP: Authorized archival tool with service account.

---

### SharePointCredSearch *(migrated from tools/)*
**Sensor:** `network_tap` | **MITRE:** T1213.002, T1530

/_api/search/query GET requests with high packet count (> 20). Keyword-driven document search for credentials/secrets. FP: Authorized search indexer with service account.

---

## Training Output

Default run (`--records-per-class 10 --admin-fps-per-class 2`):
- **200 true-positive records** -- adversarial behavioral patterns
- **40 false-positive records** -- admin activity that looks similar but isn't

Total: **240 SFT training records** across 5 sensor types:
- `network_tap` (c2_math): 11 classes
- `windows_deepsensor` (windows_math): 6 classes
- `azure_entraid` (cloud_flow): 3 classes
- `linux_sentinel` (sentinel_math): 2 classes
- `aws_cloudtrail` (cloud_flow): 2 classes

## Extending This Corpus

When adding a new tool to `arcanaeum/offsec/ttps/1_Recon/`:
1. Add a function pair `_<name>_tp(i)` / `_<name>_fp(i)` to the script
2. Add an entry to `TOOL_CLASSES` with sensor, MITRE techniques, and the two functions
3. Add an S3 query to `S3_QUERIES` if the behavior is observable in network_tap or cloud audit logs
4. Document the class in this MANIFEST under the correct source cluster
5. Run `python stage_recon_behavioral.py --tool-filter <NewClass>` to validate output
