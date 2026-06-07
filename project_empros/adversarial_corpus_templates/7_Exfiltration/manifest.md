# 7_Exfiltration -- Adversarial Corpus Manifest

**MITRE Tactic:** TA0010 -- Exfiltration
**Source tools:** `arcanaeum/offsec/ttps/7_Exfiltration/`
**Script:** `stage_exfiltration_behavioral.py`
**Pipeline target:** `make stage-exfil` / `make data-exfil`

---

## Detection Philosophy

Exfiltration tools exploit legitimate protocols (DNS, ICMP, HTTP, NTP, FTP, IMAP, BGP)
and cloud services (Discord, Pastebin, Confluence, Jira, GitHub, Dropbox, Telegram).
Detection requires looking beyond "is this protocol allowed?" to:

1. **Volume anomalies** -- sequential DNS TXT queries, 500+ ICMP requests, bulk Confluence exports
2. **Encoding signatures** -- base64 in subdomains, oversized Cookie headers, high-entropy NTP fields
3. **Process context** -- python-requests UA on Confluence API at off-hours, Go binary with no service registration
4. **Structural anomalies** -- chunk_index/total_chunks form fields, 1000-deep ZIP nesting, constant response sizes despite variable content

---

## Tool Classes

### 1. DNSTXTChunkedExfil
**Source:** `todns/`, `PyExfil/DNS`
**Sensor:** `network_tap`
**MITRE:** T1048.003

**Detection teaches:**
- Sequential numbered TXT queries: `1.evil.com`, `2.evil.com`, ..., `N.evil.com`
- Fixed chunk size per query (~250 or 255 bytes per TXT record)
- Near-zero TTL (prevents caching -- ensures fresh data each query)
- Base64-encoded subdomain labels (high entropy, no human-readable words)
- Machine-generated timing (CV < 0.10)
- Fresh domain (< 30 days)

**Admin FP:** SPF/DKIM TXT queries -- single record, descriptive content, not sequential numbered.

---

### 2. DNSOOBCallback
**Source:** `sqlmapsh/`, PyExfil OOB
**Sensor:** `network_tap`
**MITRE:** T1048.003

**Detection teaches:**
- 32-hex-character subdomain of out-of-band callback infrastructure (interact.sh, OAST)
- Query type can be A, CNAME, MX, TXT -- attacker picks what passes through
- Database query result hex-encoded as the hostname label
- Often correlated with preceding HTTP request (SQL injection trigger)
- No legitimate application queries interact.sh or oast.* domains

**Admin FP:** Authorized pentest Burp Collaborator callback -- ticketed, CISO-approved, scoped tester IP.

---

### 3. ICMPEncryptedExfil
**Source:** `pingSmuggler/`, `PyExfil/ICMP`
**Sensor:** `network_tap`
**MITRE:** T1048.003

**Detection teaches:**
- ICMP echo request payload >64 bytes (standard ping = 32-56 bytes)
- High payload entropy (>3.5) -- AES-CBC encrypted data with prepended IV
- Sequential ICMP sequence numbers with machine-generated timing
- One-way ICMP (no echo replies when firewall blocks return path)
- Requires raw socket access (CAP_NET_RAW / Administrator)

**Admin FP:** Standard network ping -- 32B payload, standard alphabet pattern, irregular timing, small count.

---

### 4. HTTPChunkedUpload
**Source:** `exfilserver/`
**Sensor:** `network_tap`
**MITRE:** T1048.002

**Detection teaches:**
- Form fields explicitly named `chunk_index` and `total_chunks` (custom protocol, not standard multipart)
- Multiple POST requests for single file with consistent chunk sizes
- XOR-encrypted payload (content obfuscated from DLP)
- Server returns hex-encoded filenames in responses
- Configurable delays between chunks to mimic user behavior

**Admin FP:** SharePoint/cloud upload uses standard multipart with Content-Range, no chunk metadata fields.

---

### 5. HTTPCookieExfil
**Source:** `PyExfil/HTTP_Cookies`
**Sensor:** `network_tap`
**MITRE:** T1048.002

**Detection teaches:**
- Cookie header size >500 bytes (legitimate session cookies are <200 bytes)
- Cookie value has uniform high entropy (base64 encoded data, not key=value pairs)
- No semicolons in cookie value (entire cookie is one encoded blob)
- No preceding session establishment (cookie not tied to login)
- Sequential GET requests with consistent cookie size = automated chunk loop

**Admin FP:** Normal session cookies -- <200 bytes, structured key=value, following session establishment.

---

### 6. RawTCPBackdoor
**Source:** `Backdoor/`
**Sensor:** `network_tap`
**MITRE:** T1041, T1059

**Detection teaches:**
- Persistent TCP connection to external IP on non-standard port (4444, 5555, 1337)
- No TLS: content visible + raw JSON framing
- JSON command/response protocol with file transfer in 1024-byte chunks
- Subprocess spawning: arbitrary OS command execution via backdoor
- 20-second reconnect interval: persistent auto-reconnect behavior

**Admin FP:** Monitoring agent on TLS 8443 -- CMDB registered, corp PKI cert, no command execution.

---

### 7. QUICTunnelExfil
**Source:** `PyExfil/QUIC`
**Sensor:** `network_tap`
**MITRE:** T1048.003, T1001

**Detection teaches:**
- UDP traffic on port 443 from non-browser process (python.exe, powershell.exe)
- No QUIC Initial packet handshake (not real QUIC -- AES-encrypted payload in raw UDP)
- High entropy UDP payloads
- Destination is not Google/CDN IP range (real browser QUIC goes to AS15169)
- Consistent packet sizes = chunked file exfiltration

**Admin FP:** Chrome QUIC to Google -- browser parent, Google ASN, proper QUIC handshake.

---

### 8. ConfluenceBulkExfil
**Source:** `Conf-Thief/`
**Sensor:** `aws_cloudtrail`
**MITRE:** T1213

**Detection teaches:**
- Bulk CQL keyword searches via `/wiki/rest/api/search` (multiple keywords from credential dictionary)
- PDF export requests for every matched page via `/wiki/spaces/flyingpdf/pdfpageexport.action`
- Export task polling: async export = attacker waiting for each PDF to generate
- Python-requests User-Agent (script, not browser)
- Off-hours operation; 50-500+ pages exported in one session

**Admin FP:** Confluence UI export of 1-5 pages with change ticket, business hours, browser UA.

---

### 9. JiraBulkExfil
**Source:** `Jir-Thief/`
**Sensor:** `aws_cloudtrail`
**MITRE:** T1213

**Detection teaches:**
- JQL query with credential-hunting keywords: `text~'password' OR text~'token' OR text~'secret'`
- .doc export for every matched issue via `/si/jira.issueviews:issue-word/<KEY>/<KEY>.doc`
- Pagination at 100 results per request (automated iteration)
- Python-requests/2.25.1 User-Agent (script)
- Rapid sequential Word document downloads matching all search results

**Admin FP:** User exporting 1 issue via Jira UI with change ticket.

---

### 10. DiscordWebhookExfil
**Source:** `DocEx/DisordExf/`
**Sensor:** `network_tap`
**MITRE:** T1567

**Detection teaches:**
- HTTPS POST to `discord.com/api/webhooks/{id}/{token}` with file attachments
- Rapid bulk uploads of document files (docx, pdf, xlsx, csv) -- not alert notifications
- python-requests User-Agent (no Discord client)
- Burst upload pattern: multiple files in seconds, automated collection
- Files are data-containing documents, not simple text notifications

**Admin FP:** CI/CD webhook sending JSON deployment notifications -- no file attachments.

---

### 11. PastebinExfil
**Source:** `Out-Pastebin.ps1`, `VeilTransfer`
**Sensor:** `sysmon_sensor`
**MITRE:** T1567

**Detection teaches:**
- Two-step API: auth (api_login.php) then post (api_post.php) -- programmatic use
- Paste size >10KB (file data, not code snippet)
- Private/unlisted paste setting (api_paste_private=1 or 2 -- hiding from detection)
- Short expiration (TTL): data retrieved and deleted quickly
- PowerShell/python parent (not browser)

**Admin FP:** Developer sharing small public code snippet via browser.

---

### 12. CloudStorageExfil
**Source:** `VeilTransfer/`
**Sensor:** `network_tap`
**MITRE:** T1567

**Detection teaches:**
- ZIP created immediately before upload (staging behavior: collect → compress → exfil)
- Upload to attacker-controlled accounts via GitHub API, Dropbox, Telegram Bot, MEGA
- OAuth token used (attacker-controlled account)
- Off-hours operation
- Parent process is a script (not a backup service binary)
- Unknown destination account (not in corporate cloud asset inventory)

**Admin FP:** Veeam backup to company-owned Azure Blob -- service account, CMDB, scheduled, ticket.

---

### 13. NTPTimestampExfil
**Source:** `PyExfil/NTP`
**Sensor:** `network_tap`
**MITRE:** T1048.003

**Detection teaches:**
- NTP-format packets from non-NTP client process (python.exe, not w32tm.exe)
- High timestamp field entropy (>3.0 vs. ~1.5 for real clock data)
- Machine-generated interval (CV < 0.10) -- not NTP's adaptive sync timing
- Destination is not pool.ntp.org or corporate NTP server
- Sustained query loop (20-200 packets) vs. NTP's infrequent sync

**Admin FP:** w32tm.exe to pool.ntp.org every ~64 minutes -- standard Windows NTP sync.

---

### 14. FTPMKDIRExfil
**Source:** `PyExfil/FTP_MKDIR`
**Sensor:** `network_tap`
**MITRE:** T1048.003

**Detection teaches:**
- Sequential FTP MKDIR commands with base64-encoded directory names
- Directory names contain file chunks (zlib+base64 encoded)
- No corresponding file PUT operations (data is in directory names, not files)
- Machine-generated timing for directory creation sequence
- No human-readable directory names

**Admin FP:** FTP admin creating 3 descriptive directories with change ticket.

---

### 15. IMAPDraftExfil
**Source:** `PyExfil/IMAP`
**Sensor:** `network_tap`
**MITRE:** T1048, T1071.003

**Detection teaches:**
- IMAP APPEND to Drafts folder with large message body (>100KB)
- No corresponding SMTP send: data staged, not transmitted
- High message body entropy (encrypted/encoded content)
- Automated client (python.exe parent, not email client)
- Bypasses email DLP that only inspects traffic via SMTP

**Admin FP:** Outlook auto-saving small draft during user composition -- will be sent via SMTP.

---

### 16. BGPSteganography
**Source:** `PyExfil/BGP_Open`
**Sensor:** `network_tap`
**MITRE:** T1048.003

**Detection teaches:**
- TCP 179 connection from non-router host (workstation)
- BGP Open packet from python/script process
- Private AS number (64512-65535) -- fabricated for exfil
- Data embedded in BGP Optional Parameters field
- Host not in BGP peer registry

**Admin FP:** Core router BGP session -- registered peer, router device, authorized ASN.

---

### 17. ImageLSBSteganography
**Source:** `PyExfil/image_steganography`, `PyExfil/PNG_transparency`
**Sensor:** `network_tap`
**MITRE:** T1027

**Detection teaches:**
- Image file larger than expected for its resolution/format
- LSB plane entropy >3.5 (natural images have ~0.5 in LSB plane)
- Alpha channel modifications in PNG (transparency carrier)
- Image uploaded to external host after local creation
- Content appears visually identical -- DLP passes without steganalysis

**Admin FP:** Normal screenshot -- expected size, low LSB entropy (~0.5).

---

### 18. ZIPNestingDLPBypass
**Source:** `PyExfil/ZIPception`
**Sensor:** `network_tap`
**MITRE:** T1027, T1048

**Detection teaches:**
- Archive nesting depth >100 levels (most DLP tools stop at 100-500)
- Created programmatically (no archive tool produces 1000-deep nesting manually)
- Inner file size ≈ outer archive size (no additional content in wrapper ZIPs)
- DLP reports "archive not fully scanned due to nesting limit"
- Inner file content passes uninspected

**Admin FP:** Normal tar.gz or zip with depth 1-3 -- well within scan limits.

---

### 19. LongPollingTunnel
**Source:** `Heavypin/`
**Sensor:** `network_tap`
**MITRE:** T1048.002, T1001

**Detection teaches:**
- Frequent HTTPS GET requests (long polling) to same server at machine-generated intervals
- CONSTANT response sizes despite variable content (random padding to prevent traffic analysis)
- Self-signed RSA 4096 certificate (high-security attacker infra)
- Local proxy port open (traffic proxied through this host)
- Professional anti-traffic-analysis design: padding + polling + self-signed cert

**Admin FP:** Slack long polling -- vendor domain, DigiCert cert, variable response sizes, user session.

---

### 20. MultiProtocolTunnel
**Source:** `Pulsar/`
**Sensor:** `network_tap`
**MITRE:** T1048.003, T1001

**Detection teaches:**
- Go binary reading from one protocol (TCP, UDP) and writing to another (DNS, ICMP, BGP)
- Multi-layer encoding chain (base32 + AES-CTR, base64 + AES-256)
- Sustained throughput (not bursty -- continuous exfiltration operation)
- No registered service context for the Go binary
- Protocol-hopping: different inspection rules apply to input vs. output protocol

**Admin FP:** stunnel (TLS wrapper) -- CMDB registered, single encoding, documented purpose.

---

### MetadataStripExfil *(migrated from tools/)*
**Sensor:** `sysmon_sensor` | **MITRE:** T1565, T1048

Bulk metadata strip (50-5000 files, mixed types) removing author/company/GPS metadata followed immediately by upload. Optional encryption layer. FP: GDPR compliance removal of 1-5 files with ticket.

---

## Training Output

Default run (`--records-per-class 10 --admin-fps-per-class 2`):
- **200 true-positive records** -- exfiltration behavioral patterns
- **40 false-positive records** -- legitimate traffic that looks similar

Total: **240 SFT training records** across 3 sensor types:
- `network_tap` (c2_math): 17 classes
- `aws_cloudtrail` (cloud_flow): 2 classes (Confluence, Jira)
- `sysmon_sensor` (windows_math): 1 class (Pastebin)

## S3 Query Patterns

Behavioral filters for Track 6 live telemetry matching:
- `DNSTXTChunkedExfil`: DNS TXT queries with high entropy and sequential numbering
- `ICMPEncryptedExfil`: ICMP packets >64B payload, high entropy, external destination
- `HTTPChunkedUpload`: Multiple POST requests to same dst with large payload
- `DiscordWebhookExfil`: POST to discord.com/api/webhooks with large payload
- `NTPTimestampExfil`: UDP 123 from non-w32tm.exe with regular intervals
- `BGPSteganography`: TCP 179 to external non-router destinations
- `LongPollingTunnel`: HTTPS with self-signed cert, constant response sizes, frequent polling

## Extending

When a new exfiltration tool appears in `arcanaeum/offsec/ttps/7_Exfiltration/`:
1. Identify the protocol/service used for data transfer
2. Find the encoding/obfuscation technique
3. Identify the discriminating behavioral signal vs. legitimate use of that protocol
4. Create `_<name>_tp(i)` / `_<name>_fp(i)` functions
5. Add to TOOL_CLASSES and S3_QUERIES
6. Document here
