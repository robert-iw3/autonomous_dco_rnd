"""
stage_exfiltration_behavioral.py -- Comprehensive Exfiltration TTP Behavioral Dataset

Detection philosophy: behavioral evidence only -- timing, size patterns, API
call sequences, entropy, protocol anomalies. No tool names in detection logic.
Every class has admin FP variants.

Output:
  data/staging/exfiltration_behavioral_v1.jsonl
  data/staging/exfiltration_query_index.json

Usage:
    python stage_exfiltration_behavioral.py
    python stage_exfiltration_behavioral.py --records-per-class 15
    python stage_exfiltration_behavioral.py --tool-filter DNSTXTChunkedExfil,ICMPEncryptedExfil
"""

import json
import random
import argparse
import logging
import hashlib
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stage-exfil")
random.seed(31)

OUTPUT_DIR  = Path("../data/staging")
OUTPUT_FILE = OUTPUT_DIR / "exfiltration_behavioral_v1.jsonl"
INDEX_FILE  = OUTPUT_DIR / "exfiltration_query_index.json"

TTP_CAT = "Exfiltration"

SYS = {
    "network_tap": (
        "You are the Network Tap Forensics Expert. Analyze the session window "
        "using pre-computed fields (port_class, JA3, cert metadata, is_internal_dst, "
        "payload_entropy, variance_inter_arrival, byte_ratio). "
        "Identify exfiltration tradecraft. Output MITRE ATT&CK + containment."
    ),
    "sysmon_sensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 6D windows_math. Source: Sysmon event stream. "
        "Schema: sysmon_event_id, Image, CommandLine, ParentImage, User, "
        "TargetFilename, QueryName, DestinationIp, DestinationPort. "
        "Identify exfiltration tradecraft. Output MITRE ATT&CK + containment."
    ),
    "linux_sentinel": (
        "You are the Host Forensics Expert. Target OS: Linux/Unix. "
        "Vector Space: 5D sentinel_math. Schema: comm, command_line, uid, dest_ip, syscall. "
        "Identify exfiltration tradecraft. Output MITRE ATT&CK + containment."
    ),
    "aws_cloudtrail": (
        "You are the Cloud Infrastructure Expert. Analyze AWS CloudTrail / Cloud Audit events. "
        "Identify data exfiltration patterns. Output MITRE + containment."
    ),
}

VECTOR = {
    "network_tap":    "c2_math",
    "sysmon_sensor":  "windows_math",
    "linux_sentinel": "sentinel_math",
    "aws_cloudtrail": "cloud_flow",
}

def _ip_int():  return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
def _ip_ext():
    p = random.choice(["45.33","104.21","172.67","185.220","198.51"])
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"
def _host():    return f"{random.choice(['WS','SRV','LT','APP'])}-{random.randint(10,99)}"
def _user():    return random.choice(["jsmith","alee","tmorgan","schen","rbrown"])
def _domain():  return f"{random.choice(['update','cdn','api','sync','data'])}.{random.choice(['io','net','co','xyz','site'])}"
def _b64(n=20): return "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", k=n))
def _hex(n=16): return "".join(random.choices("0123456789abcdef", k=n))

def _cot(a1, a2, a3, conclusion, technique, action="contain"):
    verdict = "TRUE POSITIVE" if action == "contain" else "FALSE POSITIVE"
    return (f"<analysis>\n[AXIS 1] Benign Alternative Assessment:\n  {a1}\n"
            f"[AXIS 2] Behavioral Proof Assessment:\n  {a2}\n"
            f"[AXIS 3] Entity Coverage:\n  {a3}\n"
            f"[CONCLUSION] {conclusion}\n</analysis>\n"
            f"{verdict}. {technique}\nRECOMMENDED_ACTION: {action}")

def _record(tool_class, sensor, mitre, msgs, cls, event_id=None):
    r = {"ttp_category": TTP_CAT, "tool_class": tool_class,
         "mitre_techniques": mitre, "source_type": sensor,
         "vector_name": VECTOR[sensor], "classification": cls,
         "messages": msgs}
    if event_id is not None:
        r["event_id"] = event_id
    elif sensor in ("sysmon_sensor", "linux_sentinel"):
        r["event_id"] = hashlib.md5(f"{tool_class}_{cls}_{sensor}".encode()).hexdigest()[:16]
    return r

def _msg(sensor, user_text, asst_text):
    wrapped = (
        f"Spatial Anomaly Detected.\n"
        f"Source: {sensor}\n"
        f"Vector: <|spatial_vector|>\n"
        f"{user_text}"
    )
    return [{"role": "system",    "content": SYS[sensor]},
            {"role": "user",      "content": wrapped},
            {"role": "assistant", "content": asst_text}]


# ═══════════════════════════════════════════════════════════════════════════════
# 1. DNSTXTChunkedExfil
#    Evidence: Sequential numbered TXT queries to single domain (1.evil.com,
#              2.evil.com...), base64-encoded subdomains, fixed chunk size
#              (~250 bytes per TXT record), burst query pattern
#    Sources: todns, PyExfil DNS, Invoke-PowerCloud
#    Admin FP: SPF/DKIM TXT queries (descriptive content, single record, non-sequential)
# ═══════════════════════════════════════════════════════════════════════════════

def _dns_txt_tp(i):
    domain = _domain()
    chunk_size = random.choice([250, 255, 128, 512])
    n_queries  = random.randint(20, 500)
    interval_s = round(random.uniform(0.05, 2.0), 3)
    cv         = round(random.uniform(0.0, 0.08), 4)
    p = {
        "src": _ip_int(), "domain": domain,
        "chunk_size": chunk_size, "n_queries": n_queries,
        "interval_s": interval_s, "cv": cv,
        "sample_queries": [f"{k}.{domain}" for k in range(1, 4)],
        "ttl": random.choice([0, 30, 60, 120]),
        "encoding": "Base64",
        "domain_age_days": random.randint(1, 30),
    }
    prompt = (f"Network Tap -- DNS TXT Chunked Exfiltration.\n"
              f"Source: {p['src']} → DNS resolver → {p['domain']}\n"
              f"  sequential_txt_queries={p['n_queries']}\n"
              f"  sample_queries: {p['sample_queries']}\n"
              f"  chunk_size_bytes={p['chunk_size']} (consistent)\n"
              f"  inter_query_interval_s={p['interval_s']}  cv={p['cv']:.4f}\n"
              f"  txt_response_ttl={p['ttl']}s\n"
              f"  subdomain_encoding={p['encoding']}\n"
              f"  domain_age_days={p['domain_age_days']}")
    cot = _cot(
        f"Legitimate TXT records (SPF, DKIM, DMARC) are fetched once per session, "
        f"not in sequences of {p['n_queries']} numbered queries. "
        "CDN health checks and DNS-based discovery do not produce base64-encoded subdomains with sequential numeric prefixes.",
        f"Sequential pattern 1.{domain}, 2.{domain}, ... {p['n_queries']}.{domain}: "
        "numbered index = file chunk identifier. "
        f"TXT chunk size={p['chunk_size']}B (consistent = fixed encoding stride). "
        f"TTL={p['ttl']}s (near-zero to prevent caching of exfil data). "
        f"cv={p['cv']:.4f} (machine-generated query loop). "
        f"domain_age={p['domain_age_days']}d (registered for this campaign).",
        f"Source {p['src']} is exfiltrating data via DNS TXT records to {p['domain']}. "
        f"At {p['chunk_size']}B per query x {p['n_queries']} queries = "
        f"~{p['chunk_size']*p['n_queries']/1024:.0f}KB exfiltrated via DNS. "
        "Bypasses HTTP/HTTPS firewall inspection entirely.",
        "DNS TXT exfiltration confirmed -- sequential chunked queries.",
        "MITRE T1048.003 (Exfiltration Over Alternative Protocol: DNS). "
        "Block domain at DNS resolver, capture DNS query log for data recovery.",
    )
    return prompt, cot, "true_positive"

def _dns_txt_fp(i):
    p = {"domain": "company.com", "record_type": "SPF",
         "content": "v=spf1 include:_spf.google.com ~all",
         "queries": 1, "context": "email delivery validation"}
    prompt = (f"Network Tap -- DNS TXT Query.\n"
              f"  domain={p['domain']}  record={p['record_type']}\n"
              f"  query_count={p['queries']}  content_type=SPF\n"
              f"  context={p['context']}  sequential_numbering=NO")
    cot = _cot(
        "Single SPF TXT query for email validation -- not sequential, not base64 encoded.",
        f"queries=1. Content='v=spf1...' (SPF record). No numbering. Email context.",
        "Authorized SPF record lookup for email validation.",
        "Authorized DNS TXT SPF lookup. No action.",
        "T1048.003 -- AUTHORIZED DNS LOOKUP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. DNSOOBCallback
#    Evidence: Out-of-band DNS callback during SQL injection / code execution,
#              interactsh-style subdomain (random hex + interact.sh domain),
#              DNS query carries encoded data (hostname = hex-encoded result)
#    Sources: sqlmapsh, PyExfil DNS OOB
#    Admin FP: Legitimate DNS callback in authorized pen test (known domain, ticket)
# ═══════════════════════════════════════════════════════════════════════════════

def _dns_oob_tp(i):
    callback_domain = f"{_hex(8)}.oast.{random.choice(['fun','me','pro','live'])}"
    payload_host = f"{_hex(32)}.{callback_domain}"
    p = {
        "src": _ip_int(), "dst_ip": _ip_ext(),
        "callback_domain": callback_domain,
        "payload_host": payload_host,
        "query_type": random.choice(["A","CNAME","TXT","MX"]),
        "data_in_hostname": True,
        "correlation_with_http": i%2==0,
        "db_output_encoded": True,
    }
    prompt = (f"Network Tap -- DNS Out-of-Band (OOB) Data Callback.\n"
              f"Source: {p['src']}\n"
              f"  callback_domain: {p['callback_domain']}\n"
              f"  query: {p['payload_host']}\n"
              f"  query_type={p['query_type']}\n"
              f"  encoded_data_in_hostname=YES (hex-encoded query result)\n"
              + (f"  correlated_http_request=YES (SQL injection context)\n" if p['correlation_with_http'] else "")
              + f"  random_hex_subdomain=YES  oast_infrastructure=YES")
    cot = _cot(
        "Legitimate DNS queries use human-readable hostnames. "
        "A 32-character lowercase hex string as a subdomain of an out-of-band "
        "callback infrastructure (interact.sh, Burp Collaborator) is not any "
        "legitimate application behavior.",
        f"Hostname '{p['payload_host'][:50]}': 32-hex-char subdomain of OOB callback infrastructure. "
        f"query_type={p['query_type']}: attacker selected query type that passes through DNS filters. "
        f"encoded_data_in_hostname=YES: database query results encoded in the DNS lookup. "
        + (f"Correlated HTTP request: SQL injection triggered the OOB DNS callback. " if p['correlation_with_http'] else "")
        + "interact.sh/OAST domain: public OOB infrastructure used by attackers.",
        f"Source {p['src']} is exfiltrating data via out-of-band DNS queries. "
        "The encoded hostname contains extracted data (e.g., database contents, credentials). "
        "DNS OOB bypasses firewall rules that block direct outbound data connections.",
        "DNS OOB data exfiltration confirmed.",
        "MITRE T1048.003 (Exfiltration Over Alternative Protocol: DNS OOB). "
        "Block oast/* domains, correlate with inbound request that triggered callback.",
    )
    return prompt, cot, "true_positive"

def _dns_oob_fp(i):
    p = {"domain": "r7iuz3.burpcollaborator.net",
         "context": "authorized penetration test", "ticket": f"PT-{random.randint(100,999)}"}
    prompt = (f"Network Tap -- DNS Callback (Authorized Pentest).\n"
              f"  callback_domain={p['domain']}\n"
              f"  context={p['context']}  ticket={p['ticket']}\n"
              f"  authorized_by=CISO  source_in_pentest_scope=YES")
    cot = _cot(
        "Authorized pentest using Burp Collaborator OOB -- ticketed, CISO-approved, scoped.",
        f"Ticket {p['ticket']}. CISO approval. Pentest scope. Known tester source IP.",
        "Authorized pentest OOB callback. No action.",
        "Authorized pentest DNS callback. No action.",
        "T1048.003 -- AUTHORIZED PENTEST. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ICMPEncryptedExfil
#    Evidence: ICMP echo requests with payloads >64 bytes (AES-CBC encrypted),
#              sequential ICMP sequence numbers with regular timing,
#              raw socket access on sender (requires CAP_NET_RAW / Administrator)
#    Sources: pingSmuggler, PyExfil ICMP
#    Admin FP: Network ping/troubleshooting (standard 32-56 byte payload, irregular timing)
# ═══════════════════════════════════════════════════════════════════════════════

def _icmp_tp(i):
    dst = _ip_ext()
    payload_size = random.randint(48, 1480)
    n_packets = random.randint(20, 500)
    interval_s = round(random.uniform(0.05, 0.5), 3)
    p = {
        "src": _ip_int(), "dst": dst,
        "payload_size": payload_size, "n_packets": n_packets,
        "interval_s": interval_s, "cv": round(random.uniform(0.0, 0.08), 4),
        "entropy": round(random.uniform(3.8, 5.5), 3),
        "icmp_type": 8,
        "iv_prepended": True,
        "no_echo_replies": i%3==0,
    }
    prompt = (f"Network Tap -- ICMP Encrypted Exfiltration.\n"
              f"Source: {p['src']} → {p['dst']}\n"
              f"  icmp_type={p['icmp_type']} (Echo Request)\n"
              f"  payload_size_bytes={p['payload_size']} (IV prepended + AES-CBC)\n"
              f"  total_packets={p['n_packets']}\n"
              f"  interval_s={p['interval_s']}  cv={p['cv']:.4f}\n"
              f"  payload_entropy={p['entropy']:.3f}\n"
              + (f"  echo_replies_received=0 (firewall blocking return -- attacker unconcerned)\n" if p['no_echo_replies'] else ""))
    cot = _cot(
        "Network ping for troubleshooting uses the standard payload pattern (ABCDE...) "
        "of 32-56 bytes, triggered by user or script, with irregular timing. "
        f"Payload size of {p['payload_size']}B with entropy={p['entropy']:.3f} "
        "(encrypted) and machine-generated timing has no diagnostic use case.",
        f"payload_size={p['payload_size']}B (standard ping is 32-56B -- "
        f"this is {p['payload_size']-48}B over minimum = AES ciphertext + IV). "
        f"entropy={p['entropy']:.3f} (encrypted data, not standard ping pattern). "
        f"cv={p['cv']:.4f} (machine-generated -- automated sender). "
        f"n_packets={p['n_packets']} with consistent size = chunked file transfer. "
        + (f"no echo replies: attacker doesn't care about responses -- one-way data exfil. " if p['no_echo_replies'] else ""),
        f"Source {p['src']} is exfiltrating encrypted data via ICMP to {p['dst']}. "
        f"~{p['payload_size']*p['n_packets']/1024:.0f}KB transferred via ICMP. "
        "Bypasses firewall rules that only inspect TCP/UDP.",
        "ICMP encrypted exfiltration confirmed.",
        "MITRE T1048.003 (Exfiltration Over Alternative Protocol: ICMP). "
        "Block outbound ICMP to external IPs, capture raw packets.",
    )
    return prompt, cot, "true_positive"

def _icmp_fp(i):
    p = {"dst": _ip_ext(), "payload": 32, "count": random.randint(3,10), "reason": "connectivity test"}
    prompt = (f"Network Tap -- ICMP Ping.\n"
              f"  dst={p['dst']}  payload_size_bytes={p['payload']}\n"
              f"  count={p['count']}  reason={p['reason']}\n"
              f"  entropy=0.2 (standard pattern)  timing=irregular")
    cot = _cot(
        "Standard ping -- 32-byte payload, standard alphabet pattern, irregular timing, small count.",
        f"payload=32B (standard). entropy=0.2 (standard pattern). irregular timing. count={p['count']}.",
        "Authorized connectivity test. No action.",
        "Standard network ping. No action.",
        "T1048.003 -- AUTHORIZED PING. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. HTTPChunkedUpload
#    Evidence: Multiple POST requests with form fields chunk_index/total_chunks,
#              XOR-encrypted payload, consistent chunk sizes, configurable delays,
#              hex-encoded filenames in server responses
#    Sources: exfilserver
#    Admin FP: Legitimate multipart file upload (no chunk metadata fields, TLS, CDN)
# ═══════════════════════════════════════════════════════════════════════════════

def _http_chunk_tp(i):
    dst = _ip_ext()
    chunk_size = random.choice([64*1024, 128*1024, 256*1024, 1024*1024])
    total_chunks = random.randint(5, 100)
    delay_ms = random.randint(0, 5000) if i%2==0 else 0
    p = {
        "src": _ip_int(), "dst": dst, "port": random.choice([8000, 443, 8080]),
        "chunk_size_kb": chunk_size//1024, "total_chunks": total_chunks,
        "delay_ms": delay_ms,
        "form_fields": ["file", "original_name", "chunk_index", "total_chunks"],
        "encrypted": True,
        "filename_hex": True,
    }
    prompt = (f"Network Tap -- HTTP Chunked Exfiltration Upload.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']}\n"
              f"  total_post_requests={p['total_chunks']}\n"
              f"  form_fields: {', '.join(p['form_fields'])}\n"
              f"  chunk_size_kb={p['chunk_size_kb']}  total_chunks={p['total_chunks']}\n"
              f"  delay_between_chunks_ms={p['delay_ms']} (mimicking user behavior)\n"
              f"  payload_encrypted=YES (XOR cipher)\n"
              f"  server_filenames_hex_encoded=YES")
    cot = _cot(
        "Legitimate web forms and file upload APIs don't include `chunk_index` and `total_chunks` "
        "as explicit form fields -- they use multipart boundary with Content-Range headers if "
        "chunked at all. Adversarial chunking explicitly names the chunk metadata.",
        f"Form fields include 'chunk_index' + 'total_chunks': "
        "custom chunking protocol (not standard multipart or tus resumable). "
        f"XOR-encrypted payload: content obfuscated from network inspection. "
        f"Server returns hex-encoded filenames (attacker hiding file paths). "
        + (f"Delay={p['delay_ms']}ms between chunks: mimicking user behavior to avoid rate detection. " if p['delay_ms'] > 0 else "")
        + f"{p['total_chunks']} POST requests for single file = {p['total_chunks']*p['chunk_size_kb']/1024:.1f}MB exfiltrated.",
        f"Source {p['src']} is uploading {p['total_chunks']} encrypted chunks to {p['dst']}:{p['port']}. "
        f"Total exfiltrated: ~{p['total_chunks']*p['chunk_size_kb']//1024}MB.",
        "HTTP chunked exfiltration upload confirmed.",
        "MITRE T1048.002 (Exfiltration Over Alternative Protocol: HTTP). "
        "Block destination IP, recover chunk files from server if accessible.",
    )
    return prompt, cot, "true_positive"

def _http_chunk_fp(i):
    p = {"service": "SharePoint Online", "dst": "company.sharepoint.com",
         "content_type": "multipart/form-data (standard)", "tls": True}
    prompt = (f"Network Tap -- SharePoint File Upload.\n"
              f"  dst={p['dst']}  tls={p['tls']}\n"
              f"  upload_type={p['content_type']}\n"
              f"  form_fields=standard (no chunk_index/total_chunks)\n"
              f"  dest_in_approved_cloud_list=YES")
    cot = _cot(
        "SharePoint file upload -- standard multipart, no custom chunk metadata, approved cloud.",
        f"Standard multipart. No chunk_index/total_chunks fields. Approved cloud destination.",
        "Authorized SharePoint file upload. No action.",
        "Authorized cloud file upload. No action.",
        "T1048.002 -- AUTHORIZED CLOUD UPLOAD. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. HTTPCookieExfil
#    Evidence: HTTP GET/POST requests with oversized Cookie headers (>500 bytes),
#              Cookie values are base64-encoded (high entropy, no semicolons),
#              sequential requests, no corresponding session context
#    Sources: PyExfil HTTP_Cookies
#    Admin FP: Legitimate session cookie (<200 bytes, low entropy)
# ═══════════════════════════════════════════════════════════════════════════════

def _cookie_tp(i):
    dst = _ip_ext()
    cookie_size = random.randint(500, 4000)
    n_requests = random.randint(10, 200)
    p = {
        "src": _ip_int(), "dst": dst,
        "cookie_size": cookie_size, "n_requests": n_requests,
        "entropy": round(random.uniform(3.8, 5.5), 3),
        "cookie_base64": True,
        "no_session_context": True,
        "cv": round(random.uniform(0.0, 0.10), 4),
    }
    prompt = (f"Network Tap -- HTTP Cookie Exfiltration.\n"
              f"Source: {p['src']} → {p['dst']}\n"
              f"  http_method=GET  total_requests={p['n_requests']}\n"
              f"  cookie_header_size_bytes={p['cookie_size']}\n"
              f"  cookie_value_entropy={p['entropy']:.3f}\n"
              f"  cookie_base64_encoded=YES (no semicolons, uniform entropy)\n"
              f"  no_preceding_session_establishment=YES\n"
              f"  inter_request_cv={p['cv']:.4f}")
    cot = _cot(
        f"Legitimate browser cookies are <200 bytes, contain key=value pairs separated by "
        "semicolons, and are associated with a prior session establishment (login, redirect). "
        f"A {p['cookie_size']}B base64-encoded cookie with no prior session is not browser behavior.",
        f"Cookie header size={p['cookie_size']}B (legitimate cookies are <200B). "
        f"entropy={p['entropy']:.3f} (base64 encoded file data, not structured key=value). "
        "No semicolons: entire cookie is one monolithic encoded blob. "
        "No preceding session: cookie not associated with any login/redirect. "
        f"cv={p['cv']:.4f}: machine-generated request loop with data chunks.",
        f"Source {p['src']} is encoding file data in HTTP Cookie headers. "
        f"{p['n_requests']} requests x {p['cookie_size']}B = "
        f"~{p['n_requests']*p['cookie_size']//1024}KB exfiltrated via Cookie headers.",
        "HTTP Cookie exfiltration confirmed.",
        "MITRE T1048.002 (Exfiltration Over HTTP via Cookie). "
        "Block destination, inspect Cookie header content.",
    )
    return prompt, cot, "true_positive"

def _cookie_fp(i):
    p = {"site": "accounts.google.com", "cookie_size": random.randint(50,200),
         "entropy": round(random.uniform(1.0, 2.5), 3)}
    prompt = (f"Network Tap -- Normal Web Session Cookie.\n"
              f"  site={p['site']}\n"
              f"  cookie_size_bytes={p['cookie_size']}\n"
              f"  entropy={p['entropy']:.3f} (structured key=value)\n"
              f"  session_established_first=YES  browser_parent=YES")
    cot = _cot(
        "Standard session cookie -- small, structured, following session establishment, browser-initiated.",
        f"size={p['cookie_size']}B. entropy={p['entropy']:.3f} (structured). session established first.",
        "Authorized browser session cookie. No action.",
        "Authorized web session cookie. No action.",
        "T1048.002 -- AUTHORIZED SESSION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. RawTCPBackdoor
#    Evidence: Persistent TCP connection on non-standard port to external IP,
#              JSON command/response protocol, 1024-byte file transfer chunks,
#              subprocess spawning for command execution, 20s reconnect loop
#    Sources: Backdoor.py / server.py
#    Admin FP: Legitimate application on known port with TLS and service registration
# ═══════════════════════════════════════════════════════════════════════════════

def _tcp_backdoor_tp(i):
    dst = _ip_ext()
    port = random.choice([4444, 5555, 1337, 8888, 9999, 4321])
    p = {
        "src": _ip_int(), "dst": dst, "port": port,
        "protocol": "raw TCP (no TLS)",
        "chunk_size": 1024,
        "json_framing": True,
        "reconnect_interval_s": 20,
        "subprocess_spawn": True,
        "session_duration_h": round(random.uniform(0.1, 8.0), 1),
    }
    prompt = (f"Network Tap + Sysmon -- Raw TCP Backdoor with Exfiltration.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']}\n"
              f"  protocol={p['protocol']}\n"
              f"  json_command_response_framing=YES\n"
              f"  file_transfer_chunk_size_bytes={p['chunk_size']}\n"
              f"  reconnect_interval_s={p['reconnect_interval_s']}\n"
              f"  subprocess_spawned_on_source=YES (command execution)\n"
              f"  session_duration_h={p['session_duration_h']}")
    cot = _cot(
        "Legitimate applications using TCP communicate on registered well-known ports with "
        "TLS encryption and have service registration in the CMDB. "
        f"An unencrypted persistent TCP connection to an external IP on port {port} "
        "with JSON command framing and subprocess spawning has no enterprise analog.",
        f"Raw TCP (no TLS): command content visible + data unprotected in transit. "
        f"Port {port}: non-standard, not in service registry. "
        f"JSON framing: operator sends command, victim returns output. "
        f"1024B file chunks: file download/upload capability. "
        f"subprocess_spawn: arbitrary OS command execution. "
        f"reconnect_interval={p['reconnect_interval_s']}s: auto-reconnect = persistent backdoor.",
        f"Host {p['src']} has an active backdoor connection to {p['dst']}:{port}. "
        "Attacker has full command execution and file exfiltration capability.",
        "Raw TCP backdoor with exfiltration capability confirmed.",
        "MITRE T1041 (Exfiltration Over C2 Channel) + T1059 (Command Execution). "
        "Block destination IP, kill process, forensic investigation of commands run.",
    )
    return prompt, cot, "true_positive"

def _tcp_backdoor_fp(i):
    p = {"app": "internal-monitoring-agent", "port": 8443, "tls": True,
         "cmdb": "YES", "cert": "corp-pki"}
    prompt = (f"Network Tap -- Monitoring Agent TCP Connection.\n"
              f"  app={p['app']}  port={p['port']}\n"
              f"  tls={p['tls']}  cert={p['cert']}\n"
              f"  cmdb_registered={p['cmdb']}  no_subprocess_spawn=YES")
    cot = _cot(
        "Corporate monitoring agent on TLS 8443 -- CMDB registered, corp PKI cert, no command execution.",
        f"TLS. port=8443 (registered). CMDB. Corp cert. No subprocess.",
        "Authorized monitoring agent TCP connection. No action.",
        "Authorized monitoring connection. No action.",
        "T1041 -- AUTHORIZED MONITORING. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. QUICTunnelExfil
#    Evidence: UDP traffic on port 443 from non-browser process,
#              AES-encrypted (not true QUIC TLS 1.3), high entropy UDP payloads,
#              non-QUIC timing/packet patterns
#    Sources: PyExfil QUIC module
#    Admin FP: Chrome browser using QUIC for Google services
# ═══════════════════════════════════════════════════════════════════════════════

def _quic_tp(i):
    dst = _ip_ext()
    p = {
        "src": _ip_int(), "dst": dst, "port": 443,
        "protocol": "UDP (fake QUIC)",
        "parent_proc": random.choice(["python.exe","powershell.exe","unknown.exe"]),
        "entropy": round(random.uniform(3.8, 5.5), 3),
        "not_browser": True,
        "no_quic_handshake": True,
        "packet_count": random.randint(20, 500),
    }
    prompt = (f"Network Tap -- QUIC Protocol Exfiltration Tunnel.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']} (UDP)\n"
              f"  protocol_label={p['protocol']}\n"
              f"  initiating_process={p['parent_proc']}\n"
              f"  payload_entropy={p['entropy']:.3f}\n"
              f"  quic_initial_packet_present=NO (no real QUIC handshake)\n"
              f"  browser_process=NO\n"
              f"  packet_count={p['packet_count']}")
    cot = _cot(
        "Legitimate QUIC traffic to port 443 comes from browsers (Chrome, Firefox) connecting "
        "to known Google/CDN infrastructure. QUIC begins with a specific QUIC Initial packet "
        "with a well-defined header format. AES-encrypted UDP without a QUIC handshake is not QUIC.",
        f"Parent={p['parent_proc']} (not a browser). "
        f"No QUIC Initial packet handshake: not actual QUIC -- AES payload in UDP. "
        f"entropy={p['entropy']:.3f} (encrypted data, not QUIC-framed with variable headers). "
        f"dst is not Google/GCLB IP range: not a legitimate QUIC target. "
        f"{p['packet_count']} UDP packets of consistent size = chunked file exfil.",
        f"Host {p['src']} is tunneling exfiltrated data over UDP 443 disguised as QUIC. "
        "Bypasses rules that assume UDP 443 = legitimate browser traffic.",
        "QUIC-masquerading UDP exfiltration tunnel confirmed.",
        "MITRE T1048.003 (Exfiltration Over Alternative Protocol) + T1001 (Data Obfuscation). "
        "Block UDP 443 from non-browser processes, inspect packet content.",
    )
    return prompt, cot, "true_positive"

def _quic_fp(i):
    p = {"proc": "chrome.exe", "dst": "142.250.80.14", "asn": "AS15169 Google LLC"}
    prompt = (f"Network Tap -- Chrome QUIC Traffic.\n"
              f"  parent={p['proc']}  dst={p['dst']}  dst_asn={p['asn']}\n"
              f"  quic_handshake=YES  browser_process=YES  port=443 UDP")
    cot = _cot(
        "Chrome browser QUIC to Google infrastructure -- browser parent, Google ASN, proper QUIC handshake.",
        f"parent=chrome.exe. asn=AS15169 Google. Proper QUIC Initial packet.",
        "Authorized Chrome QUIC to Google services. No action.",
        "Authorized Chrome QUIC. No action.",
        "T1048.003 -- AUTHORIZED BROWSER QUIC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. ConfluenceBulkExfil
#    Evidence: Burst of CQL keyword search API calls followed by PDF export
#              requests, export status polling, bulk PDF downloads from Confluence
#    Sources: Conf-Thief
#    Admin FP: Authorized IT exporting few pages with change ticket
# ═══════════════════════════════════════════════════════════════════════════════

def _conf_tp(i):
    confluence = f"confluence.{random.choice(['corp','company','internal'])}.com"
    n_keywords = random.randint(3, 20)
    n_pages = random.randint(50, 500)
    p = {
        "src": _ip_int(), "confluence": confluence,
        "n_keywords": n_keywords, "n_pages": n_pages,
        "api_sequence": [
            f"/wiki/rest/api/search?cql=text~'password' (keyword 1/{n_keywords})",
            f"… {n_keywords} keyword searches",
            f"/wiki/spaces/flyingpdf/pdfpageexport.action?pageId=<N> x {n_pages}",
            f"/wiki/runningtaskxml.action?taskId=<T> (polling x {n_pages})",
            f"PDF downloads x {n_pages}",
        ],
        "hours": random.choice([0, 1, 2, 3, 22, 23]),
        "ua": "python-requests/2.28.0",
    }
    prompt = (f"Cloud Audit -- Confluence Bulk Page Exfiltration.\n"
              f"Source IP: {p['src']}  Confluence: {p['confluence']}\n"
              f"  cql_keyword_searches={p['n_keywords']}\n"
              f"  pdf_export_requests={p['n_pages']}\n"
              f"  export_task_polls=YES (async export pattern)\n"
              f"  total_pdfs_downloaded={p['n_pages']}\n"
              f"  user_agent={p['ua']}\n"
              f"  hour={p['hours']:02d}:xx (off-hours)\n"
              f"  api_sequence: {p['api_sequence'][0]}")
    cot = _cot(
        "Confluence users legitimately search and export pages, but this is bounded "
        "(1-10 pages per session) and done interactively via the web UI. "
        f"A script performing {p['n_keywords']} keyword searches and exporting {p['n_pages']} PDFs "
        "via the API at off-hours with python-requests is not a user action.",
        f"API User-Agent=python-requests (script, not browser). "
        f"CQL search x {p['n_keywords']}: automated keyword list from credential/config dictionary. "
        f"PDF export x {p['n_pages']}: every matched page exported as PDF. "
        "Export task polling: attacker is waiting for each async export to complete. "
        f"Off-hours ({p['hours']:02d}:xx): avoiding detection during work day.",
        f"Source {p['src']} has exported {p['n_pages']} Confluence pages as PDFs. "
        "Content matched keywords (passwords, credentials, config, etc.). "
        "Potentially all pages matching those keywords are now in attacker's possession.",
        "Confluence bulk keyword-targeted page exfiltration confirmed.",
        "MITRE T1213 (Data from Information Repositories: Confluence). "
        "Revoke API token, review Confluence audit logs, notify data owners.",
    )
    return prompt, cot, "true_positive"

def _conf_fp(i):
    p = {"pages": random.randint(1, 5), "ticket": f"DOCS-{random.randint(100,999)}",
         "sa": "jsmith", "reason": "quarterly compliance report compilation"}
    prompt = (f"Cloud Audit -- Confluence Page Export.\n"
              f"  user={p['sa']}  pages_exported={p['pages']}\n"
              f"  ticket={p['ticket']}  reason={p['reason']}\n"
              f"  api_user_agent=Confluence-UI  business_hours=YES")
    cot = _cot(
        f"User exporting {p['pages']} pages via Confluence UI for compliance report -- bounded, ticketed.",
        f"pages={p['pages']}. UI browser. Business hours. Ticket {p['ticket']}.",
        "Authorized Confluence export for compliance documentation.",
        "Authorized Confluence export. No action.",
        "T1213 -- AUTHORIZED EXPORT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. JiraBulkExfil
#    Evidence: JQL keyword search + .doc export per issue, pagination (100/page),
#              python-requests UA, bulk sequential Word document downloads
#    Sources: Jir-Thief
#    Admin FP: Authorized single-issue export for documentation
# ═══════════════════════════════════════════════════════════════════════════════

def _jira_tp(i):
    jira = f"jira.{random.choice(['corp','company','internal'])}.com"
    n_keywords = random.randint(2, 15)
    n_issues = random.randint(30, 300)
    p = {
        "src": _ip_int(), "jira": jira,
        "n_keywords": n_keywords, "n_issues": n_issues,
        "jql": f"text~'password' OR text~'token' OR text~'secret'",
        "export_format": ".doc (Word)",
        "ua": "python-requests/2.25.1",
    }
    prompt = (f"Cloud Audit -- Jira Bulk Issue Exfiltration.\n"
              f"Source: {p['src']}  Jira: {p['jira']}\n"
              f"  jql_query: {p['jql']}\n"
              f"  keyword_count={p['n_keywords']}\n"
              f"  issues_matched_and_exported={p['n_issues']}\n"
              f"  export_format={p['export_format']}\n"
              f"  user_agent={p['ua']}\n"
              f"  pagination=100_per_request")
    cot = _cot(
        "Jira users legitimately export individual issues for documentation. "
        f"Bulk JQL search for sensitive keywords ({p['jql']}) followed by "
        f".doc export of {p['n_issues']} issues via python-requests is not a user action.",
        f"JQL: {p['jql']} (credential-hunting keywords). "
        f"n_issues={p['n_issues']}: every matched issue exported as Word doc. "
        f"pagination=100: script iterating through all results automatically. "
        f"User-Agent=python-requests: automated script, not Jira UI. "
        f"Sequential .doc downloads: issue exfiltration for offline credential mining.",
        f"Source {p['src']} has exported {p['n_issues']} Jira issues as Word documents. "
        "Issues containing passwords, tokens, and secrets are now in attacker's possession.",
        "Jira bulk keyword-targeted issue exfiltration confirmed.",
        "MITRE T1213 (Data from Information Repositories: Jira). "
        "Revoke API token, audit Jira access logs, rotate any credentials found in issues.",
    )
    return prompt, cot, "true_positive"

def _jira_fp(i):
    p = {"user": _user(), "issues": 1, "ticket": f"INC-{random.randint(100,999)}"}
    prompt = (f"Cloud Audit -- Jira Issue Export.\n"
              f"  user={p['user']}  issues_exported={p['issues']}\n"
              f"  ticket={p['ticket']}  jira_ui=YES")
    cot = _cot(
        "User exporting single Jira issue via Jira UI -- one issue, browser, authorized.",
        f"issues=1. Jira UI. Ticket {p['ticket']}.",
        "Authorized single Jira issue export. No action.",
        "Authorized Jira issue export. No action.",
        "T1213 -- AUTHORIZED SINGLE EXPORT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. DiscordWebhookExfil
#     Evidence: HTTPS POST to discord.com/api/webhooks/ with file attachments,
#               automated rapid uploads of document files (docx/pdf/xlsx),
#               no user Discord client present (API-only pattern)
#     Sources: DocEx/DisordExf
#     Admin FP: Authorized IT Discord integration sending notifications
# ═══════════════════════════════════════════════════════════════════════════════

def _discord_tp(i):
    webhook_id = f"{random.randint(10**17, 10**18-1)}/{_b64(60).replace('=','').replace('+','-').replace('/','_')}"
    n_files = random.randint(5, 50)
    file_types = random.sample(["docx","pdf","xlsx","pptx","csv","txt","zip"], k=random.randint(2,5))
    p = {
        "src": _ip_int(), "webhook": webhook_id[:30],
        "n_files": n_files, "file_types": file_types,
        "total_mb": round(random.uniform(1, 500), 1),
        "no_discord_client": True,
        "ua": "python-requests",
    }
    prompt = (f"Network Tap -- Discord Webhook File Exfiltration.\n"
              f"Source: {p['src']} → discord.com/api/webhooks/{p['webhook']}...\n"
              f"  file_attachments_sent={p['n_files']}\n"
              f"  file_types: {', '.join(p['file_types'])}\n"
              f"  total_data_mb={p['total_mb']}\n"
              f"  discord_client_active=NO (API-only)\n"
              f"  user_agent={p['ua']}\n"
              f"  burst_upload_pattern=YES")
    cot = _cot(
        "Authorized Discord integrations for IT notifications send small JSON payloads "
        "or text alerts -- they do not upload bulk document files. "
        f"Rapid posting of {p['n_files']} document files ({p['total_mb']}MB) via webhook "
        "from python-requests without a Discord client is an exfiltration script.",
        f"Webhook POST with multipart file attachments: Discord file upload API. "
        f"file_types={p['file_types']}: documents containing sensitive data. "
        f"n_files={p['n_files']}: bulk automated upload (not alert-triggered). "
        f"ua=python-requests: no browser, no Discord client = script. "
        f"Burst pattern: consecutive uploads in seconds -- automated collection loop.",
        f"Source {p['src']} has sent {p['total_mb']}MB of documents to attacker-controlled "
        "Discord server via webhook. All uploaded files are permanently accessible to webhook owner.",
        "Discord webhook bulk document exfiltration confirmed.",
        "MITRE T1567 (Exfiltration to Code Repository/Service). "
        "Block discord.com webhook API from automated processes, audit uploads.",
    )
    return prompt, cot, "true_positive"

def _discord_fp(i):
    p = {"app": "CI/CD webhook", "content": "deployment notification JSON",
         "files": 0, "authorized": True}
    prompt = (f"Network Tap -- Discord Webhook Notification.\n"
              f"  source_app={p['app']}  content_type={p['content']}\n"
              f"  file_attachments={p['files']}  authorized={p['authorized']}\n"
              f"  webhook_in_approved_list=YES")
    cot = _cot(
        "CI/CD deployment notification -- JSON text only, no file attachments, authorized integration.",
        f"file_attachments=0. JSON text only. Authorized. Approved webhook.",
        "Authorized CI/CD notification webhook. No action.",
        "Authorized webhook notification. No action.",
        "T1567 -- AUTHORIZED WEBHOOK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. PastebinExfil
#     Evidence: HTTPS POST to pastebin.com/api/api_post.php with api_paste_code
#               containing large data, PowerShell initiating API auth + paste,
#               paste content is encoded/encrypted file data
#     Sources: Out-Pastebin.ps1, VeilTransfer pastebin
#     Admin FP: Developer sharing legitimate code snippet (small, business hours)
# ═══════════════════════════════════════════════════════════════════════════════

def _pastebin_tp(i):
    p = {
        "src": _ip_int(),
        "parent": random.choice(["powershell.exe","python.exe","cmd.exe"]),
        "paste_size_kb": random.randint(10, 1000),
        "private": random.choice(["1", "2"]),  # 1=unlisted, 2=private
        "expire": random.choice(["10M","1H","1D","N"]),
        "content_type": random.choice(["base64-encoded binary","credential dump","config file dump"]),
        "api_steps": 2,  # auth + post
    }
    prompt = (f"Sysmon + Network Tap -- Pastebin Data Exfiltration.\n"
              f"Host: {p['src']}\n"
              f"  parent_process={p['parent']}\n"
              f"  step1: POST pastebin.com/api/api_login.php (auth)\n"
              f"  step2: POST pastebin.com/api/api_post.php\n"
              f"    api_paste_code_size_kb={p['paste_size_kb']}\n"
              f"    api_paste_private={p['private']} (not public)\n"
              f"    api_paste_expire_date={p['expire']}\n"
              f"  content_type={p['content_type']}")
    cot = _cot(
        "Developers legitimately use Pastebin for sharing code, but interactively and with "
        f"small payloads (<10KB). A {p['paste_size_kb']}KB paste from {p['parent']} (not a browser) "
        "set to private/unlisted with a short expiration is exfiltration-oriented behavior.",
        f"parent={p['parent']} (not a browser -- automated script). "
        f"paste_size={p['paste_size_kb']}KB (file data, not a code snippet). "
        f"private={p['private']} (hidden from public search -- reduces detection). "
        f"expire={p['expire']} (short TTL -- data retrieved and then expires to avoid forensics). "
        f"Two-step API: auth then post = programmatic API usage, not UI.",
        f"Host {p['src']}: {p['paste_size_kb']}KB of {p['content_type']} posted to Pastebin. "
        "Attacker retrieves data from known Pastebin URL and deletes paste.",
        "Pastebin data exfiltration confirmed.",
        "MITRE T1567 (Exfiltration to Code Repository/Service). "
        "Block pastebin.com API from automated processes, check paste history if accessible.",
    )
    return prompt, cot, "true_positive"

def _pastebin_fp(i):
    p = {"user": _user(), "size_kb": random.randint(1,8), "content": "Python script",
         "public": True}
    prompt = (f"Network Tap -- Pastebin Paste Creation.\n"
              f"  user={p['user']}  size_kb={p['size_kb']}\n"
              f"  content={p['content']}  public={p['public']}\n"
              f"  browser_parent=YES  business_hours=YES")
    cot = _cot(
        "Developer sharing small public code snippet via browser -- small, public, browser-initiated.",
        f"size={p['size_kb']}KB. public. browser. Business hours.",
        "Authorized developer paste share. No action.",
        "Authorized Pastebin use. No action.",
        "T1567 -- AUTHORIZED DEVELOPER PASTE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. CloudStorageExfil
#     Evidence: ZIP file created then uploaded to cloud storage via API
#               (GitHub commits, Dropbox PUT, Telegram sendDocument, MEGA upload),
#               OAuth token or API key used, off-hours automated upload
#     Sources: VeilTransfer
#     Admin FP: Authorized backup service (scheduled, service account, CMDB)
# ═══════════════════════════════════════════════════════════════════════════════

def _cloud_storage_tp(i):
    services = [
        ("api.github.com", "/repos/attacker/repo/contents/data.zip", "GitHub repo commit"),
        ("api.dropboxapi.com", "/2/files/upload", "Dropbox upload"),
        ("api.telegram.org", "/bot{TOKEN}/sendDocument", "Telegram bot upload"),
        ("mega.nz", "/cs?id=... (MEGA API)", "MEGA cloud upload"),
    ]
    svc_host, svc_path, svc_desc = random.choice(services)
    p = {
        "src": _ip_int(), "svc": svc_host, "path": svc_path, "desc": svc_desc,
        "zip_created_first": True,
        "zip_size_mb": round(random.uniform(1, 200), 1),
        "oauth_token": True,
        "hour": random.choice([0, 1, 2, 3, 22, 23]),
        "parent": random.choice(["powershell.exe","python.exe","cmd.exe"]),
    }
    prompt = (f"Network Tap -- Cloud Storage Exfiltration via {p['desc']}.\n"
              f"Source: {p['src']} → {p['svc']}{p['path']}\n"
              f"  method=POST/PUT with OAuth Bearer token\n"
              f"  zip_created_before_upload=YES\n"
              f"  zip_size_mb={p['zip_size_mb']}\n"
              f"  initiating_process={p['parent']}\n"
              f"  hour={p['hour']:02d}:xx (off-hours)\n"
              f"  destination_account=UNKNOWN (attacker-controlled)")
    cot = _cot(
        "Authorized cloud backup services use service accounts registered in the CMDB, "
        "operate on a schedule, and upload to company-owned cloud accounts. "
        f"A {p['zip_size_mb']}MB ZIP upload to an unknown {p['desc'].split()[0]} account "
        f"from {p['parent']} at {p['hour']:02d}:00 is not an authorized backup.",
        f"ZIP created immediately before upload: staging behavior (collect → compress → exfil). "
        f"Upload to {p['svc']} (cloud service) via OAuth token: attacker-controlled account. "
        f"parent={p['parent']} (not a backup service binary). "
        f"Off-hours ({p['hour']:02d}:xx): avoiding detection. "
        f"destination_account=unknown: not a company-owned cloud account.",
        f"Source {p['src']} has exfiltrated {p['zip_size_mb']}MB to attacker-controlled "
        f"{p['desc'].split()[0]} account. Data is now outside corporate infrastructure.",
        f"Cloud storage exfiltration confirmed via {p['desc']}.",
        "MITRE T1567 (Exfiltration to Code Repository/Service). "
        "Block cloud storage API endpoints from workstations, investigate ZIP contents.",
    )
    return prompt, cot, "true_positive"

def _cloud_storage_fp(i):
    p = {"svc": "Veeam → Azure Blob", "account": "corp-backup-storage",
         "sa": "svc-backup", "schedule": "nightly 02:00",
         "ticket": f"OPS-{random.randint(100,999)}"}
    prompt = (f"Network Tap -- Cloud Backup Upload.\n"
              f"  service={p['svc']}  account={p['account']}\n"
              f"  service_account={p['sa']}  schedule={p['schedule']}\n"
              f"  ticket={p['ticket']}  cmdb_registered=YES")
    cot = _cot(
        "Veeam backup to company-owned Azure Blob -- service account, CMDB, scheduled, ticket.",
        f"Veeam (signed). Company-owned account. Service account. CMDB. Ticket.",
        "Authorized cloud backup operation. No action.",
        "Authorized backup. No action.",
        "T1567 -- AUTHORIZED BACKUP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. NTPTimestampExfil
#     Evidence: NTP packets on UDP 123 with anomalous timestamp fields,
#               regular interval NTP requests from non-NTP process,
#               timestamp entropy higher than legitimate clock sync
#     Sources: PyExfil NTP Body / NTP Request
#     Admin FP: Windows NTP sync (ntpd / w32tm, infrequent, to pool.ntp.org)
# ═══════════════════════════════════════════════════════════════════════════════

def _ntp_tp(i):
    dst = _ip_ext()
    p = {
        "src": _ip_int(), "dst": dst, "port": 123,
        "packet_count": random.randint(20, 200),
        "interval_s": round(random.uniform(0.1, 5.0), 2),
        "cv": round(random.uniform(0.0, 0.08), 4),
        "timestamp_entropy": round(random.uniform(3.5, 5.5), 3),
        "not_system_ntp": True,
        "parent": random.choice(["python.exe","perl.exe","unknown.exe"]),
    }
    prompt = (f"Network Tap -- NTP Timestamp Steganography Exfiltration.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']} (UDP NTP)\n"
              f"  ntp_packets_sent={p['packet_count']}\n"
              f"  interval_s={p['interval_s']}  cv={p['cv']:.4f}\n"
              f"  ntp_timestamp_field_entropy={p['timestamp_entropy']:.3f}\n"
              f"  sender_process={p['parent']}\n"
              f"  system_time_sync_daemon_inactive=YES\n"
              f"  destination_not_ntp_pool=YES")
    cot = _cot(
        "Legitimate NTP sync (w32tm.exe, ntpd) queries pool.ntp.org or corporate NTP servers "
        "every 8-64 minutes. The timestamp fields have realistic clock values, not encrypted data.",
        f"sender={p['parent']} (not w32tm.exe or ntpd -- not the system NTP client). "
        f"interval={p['interval_s']}s at cv={p['cv']:.4f} (machine loop, not NTP sync timing). "
        f"timestamp_entropy={p['timestamp_entropy']:.3f} (should be ~1.5 for real clock data; "
        "high entropy = encoded data in timestamp fields). "
        f"dst not NTP pool server: attacker-controlled NTP server collecting embedded data.",
        f"Source {p['src']} is encoding data in NTP timestamp fields. "
        f"{p['packet_count']} packets x 32 bytes = "
        f"~{p['packet_count']*32}B exfiltrated via 'NTP' traffic.",
        "NTP timestamp steganography exfiltration confirmed.",
        "MITRE T1048.003 (Exfiltration Over Alternative Protocol: NTP). "
        "Block outbound UDP 123 to non-approved NTP servers.",
    )
    return prompt, cot, "true_positive"

def _ntp_fp(i):
    p = {"proc": "w32tm.exe", "dst": "pool.ntp.org", "interval": "~64min",
         "entropy": 1.5}
    prompt = (f"Network Tap -- NTP Time Synchronization.\n"
              f"  process={p['proc']}  dst={p['dst']}\n"
              f"  interval={p['interval']}  timestamp_entropy={p['entropy']}\n"
              f"  approved_ntp_server=YES")
    cot = _cot(
        "w32tm.exe to pool.ntp.org every ~64min -- standard Windows NTP sync, low entropy timestamps.",
        f"w32tm.exe. pool.ntp.org. ~64min interval. entropy=1.5 (real clock).",
        "Authorized Windows NTP sync. No action.",
        "Authorized NTP sync. No action.",
        "T1048.003 -- AUTHORIZED NTP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 14. FTPMKDIRExfil
#     Evidence: Sequential FTP MKDIR commands with base64/hex-encoded directory
#               names, zlib-compressed data split across dir names
#     Sources: PyExfil FTP MKDIR
#     Admin FP: FTP server administration (standard directory names, bounded)
# ═══════════════════════════════════════════════════════════════════════════════

def _ftp_mkdir_tp(i):
    dst = _ip_ext()
    n_mkdirs = random.randint(20, 200)
    p = {
        "src": _ip_int(), "dst": dst, "port": 21,
        "n_mkdirs": n_mkdirs,
        "sample_dirname": f"{_b64(20)}.chunk{random.randint(1,5)}",
        "encoding": "zlib+base64",
        "cv": round(random.uniform(0.0, 0.08), 4),
    }
    prompt = (f"Network Tap -- FTP MKDIR Steganography Exfiltration.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']}\n"
              f"  mkdir_commands_issued={p['n_mkdirs']}\n"
              f"  sample_dirname: {p['sample_dirname']}\n"
              f"  dirname_encoding={p['encoding']}\n"
              f"  cv={p['cv']:.4f}  dirnames_contain_encoded_data=YES")
    cot = _cot(
        "FTP MKDIR is used by admins to create server directory structures -- with descriptive names "
        "like 'uploads', 'logs', 'backup_2024'. "
        f"Creating {p['n_mkdirs']} directories named with base64 strings is not directory management.",
        f"{p['n_mkdirs']} MKDIR commands with directory names like '{p['sample_dirname'][:30]}': "
        "base64-encoded file data chunks embedded as directory names. "
        "zlib+base64 encoding: data compressed and encoded to fit directory name constraints. "
        f"cv={p['cv']:.4f}: automated sequential loop. "
        "No corresponding directory usage: directories created purely as data carriers.",
        f"Source {p['src']} is exfiltrating data via FTP MKDIR directory names. "
        "No actual files transferred -- data is in the directory names themselves.",
        "FTP MKDIR steganography exfiltration confirmed.",
        "MITRE T1048.003 (Exfiltration Over Alternative Protocol: FTP). "
        "Block outbound FTP to unauthorized servers, capture FTP command log.",
    )
    return prompt, cot, "true_positive"

def _ftp_mkdir_fp(i):
    p = {"user": "ftp-admin", "dirs": ["uploads","logs","archive_2024"],
         "count": 3, "ticket": f"OPS-{random.randint(100,999)}"}
    prompt = (f"Network Tap -- FTP Directory Creation.\n"
              f"  user={p['user']}  directories_created={p['count']}\n"
              f"  names={p['dirs']}  ticket={p['ticket']}\n"
              f"  descriptive_names=YES  base64=NO")
    cot = _cot(
        "FTP admin creating 3 descriptive directories -- not encoded, bounded, ticketed.",
        f"count=3. Descriptive names. No encoding. Ticket {p['ticket']}.",
        "Authorized FTP directory structure creation. No action.",
        "Authorized FTP MKDIR. No action.",
        "T1048.003 -- AUTHORIZED FTP MKDIR. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 15. IMAPDraftExfil
#     Evidence: IMAP APPEND command to Drafts folder with large message body,
#               message never sent (no SMTP RCPT TO), periodic draft creation
#               from unusual client, credentials or files in draft body
#     Sources: PyExfil IMAP Draft
#     Admin FP: Email client auto-saving drafts (browser, small, user-initiated)
# ═══════════════════════════════════════════════════════════════════════════════

def _imap_tp(i):
    p = {
        "src": _ip_int(), "imap_server": f"mail.{random.choice(['corp','company'])}.com",
        "port": random.choice([143, 993]),
        "parent": random.choice(["python.exe","powershell.exe"]),
        "draft_size_kb": random.randint(100, 5000),
        "imap_cmd": "APPEND 'Drafts' (\\Draft \\Seen) ...",
        "no_smtp": True,
        "message_body_entropy": round(random.uniform(3.5, 5.5), 3),
        "n_drafts": random.randint(3, 20),
    }
    prompt = (f"Network Tap -- IMAP Draft Folder Exfiltration.\n"
              f"Source: {p['src']} → {p['imap_server']}:{p['port']}\n"
              f"  imap_command={p['imap_cmd'][:50]}\n"
              f"  target_folder=Drafts (not Inbox/Sent)\n"
              f"  draft_size_kb={p['draft_size_kb']}\n"
              f"  drafts_created={p['n_drafts']}\n"
              f"  message_body_entropy={p['message_body_entropy']:.3f}\n"
              f"  smtp_send=NO (never transmitted)\n"
              f"  initiating_process={p['parent']}")
    cot = _cot(
        "Legitimate email clients save drafts automatically (small, <50KB, user-composing text). "
        f"A script using IMAP APPEND to save {p['draft_size_kb']}KB messages to Drafts "
        "without ever sending them is a covert channel -- attacker retrieves drafts from another location.",
        f"IMAP APPEND to 'Drafts': writes data directly without email delivery infrastructure. "
        f"draft_size={p['draft_size_kb']}KB: file data, not email text. "
        f"entropy={p['message_body_entropy']:.3f}: encrypted/encoded content. "
        f"no SMTP: data is never transmitted -- only stored in Drafts for attacker retrieval. "
        f"parent={p['parent']}: automated script, not email client. "
        "Technique bypasses DLP tools that only inspect email in transit.",
        f"Source {p['src']} is staging {p['draft_size_kb']}KB of encrypted data in "
        "email Drafts folder. Attacker retrieves from a different location (different IP, "
        "different device) without triggering email DLP.",
        "IMAP Draft covert exfiltration staging confirmed.",
        "MITRE T1048 (Exfiltration Over Alternative Protocol: IMAP) + T1071.003 (Mail). "
        "Inspect Drafts folder contents, block IMAP APPEND from automated processes.",
    )
    return prompt, cot, "true_positive"

def _imap_fp(i):
    p = {"client": "Outlook", "size_kb": random.randint(1,30), "folder": "Drafts"}
    prompt = (f"Network Tap -- IMAP Draft Auto-Save.\n"
              f"  client={p['client']}  size_kb={p['size_kb']}\n"
              f"  folder={p['folder']}  user_composing=YES\n"
              f"  smtp_sent_after=YES")
    cot = _cot(
        "Outlook auto-saving draft during composition -- small, user-initiated, will be sent.",
        f"Outlook. size={p['size_kb']}KB. User composing. SMTP send follows.",
        "Authorized email draft auto-save. No action.",
        "Authorized IMAP draft. No action.",
        "T1048 -- AUTHORIZED DRAFT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 16. BGPSteganography
#     Evidence: BGP Open packet from non-router process on TCP 179,
#               crafted BGP parameters with encoded data,
#               BGP session on host that is not a router/switch
#     Sources: PyExfil BGP Open
#     Admin FP: No admin FP -- BGP from a workstation is always adversarial
# ═══════════════════════════════════════════════════════════════════════════════

def _bgp_tp(i):
    dst = _ip_ext()
    p = {
        "src": _ip_int(), "dst": dst, "port": 179,
        "parent": random.choice(["python.exe","perl.exe","unknown.exe"]),
        "not_router": True,
        "open_packet_crafted": True,
        "data_in_optional_params": True,
        "as_number": random.randint(64512, 65535),  # private AS range
    }
    prompt = (f"Network Tap -- BGP Steganography Exfiltration.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']} (TCP BGP)\n"
              f"  bgp_open_packet=YES\n"
              f"  src_is_router=NO\n"
              f"  initiating_process={p['parent']}\n"
              f"  crafted_as_number={p['as_number']} (private range)\n"
              f"  data_in_optional_parameters=YES\n"
              f"  host_not_in_bgp_peer_list=YES")
    cot = _cot(
        "BGP is a routing protocol used only by network routers and BGP-enabled appliances. "
        f"A workstation process ({p['parent']}) establishing a BGP TCP session on port 179 "
        "has no legitimate purpose.",
        f"src_is_router=NO (workstation initiating BGP). "
        f"parent={p['parent']}: script crafting BGP packets. "
        f"AS={p['as_number']} (private AS range 64512-65535: fabricated for exfil). "
        f"data_in_optional_parameters: BGP Optional Parameters field carries encoded payload. "
        "BGP traffic from workstations is completely anomalous -- always adversarial.",
        f"Host {p['src']} is encoding data in BGP Open packets sent to {p['dst']}. "
        "BGP on TCP 179 bypasses HTTP/HTTPS/DNS inspection rules.",
        "BGP steganography exfiltration confirmed.",
        "MITRE T1048.003 (Exfiltration Over Alternative Protocol: BGP). "
        "Block TCP 179 from all non-router devices immediately.",
    )
    return prompt, cot, "true_positive"

def _bgp_fp(i):
    p = {"device": "core-router-01", "asn": 65001, "peer": "isp-peer-01"}
    prompt = (f"Network Tap -- BGP Routing Session.\n"
              f"  device={p['device']}  asn={p['asn']}\n"
              f"  peer={p['peer']}  device_type=router\n"
              f"  in_bgp_peer_list=YES")
    cot = _cot(
        "Core router BGP session -- registered peer, router device, authorized ASN.",
        f"device=core-router-01 (router). Registered peer. Normal BGP operation.",
        "Authorized BGP routing session. No action.",
        "Authorized router BGP. No action.",
        "T1048.003 -- AUTHORIZED BGP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. ImageLSBSteganography
#     Evidence: Image file upload significantly larger than expected for resolution,
#               LSB modification visible in pixel analysis,
#               image contains high-entropy regions in otherwise uniform areas
#     Sources: PyExfil image_steganography, PyExfil PNG_transparency
#     Admin FP: Normal image upload (expected size for resolution/format)
# ═══════════════════════════════════════════════════════════════════════════════

def _img_steg_tp(i):
    p = {
        "src": _ip_int(), "dst": _ip_ext(),
        "image_file": random.choice(["photo.png","screenshot.jpg","logo.bmp","avatar.png"]),
        "expected_size_kb": random.randint(50, 500),
        "actual_size_kb": None,  # will be computed
        "lsb_modified": True,
        "alpha_channel_used": i%2==0,
        "entropy_in_lsb_plane": round(random.uniform(3.8, 5.5), 3),
    }
    p["actual_size_kb"] = p["expected_size_kb"] + random.randint(50, 1000)
    prompt = (f"Network Tap + Sysmon -- Image LSB Steganography Exfiltration.\n"
              f"Source: {p['src']}\n"
              f"  image_file={p['image_file']}\n"
              f"  expected_size_kb={p['expected_size_kb']} (for resolution/format)\n"
              f"  actual_size_kb={p['actual_size_kb']} (+{p['actual_size_kb']-p['expected_size_kb']}KB anomaly)\n"
              f"  lsb_plane_entropy={p['entropy_in_lsb_plane']:.3f} (should be ~0.5 for natural images)\n"
              + (f"  alpha_channel_modified=YES (PNG transparency carrier)\n" if p['alpha_channel_used'] else "")
              + f"  uploaded_to_external_host=YES")
    cot = _cot(
        "Normal image uploads match expected file sizes for their resolution and format. "
        "Natural images have low LSB plane entropy (~0.5) because pixel values in the last "
        "bit are nearly random from natural variation. Encrypted data has uniformly high entropy.",
        f"actual_size={p['actual_size_kb']}KB vs expected={p['expected_size_kb']}KB: "
        f"+{p['actual_size_kb']-p['expected_size_kb']}KB anomaly = embedded payload size. "
        f"LSB_plane_entropy={p['entropy_in_lsb_plane']:.3f}: "
        "natural images have LSB entropy ~0.5; this is encrypted/compressed data in LSBs. "
        + (f"Alpha channel modified: PNG transparency bytes carry hidden data. " if p['alpha_channel_used'] else ""),
        f"Source {p['src']} is exfiltrating ~{p['actual_size_kb']-p['expected_size_kb']}KB of data "
        "hidden in image pixel LSBs. The image appears visually identical to a normal file. "
        "DLP tools not performing steganographic analysis will pass this as a normal image.",
        "Image LSB steganography exfiltration confirmed.",
        "MITRE T1027 (Obfuscated Files or Information: Steganography). "
        "Perform steganalysis on uploaded images, block uploading of oversized images.",
    )
    return prompt, cot, "true_positive"

def _img_steg_fp(i):
    p = {"file": "presentation.png", "size_kb": random.randint(50,500),
         "reason": "screenshot for ticket", "lsb_entropy": 0.52}
    prompt = (f"Network Tap -- Normal Image Upload.\n"
              f"  file={p['file']}  size_kb={p['size_kb']}\n"
              f"  reason={p['reason']}\n"
              f"  size_matches_resolution=YES  lsb_entropy={p['lsb_entropy']}")
    cot = _cot(
        "Normal screenshot upload -- expected size, low LSB entropy (~0.5 natural), user context.",
        f"size matches resolution. lsb_entropy=0.52 (natural). User screenshot.",
        "Normal image upload. No action.",
        "Normal image. No action.",
        "T1027 -- NATURAL IMAGE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. ZIPNestingDLPBypass
#     Evidence: Archive file with extreme nesting depth (>100 levels),
#               inner content is unchanged original data,
#               DLP tool fails to scan past nesting limit
#     Sources: PyExfil ZIPception
#     Admin FP: Normal nested archive (depth < 5)
# ═══════════════════════════════════════════════════════════════════════════════

def _zip_nest_tp(i):
    depth = random.randint(500, 1100)
    inner_size_kb = random.randint(10, 5000)
    outer_size_kb = inner_size_kb + random.randint(50, 200)  # small overhead
    p = {
        "src": _ip_int(), "dst": _ip_ext(),
        "depth": depth,
        "inner_size_kb": inner_size_kb,
        "outer_size_kb": outer_size_kb,
        "filename": "data.zip",
        "dlp_scan_depth_limit": random.choice([100, 200, 500]),
    }
    prompt = (f"Network Tap + Sysmon -- ZIP Nesting DLP Bypass.\n"
              f"Source: {p['src']} → {p['dst']}\n"
              f"  archive_file={p['filename']}\n"
              f"  nesting_depth={p['depth']} (ZIP within ZIP {p['depth']}x)\n"
              f"  inner_file_size_kb={p['inner_size_kb']}\n"
              f"  outer_archive_size_kb={p['outer_size_kb']}\n"
              f"  dlp_typical_scan_depth_limit={p['dlp_scan_depth_limit']}\n"
              f"  dlp_scan_result=incomplete (depth exceeded limit)\n"
              f"  uploaded_to_external=YES")
    cot = _cot(
        "Legitimate nested archives are created by tools like WinZip/7-Zip for specific purposes "
        f"(tar.gz, zip archives within archives) -- typically 2-5 levels deep. "
        f"No legitimate software creates {p['depth']}-level deep archives.",
        f"nesting_depth={p['depth']}: created programmatically (no archive tool would do this manually). "
        f"inner_file_size≈outer_size: minimal compression overhead = no additional content in wrapper ZIPs. "
        f"DLP scan depth limit={p['dlp_scan_depth_limit']}: DLP fails to reach inner file content. "
        "DLP sees outer ZIP as 'archive -- contents not scanned due to nesting limit'. "
        "Inner file passes through uninspected.",
        f"Source {p['src']} bypassed DLP content inspection for {p['inner_size_kb']}KB of data. "
        "Data inside the nested archive was not scanned and exfiltrated to {p['dst']}.",
        "ZIP nesting DLP bypass exfiltration confirmed.",
        "MITRE T1027 (Obfuscated Files) + T1048 (Exfiltration). "
        "Configure DLP to reject archives exceeding depth threshold (>10 levels suspicious, >100 block).",
    )
    return prompt, cot, "true_positive"

def _zip_nest_fp(i):
    p = {"file": "project_backup.tar.gz", "depth": random.randint(1,3),
         "reason": "git repository backup"}
    prompt = (f"Network Tap -- Archive Upload.\n"
              f"  file={p['file']}  nesting_depth={p['depth']}\n"
              f"  reason={p['reason']}  depth_within_normal=YES")
    cot = _cot(
        f"Normal tar.gz archive -- depth={p['depth']} (well within scan limits).",
        f"depth={p['depth']}. Normal archive tool output. No DLP bypass.",
        "Normal archive upload. No action.",
        "Normal archive. No action.",
        "T1027 -- NORMAL ARCHIVE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. LongPollingTunnel
#     Evidence: Frequent HTTPS GET requests to same server (long polling),
#               random padding on all traffic (constant-size responses),
#               self-signed RSA 4096 cert, local proxy port open
#     Sources: Heavypin (HTTPS proxy with padding)
#     Admin FP: Legitimate WebSocket/long-polling app (Slack, Teams -- known app)
# ═══════════════════════════════════════════════════════════════════════════════

def _long_poll_tp(i):
    dst = _ip_ext()
    p = {
        "src": _ip_int(), "dst": dst, "port": 443,
        "poll_interval_s": round(random.uniform(0.5, 5.0), 2),
        "cv": round(random.uniform(0.0, 0.08), 4),
        "response_size_constant": True,
        "response_size_bytes": random.randint(512, 8192),
        "cert_self_signed": True,
        "cert_key_bits": 4096,
        "local_proxy_port": 8000,
        "padding_detected": True,
    }
    prompt = (f"Network Tap -- Long Polling HTTPS Exfiltration Tunnel.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']}\n"
              f"  poll_requests_per_minute={60//max(1,int(p['poll_interval_s']))}\n"
              f"  inter_poll_cv={p['cv']:.4f}\n"
              f"  response_size_bytes={p['response_size_bytes']} (CONSTANT despite content)\n"
              f"  padding_to_constant_size=YES (anti-traffic-analysis)\n"
              f"  cert_self_signed=YES  cert_key_bits={p['cert_key_bits']}\n"
              f"  local_proxy_port={p['local_proxy_port']}")
    cot = _cot(
        "Slack, Teams, and other legitimate long-polling apps have variable response sizes "
        "(content-driven), use vendor CA certificates, and are browser or known-app initiated. "
        "Constant-size padded responses + self-signed RSA 4096 + local proxy port = covert tunnel.",
        f"poll_cv={p['cv']:.4f}: machine-generated polling loop. "
        f"response_size=CONSTANT at {p['response_size_bytes']}B despite different response content: "
        "random padding added to prevent traffic analysis (content-independent size). "
        f"cert_self_signed=True + 4096-bit key: high-security attacker-generated cert. "
        f"local_proxy_port={p['local_proxy_port']}: traffic is being proxied through this host. "
        "Padding + long polling + self-signed cert = professional exfiltration tunnel design.",
        f"Host {p['src']} is operating a covert HTTPS tunnel with anti-traffic-analysis padding. "
        "All exfiltrated data appears as constant-size HTTPS responses regardless of content.",
        "Long-polling HTTPS exfiltration tunnel with anti-traffic-analysis confirmed.",
        "MITRE T1048.002 (Exfiltration Over Alternative Protocol) + T1001 (Data Obfuscation). "
        "Block destination IP, kill local proxy, forensic investigation.",
    )
    return prompt, cot, "true_positive"

def _long_poll_fp(i):
    p = {"app": "Slack", "dst": "edge.slack.com", "cert": "DigiCert",
         "response_size": "variable"}
    prompt = (f"Network Tap -- Slack Long Polling.\n"
              f"  app={p['app']}  dst={p['dst']}\n"
              f"  cert={p['cert']}  response_size={p['response_size']}\n"
              f"  browser_or_slack_app=YES  user_session_active=YES")
    cot = _cot(
        "Slack long polling -- vendor domain, CA cert, variable response size, user session.",
        f"vendor domain. DigiCert. Variable responses (no padding). User active.",
        "Authorized Slack long polling. No action.",
        "Authorized Slack polling. No action.",
        "T1048.002 -- AUTHORIZED SLACK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 20. MultiProtocolTunnel
#     Evidence: Go binary reading from one protocol (TCP/UDP) and writing to
#               another (DNS/ICMP), data passes through multi-layer encoding
#               chain (base32 + AES), no single protocol carries all traffic
#     Sources: Pulsar
#     Admin FP: No admin FP -- multi-protocol data tunnel from workstation is adversarial
# ═══════════════════════════════════════════════════════════════════════════════

def _multiproto_tp(i):
    in_proto = random.choice(["TCP:4444","UDP:5353","TCP:8080"])
    out_proto = random.choice(["DNS:53","ICMP","UDP:443","TCP:179"])
    p = {
        "src": _ip_int(), "dst": _ip_ext(),
        "input_connector": in_proto,
        "output_connector": out_proto,
        "encoding_chain": random.choice(["base32+AES-CTR", "base64+AES-256", "hex+XOR"]),
        "bytes_rate_kbps": random.randint(5, 500),
        "go_binary": True,
    }
    prompt = (f"Network Tap + Sysmon -- Multi-Protocol Exfiltration Tunnel.\n"
              f"Host: {p['src']}\n"
              f"  input_connector: {p['input_connector']}\n"
              f"  output_connector: {p['output_connector']} → {p['dst']}\n"
              f"  encoding_chain: {p['encoding_chain']}\n"
              f"  throughput_kbps={p['bytes_rate_kbps']}\n"
              f"  tunnel_binary=Go_ELF/PE  no_registered_service=YES")
    cot = _cot(
        "No legitimate enterprise application reads from one protocol and re-encodes "
        f"the data through {p['encoding_chain']} to output via a completely different protocol. "
        "This is a purpose-built covert channel.",
        f"Input={p['input_connector']}: accepts data from local C2 agent or file reader. "
        f"Encoding={p['encoding_chain']}: multiple transformation layers obscure content. "
        f"Output={p['output_connector']} to {p['dst']}: routes data through protocol that "
        "bypasses network inspection for its category. "
        f"Go binary not registered as service: no legitimate application context. "
        f"throughput={p['bytes_rate_kbps']}kbps continuous: sustained exfil operation.",
        f"Host {p['src']} is running a multi-protocol tunnel routing exfiltrated data "
        f"from {p['input_connector']} through {p['encoding_chain']} to {p['output_connector']}. "
        "The tunnel protocol-hops to evade specific inspection rules.",
        "Multi-protocol exfiltration tunnel confirmed.",
        "MITRE T1048.003 (Exfiltration Over Alternative Protocol) + T1001 (Data Obfuscation). "
        "Kill tunnel process, block destination, capture traffic on both input and output protocols.",
    )
    return prompt, cot, "true_positive"

def _multiproto_fp(i):
    p = {"app": "stunnel", "purpose": "TLS wrapper for legacy cleartext app",
         "cmdb": "YES", "ticket": f"NET-{random.randint(100,999)}"}
    prompt = (f"Sysmon -- Protocol Conversion Tool.\n"
              f"  app={p['app']}  purpose={p['purpose']}\n"
              f"  cmdb_registered={p['cmdb']}  ticket={p['ticket']}\n"
              f"  single_encoding=TLS_only  no_re-encoding=YES")
    cot = _cot(
        "stunnel wrapping cleartext app in TLS -- CMDB registered, single encoding, documented.",
        f"cmdb=YES. Ticket {p['ticket']}. Single TLS wrapping (not multi-layer re-encoding).",
        "Authorized TLS wrapper deployment. No action.",
        "Authorized stunnel wrapper. No action.",
        "T1048 -- AUTHORIZED TLS WRAPPER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Add on (2026-06-05)
# ═══════════════════════════════════════════════════════════════════════════════

def _metadata_strip_tp(i):
    p = {"src": _ip_int(),
         "files_processed": random.randint(50, 5000),
         "file_types": random.sample(["docx","pdf","xlsx","pptx","jpg","png"], k=random.randint(3,5)),
         "metadata_removed": ["author","company","revision_history","gps_location","device_info"],
         "followed_by_upload": True,
         "encrypted_before_upload": i%2==0}
    prompt = (f"Windows Sysmon -- Bulk Metadata Strip + Pre-Exfil Preparation.\n"
              f"  files_processed={p['files_processed']:,}\n"
              f"  file_types: {', '.join(p['file_types'])}\n"
              f"  metadata_removed: {', '.join(p['metadata_removed'][:3])}\n"
              f"  followed_by_upload=YES\n"
              + (f"  files_encrypted_before_upload=YES\n" if p['encrypted_before_upload'] else ""))
    cot = _cot(
        "Privacy-conscious users strip metadata from personal photos before sharing. "
        f"Bulk processing {p['files_processed']:,} documents across {len(p['file_types'])} "
        "types immediately before upload is exfiltration preparation.",
        f"files_processed={p['files_processed']:,}: not personal file cleanup -- bulk operation. "
        f"metadata_removed={p['metadata_removed'][:2]}: removing attribution (author, company, device). "
        f"followed_by_upload: metadata stripped specifically to anonymize exfil payload. "
        + (f"encrypted_before_upload: double-layer exfil preparation. " if p['encrypted_before_upload'] else ""),
        f"Source {p['src']}: {p['files_processed']:,} documents prepared for anonymous exfiltration "
        "via metadata stripping" + (" + encryption." if p['encrypted_before_upload'] else "."),
        "Bulk metadata strip as pre-exfiltration document preparation confirmed.",
        "MITRE T1565 (Data Manipulation) + T1048. "
        "Block upload destination, preserve original files for attribution.",
    )
    return prompt, cot, "true_positive"

def _metadata_strip_fp(i):
    p = {"user": _user(), "files": random.randint(1,5), "reason": "GDPR compliance for client delivery"}
    prompt = (f"Sysmon -- Metadata Removal.\n"
              f"  user={p['user']}  files={p['files']}\n"
              f"  reason={p['reason']}  ticket=YES")
    cot = _cot(
        "User stripping metadata from 1-5 files for GDPR compliance -- bounded, documented.",
        f"files={p['files']}. GDPR compliance. Ticket.",
        "Authorized metadata removal for compliance. No action.",
        "Authorized metadata removal. No action.",
        "T1565 -- AUTHORIZED GDPR COMPLIANCE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Registry + S3 Queries + Main
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_CLASSES = {
    "DNSTXTChunkedExfil":     ("network_tap",    ["T1048.003"],          _dns_txt_tp,    _dns_txt_fp),
    "DNSOOBCallback":         ("network_tap",    ["T1048.003"],          _dns_oob_tp,    _dns_oob_fp),
    "ICMPEncryptedExfil":     ("network_tap",    ["T1048.003"],          _icmp_tp,       _icmp_fp),
    "HTTPChunkedUpload":      ("network_tap",    ["T1048.002"],          _http_chunk_tp, _http_chunk_fp),
    "HTTPCookieExfil":        ("network_tap",    ["T1048.002"],          _cookie_tp,     _cookie_fp),
    "RawTCPBackdoor":         ("network_tap",    ["T1041","T1059"],      _tcp_backdoor_tp,_tcp_backdoor_fp),
    "QUICTunnelExfil":        ("network_tap",    ["T1048.003","T1001"],  _quic_tp,       _quic_fp),
    "ConfluenceBulkExfil":    ("aws_cloudtrail", ["T1213"],              _conf_tp,       _conf_fp),
    "JiraBulkExfil":          ("aws_cloudtrail", ["T1213"],              _jira_tp,       _jira_fp),
    "DiscordWebhookExfil":    ("network_tap",    ["T1567"],              _discord_tp,    _discord_fp),
    "PastebinExfil":          ("sysmon_sensor",  ["T1567"],              _pastebin_tp,   _pastebin_fp),
    "CloudStorageExfil":      ("network_tap",    ["T1567"],              _cloud_storage_tp,_cloud_storage_fp),
    "NTPTimestampExfil":      ("network_tap",    ["T1048.003"],          _ntp_tp,        _ntp_fp),
    "FTPMKDIRExfil":          ("network_tap",    ["T1048.003"],          _ftp_mkdir_tp,  _ftp_mkdir_fp),
    "IMAPDraftExfil":         ("network_tap",    ["T1048","T1071.003"],  _imap_tp,       _imap_fp),
    "BGPSteganography":       ("network_tap",    ["T1048.003"],          _bgp_tp,        _bgp_fp),
    "ImageLSBSteganography":  ("network_tap",    ["T1027"],              _img_steg_tp,   _img_steg_fp),
    "ZIPNestingDLPBypass":    ("network_tap",    ["T1027","T1048"],      _zip_nest_tp,   _zip_nest_fp),
    "LongPollingTunnel":      ("network_tap",    ["T1048.002","T1001"],  _long_poll_tp,  _long_poll_fp),
    "MultiProtocolTunnel":    ("network_tap",    ["T1048.003","T1001"],  _multiproto_tp, _multiproto_fp),
    "MetadataStripExfil":     ("sysmon_sensor",  ["T1565","T1048"],      _metadata_strip_tp, _metadata_strip_fp),
}

S3_QUERIES = {
    "DNSTXTChunkedExfil":    {"sensor":"network_tap","where":"dns_query IS NOT NULL AND payload_entropy > 3.5 AND variance_inter_arrival < 0.10 GROUP BY src_ip,dns_query HAVING COUNT(*) > 20"},
    "ICMPEncryptedExfil":    {"sensor":"network_tap","where":"protocol_name = 'ICMP' AND payload_entropy > 5.0 AND is_internal_dst = false"},
    "HTTPChunkedUpload":     {"sensor":"network_tap","where":"http_method = 'POST' AND http_uri IS NOT NULL GROUP BY src_ip,dst_ip HAVING COUNT(*) > 10 "},
    "HTTPCookieExfil":       {"sensor":"network_tap","where":"http_useragent IS NOT NULL AND packets_src > 5 AND http_method = 'GET' GROUP BY src_ip HAVING COUNT(*) > 10"},
    "DiscordWebhookExfil":   {"sensor":"network_tap","where":"http_uri LIKE '%discord.com/api/webhooks/%' AND http_method = 'POST' AND packets_src > 10"},
    "NTPTimestampExfil":     {"sensor":"network_tap","where":"dst_port = 123 AND protocol_name = 'UDP' AND variance_inter_arrival < 0.10 AND payload_entropy > 3.0"},
    "FTPMKDIRExfil":         {"sensor":"network_tap","where":"dst_port = 21 AND protocol_name = 'TCP' AND packets_src > 5 GROUP BY src_ip HAVING COUNT(*) > 20"},
    "BGPSteganography":      {"sensor":"network_tap","where":"dst_port = 179 AND is_internal_dst = false"},
    "LongPollingTunnel":     {"sensor":"network_tap","where":"session_duration_ms > 30000 AND cert_self_signed = true AND variance_inter_arrival < 0.10 AND is_internal_dst = false"},
    "PastebinExfil":         {"sensor":"sysmon_sensor","where":"sysmon_event_id = 22 AND QueryName LIKE '%pastebin%' OR (sysmon_event_id = 3 AND Image LIKE '%powershell%')"},
    "MetadataStripExfil":    {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND CommandLine LIKE '%metadata%' OR CommandLine LIKE '%exif%' GROUP BY Image HAVING COUNT(*) > 50"},
    "DNSOOBCallback":        {"sensor":"network_tap","where":"dst_port = 53 AND payload_entropy > 4.0 AND is_internal_dst = false AND ratio_small_packets > 0.4"},
    "RawTCPBackdoor":        {"sensor":"network_tap","where":"dst_port IN (4444,5555,1337,8888,9999,4321) AND protocol_name = 'TCP' AND is_internal_dst = false AND session_duration_ms > 60000"},
    "QUICTunnelExfil":       {"sensor":"network_tap","where":"dst_port = 443 AND protocol_name = 'UDP' AND byte_ratio > 0.6 AND is_internal_dst = false"},
    "ConfluenceBulkExfil":   {"sensor":"aws_cloudtrail","where":"event_type LIKE '%search%' AND action LIKE '%export%' AND outcome = 'success' AND source_ip IS NOT NULL"},
    "JiraBulkExfil":         {"sensor":"aws_cloudtrail","where":"event_type LIKE '%jira%' AND action LIKE '%export%' AND outcome = 'success' AND user_name IS NOT NULL"},
    "CloudStorageExfil":     {"sensor":"network_tap","where":"dst_port = 443 AND is_internal_dst = false AND byte_ratio > 0.7 AND ratio_large_packets > 0.1 AND avg_inter_arrival < 1.0"},
    "IMAPDraftExfil":        {"sensor":"network_tap","where":"dst_port IN (143,993) AND byte_ratio > 0.6 AND ratio_large_packets > 0.1 AND is_internal_dst = false"},
    "ImageLSBSteganography": {"sensor":"network_tap","where":"dst_port = 443 AND byte_ratio > 0.8 AND ratio_large_packets > 0.1 AND is_internal_dst = false AND payload_entropy > 4.0"},
    "ZIPNestingDLPBypass":   {"sensor":"network_tap","where":"dst_port = 443 AND byte_ratio > 0.7 AND is_internal_dst = false AND ratio_large_packets > 0.1"},
    "MultiProtocolTunnel":   {"sensor":"network_tap","where":"payload_entropy > 4.5 AND is_internal_dst = false AND avg_inter_arrival < 2.0 AND byte_ratio > 0.5"},
}


def generate(tool_name, n_tp, n_fp):
    sensor, mitre, tp_fn, fp_fn = TOOL_CLASSES[tool_name]
    records = []
    for i in range(n_tp):
        prompt, cot, cls = tp_fn(i)
        records.append(_record(tool_name, sensor, mitre, _msg(sensor, prompt, cot), cls))
    for i in range(n_fp):
        prompt, cot, cls = fp_fn(i)
        records.append(_record(tool_name, sensor, mitre, _msg(sensor, prompt, cot), cls))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records-per-class",   type=int, default=10)
    ap.add_argument("--admin-fps-per-class", type=int, default=2)
    ap.add_argument("--tool-filter",         type=str, default="")
    args = ap.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    names = list(TOOL_CLASSES.keys())
    if args.tool_filter:
        names = [t.strip() for t in args.tool_filter.split(",")]

    all_records = []
    for name in names:
        recs = generate(name, args.records_per_class, args.admin_fps_per_class)
        all_records.extend(recs)
        tp = sum(1 for r in recs if r["classification"] == "true_positive")
        fp = sum(1 for r in recs if r["classification"] == "false_positive")
        logger.info(f"  {name}: {tp} TP + {fp} FP  ({TOOL_CLASSES[name][0]})")

    with open(OUTPUT_FILE, "w") as f:
        for r in all_records:
            f.write(json.dumps(r) + "\n")

    index = {
        "ttp_category": TTP_CAT,
        "total_records": len(all_records),
        "tp_records":    sum(1 for r in all_records if r["classification"] == "true_positive"),
        "fp_records":    sum(1 for r in all_records if r["classification"] == "false_positive"),
        "tool_classes": {
            n: {"sensor": TOOL_CLASSES[n][0], "mitre": TOOL_CLASSES[n][1],
                "s3_query": S3_QUERIES.get(n)}
            for n in names
        },
    }
    with open(INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)

    logger.info(f"[+] {len(all_records)} total records → {OUTPUT_FILE}")
    logger.info(f"    {index['tp_records']} TP  |  {index['fp_records']} FP (admin scenarios)")
    logger.info(f"    Sensors: {sorted(set(r['source_type'] for r in all_records))}")


if __name__ == "__main__":
    main()
