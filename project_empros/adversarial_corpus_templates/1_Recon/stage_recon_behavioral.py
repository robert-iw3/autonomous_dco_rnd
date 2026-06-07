"""
stage_recon_behavioral.py -- Comprehensive Recon TTP Behavioral Dataset

Detection philosophy: trains on BEHAVIORAL evidence only -- timing, ratios, call
patterns, anomalous context. Tool names never appear in detection logic.

Each tool class generates:
  --records-per-class N  true-positive SFT records  (default 10)
  --admin-fps-per-class N admin false-positive records (default 2)

Output:
  data/staging/recon_behavioral_v1.jsonl
  data/staging/recon_query_index.json

Usage:
    python stage_recon_behavioral.py
    python stage_recon_behavioral.py --records-per-class 15 --admin-fps-per-class 3
    python stage_recon_behavioral.py --tool-filter NetworkPortScan,AzureO365Spray
"""

import json
import random
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stage-recon")
random.seed(42)

OUTPUT_DIR  = Path("../data/staging")
OUTPUT_FILE = OUTPUT_DIR / "recon_behavioral_v1.jsonl"
INDEX_FILE  = OUTPUT_DIR / "recon_query_index.json"

# ── System prompts per sensor (sync with PIPELINE.md vector routing) ─────────
SYS = {
    "network_tap":        ("You are the Network Tap Forensics Expert. Analyze the session window "
                           "using pre-computed fields (port_class, JA3, cert metadata, is_internal_dst). "
                           "Attribute to MITRE ATT&CK and recommend containment."),
    "sysmon_sensor":      ("You are the Host Forensics Expert. Target OS: Windows. "
                           "Vector Space: 6D windows_math. Source: Sysmon event stream. "
                           "Schema: sysmon_event_id, Image, CommandLine, ParentImage, User, "
                           "IntegrityLevel, TargetImage, GrantedAccess, TargetObject, Details, "
                           "ImageLoaded, Signed, PipeName, QueryName, TargetFilename. "
                           "Identify adversarial tradecraft. Output MITRE ATT&CK + containment."),
    "windows_deepsensor": ("You are the Host Forensics Expert. Target OS: Windows. "
                           "Vector Space: 4D deepsensor_math. Source: DeepXDR EdrRow (UEBA). "
                           "Schema: Image, CommandLine, destination_ip, pid, ppid, "
                           "score, avg_entropy, max_velocity, tactic, technique. "
                           "Identify adversarial tradecraft. Output MITRE + containment."),
    "linux_sentinel":     ("You are the Host Forensics Expert. Target OS: Linux. "
                           "Vector Space: 5D sentinel_math. Schema: comm, command_line, uid, dest_ip. "
                           "Identify adversarial tradecraft. Output MITRE + containment."),
    "azure_entraid":      ("You are the Cloud Identity Expert. Analyze Azure AD / Entra ID events. "
                           "Identify credential-access patterns. Output MITRE + containment."),
    "aws_cloudtrail":     ("You are the Cloud Infrastructure Expert. Analyze AWS CloudTrail events. "
                           "Identify reconnaissance. Output MITRE + containment."),
}

VECTOR = {
    "network_tap":        "c2_math",
    "sysmon_sensor":      "windows_math",
    "windows_deepsensor": "deepsensor_math",
    "linux_sentinel":     "sentinel_math",
    "azure_entraid":      "cloud_flow",
    "aws_cloudtrail":     "cloud_flow",
}

TTP_CAT = "Recon"  # ttp_category field in every record

def _ip_int():   return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
def _ip_ext():
    p = random.choice(["45.33","198.51","185.220","104.21","172.67","194.165"])
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"
def _host():     return f"{random.choice(['WS','SRV','DC','LT'])}-{random.randint(10,99)}"
def _user():     return random.choice(["jsmith","alee","tmorgan","schen","rbrown","lzhang"])
def _asn():      return random.choice(["AS-CHOOPA Vultr","AS14061 DigitalOcean","AS16276 OVH","AS47583 Hostinger"])

def _cot(a1, a2, a3, conclusion, technique, action="contain"):
    return (f"<analysis>\n[AXIS 1] Benign Alternative Assessment:\n  {a1}\n"
            f"[AXIS 2] Behavioral Proof Assessment:\n  {a2}\n"
            f"[AXIS 3] Entity Coverage:\n  {a3}\n"
            f"[CONCLUSION] {conclusion}\n</analysis>\n"
            f"{'TRUE POSITIVE' if action=='contain' else 'FALSE POSITIVE'}. {technique}\n"
            f"RECOMMENDED_ACTION: {action}")

TTP_CAT = "Recon"

def _record(tool_class, sensor, mitre, msgs, cls, event_id=None):
    import hashlib
    r = {"ttp_category": TTP_CAT, "tool_class": tool_class,
         "mitre_techniques": mitre, "source_type": sensor,
         "vector_name": VECTOR[sensor], "classification": cls,
         "messages": msgs}
    if event_id is not None:
        r["event_id"] = event_id
    elif sensor in ("sysmon_sensor", "windows_deepsensor", "linux_sentinel", "macos_sensor"):
        r["event_id"] = hashlib.md5(f"{tool_class}_{cls}_{sensor}".encode()).hexdigest()[:16]
    return r

def _msg(sensor, user_text, asst_text):
    # Canonical inference format: Spatial Anomaly header + <|spatial_vector|> token
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
# 1. NetworkPortScan
#    Evidence: fan-out TCP connections, SYN-RST ratio, sub-ms sessions,
#              uniform small packets, raw socket capability
#    Admin FP: IT asset discovery -- bounded port list, business hours, IT SA
# ═══════════════════════════════════════════════════════════════════════════════

def _nps_tp(i):
    src = _ip_int() if i % 4 != 0 else _ip_ext()
    n   = random.randint(200, 1200)
    dur = random.randint(15, 300)
    cv  = round(random.uniform(0.0, 0.08), 4)
    p   = {"src": src, "subnet": f"{'.'.join(_ip_int().split('.')[:3])}.0/24",
           "sessions": random.randint(150,600), "ports": n, "dur_ms": dur, "cv": cv,
           "syn_pct": round(random.uniform(0.88,1.0),3),
           "rst_pct": round(random.uniform(0.72,0.96),3),
           "small_pkt": round(random.uniform(0.91,1.0),3),
           "bytes_src": random.randint(40,78), "entropy": round(random.uniform(0.0,0.6),3),
           "port_class":"scanning", "internal": i%4!=0}
    prompt = (f"Network Tap -- Port Sweep Detected.\n"
              f"{'Internal' if p['internal'] else 'External'} source {p['src']} → {p['subnet']}\n"
              f"Window: {p['sessions']} sessions\n"
              f"  unique_dst_ports={p['ports']}  avg_session_ms={p['dur_ms']}\n"
              f"  tcp_syn={p['syn_pct']:.1%}  tcp_rst={p['rst_pct']:.1%}\n"
              f"  ratio_small_packets={p['small_pkt']:.3f}  bytes_src={p['bytes_src']}\n"
              f"  payload_entropy={p['entropy']:.3f}  variance_inter_arrival={p['cv']:.4f}\n"
              f"  port_class={p['port_class']}")
    cot = _cot(
        f"No production application touches {p['ports']} distinct ports in one window. "
        "Monitoring agents, update clients, and CDN egress use a bounded well-known port set.",
        f"{p['ports']} unique dst_ports + avg_session_ms={p['dur_ms']} (no 3WHS completion) + "
        f"ratio_small_packets={p['small_pkt']:.3f} (uniform 60-byte SYN frames) + "
        f"payload_entropy={p['entropy']:.3f} (zero application data) -- "
        "raw-socket sweep requiring CAP_NET_RAW or Administrator privilege.",
        f"{'Internal host' if p['internal'] else 'External host'} {p['src']} is actively mapping "
        f"{p['subnet']}. Scope: live-host discovery + open-service enumeration before exploitation.",
        "Active port sweep -- no benign process generates this fan-out pattern.",
        "MITRE T1046 (Network Service Discovery). Isolate source, review for prior access chain.",
    )
    return prompt, cot, "true_positive"

def _nps_fp(i):
    # IT admin running bounded asset scan during business hours from known SA workstation
    ports = random.choice(["22,80,443,3389,8080", "22,80,443,445,5985", "80,443,8080,8443"])
    n_ports = len(ports.split(","))
    p = {"src": _ip_int(), "subnet": f"{'.'.join(_ip_int().split('.')[:3])}.0/24",
         "sessions": random.randint(20,80), "ports": n_ports, "dur_ms": random.randint(100,2000),
         "ports_str": ports, "hour": random.randint(9,16)}
    prompt = (f"Network Tap -- Structured Port Scan.\n"
              f"Internal source {p['src']} → {p['subnet']}\n"
              f"Window: {p['sessions']} sessions  unique_dst_ports={p['ports']}\n"
              f"  avg_session_ms={p['dur_ms']}  ports_targeted={p['ports_str']}\n"
              f"  scan_hour={p['hour']}:00  source_group=IT_Infrastructure\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}  port_class=admin-scan")
    cot = _cot(
        f"Only {p['ports']} ports targeted ({p['ports_str']}) -- bounded service set consistent "
        "with IT asset inventory. Source is in IT_Infrastructure group with a linked change ticket.",
        f"unique_dst_ports={p['ports']} (IT standard service set, not fan-out sweep). "
        f"Session durations {p['dur_ms']}ms (full TCP handshakes complete). "
        f"Scan hour={p['hour']}:00 (business hours). Change ticket validates authorization.",
        f"Authorized IT scan from managed workstation {p['src']}. "
        "No credential theft, no lateral movement, no post-scan activity observed.",
        "Authorized IT asset inventory -- discriminating factors: bounded port list, business hours, change ticket.",
        "MITRE T1046 -- AUTHORIZED. No containment warranted.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. WebFuzzing
#    Evidence: HTTP request velocity >100 rps, URI uniqueness ratio >0.9,
#              404 rate >0.70, non-browser UA, automated timing
#    Admin FP: DAST in CI/CD -- known source IP, off-hours, dev environment
# ═══════════════════════════════════════════════════════════════════════════════

def _wf_tp(i):
    n_req  = random.randint(800, 15000)
    n_uri  = int(n_req * random.uniform(0.87, 0.99))
    rps    = random.randint(80, 2500)
    r404   = round(random.uniform(0.68, 0.96), 3)
    r200   = round(1 - r404 - random.uniform(0.01, 0.06), 3)
    dst    = _ip_int() if i % 3 != 0 else _ip_ext()
    port   = random.choice([80,443,8080,8443])
    ua     = random.choice(["Go-http-client/1.1","python-httpx/0.24","curl/7.85","feroxbuster"])
    p = {"src":_ip_int(),"dst":dst,"port":port,"reqs":n_req,"uris":n_uri,
         "rps":rps,"r404":r404,"r200":r200,"ua":ua,"internal":i%3!=0}
    prompt = (f"Network Tap -- Web Directory Fuzzing.\n"
              f"{'Internal→Internal' if p['internal'] else 'External→Target'}: "
              f"{p['src']} → {p['dst']}:{p['port']}\n"
              f"  http_requests={p['reqs']:,}  unique_uris={p['uris']:,}\n"
              f"  request_rate_rps={p['rps']}  status_404={p['r404']:.1%}  status_200={p['r200']:.1%}\n"
              f"  user_agent={p['ua']}  port_class=web")
    cot = _cot(
        f"No user browser generates {p['reqs']:,} requests to {p['uris']:,} unique URIs at "
        f"{p['rps']} req/s. Selenium/Playwright test suites target known paths, "
        "not random wordlist traversals with a 404 rate of {:.0%}.".format(p['r404']),
        f"unique_uri_ratio={p['uris']/p['reqs']:.3f} (near 1.0 = wordlist-driven, not navigation). "
        f"status_404={p['r404']:.1%} (high miss rate confirms brute-force). "
        f"rps={p['rps']} (machine-generated). "
        f"UA '{p['ua']}' -- automated scanner, not a browser.",
        f"{'Internal host probing internal web server -- attacker has LAN access and is mapping application attack surface.' if p['internal'] else 'External attacker enumerating web application before exploitation.'} "
        f"All 200-response URIs are being catalogued.",
        "Web directory brute-force confirmed.",
        "MITRE T1595.002 (Vulnerability Scanning). Block source at WAF, review 200-response URIs.",
    )
    return prompt, cot, "true_positive"

def _wf_fp(i):
    n_req = random.randint(200, 600)
    p = {"src":_ip_int(),"dst":_ip_int(),"reqs":n_req,
         "uris":int(n_req*random.uniform(0.6,0.85)),
         "rps":random.randint(5,25),"env":"dev-env",
         "ticket":f"SEC-{random.randint(1000,9999)}","hour":random.randint(1,5)}
    prompt = (f"Network Tap -- Structured Web Scan.\n"
              f"Source: {p['src']} → {p['dst']}:443  environment={p['env']}\n"
              f"  http_requests={p['reqs']}  unique_uris={p['uris']}\n"
              f"  request_rate_rps={p['rps']}  scan_ticket={p['ticket']}\n"
              f"  scan_hour={p['hour']}:00 (off-hours maintenance window)\n"
              f"  source_pipeline=github-actions-dast")
    cot = _cot(
        f"DAST scan in CI/CD pipeline: bounded scope ({p['reqs']} requests at {p['rps']} rps), "
        f"dev environment only, authorized ticket {p['ticket']}, known pipeline source IP.",
        f"rps={p['rps']} (rate-limited DAST). Target={p['env']} (non-production). "
        f"Pipeline source authenticated. Ticket {p['ticket']} pre-authorized.",
        "Scoped dev-environment DAST in maintenance window. No production systems affected.",
        "Authorized DAST scan -- discriminators: rate-limited, dev-only, change ticket, pipeline source.",
        "MITRE T1595.002 -- AUTHORIZED CI/CD DAST. No containment.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. WAFEvasionProbe
#    Evidence: mixed payload type diversity (SQLi+XSS+traversal+cmd in same window),
#              low 200-rate despite high request volume, methodical pattern
#    Admin FP: authorized pen test with pre-announced change window
# ═══════════════════════════════════════════════════════════════════════════════

def _waf_tp(i):
    payload_types = random.sample(["sql_injection","xss","directory_traversal",
                                    "command_injection","xxe","ssti","open_redirect"], k=random.randint(4,7))
    n_req = random.randint(500, 5000)
    p = {"src":_ip_ext() if i%3==0 else _ip_int(),
         "dst":_ip_int(),"reqs":n_req,"payload_types":payload_types,
         "type_count":len(payload_types),
         "waf_block_pct":round(random.uniform(0.40,0.85),3),
         "bypass_found":random.choice([True,True,False]),
         "rps":random.randint(5,50)}
    prompt = (f"Network Tap -- WAF Evasion / Payload Probing.\n"
              f"Source: {p['src']} → {p['dst']}:443\n"
              f"  total_requests={p['reqs']:,}  distinct_payload_types={p['type_count']}\n"
              f"  payload_categories={', '.join(p['payload_types'])}\n"
              f"  waf_blocked_pct={p['waf_block_pct']:.1%}\n"
              f"  bypass_candidate_found={'YES' if p['bypass_found'] else 'NO'}\n"
              f"  request_rate_rps={p['rps']}")
    cot = _cot(
        f"No functional application testing generates {p['type_count']} distinct attack payload "
        "categories simultaneously. Legitimate DAST in CI/CD targets one vulnerability class "
        "per scan job and never requires bypass discovery against a production WAF.",
        f"{p['type_count']} payload categories in one window: {', '.join(p['payload_types'])}. "
        f"WAF blocked {p['waf_block_pct']:.0%} of requests -- attacker iterating for bypasses. "
        f"{'Bypass candidate identified -- active exploitation imminent.' if p['bypass_found'] else 'Bypass search ongoing.'}",
        f"Source {p['src']} is methodically mapping WAF rule coverage before exploitation. "
        "All payload categories will be re-tested once a bypass is found.",
        "WAF evasion probing confirmed -- multi-category payload sweep.",
        "MITRE T1595.002 + T1190 (Exploit Public-Facing Application). Block source IP at WAF.",
    )
    return prompt, cot, "true_positive"

def _waf_fp(i):
    p = {"src":_ip_int(),"ticket":f"PT-{random.randint(100,999)}",
         "payload_types":["sql_injection","xss"],"reqs":random.randint(80,200)}
    prompt = (f"Network Tap -- Structured Security Assessment.\n"
              f"Source: {p['src']} → internal web app\n"
              f"  payload_types={', '.join(p['payload_types'])}  total_requests={p['reqs']}\n"
              f"  pentest_ticket={p['ticket']}  source_group=SecurityTeam\n"
              f"  scope_approved=YES  window=maintenance")
    cot = _cot(
        "Scoped security assessment: 2 payload categories, bounded request count, "
        "authorized ticket, source in SecurityTeam group.",
        f"Only {len(p['payload_types'])} payload categories ({', '.join(p['payload_types'])}), "
        f"{p['reqs']} requests, pentest ticket {p['ticket']} pre-authorized, known source.",
        "Authorized pentest in defined scope and window. No uncontrolled exploitation.",
        "Authorized penetration test -- ticket, scope, source all validated.",
        "T1595.002 -- AUTHORIZED. No containment.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. NTLMIntercept
#    Evidence: non-DC host responding to LLMNR/NBT-NS (port 5355/137),
#              Net-NTLMv2 hashes captured, optional relay to port 445
#    Admin FP: NONE -- no legitimate admin scenario for broadcast poisoning
# ═══════════════════════════════════════════════════════════════════════════════

def _ntlm_tp(i):
    proto  = random.choice(["LLMNR","NBT-NS","mDNS","WPAD-HTTP"])
    port   = {"LLMNR":5355,"NBT-NS":137,"mDNS":5353,"WPAD-HTTP":80}[proto]
    relay  = i % 3 == 0
    p = {"attacker":_ip_int(),"victim":_ip_int(),"proto":proto,"port":port,
         "poisoned":random.randint(5,60),"hashes":random.randint(1,12),
         "hash_type":random.choice(["NTLMv2","Net-NTLMv2"]),
         "relay":relay,"relay_target":_ip_int(),"relay_sessions":random.randint(1,4)}
    prompt = (f"Network Tap -- NTLM Credential Intercept.\n"
              f"Attacker: {p['attacker']}  Victim: {p['victim']}\n"
              f"  protocol_poisoned={p['proto']}  listener_port={p['port']}\n"
              f"  poisoned_queries={p['poisoned']}  hashes_captured={p['hashes']} ({p['hash_type']})\n"
              f"  is_domain_controller=NO\n"
              + (f"  relay_attempted=YES  relay_target={p['relay_target']}  smb_sessions_from_relay={p['relay_sessions']}"
                 if p['relay'] else "  relay_attempted=NO"))
    relay_note = (f"Relay to {p['relay_target']} produced {p['relay_sessions']} authenticated SMB sessions -- lateral movement underway."
                  if p['relay'] else "Hash capture only; offline cracking will follow.")
    cot = _cot(
        f"{p['proto']} is a broadcast name-resolution fallback with no legitimate use in an enterprise "
        "where DNS is authoritative. No admin tool operates as a broadcast-poisoning responder.",
        f"Non-DC host {p['attacker']} responding to {p['proto']} broadcasts -- definitional poisoning behavior. "
        f"{p['hashes']} {p['hash_type']} hashes captured. {relay_note}",
        f"Attacker {p['attacker']} has inserted itself into the name-resolution path for victim {p['victim']}. "
        "Credentials from any host issuing broadcast lookups are at immediate risk.",
        "NTLM credential interception confirmed -- broadcast poisoning with hash capture.",
        f"MITRE T1557.001 (LLMNR/NBT-NS Poisoning). Disable {p['proto']} via GPO, isolate attacker host, reset captured accounts.",
    )
    return prompt, cot, "true_positive"

def _ntlm_fp(i):
    # Only admin FP: misconfigured legacy service -- still suspicious, recommend monitor
    p = {"host":_ip_int(),"proto":"NBT-NS","reason":"Legacy WINS client misconfiguration"}
    prompt = (f"Network Tap -- Broadcast Name Resolution Response.\n"
              f"Host: {p['host']}  protocol={p['proto']}\n"
              f"  response_count=1  hashes_captured=0\n"
              f"  is_domain_controller=NO  known_legacy_client=YES\n"
              f"  asset_tag=LEGACY-WINS-{random.randint(10,99)}")
    cot = _cot(
        f"Single response, zero hashes captured, asset is a known legacy WINS client ({p['reason']}). "
        "No credential material observed.",
        f"response_count=1 (not sustained poisoning). hashes_captured=0 (no interception occurred). "
        "Host is in legacy asset register with NBT-NS enabled for WINS compatibility.",
        "Misconfigured legacy client, not an active attacker. Risk is passive, not active.",
        "Legacy NBT-NS misconfiguration -- no credential interception. Remediate by disabling NBT-NS.",
        "T1557.001 -- MISCONFIGURATION, not active attack. Disable NBT-NS and monitor.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. TunnelInfra
#    Evidence: persistent TLS to VPS, low beacon CV, self-signed cert,
#              TUN interface creation (OS), non-browser JA3
#    Admin FP: legitimate corporate VPN -- known gateway, PKI cert, CIDR scoped
# ═══════════════════════════════════════════════════════════════════════════════

def _tun_tp(i):
    proto  = random.choice(["TLS","TLS+QUIC","TCP"])
    port   = random.choice([11601,7000,4433,8443,4444,1337])
    dur_h  = round(random.uniform(0.5, 24.0), 1)
    cv     = round(random.uniform(0.01, 0.11), 4)
    self_s = i % 4 != 3
    days   = random.randint(1, 90) if self_s else random.randint(90, 365)
    p = {"src":_ip_int(),"dst":_ip_ext(),"port":port,"proto":proto,
         "dur_h":dur_h,"interval_s":random.randint(20,180),"cv":cv,
         "bytes_src":random.randint(3000,50000),"bytes_dst":random.randint(3000,50000),
         "self_signed":self_s,"cert_days":days,"asn":_asn(),
         "tun_iface":random.choice([True,False])}
    prompt = (f"Network Tap -- Persistent Encrypted Tunnel.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']} ({p['proto']})\n"
              f"  session_duration_hours={p['dur_h']}\n"
              f"  beacon_interval_s={p['interval_s']}  variance_inter_arrival={p['cv']:.4f}\n"
              f"  bytes_src={p['bytes_src']:,}  bytes_dst={p['bytes_dst']:,}\n"
              f"  cert_self_signed={p['self_signed']}  cert_valid_days={p['cert_days']}\n"
              f"  dst_asn={p['asn']}  port_class=c2-like\n"
              + (f"  tun_interface_created=YES  requires_cap_net_admin=YES" if p['tun_iface'] else ""))
    cert_note = (f"Self-signed cert valid {p['cert_days']}d -- attacker-generated infra."
                 if p['self_signed'] else f"CA cert but VPS destination + non-standard port {p['port']} are definitive.")
    cot = _cot(
        f"No enterprise application maintains a {p['dur_h']}h persistent session to a VPS "
        f"({p['asn']}) on port {p['port']}. Corporate VPNs terminate at known gateways "
        "with PKI certificates and appear on the approved network device inventory.",
        f"Session duration {p['dur_h']}h (keepalive = tunnel). "
        f"beacon CV={p['cv']:.4f} (machine-generated heartbeat). "
        f"Destination {p['asn']} = commodity VPS. {cert_note} "
        + (f"TUN interface created on host -- kernel-level tunnel agent (e.g., ligolo-ng proxy)." if p['tun_iface'] else ""),
        f"Host {p['src']} is relaying attacker traffic to {p['dst']}:{p['port']}. "
        "All recon traffic from attacker is being proxied through this pivot.",
        "Covert tunnel infrastructure confirmed.",
        f"MITRE T1090.003 (Multi-hop Proxy). Block destination at perimeter, isolate source, capture tunnel pcap.",
    )
    return prompt, cot, "true_positive"

def _tun_fp(i):
    p = {"src":_ip_int(),"gw":_ip_int(),"proto":"IPSec/IKEv2",
         "cert":"corp-pki-ca","port":500,"dur_h":round(random.uniform(2,8),1)}
    prompt = (f"Network Tap -- VPN Session.\n"
              f"Source: {p['src']} → {p['gw']}:{p['port']} ({p['proto']})\n"
              f"  session_duration_hours={p['dur_h']}  cert_issuer={p['cert']}\n"
              f"  gateway_in_approved_list=YES  user_authenticated=YES\n"
              f"  port_class=vpn")
    cot = _cot(
        "Corporate VPN session: known gateway in approved list, corp PKI certificate, "
        "standard IKEv2 protocol on port 500.",
        f"Gateway {p['gw']} in approved_vpn_gateways list. cert_issuer={p['cert']} (internal PKI). "
        f"port=500 (standard IKEv2). Duration {p['dur_h']}h (normal workday VPN usage).",
        "Authorized remote access. No pivot behavior -- user is tunneling to corporate network, not out to VPS.",
        "Corporate VPN -- approved gateway, corp PKI, standard port.",
        "T1090 -- AUTHORIZED CORPORATE VPN. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. ReverseProxyTunnel (frp / socktail / rustunnel)
#    Evidence: outbound to external server on non-standard port, multiplexed
#              sessions, heartbeat at fixed interval, frpc-style JA3
# ═══════════════════════════════════════════════════════════════════════════════

def _rpt_tp(i):
    port  = random.choice([7000,7001,7500,9999,4433,2222])
    p = {"src":_ip_int(),"dst":_ip_ext(),"port":port,
         "multiplexed_channels":random.randint(2,15),
         "heartbeat_s":random.randint(20,60),"cv":round(random.uniform(0.01,0.08),4),
         "inbound_conns":random.randint(0,8),
         "admin_dashboard":i%4==0,"dashboard_port":7500}
    prompt = (f"Network Tap -- Reverse Proxy Tunnel.\n"
              f"Internal {p['src']} → External {p['dst']}:{p['port']}\n"
              f"  multiplexed_channels={p['multiplexed_channels']}\n"
              f"  heartbeat_interval_s={p['heartbeat_s']}  cv={p['cv']:.4f}\n"
              f"  inbound_conns_via_relay={p['inbound_conns']}\n"
              + (f"  admin_dashboard_detected=YES  dashboard_port={p['dashboard_port']}" if p['admin_dashboard'] else ""))
    cot = _cot(
        f"Legitimate reverse proxies serve inbound traffic -- they do not initiate persistent "
        f"outbound connections to attacker-controlled servers on port {p['port']}. "
        "Load balancers and API gateways use vendor-registered certificates, not raw TCP multiplexing.",
        f"Outbound-initiated relay to external VPS (attacker controls the 'server' side). "
        f"{p['multiplexed_channels']} multiplexed channels (attacker can forward any internal port). "
        f"heartbeat CV={p['cv']:.4f} -- machine-generated keepalive. "
        + (f"Admin dashboard on port {p['dashboard_port']} exposes tunnel management interface." if p['admin_dashboard'] else ""),
        f"Host {p['src']} is acting as an agent for the attacker's relay infrastructure at {p['dst']}. "
        f"{p['inbound_conns']} inbound connections already relayed inward.",
        "Reverse proxy tunnel agent confirmed -- attacker-controlled relay infrastructure.",
        "MITRE T1090.003 + T1572 (Protocol Tunneling). Terminate tunnel, isolate host, audit inbound relay connections.",
    )
    return prompt, cot, "true_positive"

def _rpt_fp(i):
    p = {"src":_ip_int(),"dst":_ip_int(),"port":443,
         "service":"internal-webhook-relay","cert":"corp-pki"}
    prompt = (f"Network Tap -- Internal Reverse Proxy.\n"
              f"Source: {p['src']} → {p['dst']}:{p['port']}\n"
              f"  service_name={p['service']}  cert_issuer={p['cert']}\n"
              f"  destination_internal=YES  registered_in_cmdb=YES")
    cot = _cot(
        "Internal destination, CMDB-registered service, corp PKI cert.",
        f"Destination {p['dst']} is internal (RFC1918). Service {p['service']} registered in CMDB. Port 443 with corp cert.",
        "Authorized internal relay -- no external attacker infrastructure.",
        "Authorized internal reverse proxy -- CMDB + corp cert + internal destination.",
        "T1090 -- AUTHORIZED INTERNAL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. WindowsHostEnum
#    Evidence: burst WMI Win32_* queries (>15 classes), scheduled task COM enum,
#              security-product process scan, LAPS DLL path probe,
#              outbound port scan to egress-check host
#    NOTE: avoids net.exe/ipconfig/whoami -- WMI/COM/PS .NET only
#    Admin FP: IT inventory from SCCM/Lansweeper service account, scheduled
# ═══════════════════════════════════════════════════════════════════════════════

def _whe_tp(i):
    wmi_classes = random.randint(16, 45)
    ldap_q = random.randint(0, 30)
    egress_scan = i % 3 == 0
    parent = random.choice(["WINWORD.EXE","EXCEL.EXE","explorer.exe","mshta.exe","wscript.exe"])
    p = {"host":_host(),"user":_user(),"wmi":wmi_classes,"ldap":ldap_q,
         "parent":parent,"sched_tasks_enum":random.choice([True,True,False]),
         "av_proc_scan":True,"laps_check":i%2==0,"egress":egress_scan,
         "egress_host":"allports.exposed"}
    prompt = (f"Windows Host Telemetry -- Host Enumeration Script.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  ParentProcess: {p['parent']}\n"
              f"  wmi_query_count_60s={p['wmi']}  wmi_classes=Win32_UserAccount,Win32_Share,"
              f"Win32_NetworkAdapterConfiguration,MSFT_DNSClientCache,...\n"
              f"  ldap_queries={p['ldap']}\n"
              f"  scheduled_task_com_enumeration={'YES' if p['sched_tasks_enum'] else 'NO'}\n"
              f"  security_product_process_scan={'YES' if p['av_proc_scan'] else 'NO'}\n"
              f"  laps_dll_path_probe={'YES (Admpwd.dll existence check)' if p['laps_check'] else 'NO'}\n"
              + (f"  outbound_port_scan_host={p['egress_host']}  (egress filtering detection)" if p['egress'] else ""))
    cot = _cot(
        f"Legitimate IT tooling does not issue {p['wmi']} distinct WMI class queries in 60 seconds "
        f"from parent process {p['parent']}. SCCM and Lansweeper run under dedicated service accounts "
        "on scheduled cycles, not interactively from an Office process.",
        f"{p['wmi']} WMI classes in 60s -- bulk host discovery breadth. "
        f"Parent={p['parent']} (Office/script host is not an IT management launcher). "
        + ("Scheduled task enumeration via COM (Schedule.Service). " if p['sched_tasks_enum'] else "")
        + "Security product process scan (AV/EDR fingerprinting). "
        + ("LAPS DLL presence check (detecting credential management). " if p['laps_check'] else "")
        + (f"Outbound scan to {p['egress_host']} (mapping allowed ports for C2 channel selection)." if p['egress'] else ""),
        f"Host {p['host']} ({p['user']}) has been fully enumerated: local users, shares, "
        "network config, domain info, security products, LAPS status. "
        "Attacker now has complete situational awareness for follow-on activity.",
        "Windows host recon confirmed -- WMI burst + security product fingerprinting.",
        "MITRE T1082+T1087+T1518 (System Info + Account + Security Software Discovery). Quarantine host.",
    )
    return prompt, cot, "true_positive"

def _whe_fp(i):
    p = {"sa":"svc-lansweeper","wmi":random.randint(4,8),"schedule":"daily 02:00",
         "ticket":f"CHG-{random.randint(10000,99999)}"}
    prompt = (f"Windows Host Telemetry -- Scheduled IT Inventory.\n"
              f"  executing_account={p['sa']}  account_type=service_account\n"
              f"  wmi_query_count_60s={p['wmi']}  schedule={p['schedule']}\n"
              f"  parent_process=LsAgent.exe  change_ticket={p['ticket']}\n"
              f"  source_group=IT_Operations")
    cot = _cot(
        f"Service account {p['sa']} in IT_Operations running {p['wmi']} WMI queries -- "
        "bounded inventory collection, not bulk enumeration.",
        f"wmi_count={p['wmi']} (bounded, specific classes). Service account (not interactive user). "
        f"Parent=LsAgent.exe (Lansweeper agent). Scheduled {p['schedule']}. Ticket {p['ticket']}.",
        "Authorized IT asset inventory -- no interactive user, no security product scanning, no egress probe.",
        "Scheduled IT inventory -- service account, bounded scope, change ticket.",
        "T1082 -- AUTHORIZED IT INVENTORY. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. ADDomainEnum
#    Evidence: LDAP search breadth (large base DN, all-object filter),
#              high object retrieval count, cert template enumeration,
#              AdminSDHolder / ACL queries
#    Admin FP: helpdesk scoped LDAP lookup -- specific OU, single attribute
# ═══════════════════════════════════════════════════════════════════════════════

def _ade_tp(i):
    obj_count = random.randint(500, 10000)
    scope = random.choice(["SUBTREE","SUBTREE","SUBTREE","ONE_LEVEL"])
    cert_enum = i % 2 == 0
    p = {"src":_ip_int(),"dc":_ip_int(),"obj":obj_count,"scope":scope,
         "filter":"(&(objectClass=*)(objectCategory=*))",
         "attrs":"*","ldap_sessions":random.randint(8,50),
         "cert_templates":cert_enum,"acl_queries":i%3==0,
         "adminsdholder":i%4==0,"kerberoastable":i%3==0}
    prompt = (f"Network Tap + Windows -- AD Domain Enumeration.\n"
              f"Source: {p['src']} → DC {p['dc']}:389 (LDAP)\n"
              f"  ldap_sessions={p['ldap_sessions']}  objects_returned={p['obj']:,}\n"
              f"  search_scope={p['scope']}  search_base=DC=corp,DC=local\n"
              f"  ldap_filter={p['filter']}  requested_attributes={p['attrs']}\n"
              f"  cert_template_enumeration={'YES (CN=Certificate Templates)' if p['cert_templates'] else 'NO'}\n"
              f"  acl_queries={'YES (nTSecurityDescriptor)' if p['acl_queries'] else 'NO'}\n"
              f"  adminsdholder_query={'YES' if p['adminsdholder'] else 'NO'}\n"
              f"  kerberoastable_accounts_query={'YES (servicePrincipalName=*)' if p['kerberoastable'] else 'NO'}")
    cot = _cot(
        f"Helpdesk and application LDAP queries are scoped to specific OUs with targeted filters "
        f"(e.g., (&(sAMAccountName=jsmith)(objectClass=user))). "
        f"Returning {p['obj']:,} objects with filter {p['filter']} retrieves the entire directory.",
        f"SUBTREE scope + base=DC root + filter (*) = full directory dump. "
        f"{p['obj']:,} objects returned across {p['ldap_sessions']} sessions. "
        + ("CN=Certificate Templates enumerated -- ADCS attack path discovery. " if p['cert_templates'] else "")
        + ("nTSecurityDescriptor queries -- ACL-based attack path mapping (BloodHound-style). " if p['acl_queries'] else "")
        + ("servicePrincipalName=* query -- Kerberoasting target enumeration." if p['kerberoastable'] else ""),
        f"Full AD directory dumped from {p['src']}. Attacker now has: all user/group/computer objects, "
        + ("certificate templates for ESC1-8 attacks, " if p['cert_templates'] else "")
        + "trust relationships, and privilege paths.",
        "AD domain enumeration confirmed -- full directory dump.",
        "MITRE T1087.002+T1069.002+T1482 (Domain Account/Group Discovery + Domain Trust Discovery). "
        "Block LDAP from source, alert AD team, rotate sensitive accounts.",
    )
    return prompt, cot, "true_positive"

def _ade_fp(i):
    p = {"src":_ip_int(),"sa":"svc-helpdesk","ou":"OU=Users,OU=HQ",
         "filter":"(&(sAMAccountName=jsmith)(objectClass=user))","obj":1}
    prompt = (f"Network Tap -- Scoped LDAP Query.\n"
              f"Source: {p['src']} → DC:389  account={p['sa']}\n"
              f"  search_base={p['ou']}  filter={p['filter']}\n"
              f"  objects_returned={p['obj']}  search_scope=BASE\n"
              f"  source_application=ServiceDesk-Plus")
    cot = _cot(
        f"Single-object LDAP lookup by service account in helpdesk application -- "
        "scoped to specific OU, targeted filter, 1 object returned.",
        f"search_base={p['ou']} (not DC root). filter targets specific account. "
        f"objects_returned={p['obj']}. ServiceDesk-Plus parent application. Service account.",
        "Scoped helpdesk LDAP lookup -- no directory sweep, no sensitive attribute enumeration.",
        "Authorized helpdesk LDAP lookup -- scoped, single-object, service account.",
        "T1087 -- AUTHORIZED HELPDESK QUERY. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. SMBShareHarvest
#    Evidence: SMB fan-out to many hosts, file content reading (not just listing),
#              regex keyword pattern matching, cross-user file access,
#              credential-related file types targeted
# ═══════════════════════════════════════════════════════════════════════════════

def _smb_tp(i):
    hosts = random.randint(8, 60)
    files = random.randint(50, 800)
    ftypes = random.sample(["xlsx","docx","pdf","ps1","txt","config","key","pfx","pem","ini","kdbx"], k=random.randint(4,8))
    keyword_hit = i % 3 != 0
    loot = i % 2 == 0
    p = {"src":_ip_int(),"hosts":hosts,"shares":random.randint(hosts,hosts*3),
         "files":files,"ftypes":ftypes,"kw_hit":keyword_hit,"loot":loot,
         "auth":"NTLM" if i%3==0 else "Kerberos"}
    prompt = (f"Network Tap -- SMB Share Crawl.\n"
              f"Source: {p['src']} → internal subnet  auth={p['auth']}\n"
              f"  unique_dst_hosts={p['hosts']}  shares_enumerated={p['shares']}\n"
              f"  files_opened={p['files']:,}  file_types_targeted={','.join(p['ftypes'])}\n"
              f"  keyword_pattern_match={'YES -- password/credential content found' if p['kw_hit'] else 'NO matches yet'}\n"
              f"  files_downloaded={'YES' if p['loot'] else 'NO'}\n"
              f"  port=445  is_internal_dst=YES")
    cot = _cot(
        f"Backup agents and DFS clients follow a scheduled, bounded pattern against known paths. "
        f"No legitimate agent opens {p['files']:,} files across {p['hosts']} hosts while filtering "
        f"for credential-related extensions ({','.join(p['ftypes'][:3])}, ...).",
        f"{p['hosts']} unique hosts + {p['shares']} shares in one window = subnet-wide crawl. "
        f"{p['files']:,} files opened with content inspection (not just directory listing). "
        f"File type filter targets secrets/config. "
        + ("Keyword hits confirm password-hunting content match." if p['kw_hit'] else "")
        + (" Files downloaded -- credential material exfiltrated." if p['loot'] else ""),
        f"Source {p['src']} has SMB read access to {p['hosts']} internal hosts via {p['auth']}. "
        "Attacker has valid domain credentials and is harvesting stored secrets from network shares.",
        "SMB share credential harvest confirmed.",
        "MITRE T1039+T1083+T1135 (Data from Network Share + File Discovery + Network Share Discovery). "
        "Block SMB from source, audit accessed shares, rotate credentials.",
    )
    return prompt, cot, "true_positive"

def _smb_fp(i):
    p = {"src":_ip_int(),"sa":"svc-backup","share":"\\\\FILESERVER\\Backup$",
         "files":random.randint(5,30),"schedule":"nightly 01:00"}
    prompt = (f"Network Tap -- Scheduled Backup SMB.\n"
              f"Source: {p['src']}  account={p['sa']}  target={p['share']}\n"
              f"  files_accessed={p['files']}  file_types=.bak,.zip\n"
              f"  schedule={p['schedule']}  keyword_scan=NO  download=NO\n"
              f"  source_application=Veeam")
    cot = _cot(
        "Veeam backup service account accessing a single known backup share -- no content scanning, no keyword matching.",
        f"Single target share. files={p['files']} (bounded). No keyword scan. No download to unknown destination. "
        "Service account. Scheduled window. Veeam parent process.",
        "Authorized backup job -- no cross-host crawl, no content inspection, no credential targeting.",
        "Scheduled backup -- service account, single share, no content scanning.",
        "T1039 -- AUTHORIZED BACKUP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. CredentialMemoryAccess
#     Evidence: cross-user process handle (PROCESS_VM_READ) to browser/lsass,
#               NtCreateSection/NtMapViewOfSection for injection,
#               DPAPI key access outside browser context,
#               SQLite DB access to browser credential store
# ═══════════════════════════════════════════════════════════════════════════════

def _cma_tp(i):
    targets = [
        ("chrome.exe","DPAPI-encrypted cookie/password DB + memory read","T1555.003"),
        ("msedge.exe","App-Bound Encryption key extraction via memory","T1555.003"),
        ("mstsc.exe","RDP credential cache via API hook injection","T1056.004"),
        ("lsass.exe","LSASS memory dump / minidump","T1003.001"),
        ("svchost.exe","DPAPI master key access via impersonation","T1555"),
    ]
    tgt, method, technique = targets[i % len(targets)]
    p = {"src_proc":random.choice(["powershell.exe","cmd.exe","python.exe","unknown.exe"]),
         "tgt":tgt,"method":method,"technique":technique,
         "user":_user(),"cross_user":i%2==0,
         "ntcreatesection":tgt in ("lsass.exe","svchost.exe"),
         "dpapi":tgt not in ("lsass.exe",),
         "sqlite_access":tgt in ("chrome.exe","msedge.exe")}
    prompt = (f"Windows Host Telemetry -- Credential Memory Access.\n"
              f"Host: {_host()}  User: {p['user']}\n"
              f"  SourceProcess: {p['src_proc']}\n"
              f"  TargetProcess: {p['tgt']}  access_right=PROCESS_VM_READ\n"
              f"  cross_user_process_access={'YES' if p['cross_user'] else 'same user context'}\n"
              f"  method: {p['method']}\n"
              + (f"  NtCreateSection+NtMapViewOfSection_sequence=YES\n" if p['ntcreatesection'] else "")
              + (f"  DPAPI_masterkey_request=YES\n" if p['dpapi'] else "")
              + (f"  browser_sqlite_db_access=YES  (Cookies/Login Data)\n" if p['sqlite_access'] else ""))
    cot = _cot(
        f"No legitimate application requires {p['src_proc']} to open a "
        f"PROCESS_VM_READ handle to {p['tgt']}. "
        + ("Cross-user process access has no administrative use case outside of security tooling running under SYSTEM." if p['cross_user'] else ""),
        f"PROCESS_VM_READ on {p['tgt']} -- reads credential material from process memory. "
        + (f"NtCreateSection+NtMapViewOfSection = classic injection sequence for in-memory credential extraction. " if p['ntcreatesection'] else "")
        + (f"DPAPI master key access outside {p['tgt']} context = decrypting stored secrets. " if p['dpapi'] else "")
        + (f"Browser SQLite DB access (Cookies/Login Data) -- plaintext credential file read. " if p['sqlite_access'] else ""),
        f"Host has been compromised. Credential material from {p['tgt']} is at immediate risk. "
        "Saved browser passwords, session cookies, and/or NTLM hashes may be extracted.",
        f"In-memory credential theft confirmed ({p['method']}).",
        f"MITRE {p['technique']} (Credential Access). Isolate host immediately, rotate all credentials used on this endpoint.",
    )
    return prompt, cot, "true_positive"

def _cma_fp(i):
    p = {"proc":"SecurityAgent.exe","tgt":"lsass.exe","vendor":"CrowdStrike"}
    prompt = (f"Windows Host Telemetry -- Security Agent Process Access.\n"
              f"  SourceProcess: {p['proc']}  TargetProcess: {p['tgt']}\n"
              f"  access_right=PROCESS_VM_READ  vendor={p['vendor']}\n"
              f"  signed_binary=YES  code_signing_cert=CrowdStrike\n"
              f"  source_group=EDR_Agents  running_as=SYSTEM")
    cot = _cot(
        f"EDR agent ({p['vendor']}) routinely reads LSASS for credential guard and anomaly detection. "
        "Signed binary with vendor code signing cert running under SYSTEM.",
        f"code_signing_cert={p['vendor']} (trusted vendor). running_as=SYSTEM (service context). "
        "EDR_Agents group. Expected behavior for this endpoint.",
        "Authorized EDR telemetry collection -- no evidence of attacker tooling.",
        f"EDR agent LSASS access -- authorized, signed, SYSTEM context.",
        "T1003.001 -- AUTHORIZED EDR AGENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. SCCMRecon
#     Evidence: WMI queries to SMS_R_System class, SCCM admin share access,
#               MSSQL to CM_ database, NAA credential extraction via WMI
# ═══════════════════════════════════════════════════════════════════════════════

def _sccm_tp(i):
    p = {"src":_ip_int(),"sccm_srv":_ip_int(),
         "sms_queries":random.randint(5,25),
         "db_conn":i%2==0,"share_access":i%3==0,"naa_extract":i%4==0}
    prompt = (f"Windows Host Telemetry -- SCCM Reconnaissance.\n"
              f"Source: {p['src']} → SCCM Server: {p['sccm_srv']}\n"
              f"  wmi_classes=SMS_R_System,SMS_G_System_NETWORK_ADAPTER,SMS_Site\n"
              f"  sms_wmi_queries={p['sms_queries']}\n"
              f"  mssql_connection={'YES → CM_<SiteCode> database' if p['db_conn'] else 'NO'}\n"
              f"  sccm_admin_share_access={'YES → \\\\{p[\"sccm_srv\"]}\\SMS_<SiteCode>$' if p['share_access'] else 'NO'}\n"
              f"  naa_credential_extraction={'YES (Network Access Account via WMI)' if p['naa_extract'] else 'NO'}")
    cot = _cot(
        "Legitimate SCCM clients communicate through the SMS Agent Host service (CcmExec.exe) "
        "using approved communication channels. Direct WMI queries to SMS_R_System classes "
        "are reserved for the SCCM console running under admin credentials.",
        f"{p['sms_queries']} SMS_R_System WMI queries -- direct AD-joined client inventory dump. "
        + ("MSSQL connection to CM_ database -- full SCCM inventory and policy data accessible. " if p['db_conn'] else "")
        + ("SCCM admin share access -- reading deployment package content and scripts. " if p['share_access'] else "")
        + ("NAA credential extraction via WMI -- Network Access Account credentials in plaintext. " if p['naa_extract'] else ""),
        f"Source {p['src']} is enumerating all managed endpoints via SCCM. "
        "NAA credentials (if extracted) provide authenticated access to all distribution points.",
        "SCCM reconnaissance confirmed -- inventory dump via SMS WMI classes.",
        "MITRE T1087+T1078 (Account Discovery + Valid Accounts). Audit SCCM admin access, rotate NAA.",
    )
    return prompt, cot, "true_positive"

def _sccm_fp(i):
    p = {"sa":"svc-sccm-reporting","queries":random.randint(1,4)}
    prompt = (f"Windows Host Telemetry -- SCCM Reporting Query.\n"
              f"  account={p['sa']}  wmi_queries={p['queries']}\n"
              f"  wmi_classes=SMS_R_System  scope=single_collection\n"
              f"  source_application=ConfigMgr_Console  parent=mmc.exe")
    cot = _cot(
        f"Service account {p['sa']} running {p['queries']} scoped WMI queries from ConfigMgr Console (mmc.exe).",
        f"queries={p['queries']} (bounded). Service account. mmc.exe parent (ConfigMgr Console). Scoped to single collection.",
        "Authorized SCCM reporting -- service account, console parent, bounded scope.",
        "Authorized SCCM console query. No action.",
        "T1087 -- AUTHORIZED SCCM CONSOLE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. LinuxPrivescEnum
#     Evidence: /proc traversal (100+ reads), /etc/passwd+shadow access,
#               SUID binary enumeration, kernel version + exploitdb lookups,
#               broad cron/writable-dir checks
# ═══════════════════════════════════════════════════════════════════════════════

def _lpe_tp(i):
    uid = random.choice([0,1000,1001,1002])
    shadow = i % 2 == 0
    p = {"host":_host().lower(),"user":_user(),"uid":uid,
         "file_reads":random.randint(100,500),
         "suid_checks":random.randint(10,60),
         "cron_reads":random.randint(1,6),
         "passwd_reads":random.randint(1,3),
         "shadow":shadow,"writable":random.randint(15,80),
         "kernel_ver_read":True,"exploitdb":i%3==0,
         "net_connections":_ip_ext() if i%4==0 else None}
    prompt = (f"Linux Sentinel -- Privilege Escalation Enumeration.\n"
              f"Host: {p['host']}  User: {p['user']} (uid={p['uid']})\n"
              f"  file_reads_120s={p['file_reads']}  suid_binary_checks={p['suid_checks']}\n"
              f"  cron_reads={p['cron_reads']}  /etc/passwd_reads={p['passwd_reads']}\n"
              f"  /etc/shadow_access_attempt={'YES' if p['shadow'] else 'NO'}\n"
              f"  writable_dir_probes={p['writable']}\n"
              f"  /proc/version_read={'YES' if p['kernel_ver_read'] else 'NO'}\n"
              f"  external_download={'YES → '+p['net_connections'] if p['net_connections'] else 'NO'}")
    uid_note = ("Root context -- full visibility." if uid==0 else
                f"Unprivileged uid={uid} -- enumerating paths to escalate.")
    cot = _cot(
        f"No scheduled audit or health check reads {p['file_reads']} files, checks {p['suid_checks']} "
        "SUID binaries, and probes writable paths in 120 seconds. "
        "System management agents run from known service accounts at defined intervals.",
        f"{p['file_reads']} file reads in 120s (bulk traversal). "
        f"{p['suid_checks']} SUID checks (mapping exploitable setuid binaries). "
        + ("/etc/shadow access attempt (credential theft vector). " if p['shadow'] else "")
        + f"/proc/version read (kernel version for exploit selection). "
        + (f"External download from {p['net_connections']} (pulling exploit/tool stage 2). " if p['net_connections'] else ""),
        f"Host {p['host']}. {uid_note} Full enumeration of privilege escalation vectors complete.",
        "Linux privilege escalation enumeration confirmed.",
        "MITRE T1083+T1087.001+T1068 (File Discovery + Local Account Discovery + Exploitation for Privilege Escalation). Isolate host.",
    )
    return prompt, cot, "true_positive"

def _lpe_fp(i):
    p = {"sa":"nagios","reads":random.randint(5,15),"schedule":"every 5min"}
    prompt = (f"Linux Sentinel -- Monitoring Agent Activity.\n"
              f"  comm=check_linux  uid=nagios(999)  file_reads={p['reads']}\n"
              f"  paths=/proc/meminfo,/proc/loadavg,/etc/os-release\n"
              f"  schedule={p['schedule']}  parent=nagios-agent")
    cot = _cot(
        f"Nagios monitoring agent reading known system metrics paths -- bounded, scheduled, service uid.",
        f"file_reads={p['reads']} (known metric paths only). uid=nagios (service). Scheduled {p['schedule']}. No SUID/shadow access.",
        "Authorized monitoring agent -- no enumeration breadth, no privilege escalation indicators.",
        "Authorized monitoring agent. No action.",
        "T1083 -- AUTHORIZED MONITORING. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. SSHKeyHarvest
#     Evidence: ~/.ssh/ directory reads (id_rsa/id_ed25519/known_hosts),
#               SSH agent socket access, cross-user home directory traversal
# ═══════════════════════════════════════════════════════════════════════════════

def _ssh_tp(i):
    cross_user = i % 2 == 0
    p = {"host":_host().lower(),"user":_user(),
         "key_files_read":random.randint(2,12),
         "users_accessed":random.randint(2,8) if cross_user else 1,
         "ssh_agent":i%3==0,"known_hosts":True,"authorized_keys":True}
    prompt = (f"Linux Sentinel -- SSH Key Harvesting.\n"
              f"Host: {p['host']}  Accessor: {p['user']}\n"
              f"  ssh_private_key_files_read={p['key_files_read']}\n"
              f"  cross_user_home_access={'YES -- ' + str(p['users_accessed']) + ' user home dirs' if cross_user else 'NO'}\n"
              f"  known_hosts_read={'YES' if p['known_hosts'] else 'NO'}\n"
              f"  authorized_keys_read={'YES' if p['authorized_keys'] else 'NO'}\n"
              f"  ssh_agent_socket_access={'YES' if p['ssh_agent'] else 'NO'}")
    cot = _cot(
        "SSH key rotation scripts access only the specific key paths they manage under a service account. "
        f"No legitimate tool reads private keys from {p['users_accessed']} different user home directories.",
        f"{p['key_files_read']} private key files read. "
        + (f"Cross-user access to {p['users_accessed']} home dirs -- requires elevated privilege. " if cross_user else "")
        + ("known_hosts read -- mapping trusted SSH targets for pivoting. "
           "authorized_keys read -- mapping which keys grant access to this host. ")
        + ("SSH agent socket access -- hijacking live agent for key-free authentication." if p['ssh_agent'] else ""),
        f"Host {p['host']} private keys are compromised. known_hosts reveals additional pivot targets. "
        "Attacker can authenticate to all hosts that trust these keys.",
        "SSH credential harvesting confirmed.",
        "MITRE T1552.004 (Private Keys). Rotate all affected SSH key pairs, audit known_hosts targets.",
    )
    return prompt, cot, "true_positive"

def _ssh_fp(i):
    p = {"sa":"svc-keyrotation","keys":2,"path":"/opt/keyrotation/managed_keys/"}
    prompt = (f"Linux Sentinel -- SSH Key Rotation.\n"
              f"  comm=key-rotation  uid=svc-keyrotation  files_read={p['keys']}\n"
              f"  paths={p['path']}  cross_user_access=NO\n"
              f"  schedule=quarterly  ticket=KR-{random.randint(100,999)}")
    cot = _cot(
        "Service account reading managed key paths only -- no cross-user access.",
        f"uid=svc-keyrotation. reads={p['keys']} (managed paths only). No cross-user. Scheduled quarterly. Ticket.",
        "Authorized key rotation -- no harvesting of user home directories.",
        "Authorized key rotation service. No action.",
        "T1552.004 -- AUTHORIZED KEY ROTATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 14. AzureO365Spray
#     Evidence: auth velocity to /common/oauth2/token, diverse error codes
#               (50126/50053/50057), many UPNs, non-browser UA,
#               seasonal password patterns, optional lockout-aware pacing
# ═══════════════════════════════════════════════════════════════════════════════

def _o365_tp(i):
    n_users = random.randint(20, 400)
    n_auth  = random.randint(n_users, n_users * 3)
    success = random.randint(0, 3)
    p = {"src":_ip_ext(),"tenant":random.choice(["contoso","acmecorp","globaltec"])+".onmicrosoft.com",
         "attempts":n_auth,"users":n_users,"success":success,
         "mfa_blocked":random.randint(0,12),"locked":random.randint(0,5),
         "ua":random.choice(["python-requests/2.28","Go-http-client/1.1","AutodiscoverClient","curl/7.85"]),
         "endpoint":random.choice(["/common/oauth2/token","/organizations/oauth2/v2.0/token"]),
         "pw":random.choice(["Winter2024!","Spring2024!","Company@2024","Welcome1","P@ssw0rd1"]),
         "lockout_aware":i%3==0,"window_min":random.randint(5,90)}
    prompt = (f"Azure AD / Entra ID -- Password Spray Detected.\n"
              f"Source: {p['src']} → tenant: {p['tenant']}\n"
              f"  auth_attempts={p['attempts']}  unique_upns_targeted={p['users']}\n"
              f"  window_minutes={p['window_min']}\n"
              f"  successful_auths={'*'+str(p['success'])+' -- VALID CREDS CONFIRMED*' if p['success'] else '0'}\n"
              f"  mfa_blocked={p['mfa_blocked']}  accounts_locked={p['locked']}\n"
              f"  user_agent={p['ua']}\n"
              f"  target_endpoint={p['endpoint']}\n"
              f"  password_tried={p['pw']}\n"
              f"  lockout_aware_pacing={'YES -- requests spaced to avoid lockout' if p['lockout_aware'] else 'NO'}")
    success_note = (f"{p['success']} accounts authenticated -- ACTIVE ACCOUNT TAKEOVER." if p['success']
                    else "No successes yet -- spray ongoing.")
    cot = _cot(
        f"{p['attempts']} auth attempts against {p['users']} UPNs in {p['window_min']}min cannot be "
        "explained by a password reset, SSO misconfiguration, or federated auth issue. "
        "All legitimate multi-account failures come from known enterprise IP ranges with admin tickets.",
        f"{p['attempts']}/{p['users']} ratio = {p['attempts']//max(p['users'],1)} tries/user (spray, not brute-force). "
        f"UA='{p['ua']}' (automated client). Password '{p['pw']}' (seasonal pattern). "
        f"{p['mfa_blocked']} MFA-blocked = attacker has valid user list. "
        + (f"Lockout-aware pacing = deliberate evasion of Smart Lockout. " if p['lockout_aware'] else ""),
        f"Tenant {p['tenant']} under credential attack from {p['src']}. {success_note} "
        f"Accounts with MFA gaps are immediate compromise risk.",
        "O365/Azure AD password spray confirmed.",
        "MITRE T1110.003 (Password Spraying). Block source IP, enforce MFA universally, alert affected users.",
    )
    return prompt, cot, "true_positive"

def _o365_fp(i):
    p = {"sa":"svc-sso-sync","attempts":random.randint(2,5),"reason":"SSO token refresh failure"}
    prompt = (f"Azure AD -- Authentication Failures.\n"
              f"  source_app={p['sa']}  failures={p['attempts']}  unique_upns=1\n"
              f"  error_code=AADSTS50126  reason={p['reason']}\n"
              f"  source_ip_in_corporate_range=YES  service_account=YES")
    cot = _cot(
        f"SSO sync service account with {p['attempts']} failures for a single UPN -- "
        "token refresh issue, not credential stuffing.",
        f"unique_upns=1 (not spray). failures={p['attempts']} (bounded). Corporate IP. Service account.",
        "SSO misconfiguration -- single account, bounded failures, known source.",
        "SSO token refresh failure -- single account, corporate IP, service account.",
        "T1110.003 -- MISCONFIGURATION. Remediate SSO token config. No security containment.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 15. ADPasswordSpray
#     Evidence: LDAP bind failure fan-out (many accounts, <lockout_threshold per acct),
#               Kerberos AS-REQ failures (KDC_ERR_PREAUTH_FAILED) from one source,
#               lockout-window awareness
# ═══════════════════════════════════════════════════════════════════════════════

def _adps_tp(i):
    n_users = random.randint(15, 200)
    fails_per = random.randint(1, 3)
    p = {"src":_ip_int(),"host":_host(),"dc":_ip_int(),
         "users":n_users,"fails":n_users*fails_per,
         "success":random.randint(0,2),"proto":random.choice(["LDAP","Kerberos","LDAP+Kerberos"]),
         "pw":random.choice(["Summer2024!","Autumn2024#","Welcome123","Password1"]),
         "lockout_thresh":random.randint(3,10),"window_min":random.randint(10,60)}
    prompt = (f"Windows Host + Network Tap -- AD Password Spray.\n"
              f"Source: {p['src']} ({p['host']}) → DC: {p['dc']}\n"
              f"  protocol={p['proto']}  window_minutes={p['window_min']}\n"
              f"  unique_users_targeted={p['users']}\n"
              f"  total_auth_failures={p['fails']}  failures_per_account={fails_per}\n"
              f"  domain_lockout_threshold={p['lockout_thresh']}\n"
              f"  successful_binds={'*'+str(p['success'])+'*' if p['success'] else '0'}\n"
              f"  password_tried={p['pw']}")
    cot = _cot(
        f"Service account misconfiguration produces repeated failures for a single account. "
        f"This pattern shows {fails_per} failure(s) across {p['users']} distinct accounts -- "
        "definitional spray ratio that cannot be caused by a forgotten password.",
        f"{p['users']} unique accounts × {fails_per} failures = {p['fails']} total -- staying below "
        f"lockout threshold {p['lockout_thresh']}. "
        f"Single-password attempt across the user list = spray (not brute-force). "
        f"Password '{p['pw']}' = seasonal pattern typical of spray wordlists.",
        f"Domain at risk. Source {p['src']} has tested {p['users']} accounts. "
        + (f"{p['success']} SUCCESSFUL -- domain account compromised." if p['success'] else "Spray ongoing."),
        "Active Directory password spray confirmed.",
        "MITRE T1110.003 (Password Spraying) -- LDAP/Kerberos. Isolate source, alert AD admins, enable AD Smart Lockout.",
    )
    return prompt, cot, "true_positive"

def _adps_fp(i):
    p = {"sa":"svc-jenkins","fails":random.randint(5,15),"reason":"stale cached credentials"}
    prompt = (f"Windows Host -- AD Authentication Failures.\n"
              f"  account={p['sa']}  failures={p['fails']}  unique_accounts=1\n"
              f"  error=0xC000006A (wrong password)  reason={p['reason']}\n"
              f"  source_host=JENKINS-01  alert_ticket=INC-{random.randint(10000,99999)}")
    cot = _cot(
        f"Single service account with {p['fails']} failures -- stale password in Jenkins credential store.",
        f"unique_accounts=1 (not spray). Source=JENKINS-01 (known CI/CD server). Stale credential.",
        "Service account password rotation not propagated to Jenkins -- remediation required.",
        "Stale service account credential -- single account, known CI/CD host.",
        "T1110.003 -- SERVICE ACCOUNT MISCONFIGURATION. Update credentials. No containment.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 16. CloudStorageEnum
#     Evidence: unauthenticated S3/GCS/Spaces API calls (no auth header),
#               ListBucket + GetBucketAcl probes, anonymous 403/200 mapping,
#               multi-provider enumeration
# ═══════════════════════════════════════════════════════════════════════════════

def _cse_tp(i):
    providers = random.sample(["AWS_S3","GCP_Storage","DigitalOcean_Spaces","Linode_ObjectStorage"],
                               k=random.randint(2,4))
    p = {"src":_ip_ext(),"buckets_probed":random.randint(20,500),
         "public_found":random.randint(0,10),"anon_listable":random.randint(0,5),
         "providers":providers,"acl_probes":True,
         "objects_listed":random.randint(0,1000) if random.random()>0.5 else 0}
    prompt = (f"AWS CloudTrail / Cloud API -- Storage Enumeration.\n"
              f"Source IP: {p['src']}  no_auth_header=YES\n"
              f"  providers_targeted={','.join(p['providers'])}\n"
              f"  buckets_probed={p['buckets_probed']}  public_buckets_found={p['public_found']}\n"
              f"  anonymously_listable={p['anon_listable']}\n"
              f"  bucket_acl_probes={'YES (GetBucketAcl API)' if p['acl_probes'] else 'NO'}\n"
              f"  objects_listed={p['objects_listed']:,}")
    cot = _cot(
        f"Legitimate cloud clients authenticate with IAM credentials. Anonymous bucket probing "
        "has no operational use case -- AWS SDKs with valid credentials send signed requests.",
        f"No Authorization header on {p['buckets_probed']} bucket requests = anonymous enumeration. "
        f"Multi-provider scope ({','.join(p['providers'])}) = systematic cloud asset discovery. "
        + (f"GetBucketAcl calls = permission mapping for data access. " if p['acl_probes'] else "")
        + (f"{p['objects_listed']:,} objects listed from {p['anon_listable']} public buckets." if p['objects_listed'] else ""),
        f"External attacker {p['src']} is mapping cloud storage exposure. "
        f"{p['public_found']} public buckets found; {p['anon_listable']} listable without credentials.",
        "Cloud storage enumeration confirmed -- anonymous multi-provider bucket sweep.",
        "MITRE T1619 (Cloud Storage Object Discovery). Restrict bucket ACLs, enable S3 Block Public Access.",
    )
    return prompt, cot, "true_positive"

def _cse_fp(i):
    p = {"sa":"svc-cloudaudit","buckets":random.randint(3,10)}
    prompt = (f"AWS CloudTrail -- Cloud Storage Audit.\n"
              f"  principal=arn:aws:iam::123456789:role/CloudAuditRole\n"
              f"  api_calls=ListBuckets,GetBucketAcl  buckets_checked={p['buckets']}\n"
              f"  auth_header=AWS4-HMAC-SHA256  source_vpc=internal\n"
              f"  ticket=AUDIT-{random.randint(100,999)}")
    cot = _cot(
        "Authenticated IAM role performing quarterly security audit -- valid credentials, internal VPC, audit ticket.",
        f"auth_header=AWS4-HMAC-SHA256 (signed request). IAM role with audit permissions. buckets={p['buckets']} (bounded). Ticket.",
        "Authorized cloud security audit -- IAM role, signed requests, audit ticket.",
        "Authorized cloud storage audit. No action.",
        "T1619 -- AUTHORIZED AUDIT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. CICDSecretsHarvest
#     Evidence: API calls to /actions/secrets, /environments endpoints,
#               new workflow creation, log deletion after run,
#               OIDC token to external STS
# ═══════════════════════════════════════════════════════════════════════════════

def _cicd_tp(i):
    platform = random.choice(["GitHub","GitLab","AzureDevOps"])
    p = {"platform":platform,"src":_ip_ext(),
         "secrets_enum":True,"env_enum":i%2==0,
         "workflow_created":i%3==0,"logs_deleted":i%2==0,
         "oidc_token":i%4==0,"repos_accessed":random.randint(2,20)}
    prompt = (f"Cloud Audit -- CI/CD Platform Secrets Harvest ({p['platform']}).\n"
              f"Source: {p['src']}  repos_accessed={p['repos_accessed']}\n"
              f"  secrets_enumeration_api={'YES (/repos/*/actions/secrets)' if p['secrets_enum'] else 'NO'}\n"
              f"  environment_secrets_enum={'YES (/repos/*/environments)' if p['env_enum'] else 'NO'}\n"
              f"  new_workflow_created={'YES (malicious job injected)' if p['workflow_created'] else 'NO'}\n"
              f"  workflow_logs_deleted={'YES (covering tracks)' if p['logs_deleted'] else 'NO'}\n"
              f"  oidc_token_to_external_sts={'YES' if p['oidc_token'] else 'NO'}")
    cot = _cot(
        f"Normal CI/CD usage reads secrets at pipeline execution time via the runner -- it does not "
        "enumerate secrets via the REST API. Developers do not read other repositories' secret lists.",
        f"Secrets API enumeration across {p['repos_accessed']} repos = systematic harvest, not pipeline execution. "
        + ("Environment secrets API = staging/prod credential enumeration. " if p['env_enum'] else "")
        + ("New workflow created = malicious job to exfiltrate secrets at pipeline runtime. " if p['workflow_created'] else "")
        + ("Workflow logs deleted after run = covering tracks. " if p['logs_deleted'] else "")
        + ("OIDC token to external STS = cloud credential exfiltration." if p['oidc_token'] else ""),
        f"{p['repos_accessed']} repositories accessed. Attacker may have extracted "
        "cloud credentials, API keys, and deployment secrets stored in CI/CD environment.",
        f"CI/CD secrets harvest confirmed on {p['platform']}.",
        "MITRE T1552.004+T1098 (Credentials in Files + Account Manipulation). Revoke pipeline tokens, rotate all secrets.",
    )
    return prompt, cot, "true_positive"

def _cicd_fp(i):
    p = {"sa":"svc-devsecops","repos":2}
    prompt = (f"Cloud Audit -- CI/CD Security Scan.\n"
              f"  principal={p['sa']}  repos_accessed={p['repos']}\n"
              f"  api_calls=ListRepositorySecrets  new_workflow=NO  log_deletion=NO\n"
              f"  ticket=DEVSEC-{random.randint(100,999)}  scope=approved_repos_only")
    cot = _cot(
        f"DevSecOps service account auditing {p['repos']} approved repos -- no workflow creation, no log deletion.",
        f"No workflow creation. No log deletion. repos={p['repos']} (approved scope). Service account. Ticket.",
        "Authorized DevSecOps audit -- no malicious workflow, no secret exfiltration.",
        "Authorized DevSecOps audit. No action.",
        "T1552 -- AUTHORIZED AUDIT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. MultiProtocolBrute
#     Evidence: connection fan-out across service ports (22,3389,389,5985,1433),
#               credential pair testing pattern, timeout-adjusted retry rate
# ═══════════════════════════════════════════════════════════════════════════════

def _mpb_tp(i):
    services = random.sample(["SSH:22","RDP:3389","LDAP:389","WinRM:5985","MSSQL:1433",
                               "MySQL:3306","Redis:6379","FTP:21","VNC:5900"], k=random.randint(3,7))
    p = {"src":_ip_ext() if i%3==0 else _ip_int(),
         "services":services,"attempts":random.randint(200,5000),
         "success":random.randint(0,3),"cred_pairs":random.randint(50,500)}
    prompt = (f"Network Tap -- Multi-Protocol Brute Force.\n"
              f"Source: {p['src']}\n"
              f"  services_targeted={','.join(p['services'])}\n"
              f"  total_auth_attempts={p['attempts']:,}  credential_pairs_tested={p['cred_pairs']}\n"
              f"  successful_auths={p['success']}\n"
              f"  protocol_count={len(p['services'])}")
    cot = _cot(
        f"No legitimate connectivity testing targets {len(p['services'])} distinct service protocols simultaneously. "
        "IT connectivity checks use ping, telnet to a single port, or a known monitoring probe.",
        f"{len(p['services'])} protocols in one window = systematic credential sweep across service portfolio. "
        f"{p['cred_pairs']} credential pairs = password list. "
        f"{p['attempts']:,} attempts = automated tool, not human. "
        + (f"{p['success']} successful authentications -- valid credentials found." if p['success'] else ""),
        f"Source {p['src']} is testing credentials across all exposed services. "
        f"Any successful login grants authenticated access to that service.",
        "Multi-protocol credential brute-force confirmed.",
        "MITRE T1110.001 (Brute Force: Password Guessing). Block source, enforce MFA on all services, audit successful logins.",
    )
    return prompt, cot, "true_positive"

def _mpb_fp(i):
    p = {"sa":"monitoring-agent","services":["SSH:22","HTTPS:443"],"attempts":random.randint(1,3)}
    prompt = (f"Network Tap -- Service Connectivity Check.\n"
              f"  source_app={p['sa']}  services_tested={','.join(p['services'])}\n"
              f"  attempts_per_service=1  auth_failures={p['attempts']}\n"
              f"  credential_pairs=1  timeout=5s  schedule=every_60s")
    cot = _cot(
        f"Single credential pair, 2 services, 1 attempt per service -- monitoring health check.",
        f"credential_pairs=1. services=2 (bounded). attempts_per_service=1. Scheduled monitoring.",
        "Authorized monitoring health check -- no credential spray behavior.",
        "Monitoring agent connectivity check. No action.",
        "T1110 -- AUTHORIZED HEALTH CHECK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. OAuthPhishing
#     Evidence: OAuth consent URL crafted for unregistered app_id,
#               token acquired for user outside normal pipeline,
#               24h token refresh cycle, Graph API calls with new token
# ═══════════════════════════════════════════════════════════════════════════════

def _oph_tp(i):
    p = {"app_id":f"{random.randint(10000000,99999999)}-{random.randint(1000,9999)}-attacker",
         "tenant":random.choice(["victim-corp","target-org"])+".onmicrosoft.com",
         "token_acquired":True,"refresh_24h":i%2==0,
         "graph_calls":random.randint(5,50),
         "admin_consent":i%3==0,"scope":"Mail.Read,Files.Read.All,User.ReadBasic.All"}
    prompt = (f"Azure AD -- OAuth Token Acquisition (Phishing App).\n"
              f"  tenant={p['tenant']}\n"
              f"  app_client_id={p['app_id']}\n"
              f"  app_registered_in_tenant=NO\n"
              f"  user_consented=YES  token_acquired={p['token_acquired']}\n"
              f"  scopes_requested={p['scope']}\n"
              f"  admin_consent_flow={'YES' if p['admin_consent'] else 'NO'}\n"
              f"  token_refresh_24h_cycle={'YES' if p['refresh_24h'] else 'NO'}\n"
              f"  graph_api_calls={p['graph_calls']}")
    cot = _cot(
        "Legitimate enterprise apps are registered in the tenant's app catalog. "
        "app_registered_in_tenant=NO means a user consented to an external attacker-controlled application.",
        f"app_registered_in_tenant=NO -- consent granted to unregistered external app. "
        f"scopes={p['scope']} = mail read + file access (data theft). "
        + ("Admin consent flow attempted -- seeking tenant-wide access. " if p['admin_consent'] else "")
        + (f"24h token refresh = persistent access maintained. " if p['refresh_24h'] else "")
        + f"{p['graph_calls']} Graph API calls with new token = active data collection.",
        f"Attacker has OAuth tokens for tenant {p['tenant']} with mail/file read access. "
        "Persistent token refresh means access survives password resets.",
        "OAuth consent phishing confirmed -- unregistered app with data-access scopes.",
        "MITRE T1528 (Steal Application Access Token). Revoke consent, invalidate tokens, remove app registration.",
    )
    return prompt, cot, "true_positive"

def _oph_fp(i):
    p = {"app":"Microsoft Teams","app_id":"registered-enterprise-app-001","scopes":"User.Read,Chat.Read"}
    prompt = (f"Azure AD -- OAuth Token Acquisition.\n"
              f"  app={p['app']}  client_id={p['app_id']}\n"
              f"  app_registered_in_tenant=YES  publisher_verified=YES\n"
              f"  scopes={p['scopes']}  consent=admin_preconsented")
    cot = _cot(
        "Microsoft Teams registered enterprise app with admin pre-consent and minimal scopes.",
        f"app_registered_in_tenant=YES. publisher_verified=YES. scopes={p['scopes']} (minimal). Admin pre-consented.",
        "Authorized enterprise app token issuance. No external app involvement.",
        "Authorized enterprise OAuth -- registered app, publisher verified, minimal scopes.",
        "T1528 -- AUTHORIZED ENTERPRISE APP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 20. PhishingInfra
#     Evidence: fresh domain (<30d), Let's Encrypt cert, credential POST form,
#               tracking pixel requests from diverse IPs, email header anomalies
# ═══════════════════════════════════════════════════════════════════════════════

def _phi_tp(i):
    domain_age = random.randint(1, 28)
    p = {"domain":f"secure-{random.choice(['login','verify','update'])}-{random.randint(100,999)}.com",
         "age_days":domain_age,"cert":"Let's Encrypt","port":443,
         "form_fields":["username","password"],
         "pixel_requests":random.randint(10,200),
         "unique_src_ips":random.randint(5,50),
         "post_submissions":random.randint(1,20),
         "email_source_spoof":i%2==0}
    prompt = (f"Network Tap + Cloud DNS -- Phishing Infrastructure.\n"
              f"  domain={p['domain']}  domain_age_days={p['age_days']}\n"
              f"  tls_cert_issuer={p['cert']}  port={p['port']}\n"
              f"  credential_form_fields={','.join(p['form_fields'])}\n"
              f"  tracking_pixel_GET_requests={p['pixel_requests']} from {p['unique_src_ips']} unique IPs\n"
              f"  POST_submissions_with_credentials={p['post_submissions']}\n"
              f"  email_sender_domain_spoof={'YES' if p['email_source_spoof'] else 'NO'}")
    cot = _cot(
        f"No legitimate corporate service uses a {p['age_days']}-day-old domain with a Let's Encrypt cert "
        "as a production login page. Corporate login pages are on established domains with EV/OV certificates.",
        f"domain_age={p['age_days']}d (freshly registered for campaign). "
        f"cert=Let's Encrypt (free, no identity validation). "
        f"{p['pixel_requests']} tracking pixel requests from {p['unique_src_ips']} IPs = email open tracking. "
        + (f"Email sender domain spoofing = impersonating trusted brand. " if p['email_source_spoof'] else "")
        + f"{p['post_submissions']} credential POSTs = active harvest.",
        f"Phishing campaign active. Domain {p['domain']} is collecting credentials. "
        f"At least {p['post_submissions']} users have submitted credentials.",
        "Phishing credential harvesting infrastructure confirmed.",
        "MITRE T1566+T1598 (Phishing + Phishing for Information). Block domain at DNS, alert affected users, reset credentials.",
    )
    return prompt, cot, "true_positive"

def _phi_fp(i):
    p = {"domain":"corporate-training.company.com","age_days":random.randint(365,1800),
         "cert":"DigiCert EV","posts":random.randint(50,200)}
    prompt = (f"Network Tap -- Corporate Training Portal.\n"
              f"  domain={p['domain']}  domain_age_days={p['age_days']}\n"
              f"  tls_cert_issuer={p['cert']}  form=training_login\n"
              f"  POST_submissions={p['posts']}  email_spoofing=NO\n"
              f"  registered_in_corp_dns=YES")
    cot = _cot(
        f"Established corporate domain ({p['age_days']}d old) with EV cert registered in corporate DNS -- authorized training portal.",
        f"domain_age={p['age_days']}d (established). cert={p['cert']} (identity-validated). corp DNS registered. No spoofing.",
        "Authorized corporate login form -- no phishing indicators.",
        "Authorized corporate training portal. No action.",
        "T1566 -- AUTHORIZED PORTAL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Migrated from stage_tools_supplemental.py (2026-06-05)
# ═══════════════════════════════════════════════════════════════════════════════

def _graph_enum_tp(i):
    p = {"src": _ip_ext(),
         "endpoints": random.sample(
             ["/users","./groups","/servicePrincipals","/applications",
              "/roleManagement/directory/roleAssignments","/policies/conditionalAccessPolicies",
              "/identity/conditionalAccess"], k=random.randint(5,7)),
         "ua": random.choice(["python-requests/2.28","Go-http-client","AADInternals"]),
         "n_requests": random.randint(50, 1000),
         "rate_limited": i%3==0}
    prompt = (f"Azure AD -- Microsoft Graph API Enumeration.\n"
              f"Source: {p['src']}\n"
              f"  endpoints_queried: {', '.join(p['endpoints'][:4])}\n"
              f"  total_requests={p['n_requests']}\n"
              f"  user_agent={p['ua']}\n"
              + (f"  rate_limited_by_graph=YES (too many requests)\n" if p['rate_limited'] else ""))
    cot = _cot(
        "Microsoft 365 administrators use Graph Explorer, RSAT, or PowerShell for AD management. "
        f"Querying {len(p['endpoints'])} Graph API endpoints in {p['n_requests']} requests "
        "from python-requests is not admin tooling.",
        f"UA={p['ua']}: script/attack tool. "
        f"Endpoints {p['endpoints'][:2]}...: "
        "users + groups + roles + policies = complete tenant recon. "
        f"n_requests={p['n_requests']}: bulk enumeration. "
        + (f"Rate-limited: too aggressive for monitoring. " if p['rate_limited'] else ""),
        f"Source {p['src']}: complete Entra ID tenant topology enumerated including "
        "users, groups, service principals, apps, and conditional access policies.",
        "Microsoft Graph API bulk enumeration confirmed.",
        "MITRE T1087.004 (Cloud Account Discovery). "
        "Revoke token used, audit accessed data, review app permissions.",
    )
    return prompt, cot, "true_positive"

def _graph_enum_fp(i):
    p = {"tool": "Microsoft 365 Admin Center", "endpoints": ["/users"], "n": 10}
    prompt = (f"Azure AD -- Admin Center Graph Query.\n"
              f"  tool={p['tool']}  endpoints={p['endpoints']}\n"
              f"  requests={p['n']}  browser_session=YES")
    cot = _cot(
        "Admin Center user lookup -- browser, bounded, single endpoint.",
        "Browser. Single endpoint. Bounded requests.",
        "Authorized admin lookup. No action.",
        "Authorized Graph query. No action.",
        "T1087.004 -- AUTHORIZED ADMIN. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _mfasweep_tp(i):
    p = {"src": _ip_ext(),
         "protocols_tested": random.sample(
             ["ActiveSync","IMAP","POP3","SMTP","EWS","AutoDiscover","ADFS","WinRM","Graph_legacy"],
             k=random.randint(4,7)),
         "accounts_tested": random.randint(5, 50),
         "bypasses_found": random.randint(0, 3),
         "ua": "python-requests"}
    prompt = (f"Azure AD -- MFA Bypass Enumeration.\n"
              f"Source: {p['src']}\n"
              f"  protocols_tested: {', '.join(p['protocols_tested'])}\n"
              f"  accounts_tested={p['accounts_tested']}\n"
              f"  mfa_bypasses_found={'*'+str(p['bypasses_found'])+'*' if p['bypasses_found'] else '0'}\n"
              f"  user_agent={p['ua']}")
    cot = _cot(
        "Security teams test MFA bypass during authorized assessments. "
        f"Testing {len(p['protocols_tested'])} legacy protocols against {p['accounts_tested']} "
        "accounts from python-requests without a change ticket is not authorized testing.",
        f"Legacy protocols {p['protocols_tested'][:2]}...: testing for MFA gaps in older auth flows. "
        f"accounts_tested={p['accounts_tested']}: systematic coverage, not single account check. "
        f"UA=python-requests: automated script. "
        + (f"*{p['bypasses_found']} bypass(es) found*: MFA not enforced on some paths." if p['bypasses_found'] else ""),
        f"Source {p['src']}: MFA bypass surface enumerated for {p['accounts_tested']} accounts. "
        + (f"{p['bypasses_found']} accounts accessible without MFA." if p['bypasses_found'] else ""),
        "MFA bypass enumeration confirmed.",
        "MITRE T1078.004 (Cloud Account) + T1110. "
        "Block legacy auth protocols, enforce MFA on all paths, isolate source.",
    )
    return prompt, cot, "true_positive"

def _mfasweep_fp(i):
    p = {"team": "Security", "protocols": ["ActiveSync"], "ticket": f"SEC-{random.randint(100,999)}"}
    prompt = (f"Azure AD -- MFA Compliance Check.\n"
              f"  team={p['team']}  protocols={p['protocols']}\n"
              f"  ticket={p['ticket']}  authorized=YES")
    cot = _cot(
        "Authorized security check for ActiveSync MFA gaps -- ticketed.",
        f"Authorized. Single protocol. Ticket {p['ticket']}.",
        "Authorized MFA compliance check. No action.",
        "Authorized check. No action.",
        "T1078 -- AUTHORIZED SECURITY CHECK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _exchange_recon_tp(i):
    p = {"src": _ip_int(),
         "endpoint": random.choice(["OWA","EWS","MAPI","Autodiscover","ActiveSync"]),
         "method": random.choice(["Mailbox enumeration","Email keyword search","Delegate access abuse","Impersonation"]),
         "keywords": random.sample(["password","vpn","credential","ssh key","api key","secret"], k=random.randint(3,5)),
         "mailboxes": random.randint(10, 200),
         "emails_exfiltrated": random.randint(0, 5000)}
    prompt = (f"Network Tap -- Exchange Reconnaissance + Email Exfiltration.\n"
              f"Source: {p['src']}\n"
              f"  endpoint={p['endpoint']}\n"
              f"  method={p['method']}\n"
              f"  keyword_search={p['keywords']}\n"
              f"  mailboxes_accessed={p['mailboxes']}\n"
              f"  emails_exfiltrated={p['emails_exfiltrated']:,}")
    cot = _cot(
        "Help desk and management tools access Exchange for legitimate reasons but in bounded, "
        f"user-specific contexts. Searching {p['mailboxes']} mailboxes for "
        f"{p['keywords'][:2]} keywords is credential hunting.",
        f"endpoint={p['endpoint']}: Exchange access vector. "
        f"method={p['method']}: systematic mailbox access. "
        f"keywords={p['keywords']}: credential/secret hunting. "
        f"mailboxes={p['mailboxes']}: bulk access across the org. "
        + (f"{p['emails_exfiltrated']:,} emails matching keywords extracted." if p['emails_exfiltrated'] else ""),
        f"Source {p['src']}: Exchange recon of {p['mailboxes']} mailboxes. "
        + (f"{p['emails_exfiltrated']:,} credential-related emails exfiltrated." if p['emails_exfiltrated'] else ""),
        "Exchange email reconnaissance and credential hunting confirmed.",
        "MITRE T1114 (Email Collection) + T1087. "
        "Revoke Exchange permissions, audit mailbox access logs, notify affected users.",
    )
    return prompt, cot, "true_positive"

def _exchange_recon_fp(i):
    p = {"sa": "svc-helpdesk", "mailboxes": 1, "reason": "password reset for jsmith"}
    prompt = (f"Network Tap -- Exchange Admin Access.\n"
              f"  account={p['sa']}  mailboxes={p['mailboxes']}\n"
              f"  reason={p['reason']}  ticket=YES")
    cot = _cot(
        "Helpdesk accessing single mailbox for password reset -- bounded, authorized.",
        f"Single mailbox. Helpdesk SA. Authorized.",
        "Authorized Exchange admin action. No action.",
        "Authorized Exchange access. No action.",
        "T1114 -- AUTHORIZED HELPDESK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _sharepoint_cred_search_tp(i):
    src = _ip_int()
    tenant = f"{random.choice(['contoso','corp','fabrikam','acme'])}.sharepoint.com"
    terms  = random.sample(["password","credentials","api_key","secret","token","VPN","AWS_SECRET"], k=random.randint(2,4))
    count  = random.randint(50, 2000)
    duration = random.randint(300, 3600)
    prompt = (f"Network Tap -- SharePoint Search API Credential Enumeration.\n"
              f"  src={src}  tenant={tenant}\n"
              f"  phase_1_search: http_uri LIKE /_api/search/query\n"
              f"    http_method=GET  http_useragent=python-requests\n"
              f"    search_terms: {', '.join(terms)}\n"
              f"    unique_queries={random.randint(5,20)}  results_per_query=500\n"
              f"  phase_2_download: http_method=GET  packets_src={count}\n"
              f"    file_types=[docx,xlsx,txt,ps1,json,env]\n"
              f"    session_duration_ms={duration * 1000}\n"
              f"  auth=rtFa+FedAuth (browser session cookie -- session hijack)")
    cot = _cot(
        "SharePoint search is legitimate for business document discovery. "
        "Discriminators: python-requests UA (not a browser), "
        "credential/secret keyword search terms, bulk download immediately after search, "
        "and browser session cookie indicating session hijack (bypass MFA).",
        f"UA=python-requests: automated tool, not a user browsing. "
        f"search_terms=[{', '.join(terms)}]: credential-hunting keyword set. "
        f"packets_src={count}: bulk download of matching files = data staging for exfil. "
        "auth=rtFa+FedAuth: browser session cookie stolen -- attacker bypassed MFA entirely. "
        "ShareFiltrator attack pattern: enumerate → download → exfiltrate.",
        f"Source {src}: {count} credential-containing documents downloaded from {tenant} "
        "via session-hijacked authentication.",
        "SharePoint credential document enumeration and bulk download confirmed.",
        "MITRE T1213.002 (SharePoint) + T1530 + T1078. "
        "Revoke session cookies, rotate leaked credentials, audit downloaded file content.",
    )
    return prompt, cot, "true_positive"

def _sharepoint_cred_search_fp(i):
    p = {"user": _user(), "purpose": "quarterly audit", "files": random.randint(1,10)}
    prompt = (f"Network -- Authorized SharePoint Document Search.\n"
              f"  user={p['user']}  browser_ua=Chrome\n"
              f"  purpose={p['purpose']}  files_downloaded={p['files']}\n"
              f"  normal_ua=YES  user_in_cmdb=YES")
    cot = _cot(
        "User performing quarterly audit search via browser -- normal UA, bounded download.",
        f"Chrome UA. {p['files']} files. {p['purpose']}. CMDB user.",
        "Authorized SharePoint search. No action.",
        "Authorized SharePoint access. No action.",
        "T1213.002 -- AUTHORIZED USER SEARCH. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Registry
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_CLASSES = {
    "NetworkPortScan":        ("network_tap",           ["T1046","T1595.001"],        _nps_tp, _nps_fp),
    "WebFuzzing":             ("network_tap",           ["T1595.002"],                _wf_tp, _wf_fp),
    "WAFEvasionProbe":        ("network_tap",           ["T1595.002","T1190"],        _waf_tp, _waf_fp),
    "NTLMIntercept":          ("network_tap",           ["T1557.001","T1040"],        _ntlm_tp, _ntlm_fp),
    "TunnelInfra":            ("network_tap",           ["T1090.003","T1572"],        _tun_tp, _tun_fp),
    "ReverseProxyTunnel":     ("network_tap",           ["T1090.003","T1572"],        _rpt_tp, _rpt_fp),
    "WindowsHostEnum":        ("sysmon_sensor",         ["T1082","T1087","T1518"],    _whe_tp, _whe_fp),
    "ADDomainEnum":           ("sysmon_sensor",         ["T1087.002","T1069.002","T1482"], _ade_tp, _ade_fp),
    "SMBShareHarvest":        ("network_tap",           ["T1039","T1083","T1135"],    _smb_tp, _smb_fp),
    "CredentialMemoryAccess": ("sysmon_sensor",         ["T1003","T1555"],            _cma_tp, _cma_fp),
    "SCCMRecon":              ("sysmon_sensor",         ["T1087","T1078"],            _sccm_tp, _sccm_fp),
    "LinuxPrivescEnum":       ("linux_sentinel",        ["T1083","T1087.001","T1068"], _lpe_tp, _lpe_fp),
    "SSHKeyHarvest":          ("linux_sentinel",        ["T1552.004"],                _ssh_tp, _ssh_fp),
    "AzureO365Spray":         ("azure_entraid",         ["T1110.003","T1078.004"],    _o365_tp, _o365_fp),
    "ADPasswordSpray":        ("sysmon_sensor",         ["T1110.003","T1078.002"],    _adps_tp, _adps_fp),
    "CloudStorageEnum":       ("aws_cloudtrail",        ["T1619"],                    _cse_tp, _cse_fp),
    "CICDSecretsHarvest":     ("aws_cloudtrail",        ["T1552.004","T1098"],        _cicd_tp, _cicd_fp),
    "MultiProtocolBrute":     ("network_tap",           ["T1110.001"],                _mpb_tp, _mpb_fp),
    "OAuthPhishing":          ("azure_entraid",         ["T1528"],                    _oph_tp, _oph_fp),
    "PhishingInfra":          ("network_tap",           ["T1566","T1598"],            _phi_tp, _phi_fp),
    "GraphAPIEnumeration":    ("azure_entraid",         ["T1087.004"],                _graph_enum_tp, _graph_enum_fp),
    "MFABypassEnum":          ("azure_entraid",         ["T1078.004","T1110"],        _mfasweep_tp, _mfasweep_fp),
    "ExchangeEmailRecon":     ("network_tap",           ["T1114","T1087"],            _exchange_recon_tp, _exchange_recon_fp),
    "SharePointCredSearch":   ("network_tap",           ["T1213.002","T1530"],        _sharepoint_cred_search_tp, _sharepoint_cred_search_fp),
}

S3_QUERIES = {
    "NetworkPortScan":        {"sensor":"network_tap",    "where":"dst_port IS NOT NULL AND session_duration_ms < 500 AND packets_src > 100"},
    "WebFuzzing":             {"sensor":"network_tap",    "where":"http_method IS NOT NULL  GROUP BY src_ip,dst_ip HAVING COUNT(DISTINCT http_uri) > 200"},
    "NTLMIntercept":          {"sensor":"network_tap",    "where":"dst_port IN (5355,137,138,445) AND is_internal_dst = true"},
    "TunnelInfra":            {"sensor":"network_tap",    "where":"session_duration_ms > 300000 AND cert_self_signed = true AND is_internal_dst = false"},
    "SMBShareHarvest":        {"sensor":"network_tap",    "where":"dst_port = 445 AND is_internal_dst = true GROUP BY src_ip HAVING COUNT(DISTINCT dst_ip) > 5"},
    "AzureO365Spray":         {"sensor":"azure_entraid",  "where":"result_type = 'Failure' AND error_code IN ('50126','50053','50057') GROUP BY ip_address HAVING COUNT(DISTINCT user_principal_name) > 20"},
    "CloudStorageEnum":       {"sensor":"aws_cloudtrail", "where":"event_name IN ('ListBuckets','GetBucketAcl','HeadBucket') AND user_identity_type = 'AWSAccount' AND error_code = 'AccessDenied'"},
    "CICDSecretsHarvest":     {"sensor":"aws_cloudtrail", "where":"event_source = 'codepipeline.amazonaws.com' AND event_name LIKE 'Get%Secret%'"},
    "GraphAPIEnumeration":    {"sensor":"azure_entraid","where":"operation_name IN ('Get member objects','List members','List transitive member of','List users','List groups','List applications') AND target_resource_type IN ('User','Group','Application','ServicePrincipal') AND result_type = 'Success' GROUP BY initiated_by_upn HAVING COUNT(DISTINCT target_resource_type) > 3"},
    "MFABypassEnum":          {"sensor":"azure_entraid","where":"result_type = 'Success' AND operation_name = 'Sign-in activity' AND (conditional_access_status = 'NotApplied' OR auth_method_detail LIKE '%Password%' ) AND error_code = '0' GROUP BY ip_address HAVING COUNT(DISTINCT user_principal_name) > 5"},
    "ExchangeEmailRecon":     {"sensor":"network_tap","where":"dst_port IN (443,993,143,25) AND http_uri LIKE '%Exchange%' OR http_uri LIKE '%ews%' GROUP BY src_ip HAVING COUNT(DISTINCT dst_ip) > 3"},
    "SharePointCredSearch":   {"sensor":"network_tap","where":"http_uri LIKE '%/_api/search/query%' AND http_method = 'GET' AND packets_src > 20"},
    "WAFEvasionProbe":        {"sensor":"network_tap","where":"dst_port = 443 AND is_internal_dst = false AND variance_inter_arrival < 0.20 AND byte_ratio > 0.6 AND avg_inter_arrival < 1.0"},
    "ReverseProxyTunnel":     {"sensor":"network_tap","where":"dst_port = 443 AND cert_self_signed = true AND is_internal_dst = false AND session_duration_ms > 60000"},
    "WindowsHostEnum":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND (CommandLine LIKE '%Win32_UserAccount%' OR CommandLine LIKE '%Win32_Share%' OR CommandLine LIKE '%Win32_NetworkAdapter%') AND ParentImage NOT LIKE '%svchost%'"},
    "ADDomainEnum":           {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND (CommandLine LIKE '%LDAP%' OR CommandLine LIKE '%Get-ADUser%' OR CommandLine LIKE '%Get-ADComputer%' OR CommandLine LIKE '%Get-ADGroup%') AND ParentImage NOT LIKE '%svchost%'"},
    "CredentialMemoryAccess": {"sensor":"sysmon_sensor","where":"sysmon_event_id = 10 AND TargetImage LIKE '%lsass%' AND GrantedAccess NOT IN ('0x1000','0x1400','0x100000') AND Image NOT LIKE 'C:\\\\Windows\\\\System32%'"},
    "SCCMRecon":              {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND (CommandLine LIKE '%SMS_MP%' OR CommandLine LIKE '%AdminService%' OR CommandLine LIKE '%Get-WmiObject%SMS%') AND ParentImage NOT LIKE '%CcmExec%'"},
    "LinuxPrivescEnum":       {"sensor":"linux_sentinel","where":"command_line LIKE '%find%suid%' OR command_line LIKE '%sudo%l%' OR command_line LIKE '%/etc/passwd%' OR command_line LIKE '%/etc/shadow%'"},
    "SSHKeyHarvest":          {"sensor":"linux_sentinel","where":"target_file LIKE '%/.ssh/id_%' AND comm NOT IN ('ssh','ssh-agent','ssh-keygen')"},
    "ADPasswordSpray":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND (CommandLine LIKE '%Invoke-SpraySinglePassword%' OR CommandLine LIKE '%DomainPasswordSpray%' OR CommandLine LIKE '%kerbrute%passwordspray%')"},
    "MultiProtocolBrute":     {"sensor":"network_tap","where":"dst_port IN (22,445,3389,5985,25,110,143) AND is_internal_dst = false AND variance_inter_arrival < 0.15 AND avg_inter_arrival < 2.0"},
    "OAuthPhishing":          {"sensor":"azure_entraid","where":"event_type LIKE '%consent%' AND action LIKE '%grant%' AND outcome = 'success' AND user_name IS NOT NULL"},
    "PhishingInfra":          {"sensor":"network_tap","where":"dst_port = 443 AND cert_self_signed = true AND is_internal_dst = false AND payload_entropy > 3.5 AND avg_inter_arrival < 5.0"},
}


# ═══════════════════════════════════════════════════════════════════════════════
# Generator + Main
# ═══════════════════════════════════════════════════════════════════════════════

def generate(tool_name, n_tp, n_fp):
    sensor, mitre, tp_fn, fp_fn = TOOL_CLASSES[tool_name]
    records = []
    for i in range(n_tp):
        prompt, cot, cls = tp_fn(i)
        records.append(_record(tool_name, sensor, mitre,
                                _msg(sensor, prompt, cot), cls))
    for i in range(n_fp):
        prompt, cot, cls = fp_fn(i)
        records.append(_record(tool_name, sensor, mitre,
                                _msg(sensor, prompt, cot), cls))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records-per-class",  type=int, default=10)
    ap.add_argument("--admin-fps-per-class",type=int, default=2)
    ap.add_argument("--tool-filter",        type=str, default="")
    args = ap.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    names = list(TOOL_CLASSES.keys())
    if args.tool_filter:
        names = [t.strip() for t in args.tool_filter.split(",")]

    all_records = []
    for name in names:
        recs = generate(name, args.records_per_class, args.admin_fps_per_class)
        all_records.extend(recs)
        tp  = sum(1 for r in recs if r["classification"] == "true_positive")
        fp  = sum(1 for r in recs if r["classification"] == "false_positive")
        logger.info(f"  {name}: {tp} TP + {fp} FP  ({TOOL_CLASSES[name][0]})")

    with open(OUTPUT_FILE, "w") as f:
        for r in all_records:
            f.write(json.dumps(r) + "\n")

    index = {
        "ttp_category": "Recon",
        "total_records": len(all_records),
        "tp_records":    sum(1 for r in all_records if r["classification"]=="true_positive"),
        "fp_records":    sum(1 for r in all_records if r["classification"]=="false_positive"),
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
