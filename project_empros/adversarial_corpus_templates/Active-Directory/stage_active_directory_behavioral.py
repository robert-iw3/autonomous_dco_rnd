"""
stage_active_directory_behavioral.py -- Active Directory TTP Behavioral Dataset

Detection philosophy: behavioral evidence only -- LDAP query patterns, Kerberos
protocol anomalies, NTLM relay timing, AD object modification sequences.
No tool names in detection logic. Every class has admin FP variants.

Output:
  data/staging/active_directory_behavioral_v1.jsonl
  data/staging/active_directory_query_index.json

Usage:
    python stage_active_directory_behavioral.py
    python stage_active_directory_behavioral.py --records-per-class 15
    python stage_active_directory_behavioral.py --tool-filter ADPasswordSprayLDAP,DCSyncHashExtract
"""

import json
import random
import argparse
import logging
import hashlib
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stage-ad")
random.seed(37)

OUTPUT_DIR  = Path("../data/staging")
OUTPUT_FILE = OUTPUT_DIR / "active_directory_behavioral_v1.jsonl"
INDEX_FILE  = OUTPUT_DIR / "active_directory_query_index.json"

TTP_CAT = "ActiveDirectory"

SYS = {
    "sysmon_sensor": (
        "You are the Host Forensics Expert. Target OS: Windows Domain Controller / Member Server. "
        "Vector Space: 4D windows_math. Source: Sysmon event stream + Windows Security Event Log. "
        "Schema: sysmon_event_id, Image, CommandLine, TargetObject, Details, "
        "QueryName, DestinationIp, DestinationPort. "
        "Identify Active Directory attack tradecraft. Output MITRE ATT&CK + containment."
    ),
    "network_tap": (
        "You are the Network Tap Forensics Expert. Analyze network session data "
        "including LDAP, Kerberos, SMB, and RPC protocol patterns. "
        "Identify Active Directory attack tradecraft. Output MITRE ATT&CK + containment."
    ),
    "azure_entraid": (
        "You are the Cloud Identity Expert. Analyze Azure AD / Entra ID events "
        "including Kerberos ticket requests, certificate authentication, and LDAP operations. "
        "Identify Active Directory attack tradecraft. Output MITRE + containment."
    ),
}

VECTOR = {
    "sysmon_sensor":  "windows_math",
    "network_tap":    "c2_math",
    "azure_entraid":  "cloud_flow",
}

def _ip_int():  return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
def _dc():      return f"DC{random.randint(1,3)}.{random.choice(['corp','domain','internal'])}.local"
def _host():    return f"{random.choice(['WS','SRV','APP'])}-{random.randint(10,99)}"
def _user():    return random.choice(["jsmith","alee","tmorgan","schen","rbrown"])
def _domain():  return random.choice(["CORP","DOMAIN","INTERNAL"])
def _b64(n=20): return "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", k=n))
def _guid():    return f"{{{random.randint(0x10000000,0xFFFFFFFF):08X}-{random.randint(0x1000,0xFFFF):04X}-{random.randint(0x1000,0xFFFF):04X}-{random.randint(0x1000,0xFFFF):04X}-{random.randint(0x100000000000,0xFFFFFFFFFFFF):012X}}}"

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
         "vector_name": VECTOR[sensor], "classification": cls, "messages": msgs}
    if event_id is not None:
        r["event_id"] = event_id
    elif sensor == "sysmon_sensor":
        r["event_id"] = hashlib.md5(f"{tool_class}_{cls}_{sensor}".encode()).hexdigest()[:16]
    return r

def _msg(sensor, user_text, asst_text):
    wrapped = (f"Spatial Anomaly Detected.\nSource: {sensor}\n"
               f"Vector: <|spatial_vector|>\n{user_text}")
    return [{"role": "system",    "content": SYS[sensor]},
            {"role": "user",      "content": wrapped},
            {"role": "assistant", "content": asst_text}]


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ADPasswordSprayLDAP
#    Evidence: LDAP auth fan-out (many UPNs, few failures per account),
#              lockout-window awareness (delays between spray rounds),
#              LDAP policy query to discover lockout threshold
#    Admin FP: Service account misconfiguration (single UPN, many failures)
# ═══════════════════════════════════════════════════════════════════════════════

def _adps_tp(i):
    dc = _dc(); src = _ip_int()
    n = random.randint(50, 500); pw = random.choice(["Spring2025!","Summer2025!","P@ssw0rd1","Welcome1"])
    p = {"src": src, "dc": dc, "n": n, "pw": pw,
         "fails_per_acct": random.randint(1,2),
         "lockout_thresh": random.randint(3,10),
         "success": random.randint(0,3),
         "ldap_policy_query": True,
         "window_s": random.randint(600, 3600)}
    prompt = (f"Network Tap -- AD Password Spray (LDAP).\n"
              f"Source: {p['src']} → DC {p['dc']}:389\n"
              f"  unique_upns_targeted={p['n']}  password_tried={p['pw']}\n"
              f"  failures_per_account={p['fails_per_acct']} (below lockout threshold {p['lockout_thresh']})\n"
              f"  successful_binds={'*'+str(p['success'])+'*' if p['success'] else '0'}\n"
              f"  ldap_policy_query_first=YES (DefaultDomainPasswordPolicy)\n"
              f"  spray_window_s={p['window_s']}")
    cot = _cot(
        f"Service account misconfiguration produces many failures for one UPN. "
        f"This pattern has {p['n']} unique UPNs × {p['fails_per_acct']} failure(s) each -- "
        "definitional spray (not brute-force).",
        f"LDAP policy query first: attacker read lockout threshold ({p['lockout_thresh']}) before spraying. "
        f"{p['n']} UPNs × {p['fails_per_acct']} failure(s) = spray ratio. "
        f"Window={p['window_s']}s: paced to stay below lockout observation window. "
        + (f"*{p['success']} valid credential(s) found.* " if p['success'] else ""),
        f"Domain {p['dc']}: {p['n']} accounts tested. "
        + (f"{p['success']} accounts compromised." if p['success'] else "Spray ongoing."),
        "AD LDAP password spray confirmed.",
        "MITRE T1110.003 (Password Spraying). "
        "Block source IP, enable AD Smart Lockout, force password reset for compromised accounts.",
    )
    return prompt, cot, "true_positive"

def _adps_fp(i):
    p = {"sa": "svc-app01", "fails": random.randint(5,20), "upns": 1}
    prompt = (f"Network Tap -- LDAP Auth Failures.\n"
              f"  account={p['sa']}  unique_upns={p['upns']}  failures={p['fails']}\n"
              f"  source=APP-SERVER-01  cause=stale_cached_credentials")
    cot = _cot(
        f"Single UPN with {p['fails']} failures -- stale service account credential.",
        f"unique_upns=1. Known service account. APP-SERVER-01 source.",
        "Service account credential rotation needed. No spray.",
        "Stale credential -- no spray.",
        "T1110.003 -- MISCONFIGURATION. Update credential. No containment.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ADCSCertAbuse (certipy ESC1-ESC16)
#    Evidence: LDAP template enumeration (pKICertificateTemplate class),
#              certificate enrollment (HTTPS to CA enrollment endpoint),
#              PKINIT AS-REQ with attacker-enrolled certificate
# ═══════════════════════════════════════════════════════════════════════════════

def _adcs_tp(i):
    dc = _dc(); src = _ip_int()
    esc = random.choice(["ESC1","ESC3","ESC4","ESC8","ESC9","ESC13"])
    target_template = random.choice(["User","WebServer","SubCA","DomainController","Machine"])
    p = {
        "src": src, "ca": f"CA.{dc.split('.', 1)[1]}",
        "esc": esc, "template": target_template,
        "ldap_template_enum": True,
        "enrollment_endpoint": f"https://CA.corp.local/certsrv/mscep/mscep.dll",
        "pkinit_asreq": True,
        "impersonated_account": random.choice(["Administrator","krbtgt","DA-jsmith"]),
    }
    prompt = (f"Network Tap + Sysmon -- ADCS Certificate Abuse ({p['esc']}).\n"
              f"Source: {p['src']}\n"
              f"  step1: LDAP query pKICertificateTemplate objects (template enumeration)\n"
              f"  step2: Certificate enrollment to {p['ca']} template={p['template']}\n"
              f"  step3: Kerberos AS-REQ with PKINIT (cert-based auth)\n"
              f"  esc_technique={p['esc']}\n"
              f"  impersonated_account={p['impersonated_account']}")
    cot = _cot(
        "Authorized certificate enrollment queries template objects for auto-enrollment or "
        "user cert requests. Certificate enrollment followed immediately by PKINIT for a "
        "Domain Admin account from a non-DC host is not auto-enrollment behavior.",
        f"LDAP pKICertificateTemplate enumeration: attacker mapping ESC attack surface. "
        f"ESC={p['esc']}: specific misconfiguration exploited in template {p['template']}. "
        f"PKINIT AS-REQ from {p['src']}: certificate used to obtain TGT for {p['impersonated_account']}. "
        "Cert-to-hash: attacker now has NTLM hash and TGT for impersonated account.",
        f"Source {p['src']} has obtained Domain Admin TGT via ADCS {p['esc']}. "
        "Full domain compromise possible from this certificate.",
        f"ADCS {p['esc']} certificate abuse confirmed.",
        "MITRE T1649 (Steal/Forge Authentication Certificates). "
        "Revoke certificate, fix template misconfiguration, rotate impersonated account.",
    )
    return prompt, cot, "true_positive"

def _adcs_fp(i):
    p = {"user": _user(), "template": "User", "ca": "CA.corp.local",
         "reason": "auto-enrollment via Group Policy"}
    prompt = (f"Sysmon -- Certificate Auto-Enrollment.\n"
              f"  user={p['user']}  template={p['template']}\n"
              f"  ca={p['ca']}  reason={p['reason']}\n"
              f"  gp_scheduled=YES  no_pkinit_impersonation=YES")
    cot = _cot(
        "Auto-enrollment via GPO for standard User template -- scheduled, no impersonation.",
        f"GPO-scheduled. Standard User template. No PKINIT for DA.",
        "Authorized auto-enrollment. No action.",
        "Authorized cert auto-enrollment. No action.",
        "T1649 -- AUTHORIZED AUTO-ENROLLMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. NTLMPoisoningRelay (Responder)
#    Evidence: Rogue responses to LLMNR/NBT-NS broadcasts,
#              NTLMv2 hash capture, optional relay to third host
# ═══════════════════════════════════════════════════════════════════════════════

def _responder_tp(i):
    attacker = _ip_int(); victim = _ip_int(); relay = _ip_int()
    proto = random.choice(["LLMNR","NBT-NS","mDNS","WPAD"])
    p = {
        "attacker": attacker, "victim": victim, "relay": relay,
        "proto": proto, "port": {"LLMNR":5355,"NBT-NS":137,"mDNS":5353,"WPAD":80}[proto],
        "hashes_captured": random.randint(1,8),
        "services_listening": random.sample(["HTTP","HTTPS","SMB","LDAP","MSSQL","FTP","SMTP"], k=random.randint(3,6)),
        "wpad_rogue": "WPAD" in proto or i%3==0,
        "relay_to": relay if i%2==0 else None,
    }
    prompt = (f"Network Tap -- LLMNR/NBT-NS Poisoning + NTLMv2 Capture.\n"
              f"Attacker: {p['attacker']}  Victim: {p['victim']}\n"
              f"  protocol_poisoned={p['proto']}:{p['port']}\n"
              f"  rogue_services_listening: {', '.join(p['services_listening'])}\n"
              f"  ntlmv2_hashes_captured={p['hashes_captured']}\n"
              + (f"  wpad_rogue_proxy=YES\n" if p['wpad_rogue'] else "")
              + (f"  relay_to={p['relay_to']} (relay attack)\n" if p['relay_to'] else ""))
    cot = _cot(
        f"Legacy WINS clients may respond to {p['proto']} broadcasts but do not listen on "
        f"HTTP/SMB/LDAP/MSSQL simultaneously. A host operating as a multi-service rogue "
        "authentication server has no legitimate administrative purpose.",
        f"Multi-service rogue listener ({', '.join(p['services_listening'][:3])}...): "
        "Responder-style tool capturing credentials across all protocols. "
        f"{p['hashes_captured']} NTLMv2 hashes captured from {p['victim']}. "
        + (f"WPAD rogue: all browser traffic proxied for credential capture. " if p['wpad_rogue'] else "")
        + (f"Relay to {p['relay_to']}: hashes being relayed for authenticated access." if p['relay_to'] else ""),
        f"Attacker {p['attacker']} has poisoned {p['proto']} and captured "
        f"{p['hashes_captured']} NTLMv2 hashes from victim {p['victim']}.",
        "LLMNR/NBT-NS poisoning with NTLMv2 capture confirmed.",
        "MITRE T1557.001 (LLMNR/NBT-NS Poisoning). "
        "Disable LLMNR/NBT-NS via GPO, isolate attacker host, rotate captured accounts.",
    )
    return prompt, cot, "true_positive"

def _responder_fp(i):
    p = {"host": _ip_int(), "reason": "legacy WINS client misconfiguration", "hashes": 0}
    prompt = (f"Network Tap -- NBT-NS Broadcast Response.\n"
              f"  host={p['host']}  reason={p['reason']}\n"
              f"  single_response=YES  hashes_captured={p['hashes']}\n"
              f"  multi_service_listener=NO")
    cot = _cot(
        "Legacy WINS client misconfiguration -- single response, no hash capture.",
        f"Single response. No rogue services. hashes=0.",
        "Legacy misconfiguration. Disable NBT-NS. No immediate threat.",
        "Legacy NBT-NS misconfiguration. No action.",
        "T1557.001 -- MISCONFIGURATION. Remediate.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. TimeroastNTPHash
#    Evidence: NTP queries to DC on UDP 123, RID-based account enumeration,
#              MD5 hash extraction from NTP response (SNTP mode 3/4)
# ═══════════════════════════════════════════════════════════════════════════════

def _timeroast_tp(i):
    dc = _dc(); src = _ip_int()
    p = {
        "src": src, "dc": dc,
        "ntp_queries": random.randint(20, 500),
        "rids_probed": random.randint(500, 5000),
        "sntp_mode": "3/4 (client/server)",
        "hash_count": random.randint(5, 50),
        "accounts_type": random.choice(["computer accounts", "trust accounts", "service accounts"]),
        "cv": round(random.uniform(0.0, 0.08), 4),
    }
    prompt = (f"Network Tap -- Timeroasting NTP Hash Extraction.\n"
              f"Source: {p['src']} → DC {p['dc']}:123 (UDP NTP)\n"
              f"  ntp_queries={p['ntp_queries']}  rids_probed={p['rids_probed']}\n"
              f"  sntp_mode={p['sntp_mode']}\n"
              f"  hashes_extractable={p['hash_count']} ({p['accounts_type']})\n"
              f"  inter_query_cv={p['cv']:.4f}")
    cot = _cot(
        "Windows NTP sync (w32tm.exe) sends 1-4 NTP queries to configured servers. "
        f"An external host sending {p['ntp_queries']} NTP queries to a DC while "
        f"probing {p['rids_probed']} RIDs is not clock synchronization.",
        f"UDP 123 to DC: Timeroasting uses NTP request with RID in reference ID field. "
        f"{p['rids_probed']} RIDs probed: systematic enumeration of all AD accounts. "
        f"SNTP mode=3/4: client polls DC; DC response contains MD5(account_password). "
        f"cv={p['cv']:.4f}: automated sequential RID sweep. "
        f"{p['hash_count']} {p['accounts_type']} hashes extractable for offline cracking.",
        f"Source {p['src']}: {p['hash_count']} AD account NTP hashes captured. "
        "Computer/trust accounts with weak/default passwords crackable offline.",
        "Timeroasting NTP hash extraction confirmed.",
        "MITRE T1558 (Steal/Forge Kerberos Tickets) + T1110 (Brute Force). "
        "Rotate computer/trust account passwords, block external UDP 123 to DCs.",
    )
    return prompt, cot, "true_positive"

def _timeroast_fp(i):
    p = {"proc": "w32tm.exe", "queries": random.randint(1,4), "dst": "pool.ntp.org"}
    prompt = (f"Network Tap -- Windows NTP Sync.\n"
              f"  process={p['proc']}  queries={p['queries']}  dst={p['dst']}\n"
              f"  rids_probed=0  standard_ntp=YES")
    cot = _cot(
        "w32tm.exe standard NTP sync -- 1-4 queries, pool.ntp.org, no RID probing.",
        f"queries={p['queries']}. w32tm.exe. No RID sweep.",
        "Authorized Windows NTP sync. No action.",
        "Standard NTP. No action.",
        "T1558 -- AUTHORIZED NTP SYNC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. GPORelayInjection (GPOddity + OUned)
#    Evidence: NTLM relay + LDAP GPC/GPT modification + malicious scheduled
#              task XML written to SYSVOL, affects child OU objects
# ═══════════════════════════════════════════════════════════════════════════════

def _gpo_relay_tp(i):
    dc = _dc(); attacker = _ip_int()
    gpo_guid = _guid()
    p = {
        "attacker": attacker, "dc": dc, "gpo_guid": gpo_guid,
        "relay_source": random.choice(["coerced auth via MS-RPRN","WebDAV trigger","UNC path in email"]),
        "ldap_attrs_modified": ["gPCFileSysPath","gPCMachineExtensionNames"],
        "sysvol_task_written": True,
        "affected_ou": f"OU=Workstations,DC={dc.split('.')[1]},DC=local",
        "n_objects_affected": random.randint(10, 500),
        "task_cmd": random.choice(["powershell.exe -enc JAB","cmd.exe /c net user backdoor P@ss1 /add /domain"]),
    }
    prompt = (f"Network Tap + Sysmon -- GPO NTLM Relay + Policy Injection.\n"
              f"Attacker: {p['attacker']} → DC {p['dc']}\n"
              f"  relay_trigger: {p['relay_source']}\n"
              f"  ldap_attributes_modified: {', '.join(p['ldap_attrs_modified'])}\n"
              f"  gpo_guid: {p['gpo_guid']}\n"
              f"  malicious_task_written_to_sysvol=YES\n"
              f"  affected_ou={p['affected_ou']}\n"
              f"  objects_affected={p['n_objects_affected']}\n"
              f"  task_command: {p['task_cmd'][:50]}")
    cot = _cot(
        "Legitimate GPO changes come from IT administrators using GPMC with domain admin "
        "credentials and change tickets. A modification originating from an NTLM relay "
        "with an injected malicious scheduled task has no authorized analog.",
        f"NTLM relay via {p['relay_source']}: DC authenticates to attacker, relay used for LDAP writes. "
        f"gPCFileSysPath + gPCMachineExtensionNames modified: GPO configuration replaced. "
        f"Malicious task XML written to SYSVOL/Policies/{p['gpo_guid']}: "
        f"'{p['task_cmd'][:40]}' executes on next GP refresh. "
        f"{p['n_objects_affected']} objects in {p['affected_ou']} affected.",
        f"Domain-wide attack via GPO relay: {p['n_objects_affected']} computers in "
        f"{p['affected_ou']} will execute malicious code at next Group Policy refresh (every 90-120 min).",
        "GPO NTLM relay injection confirmed.",
        "MITRE T1484.001 (Domain Policy Modification: GPO). "
        "Remove malicious task from SYSVOL, revert GPO attributes, block coercion source.",
    )
    return prompt, cot, "true_positive"

def _gpo_relay_fp(i):
    p = {"admin": "svc-gpo-admin", "gpo": "Security Baseline", "ticket": f"CHG-{random.randint(10000,99999)}"}
    prompt = (f"Network Tap -- GPO Modification.\n"
              f"  admin={p['admin']}  gpo={p['gpo']}  ticket={p['ticket']}\n"
              f"  ntlm_relay=NO  maintenance_window=YES")
    cot = _cot(
        "Authorized GPO change by dedicated admin -- no relay, change ticket, maintenance window.",
        f"admin account. No relay. Ticket {p['ticket']}. Maintenance window.",
        "Authorized GPO modification. No action.",
        "Authorized GPO change. No action.",
        "T1484.001 -- AUTHORIZED GPO. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. ADWSSOAPEnum (SoaPy -- ADWS port 9389)
#    Evidence: SOAP/NNS/NMF traffic to DC port 9389 (ADWS),
#              LDAP write operations via SOAP (SPN/RBCD/ASREP),
#              non-standard AD management client
# ═══════════════════════════════════════════════════════════════════════════════

def _adws_tp(i):
    dc = _dc(); src = _ip_int()
    op = random.choice(["SPN_modification","RBCD_write","ASREP_roasting_flag","shadow_credentials"])
    p = {
        "src": src, "dc": dc, "port": 9389,
        "protocol": "SOAP/NNS/NMF (ADWS)",
        "operation": op,
        "target_account": random.choice(["svc-sql","DC$","krbtgt","Administrator"]),
        "non_standard_client": True,
    }
    prompt = (f"Network Tap -- ADWS SOAP LDAP Write (Port 9389).\n"
              f"Source: {p['src']} → DC {p['dc']}:9389\n"
              f"  protocol={p['protocol']}\n"
              f"  operation={p['operation']}\n"
              f"  target_account={p['target_account']}\n"
              f"  standard_ad_management_client=NO\n"
              f"  uses_custom_nnm_framing=YES")
    cot = _cot(
        "Active Directory Web Services (port 9389) is used by Remote Server Administration Tools "
        "and PowerShell AD module. These communicate from known management workstations during "
        "business hours. Custom NNS/NMF framing from a non-RSAT client indicates an attack tool.",
        f"Port 9389 + custom SOAP/NNS framing: SoaPy-style ADWS client bypassing standard LDAP port 389. "
        f"Operation={p['operation']} on {p['target_account']}: "
        "adversarial AD write operation via SOAP interface. "
        "Non-standard client: not RSAT, not PowerShell AD module -- custom attack tooling.",
        f"Source {p['src']} has performed {p['operation']} on {p['target_account']} via ADWS. "
        "ADWS writes bypass some LDAP monitoring rules that only watch port 389.",
        "ADWS SOAP-based AD write confirmed.",
        "MITRE T1098 (Account Manipulation) via ADWS. "
        "Revert modified AD object, block port 9389 from non-management workstations.",
    )
    return prompt, cot, "true_positive"

def _adws_fp(i):
    p = {"host": "mgmt-ws-01", "tool": "RSAT Active Directory module"}
    prompt = (f"Network Tap -- ADWS Connection.\n"
              f"  source={p['host']}  tool={p['tool']}\n"
              f"  port=9389  authorized_mgmt_host=YES")
    cot = _cot(
        "RSAT from authorized management workstation -- standard ADWS usage.",
        f"RSAT. Authorized host. Standard SOAP framing.",
        "Authorized ADWS connection from RSAT. No action.",
        "Authorized ADWS. No action.",
        "T1098 -- AUTHORIZED ADWS. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. LDAPDomainDump
#    Evidence: Full LDAP SUBTREE search from DC= root, all object classes,
#              large response sets, python-ldap3/impacket UA, off-hours
# ═══════════════════════════════════════════════════════════════════════════════

def _ldap_dump_tp(i):
    dc = _dc(); src = _ip_int()
    p = {
        "src": src, "dc": dc,
        "objects_returned": random.randint(5000, 100000),
        "ldap_filter": "(&(objectClass=*))",
        "base_dn": f"DC={dc.split('.')[1]},DC=local",
        "attributes": "*",
        "sessions": random.randint(5, 30),
        "hour": random.choice([0,1,2,3,22,23]),
        "ua": random.choice(["python-ldap3/2.9","impacket/0.12.0","python-requests/2.28"]),
    }
    prompt = (f"Network Tap -- Full LDAP Domain Dump.\n"
              f"Source: {p['src']} → DC {p['dc']}:389\n"
              f"  ldap_filter={p['ldap_filter']}\n"
              f"  search_base={p['base_dn']}  scope=SUBTREE\n"
              f"  attributes_requested={p['attributes']} (all)\n"
              f"  objects_returned={p['objects_returned']:,}\n"
              f"  ldap_sessions={p['sessions']}  hour={p['hour']:02d}:xx\n"
              f"  user_agent={p['ua']}")
    cot = _cot(
        "Legitimate LDAP queries are scoped (specific OU, targeted filter, bounded result set). "
        f"Returning {p['objects_returned']:,} objects from the domain root at {p['hour']:02d}:xx "
        "with python-ldap3/impacket is not an admin query.",
        f"filter=(&(objectClass=*)) + base=DC root + scope=SUBTREE + attributes=*: "
        "complete directory dump. "
        f"{p['objects_returned']:,} objects: entire AD directory. "
        f"UA={p['ua']}: script/attack tool, not RSAT. "
        f"Off-hours ({p['hour']:02d}:xx): avoiding detection.",
        f"Source {p['src']}: complete AD directory dump obtained "
        f"({p['objects_returned']:,} objects). Attacker has all users, groups, computers, "
        "trust relationships, and ACLs.",
        "Full LDAP domain dump confirmed.",
        "MITRE T1087.002 (Domain Account Discovery) + T1069.002. "
        "Block source, audit what was extracted, review AD attack path exposure.",
    )
    return prompt, cot, "true_positive"

def _ldap_dump_fp(i):
    p = {"tool": "RSAT", "filter": "(sAMAccountName=jsmith)", "objects": 1, "scope": "BASE"}
    prompt = (f"Network Tap -- Scoped LDAP Query.\n"
              f"  tool={p['tool']}  filter={p['filter']}\n"
              f"  objects_returned={p['objects']}  scope={p['scope']}\n"
              f"  attributes=sAMAccountName,mail (specific)")
    cot = _cot(
        "RSAT scoped lookup -- single user, specific attributes, BASE scope.",
        f"filter=sAMAccountName=jsmith. objects=1. BASE scope. RSAT.",
        "Authorized scoped LDAP query. No action.",
        "Authorized LDAP lookup. No action.",
        "T1087.002 -- AUTHORIZED LOOKUP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. DACLACEEnumeration (dacl_search, Cable)
#    Evidence: LDAP queries for nTSecurityDescriptor attribute (ACL data),
#              large-scale ACE extraction, privilege path analysis queries
# ═══════════════════════════════════════════════════════════════════════════════

def _dacl_tp(i):
    dc = _dc(); src = _ip_int()
    p = {
        "src": src, "dc": dc,
        "objects_enumerated": random.randint(500, 20000),
        "attribute": "nTSecurityDescriptor",
        "flags": "LDAP_SERVER_SD_FLAGS (DACL only)",
        "ace_types_found": random.sample(["GenericAll","WriteDACL","WriteOwner","DCSync","RBCD_write"], k=random.randint(2,4)),
        "rbcd_candidates": random.randint(0, 20),
        "sqlite_output": i%2==0,
    }
    prompt = (f"Network Tap -- DACL/ACE Enumeration.\n"
              f"Source: {p['src']} → DC {p['dc']}:389\n"
              f"  attribute_requested={p['attribute']}\n"
              f"  ldap_flags={p['flags']}\n"
              f"  objects_enumerated={p['objects_enumerated']:,}\n"
              f"  dangerous_aces_found: {', '.join(p['ace_types_found'])}\n"
              f"  rbcd_candidates={p['rbcd_candidates']}\n"
              + (f"  sqlite_database_created=YES\n" if p['sqlite_output'] else ""))
    cot = _cot(
        "Legitimate security audits enumerate ACEs, but from authorized auditing tools "
        "(PingCastle, Purple Knight) on scheduled cycles with management approval. "
        f"Enumerating nTSecurityDescriptor for {p['objects_enumerated']:,} objects from "
        "a script is not a scheduled audit.",
        f"nTSecurityDescriptor on {p['objects_enumerated']:,} objects: "
        "comprehensive DACL map of the domain. "
        f"Dangerous ACE types found: {', '.join(p['ace_types_found'])}. "
        f"{p['rbcd_candidates']} RBCD-exploitable candidates: "
        "attacker mapping privilege escalation paths. "
        + (f"SQLite database: offline attack path analysis. " if p['sqlite_output'] else ""),
        f"Source {p['src']} has mapped all dangerous ACEs in the domain. "
        "Attack path discovery complete for privilege escalation.",
        "DACL/ACE enumeration for attack path discovery confirmed.",
        "MITRE T1069 (Permission Groups Discovery). "
        "Review dangerous ACE holders, remove unnecessary permissions.",
    )
    return prompt, cot, "true_positive"

def _dacl_fp(i):
    p = {"tool": "PingCastle", "objects": 200, "ticket": f"SEC-{random.randint(100,999)}"}
    prompt = (f"Network Tap -- Security Audit DACL Check.\n"
              f"  tool={p['tool']}  objects={p['objects']}\n"
              f"  ticket={p['ticket']}  scheduled=YES")
    cot = _cot(
        "Authorized security audit via PingCastle -- bounded, scheduled, ticketed.",
        f"PingCastle. objects={p['objects']} (bounded). Ticket {p['ticket']}.",
        "Authorized security audit. No action.",
        "Authorized DACL audit. No action.",
        "T1069 -- AUTHORIZED AUDIT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. BloodHoundCollection (ShadowHound, bloodhound-automation)
#    Evidence: Mass LDAP queries matching BloodHound collection patterns
#              (all users/groups/computers/trusts/GPOs/containers),
#              graph JSON output files
# ═══════════════════════════════════════════════════════════════════════════════

def _bh_tp(i):
    dc = _dc(); src = _ip_int()
    p = {
        "src": src, "dc": dc,
        "collection_methods": random.sample(
            ["Group","LocalAdmin","Session","Trusts","ACL","Container","GPO","RDP","DCOM","PSRemote"],
            k=random.randint(5,9)),
        "ldap_queries": random.randint(50, 300),
        "objects": random.randint(1000, 50000),
        "json_files": ["users.json","groups.json","computers.json","gpos.json","acls.json"],
        "adws_mode": i%3==0,
    }
    prompt = (f"Network Tap -- BloodHound-Style Mass AD Collection.\n"
              f"Source: {p['src']} → DC {p['dc']}\n"
              f"  collection_methods: {', '.join(p['collection_methods'])}\n"
              f"  ldap_queries={p['ldap_queries']}  objects_collected={p['objects']:,}\n"
              f"  output_files: {', '.join(p['json_files'])}\n"
              + (f"  adws_port_9389_mode=YES (no LDAP port 389)\n" if p['adws_mode'] else ""))
    cot = _cot(
        "Security teams run BloodHound for authorized red team exercises with change tickets. "
        f"The distinct pattern here -- {len(p['collection_methods'])} simultaneous collection "
        "methods ({', '.join(p['collection_methods'][:3])}...) -- has no single-purpose admin analog.",
        f"Collection methods {p['collection_methods']}: "
        "simultaneous ACL+Session+LocalAdmin+Trust+GPO = BloodHound attack path collection. "
        f"{p['ldap_queries']} LDAP queries, {p['objects']:,} objects: "
        "complete domain graph. "
        f"JSON output files ({', '.join(p['json_files'][:2])}...): "
        "graph database import format for attack path analysis.",
        f"Source {p['src']} has collected a complete BloodHound graph of the domain. "
        "All attack paths to Domain Admin are now mapped.",
        "BloodHound-style AD graph collection confirmed.",
        "MITRE T1087 (Account Discovery) + T1069 (Permission Groups). "
        "Isolate source, review domain for high-value attack paths, reduce attack surface.",
    )
    return prompt, cot, "true_positive"

def _bh_fp(i):
    p = {"team": "Red_Team", "ticket": f"RT-{random.randint(100,999)}", "methods": ["Group","ACL"]}
    prompt = (f"Network Tap -- Authorized BloodHound Collection.\n"
              f"  team={p['team']}  ticket={p['ticket']}\n"
              f"  methods={p['methods']}  scope=limited_ous_only")
    cot = _cot(
        "Authorized red team BloodHound -- limited methods, scoped OUs, change ticket.",
        f"Red team. Ticket {p['ticket']}. Limited scope.",
        "Authorized red team BloodHound. No action.",
        "Authorized BloodHound. No action.",
        "T1087 -- AUTHORIZED RED TEAM. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. RemoteRegistrySessionEnum (Invoke-SessionHunter)
#     Evidence: Remote registry connection to HKEY_USERS on target hosts,
#               SID-to-username resolution, active session identification
# ═══════════════════════════════════════════════════════════════════════════════

def _session_hunt_tp(i):
    src = _host(); n_hosts = random.randint(10, 100)
    p = {
        "src": src, "hosts_queried": n_hosts,
        "api_seq": ["OpenRemoteRegistry(hostname)",
                    "RegOpenKeyEx(HKEY_USERS)",
                    "RegEnumKeyEx (enumerate SIDs)",
                    "LookupAccountSid (SID to username)"],
        "sessions_found": random.randint(5, 50),
        "high_value_found": random.sample(["DA-jsmith","IT-admin","svc-sql"], k=random.randint(1,3)),
        "remreg_started_by_attacker": i%2==0,
    }
    prompt = (f"Windows Sysmon -- Remote Registry Session Enumeration.\n"
              f"Source: {p['src']}\n"
              f"  hosts_queried={p['hosts_queried']}\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  active_sessions_found={p['sessions_found']}\n"
              f"  high_value_users_found: {', '.join(p['high_value_found'])}\n"
              + (f"  RemoteRegistry_service_started_on_targets=YES\n" if p['remreg_started_by_attacker'] else ""))
    cot = _cot(
        "SCCM and monitoring agents enumerate sessions but do so from dedicated service "
        "accounts against a bounded host list on scheduled cycles. "
        f"Iterating through {p['hosts_queried']} hosts via HKEY_USERS to find high-value "
        "sessions is session-hunting for lateral movement targeting.",
        f"OpenRemoteRegistry + HKEY_USERS + EnumKeyEx: "
        "enumerating all logged-in users by reading their profile registry hive keys. "
        f"LookupAccountSid: resolving each SID to username. "
        f"High-value targets found: {', '.join(p['high_value_found'])} -- "
        "attacker identifying which hosts to pivot to. "
        + (f"RemoteRegistry service started: attacker enabled the service to gain access. " if p['remreg_started_by_attacker'] else ""),
        f"Source {p['src']}: active sessions mapped across {p['hosts_queried']} hosts. "
        f"High-value targets ({', '.join(p['high_value_found'])}) identified for lateral movement.",
        "Remote registry session enumeration confirmed.",
        "MITRE T1049 (System Network Connections Discovery) + T1087. "
        "Disable RemoteRegistry where not needed, isolate source.",
    )
    return prompt, cot, "true_positive"

def _session_hunt_fp(i):
    p = {"sa": "svc-sccm", "hosts": 5, "purpose": "session-based software deployment check"}
    prompt = (f"Sysmon -- SCCM Session Check.\n"
              f"  account={p['sa']}  hosts={p['hosts']}\n"
              f"  purpose={p['purpose']}  cmdb_registered=YES")
    cot = _cot(
        "SCCM service account checking sessions on 5 managed hosts -- bounded, service account.",
        f"svc-sccm. hosts=5. CMDB registered. Deployment context.",
        "Authorized SCCM session check. No action.",
        "Authorized SCCM. No action.",
        "T1049 -- AUTHORIZED SCCM. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. DCSyncHashExtract (secretsdump, DCSync-To-Hashcat)
#     Evidence: DRS replication protocol from non-DC source,
#               GetNCChanges RPC call (MS-DRSR), Event 4662 on DC
# ═══════════════════════════════════════════════════════════════════════════════

def _dcsync_tp(i):
    dc = _dc(); src = _ip_int()
    p = {
        "src": src, "dc": dc,
        "rpc_call": "IDL_DRSGetNCChanges (MS-DRSR opnum 3)",
        "src_is_dc": False,
        "hashes_extracted": random.randint(500, 50000),
        "includes_krbtgt": True,
        "event_4662": True,
        "auth": random.choice(["Domain Admin creds","Pass-the-Hash","Pass-the-Ticket"]),
    }
    prompt = (f"Network Tap + Sysmon -- DCSync Hash Extraction.\n"
              f"Source: {p['src']} (NOT a DC) → DC {p['dc']}\n"
              f"  rpc_call={p['rpc_call']}\n"
              f"  source_is_domain_controller={p['src_is_dc']}\n"
              f"  hashes_extracted={p['hashes_extracted']:,}\n"
              f"  krbtgt_hash_extracted=YES\n"
              f"  authentication_used={p['auth']}\n"
              f"  event_4662_ds_access_on_dc=YES")
    cot = _cot(
        "DC-to-DC replication via DRS is a normal domain operation. "
        f"However, source {p['src']} is NOT a domain controller -- "
        "non-DC hosts have no legitimate reason to call IDL_DRSGetNCChanges.",
        f"IDL_DRSGetNCChanges (MS-DRSR opnum 3) from non-DC: "
        "definitional DCSync attack. "
        f"{p['hashes_extracted']:,} NTLM hashes extracted including krbtgt. "
        f"Auth={p['auth']}: attacker obtained replication privileges via {p['auth'].lower()}. "
        "Event 4662 on DC: 'DS-Replication-Get-Changes' right exercised.",
        f"Source {p['src']}: ALL domain account NTLM hashes extracted including krbtgt. "
        "Golden ticket and pass-the-hash for every account in the domain is now possible.",
        "DCSync hash extraction confirmed -- complete domain credential compromise.",
        "MITRE T1003.006 (OS Credential Dumping: DCSync). "
        "Full incident response: rotate krbtgt (twice), all domain accounts, review Golden Ticket usage.",
    )
    return prompt, cot, "true_positive"

def _dcsync_fp(i):
    p = {"src_dc": f"DC2.corp.local", "dest_dc": _dc(), "type": "AD replication"}
    prompt = (f"Network Tap -- DC Replication.\n"
              f"  source={p['src_dc']} (IS a DC)\n"
              f"  dest={p['dest_dc']}  type={p['type']}\n"
              f"  both_in_dc_group=YES")
    cot = _cot(
        "Normal DC-to-DC replication -- both hosts are domain controllers.",
        f"source=DC2.corp.local (registered DC). Normal AD replication.",
        "Authorized DC replication. No action.",
        "Authorized DC replication. No action.",
        "T1003.006 -- AUTHORIZED DC REPLICATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. UnderlayCopyNTDS (underlay_copy)
#     Evidence: Raw volume reads (\\.\PhysicalDriveN or \\.\C:),
#               MFT parsing, locked file extraction without VSS
# ═══════════════════════════════════════════════════════════════════════════════

def _underlay_tp(i):
    dc = _dc(); actor = random.choice(["cmd.exe","powershell.exe","unknown.exe"])
    p = {
        "dc": dc, "actor": actor,
        "method": random.choice(["MFT_mode (raw volume read)", "Metadata_mode (sector copy)"]),
        "targets": random.sample([r"C:\Windows\NTDS\ntds.dit",
                                   r"C:\Windows\System32\config\SAM",
                                   r"C:\Windows\System32\config\SYSTEM",
                                   r"C:\Windows\System32\config\SECURITY"], k=random.randint(2,4)),
        "raw_device": random.choice([r"\\.\PhysicalDrive0", r"\\.\C:"]),
        "no_vss": True,
    }
    prompt = (f"Windows Sysmon -- Raw NTFS NTDS.dit Extraction.\n"
              f"DC: {p['dc']}  Actor: {p['actor']}\n"
              f"  method: {p['method']}\n"
              f"  raw_device: {p['raw_device']}\n"
              f"  targets_extracted: {', '.join([t.split('\\')[-1] for t in p['targets']])}\n"
              f"  volume_shadow_copy_used=NO\n"
              f"  files_locked_but_copied=YES")
    cot = _cot(
        "VSS shadow copies are the standard method for copying locked NTDS.dit in authorized "
        "backup scenarios. Accessing the raw volume device (\\\\.\\ path) to bypass file locks "
        "via MFT parsing has no backup tool analog.",
        f"Raw device access {p['raw_device']}: direct sector-level read bypassing Windows I/O stack. "
        f"MFT parsing: locates file extents without requiring unlocked file handles. "
        f"No VSS: bypasses the standard locked-file copy mechanism -- deliberately avoids "
        f"VSS creation events that would appear in logs. "
        f"Targets: {', '.join([t.split(chr(92))[-1] for t in p['targets']])} = "
        "credential store files (NT hashes, domain hashes, LSA secrets).",
        f"DC {p['dc']}: NTDS.dit and associated hive files extracted via raw volume read. "
        "All domain account NTLM hashes are now offline and crackable.",
        "Raw NTFS credential file extraction confirmed.",
        "MITRE T1003.003 (OS Credential Dumping: NTDS). "
        "Full incident response: DCSync equivalent -- rotate all domain credentials.",
    )
    return prompt, cot, "true_positive"

def _underlay_fp(i):
    p = {"tool": "Veeam Agent", "method": "VSS (Volume Shadow Copy)", "ticket": f"BAK-{random.randint(100,999)}"}
    prompt = (f"Windows Sysmon -- Backup of Domain Controller.\n"
              f"  tool={p['tool']}  method={p['method']}\n"
              f"  ticket={p['ticket']}  raw_device_access=NO")
    cot = _cot(
        "Veeam Agent backup via VSS -- standard mechanism, no raw device access.",
        f"VSS method. No raw device. Ticket {p['ticket']}.",
        "Authorized DC backup via VSS. No action.",
        "Authorized DC backup. No action.",
        "T1003.003 -- AUTHORIZED BACKUP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. NRPCUnauthEnum (nauth_nrpc -- Netlogon without credentials)
#     Evidence: MS-NRPC calls at auth-level=1 (no authentication),
#               NetrGetDCName / DsrGetDcName without credentials,
#               user/computer lookup bypassing LDAP auth requirement
# ═══════════════════════════════════════════════════════════════════════════════

def _nrpc_tp(i):
    dc = _dc(); src = _ip_int()
    p = {
        "src": src, "dc": dc,
        "auth_level": 1,
        "calls": random.sample(["NetrGetDCName","DsrGetDcName","NetrServerAuthenticate",
                                 "DsrEnumerateDomainTrusts","NetrGetAnyDCName"], k=random.randint(3,5)),
        "no_credentials": True,
        "users_enumerated": random.randint(10, 500),
    }
    prompt = (f"Network Tap -- NRPC Unauthenticated Enumeration.\n"
              f"Source: {p['src']} → DC {p['dc']}\n"
              f"  authentication_level={p['auth_level']} (none)\n"
              f"  netlogon_calls: {', '.join(p['calls'])}\n"
              f"  credentials_provided=NO\n"
              f"  objects_enumerated={p['users_enumerated']}")
    cot = _cot(
        "Netlogon is used for domain join, secure channel, and DC location. These operations "
        "require domain authentication (auth-level >= 2). Auth-level=1 (no authentication) "
        "while still receiving data is an exploitation/reconnaissance pattern.",
        f"NRPC auth_level=1: Netlogon accepting unauthenticated enumeration calls. "
        f"Calls {', '.join(p['calls'][:3])}: DC discovery + trust enumeration + user lookup "
        "without any credentials. "
        f"{p['users_enumerated']} objects enumerated: LDAP-equivalent data without LDAP credentials. "
        "Source is external network: no domain membership required.",
        f"Source {p['src']}: DC topology, trust relationships, and user accounts enumerated "
        "without any domain credentials via unauthenticated NRPC.",
        "NRPC unauthenticated enumeration confirmed.",
        "MITRE T1087 (Account Discovery via NRPC). "
        "Block unauthenticated NRPC from external sources, apply NRPC hardening GPO.",
    )
    return prompt, cot, "true_positive"

def _nrpc_fp(i):
    p = {"host": "workstation.corp.local", "call": "DsrGetDcName", "context": "domain join"}
    prompt = (f"Network Tap -- NRPC Domain Join.\n"
              f"  host={p['host']}  call={p['call']}\n"
              f"  auth_level=6 (encrypted)  context={p['context']}")
    cot = _cot(
        "Workstation domain join via authenticated NRPC -- auth-level=6, encrypted.",
        f"auth_level=6. Domain-joined workstation. Standard NRPC.",
        "Authorized NRPC domain join. No action.",
        "Authorized NRPC. No action.",
        "T1087 -- AUTHORIZED NRPC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 14. KerberosTicketAbuse (Rubeus)
#     Evidence: Kerberos AS-REQ/TGS-REQ anomalies (RC4 downgrade,
#               forged PACs, encrypted ticket relay),
#               raw Kerberos socket from non-lsass process
# ═══════════════════════════════════════════════════════════════════════════════

def _kerberos_tp(i):
    dc = _dc(); src = _ip_int()
    technique = random.choice([
        ("AS-REP roasting", "AS-REQ without pre-auth for accounts with UF_DONT_REQUIRE_PREAUTH", "T1558.004"),
        ("Kerberoasting", "TGS-REQ for service tickets with RC4 (downgrade from AES)", "T1558.003"),
        ("Pass-the-Ticket", "TGT injected into logon session without kerberos ticket re-negotiation", "T1550.003"),
        ("Golden Ticket", "TGT with forged PAC, 10-year validity, from non-DC krbtgt encrypt", "T1558.001"),
    ])
    name, desc, mitre_id = technique
    p = {
        "src": src, "dc": dc, "technique": name,
        "desc": desc, "mitre_id": mitre_id,
        "from_lsass": False,
        "ticket_count": random.randint(1, 50),
        "rc4_downgrade": "Kerberoast" in name or "Golden" in name,
        "pre_auth_missing": "AS-REP" in name,
    }
    prompt = (f"Network Tap + Sysmon -- Kerberos Ticket Abuse ({p['technique']}).\n"
              f"Source: {p['src']} → DC {p['dc']}:88\n"
              f"  technique={p['technique']}\n"
              f"  description: {p['desc']}\n"
              f"  tickets_processed={p['ticket_count']}\n"
              f"  raw_kerberos_from_non_lsass=YES\n"
              + (f"  rc4_encryption_requested=YES (AES-capable DC downgraded)\n" if p['rc4_downgrade'] else "")
              + (f"  preauth_missing_accounts_targeted=YES\n" if p['pre_auth_missing'] else ""))
    cot = _cot(
        "Windows Kerberos authentication is handled by lsass.exe. Raw Kerberos socket "
        "connections from non-lsass processes indicate a Kerberos attack tool.",
        f"Kerberos port 88 from non-lsass process: Rubeus-style direct Kerberos manipulation. "
        f"Technique={p['technique']}: {p['desc']}. "
        + (f"RC4 downgrade: attacker forced weaker encryption for offline cracking. " if p['rc4_downgrade'] else "")
        + (f"No preauth: targeted accounts do not require Kerberos pre-authentication -- "
           "TGT issued without valid password. " if p['pre_auth_missing'] else "")
        + f"{p['ticket_count']} tickets processed.",
        f"Source {p['src']}: Kerberos {p['technique']} active. "
        "Depending on technique: offline cracking possible / direct lateral movement possible.",
        f"Kerberos {p['technique']} confirmed.",
        f"MITRE {p['mitre_id']}. "
        "Enforce AES-only Kerberos, disable DONT_REQUIRE_PREAUTH, monitor raw Kerberos from workstations.",
    )
    return prompt, cot, "true_positive"

def _kerberos_fp(i):
    p = {"proc": "lsass.exe", "type": "TGS-REQ", "acct": "svc-sql", "context": "service ticket renewal"}
    prompt = (f"Sysmon -- Kerberos Service Ticket.\n"
              f"  process={p['proc']}  request_type={p['type']}\n"
              f"  account={p['acct']}  context={p['context']}\n"
              f"  aes256_encryption=YES  preauth_present=YES")
    cot = _cot(
        "lsass.exe service ticket renewal -- AES256, preauth present, normal operation.",
        f"lsass.exe. AES256. Preauth present. Service ticket renewal.",
        "Authorized Kerberos service ticket. No action.",
        "Authorized Kerberos. No action.",
        "T1558 -- AUTHORIZED KERBEROS. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 15. TargetedKerberoast (targetedKerberoast + ACL)
#     Evidence: LDAP write of servicePrincipalName on account without SPN,
#               TGS-REQ for newly-added SPN, LDAP cleanup of SPN afterward
# ═══════════════════════════════════════════════════════════════════════════════

def _tkerberoast_tp(i):
    dc = _dc(); src = _ip_int()
    target = f"svc-{random.choice(['hr','finance','it','ops'])}"
    spn = f"http/{_host()}.corp.local"
    p = {
        "src": src, "dc": dc, "target": target, "spn": spn,
        "api_seq": [
            f"LDAP write: servicePrincipalName={spn} on {target}",
            f"Kerberos TGS-REQ for {spn} (RC4 encrypted)",
            f"LDAP delete: servicePrincipalName cleared (cleanup)",
        ],
        "acl_abuse": True,
    }
    prompt = (f"Network Tap + Sysmon -- Targeted Kerberoasting via ACL SPN Write.\n"
              f"Source: {p['src']} → DC {p['dc']}\n"
              f"  target_account={p['target']}\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  acl_write_then_cleanup=YES (anti-forensic)\n"
              f"  required_right=WriteSPN or GenericWrite on target")
    cot = _cot(
        "SPN modifications are performed by service account administrators to "
        "register services. Temporary SPN addition on a non-service account "
        "followed immediately by a service ticket request and SPN removal is not administration.",
        f"Three-step sequence: LDAP write SPN → Kerberos TGS-REQ → LDAP delete SPN. "
        f"SPN write on {p['target']} (non-service account): abusing WriteSPN/GenericWrite ACE. "
        f"TGS-REQ with RC4: forcing weak encryption for offline hash cracking. "
        "SPN cleanup: anti-forensic removal to hide the attack.",
        f"Account {p['target']} service ticket captured via temporary SPN. "
        "RC4-encrypted TGS available for offline cracking.",
        "Targeted Kerberoasting via ACL-based SPN write confirmed.",
        "MITRE T1558.003 (Kerberoasting) + T1098 (Account Manipulation). "
        "Monitor SPN write+TGS+SPN-delete sequences, fix WriteSPN ACEs.",
    )
    return prompt, cot, "true_positive"

def _tkerberoast_fp(i):
    p = {"admin": "svc-admin", "spn": "HTTP/webapp.corp.local", "account": "svc-webapp"}
    prompt = (f"Sysmon -- SPN Registration.\n"
              f"  admin={p['admin']}  spn={p['spn']}\n"
              f"  account={p['account']}  persisted=YES\n"
              f"  immediate_tgs_request=NO")
    cot = _cot(
        "Admin registering SPN for web application -- persisted, no immediate TGS.",
        f"SPN persisted. No TGS-REQ immediately after. Service admin context.",
        "Authorized SPN registration. No action.",
        "Authorized SPN. No action.",
        "T1558.003 -- AUTHORIZED SPN REG. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 16. ShadowCredentialWrite (pywhisker, KeyCredentialLink)
#     Evidence: LDAP write to msDS-KeyCredentialLink on target account,
#               PKINIT Kerberos AS-REQ using newly-added certificate,
#               certificate generated by attacker, not issued by CA
# ═══════════════════════════════════════════════════════════════════════════════

def _shadow_cred_tp(i):
    dc = _dc(); src = _ip_int()
    target = random.choice(["Administrator","DA-jsmith","svc-sql","WS-42$"])
    p = {
        "src": src, "dc": dc, "target": target,
        "ldap_attr": "msDS-KeyCredentialLink",
        "cert_self_generated": True,
        "pkinit_asreq": True,
        "ntlm_hash_obtained": True,
        "requires_dc_2016": True,
    }
    prompt = (f"Sysmon -- Shadow Credentials Attack.\n"
              f"Source: {p['src']} → DC {p['dc']}\n"
              f"  ldap_write: {p['ldap_attr']} on {p['target']}\n"
              f"  certificate_self_generated=YES (not CA-issued)\n"
              f"  pkinit_asreq_with_new_cert=YES\n"
              f"  ntlm_hash_via_unpac=YES\n"
              f"  requires_write_on_{p['target']}=YES")
    cot = _cot(
        "Windows Hello for Business and Smart Card enrollment write to msDS-KeyCredentialLink, "
        "but these use certificates issued by the enterprise CA with known keys. "
        "A self-generated certificate written from a workstation is not a WHfB enrollment.",
        f"LDAP write to msDS-KeyCredentialLink on {p['target']}: "
        "adding attacker-controlled certificate as authentication credential. "
        "Self-generated cert: not CA-issued, no PKI enrollment record. "
        "PKINIT AS-REQ with new cert: DC authenticates shadow credential. "
        "UnPAC-the-Hash: NTLM hash extracted from TGT. "
        "Full account takeover without password.",
        f"Account {p['target']}: shadow credential added. "
        "Attacker can authenticate as this account indefinitely even after password change.",
        "Shadow credential attack confirmed.",
        "MITRE T1556.006 (Modify Authentication Process: msDS-KeyCredentialLink). "
        "Remove malicious msDS-KeyCredentialLink entry, revoke sessions, monitor PKINIT.",
    )
    return prompt, cot, "true_positive"

def _shadow_cred_fp(i):
    p = {"device": "WS-42.corp.local", "reason": "Windows Hello for Business enrollment",
         "cert_issuer": "corp-pki-ca"}
    prompt = (f"Sysmon -- WHfB msDS-KeyCredentialLink Write.\n"
              f"  device={p['device']}  reason={p['reason']}\n"
              f"  cert_issuer={p['cert_issuer']}  gp_triggered=YES")
    cot = _cot(
        "Windows Hello for Business enrollment -- corp PKI cert, GPO triggered.",
        f"cert_issuer={p['cert_issuer']} (CA-issued). GPO triggered. Known device.",
        "Authorized WHfB enrollment. No action.",
        "Authorized WHfB. No action.",
        "T1556.006 -- AUTHORIZED WHFB. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. DCShadowReplication
#     Evidence: Rogue DC registered via Netlogon on non-DC host,
#               AD replication events from unexpected source,
#               attribute modifications replicated silently to real DCs
# ═══════════════════════════════════════════════════════════════════════════════

def _dcshadow_tp(i):
    src = _ip_int(); dc = _dc()
    p = {
        "src": src, "dc": dc,
        "rogue_dc_name": f"ATTACKER-DC-{random.randint(10,99)}",
        "netlogon_registration": True,
        "attrs_modified": random.sample(
            ["primaryGroupID (DA)","adminCount","SIDHistory","member (Group)","userAccountControl","nTSecurityDescriptor"],
            k=random.randint(2,4)),
        "event_4742_4728": True,
        "replication_in_progress_ms": random.randint(5000, 30000),
    }
    prompt = (f"Sysmon -- DCShadow Rogue DC Replication.\n"
              f"Source: {p['src']} (NOT a DC)\n"
              f"  rogue_dc_registered: {p['rogue_dc_name']}\n"
              f"  netlogon_dc_registration=YES\n"
              f"  attributes_modified_via_replication: {', '.join(p['attrs_modified'])}\n"
              f"  event_4742_computer_change=YES  event_4728_group_member=YES\n"
              f"  replication_window_ms={p['replication_in_progress_ms']}")
    cot = _cot(
        "Domain controller registration happens only when promoting a Windows Server to DC role "
        "via dcpromo/ADDS. A workstation registering as a DC via Netlogon for a brief window "
        "to push attribute changes is a DCShadow attack.",
        f"Non-DC {p['src']} registered {p['rogue_dc_name']} via Netlogon: "
        "impersonating a DC for the replication window. "
        f"Attributes modified: {', '.join(p['attrs_modified'])}: "
        "privilege escalation via AD object manipulation. "
        f"Replication window {p['replication_in_progress_ms']/1000:.0f}s: "
        "changes replicated to {p['dc']} before attacker deregisters. "
        "Changes appear as normal AD replication in logs -- very stealthy.",
        f"AD attributes modified via DCShadow: {', '.join(p['attrs_modified'][:2])}. "
        "Changes are indistinguishable from legitimate admin operations in standard logs.",
        "DCShadow AD replication attack confirmed.",
        "MITRE T1207 (Rogue Domain Controller). "
        "Monitor non-DC Netlogon registrations, audit attribute changes for DCShadow IOCs.",
    )
    return prompt, cot, "true_positive"

def _dcshadow_fp(i):
    p = {"host": "DC2.corp.local", "type": "normal AD replication"}
    prompt = (f"Sysmon -- AD Replication.\n"
              f"  source={p['host']} (registered DC)\n"
              f"  type={p['type']}  both_in_dc_group=YES")
    cot = _cot(
        "Normal DC-to-DC replication from registered domain controller.",
        f"Registered DC. Normal replication.",
        "Authorized AD replication. No action.",
        "Authorized replication. No action.",
        "T1207 -- AUTHORIZED DC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. GPOBackdoor (GroupPolicyBackdoor, pyGPOAbuse, gpo-backdoor)
#     Evidence: GPO creation/modification + malicious scheduled task XML in SYSVOL,
#               optional targeting filters (WMI/hostname/group)
# ═══════════════════════════════════════════════════════════════════════════════

def _gpo_backdoor_tp(i):
    dc = _dc(); src = _ip_int()
    gpo = _guid()
    p = {
        "src": src, "dc": dc, "gpo_guid": gpo,
        "ldap_modified": ["gPCMachineExtensionNames","gPCFileSysPath"],
        "task_cmd": random.choice(
            ["powershell.exe -enc JABhAGI=",
             "net user backdoor P@ss1 /add && net localgroup Administrators backdoor /add",
             f"C:\\Windows\\Temp\\{random.randint(100,999)}.exe"]),
        "filter_type": random.choice(["ALL_domain_computers","WMI_filter","specific_group"]),
        "scope": random.randint(10, 1000),
    }
    prompt = (f"Sysmon -- GPO Backdoor / Persistence.\n"
              f"Source: {p['src']} → DC {p['dc']}\n"
              f"  gpo_guid={p['gpo_guid']}\n"
              f"  ldap_attrs_modified: {', '.join(p['ldap_modified'])}\n"
              f"  malicious_task_xml_in_sysvol=YES\n"
              f"  task_command: {p['task_cmd'][:60]}\n"
              f"  scope_filter={p['filter_type']}\n"
              f"  objects_affected_estimate={p['scope']}")
    cot = _cot(
        "Authorized GPO changes use GPMC with dedicated service accounts and change tickets. "
        "SYSVOL task injection contains commands (PowerShell -enc / net user / temp binary) "
        "that no legitimate scheduled task would contain.",
        f"LDAP modified {', '.join(p['ldap_modified'])}: "
        "GPO pointing to attacker-controlled template. "
        f"Task XML in SYSVOL: '{p['task_cmd'][:50]}' -- "
        "clearly malicious command in task definition. "
        f"Scope={p['filter_type']}, {p['scope']} objects: "
        "widespread persistence established.",
        f"GPO backdoor active -- {p['scope']} computers will execute '{p['task_cmd'][:40]}' "
        "at next Group Policy refresh.",
        "GPO backdoor persistence confirmed.",
        "MITRE T1484.001 (Group Policy Modification). "
        "Remove malicious task XML from SYSVOL, revert GPO attributes, audit affected computers.",
    )
    return prompt, cot, "true_positive"

def _gpo_backdoor_fp(i):
    p = {"admin": "svc-gpo", "task": "weekly_patch_scan", "ticket": f"CHG-{random.randint(10000,99999)}"}
    prompt = (f"Sysmon -- GPO Scheduled Task.\n"
              f"  admin={p['admin']}  task_name={p['task']}\n"
              f"  ticket={p['ticket']}  cmd=nessus-agent.exe --scan")
    cot = _cot(
        "IT task via GPMC -- descriptive name, vendor binary, change ticket.",
        f"Descriptive task. Vendor binary. Ticket {p['ticket']}.",
        "Authorized GPO task. No action.",
        "Authorized GPO task. No action.",
        "T1484.001 -- AUTHORIZED GPO TASK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. DACLPrivEsc (PowerDACL)
#     Evidence: LDAP write to nTSecurityDescriptor (ACE modification),
#               granting DCSync/GenericAll/WriteDACL to attacker account
# ═══════════════════════════════════════════════════════════════════════════════

def _dacl_priv_tp(i):
    src = _ip_int(); dc = _dc()
    right = random.choice(["DCSync (DS-Replication-Get-Changes-All)","GenericAll","WriteDACL","WriteOwner"])
    target_obj = random.choice(["domain root","DC Computer object","Domain Admins group","Administrator account"])
    p = {
        "src": src, "dc": dc, "right": right, "target": target_obj,
        "src_account": f"{_user()}@{_domain().lower()}.local",
        "event_4662": True,
        "cleanup_after": i%2==0,
    }
    prompt = (f"Sysmon -- DACL Privilege Escalation (ACE Write).\n"
              f"Source: {p['src']}\n"
              f"  ldap_write: nTSecurityDescriptor on {p['target']}\n"
              f"  ace_granted: {p['right']}\n"
              f"  granted_to: {p['src_account']}\n"
              f"  event_4662_ds_access_audited=YES\n"
              + (f"  ace_removed_after=YES (anti-forensic cleanup)\n" if p['cleanup_after'] else ""))
    cot = _cot(
        "Domain admins legitimately modify DACLs for delegated administration, but this is "
        "documented in change management and targets specific OUs/accounts for limited access. "
        f"Granting {p['right']} on {p['target']} to a standard user account has no authorized purpose.",
        f"nTSecurityDescriptor write on {p['target']}: ACL modification. "
        f"ACE grants {p['right']} to {p['src_account']}: "
        "either replication rights or full control. "
        f"Event 4662 (Auditing): 'Write Property' on {p['target']}. "
        + (f"ACE removed after: anti-forensic cleanup -- attacker exploited then erased the path. " if p['cleanup_after'] else ""),
        f"Account {p['src_account']} now has {p['right']} on {p['target']}. "
        "This enables direct privilege escalation to Domain Admin.",
        f"DACL privilege escalation ({p['right']}) confirmed.",
        "MITRE T1222 (File/Directory Permissions Modification) + T1098. "
        "Revert ACE, investigate what attacker did with elevated rights.",
    )
    return prompt, cot, "true_positive"

def _dacl_priv_fp(i):
    p = {"admin": "domain admin", "right": "Read (limited)", "target": "OU=Helpdesk",
         "ticket": f"IT-{random.randint(100,999)}"}
    prompt = (f"Sysmon -- DACL Delegation.\n"
              f"  admin={p['admin']}  right={p['right']}\n"
              f"  target={p['target']}  ticket={p['ticket']}\n"
              f"  limited_delegation=YES")
    cot = _cot(
        "Domain admin delegating read access to helpdesk OU -- limited right, change ticket.",
        f"Limited right. Specific OU. Ticket {p['ticket']}.",
        "Authorized DACL delegation. No action.",
        "Authorized DACL. No action.",
        "T1222 -- AUTHORIZED DELEGATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 20. BadSuccessorDMSA (badSuccessor)
#     Evidence: Computer object creation in OU with CreateChild permission,
#               dMSA (Delegated Managed Service Account) instantiation,
#               Kerberos impersonation of any domain account via dMSA
# ═══════════════════════════════════════════════════════════════════════════════

def _badsuccessor_tp(i):
    dc = _dc(); src = _ip_int()
    target_account = random.choice(["krbtgt","Administrator","Domain Admin"])
    p = {
        "src": src, "dc": dc, "target": target_account,
        "api_seq": [
            "LDAP write: Create computer object in OU (CreateChild right)",
            "LDAP write: msDS-ManagedAccountPrecededBy = target account",
            "Kerberos S4U2self + S4U2proxy via dMSA",
            "Service ticket for any resource as impersonated account",
        ],
        "low_priv_required": True,
        "requires_dc_2025": True,
    }
    prompt = (f"Sysmon -- badSuccessor dMSA Privilege Escalation.\n"
              f"Source: {p['src']} → DC {p['dc']}\n"
              f"  step_1: computer_object_created (only CreateChild required)\n"
              f"  step_2: msDS-ManagedAccountPrecededBy = {p['target']}\n"
              f"  step_3: Kerberos S4U2self+S4U2proxy via dMSA\n"
              f"  target_impersonated={p['target']}\n"
              f"  low_privilege_required=YES\n"
              f"  dc_2025_required=YES")
    cot = _cot(
        "CreateChild on an OU is a common delegation for service desk (creating computer "
        "accounts for domain join). Setting msDS-ManagedAccountPrecededBy on a newly created "
        "computer to target a privileged account is not domain-join behavior.",
        f"Computer object created with CreateChild: legitimate delegation right. "
        f"msDS-ManagedAccountPrecededBy={p['target']}: attacker weaponizes dMSA mechanism. "
        "S4U2self+S4U2proxy via dMSA: Kerberos protocol allows obtaining tickets "
        f"impersonating {p['target']} for any service. "
        "Low privilege + domain elevation: critical badSuccessor attack path.",
        f"Source {p['src']}: obtained tickets impersonating {p['target']} "
        "via dMSA chain. Privilege escalation from CreateChild to full domain admin.",
        "badSuccessor dMSA privilege escalation confirmed.",
        "MITRE T1134 (Access Token Manipulation via Kerberos delegation). "
        "Remove created computer object, audit OU CreateChild delegation, patch DC 2025.",
    )
    return prompt, cot, "true_positive"

def _badsuccessor_fp(i):
    p = {"sa": "svc-it", "ou": "OU=Workstations", "purpose": "domain join delegation"}
    prompt = (f"Sysmon -- Computer Object Creation.\n"
              f"  account={p['sa']}  ou={p['ou']}\n"
              f"  purpose={p['purpose']}\n"
              f"  msDS-ManagedAccountPrecededBy_set=NO")
    cot = _cot(
        "IT service account creating computer for domain join -- no dMSA attribute set.",
        f"No msDS-ManagedAccountPrecededBy. Domain join purpose. IT account.",
        "Authorized domain join computer creation. No action.",
        "Authorized computer creation. No action.",
        "T1134 -- AUTHORIZED DOMAIN JOIN. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Registry + S3 Queries + Main
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_CLASSES = {
    "ADPasswordSprayLDAP":       ("network_tap",   ["T1110.003"],              _adps_tp,       _adps_fp),
    "ADCSCertAbuse":             ("network_tap",   ["T1649","T1558.003"],      _adcs_tp,       _adcs_fp),
    "NTLMPoisoningRelay":        ("network_tap",   ["T1557.001","T1040"],      _responder_tp,  _responder_fp),
    "TimeroastNTPHash":          ("network_tap",   ["T1558","T1110"],          _timeroast_tp,  _timeroast_fp),
    "GPORelayInjection":         ("network_tap",   ["T1484.001","T1557.001"],  _gpo_relay_tp,  _gpo_relay_fp),
    "ADWSSOAPEnum":              ("network_tap",   ["T1098"],                  _adws_tp,       _adws_fp),
    "LDAPDomainDump":            ("network_tap",   ["T1087.002","T1069.002"],  _ldap_dump_tp,  _ldap_dump_fp),
    "DACLACEEnumeration":        ("network_tap",   ["T1069","T1087"],          _dacl_tp,       _dacl_fp),
    "BloodHoundCollection":      ("network_tap",   ["T1087","T1069","T1482"],  _bh_tp,         _bh_fp),
    "RemoteRegistrySessionEnum": ("sysmon_sensor", ["T1049","T1087"],          _session_hunt_tp,_session_hunt_fp),
    "DCSyncHashExtract":         ("network_tap",   ["T1003.006"],              _dcsync_tp,     _dcsync_fp),
    "UnderlayCopyNTDS":          ("sysmon_sensor", ["T1003.003"],              _underlay_tp,   _underlay_fp),
    "NRPCUnauthEnum":            ("network_tap",   ["T1087"],                  _nrpc_tp,       _nrpc_fp),
    "KerberosTicketAbuse":       ("network_tap",   ["T1558","T1550.003"],      _kerberos_tp,   _kerberos_fp),
    "TargetedKerberoast":        ("sysmon_sensor", ["T1558.003","T1098"],      _tkerberoast_tp,_tkerberoast_fp),
    "ShadowCredentialWrite":     ("sysmon_sensor", ["T1556.006"],              _shadow_cred_tp,_shadow_cred_fp),
    "DCShadowReplication":       ("network_tap",   ["T1207"],                  _dcshadow_tp,   _dcshadow_fp),
    "GPOBackdoor":               ("sysmon_sensor", ["T1484.001"],              _gpo_backdoor_tp,_gpo_backdoor_fp),
    "DACLPrivEsc":               ("sysmon_sensor", ["T1222","T1098"],          _dacl_priv_tp,  _dacl_priv_fp),
    "BadSuccessorDMSA":          ("sysmon_sensor", ["T1134"],                  _badsuccessor_tp,_badsuccessor_fp),
}

S3_QUERIES = {
    "ADPasswordSprayLDAP":   {"sensor":"network_tap","where":"dst_port = 389 AND protocol_name = 'LDAP' GROUP BY src_ip HAVING COUNT(DISTINCT query_name) > 20 AND COUNT(*) > 50"},
    "NTLMPoisoningRelay":    {"sensor":"network_tap","where":"dst_port IN (5355,137,5353) AND is_internal_dst = true AND packets_src > 1"},
    "TimeroastNTPHash":      {"sensor":"network_tap","where":"dst_port = 123 AND protocol_name = 'UDP' AND variance_inter_arrival < 0.10 "},
    "LDAPDomainDump":        {"sensor":"network_tap","where":"dst_port IN (389,636) AND session_duration_ms > 5000 GROUP BY src_ip,dst_ip HAVING COUNT(*) > 20"},
    "DCSyncHashExtract":     {"sensor":"network_tap","where":"dst_port IN (135,445) AND is_internal_dst = true AND protocol_name = 'DCE/RPC'"},
    "KerberosTicketAbuse":   {"sensor":"network_tap","where":"dst_port = 88 AND is_internal_dst = true GROUP BY src_ip HAVING COUNT(*) > 5"},
    "TargetedKerberoast":    {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%servicePrincipalName%' AND Image NOT LIKE '%system32%'"},
    "ShadowCredentialWrite": {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%msDS-KeyCredentialLink%'"},
    "GPOBackdoor":           {"sensor":"sysmon_sensor","where":"sysmon_event_id = 11 AND TargetFilename LIKE '%SYSVOL%ScheduledTasks%'"},
    "DACLPrivEsc":           {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%nTSecurityDescriptor%'"},
    "ADCSCertAbuse":         {"sensor":"network_tap","where":"dst_port IN (389,443) AND is_internal_dst = true AND avg_inter_arrival < 5.0 AND variance_inter_arrival < 0.20"},
    "GPORelayInjection":     {"sensor":"network_tap","where":"dst_port = 445 AND is_internal_dst = true AND variance_inter_arrival < 0.10 AND avg_inter_arrival < 2.0"},
    "ADWSSOAPEnum":          {"sensor":"network_tap","where":"dst_port = 9389 AND is_internal_dst = true"},
    "DACLACEEnumeration":    {"sensor":"network_tap","where":"dst_port IN (389,636) AND is_internal_dst = true AND variance_inter_arrival < 0.15 AND avg_inter_arrival < 1.0"},
    "BloodHoundCollection":  {"sensor":"network_tap","where":"dst_port IN (389,636,445,88) AND is_internal_dst = true AND variance_inter_arrival < 0.15 AND avg_inter_arrival < 2.0"},
    "RemoteRegistrySessionEnum": {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%HKEY_USERS%' AND Image NOT LIKE '%svchost%' AND Image NOT LIKE 'C:\\\\Windows\\\\System32%'"},
    "UnderlayCopyNTDS":      {"sensor":"sysmon_sensor","where":"sysmon_event_id = 11 AND (TargetFilename LIKE '%ntds.dit%' OR TargetFilename LIKE '%NTDS%') AND Image NOT LIKE '%Veeam%' AND Image NOT LIKE '%wbengine%'"},
    "NRPCUnauthEnum":        {"sensor":"network_tap","where":"dst_port = 135 AND is_internal_dst = true AND variance_inter_arrival < 0.15 AND avg_inter_arrival < 3.0"},
    "DCShadowReplication":   {"sensor":"network_tap","where":"dst_port IN (135,389,445) AND is_internal_dst = true AND variance_inter_arrival < 0.10 AND avg_inter_arrival < 5.0"},
    "BadSuccessorDMSA":      {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%msDS-ManagedAccountPrecededBy%'"},
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