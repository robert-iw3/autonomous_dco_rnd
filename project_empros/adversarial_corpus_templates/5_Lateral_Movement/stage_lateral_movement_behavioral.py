"""
stage_lateral_movement_behavioral.py -- Comprehensive Lateral Movement TTP Behavioral Dataset

Detection philosophy: behavioral evidence only -- API sequences, event IDs, network
patterns, process parent-child anomalies. No tool names in detection logic.
Every class has admin FP variants.

Output:
  data/staging/lateral_movement_behavioral_v1.jsonl
  data/staging/lateral_movement_query_index.json

Usage:
    python stage_lateral_movement_behavioral.py
    python stage_lateral_movement_behavioral.py --records-per-class 15
    python stage_lateral_movement_behavioral.py --tool-filter SCMServiceHijack,WMILateralExec
"""

import json
import random
import argparse
import logging
import hashlib
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stage-lateral")
random.seed(23)

OUTPUT_DIR  = Path("../data/staging")
OUTPUT_FILE = OUTPUT_DIR / "lateral_movement_behavioral_v1.jsonl"
INDEX_FILE  = OUTPUT_DIR / "lateral_movement_query_index.json"

TTP_CAT = "LateralMovement"

SYS = {
    "sysmon_sensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 6D windows_math. Source: Sysmon event stream. "
        "Schema: sysmon_event_id, Image, CommandLine, ParentImage, User, IntegrityLevel, "
        "TargetImage, GrantedAccess, TargetObject, Details, EventType_reg, ImageLoaded, "
        "Signed, PipeName, QueryName, TargetFilename, TamperingType. "
        "Identify lateral movement tradecraft. Output MITRE ATT&CK + containment."
    ),
    "windows_deepsensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 4D deepsensor_math. Source: DeepXDR EdrRow (UEBA). "
        "Schema: Image, CommandLine, destination_ip, pid, ppid, score, avg_entropy, max_velocity. "
        "Identify lateral movement tradecraft. Output MITRE ATT&CK + containment."
    ),
    "network_tap": (
        "You are the Network Tap Forensics Expert. Analyze the session window "
        "using pre-computed fields (port_class, JA3, cert metadata, is_internal_dst). "
        "Attribute to MITRE ATT&CK and recommend containment."
    ),
    "linux_sentinel": (
        "You are the Host Forensics Expert. Target OS: Linux/Unix. "
        "Vector Space: 5D sentinel_math. Schema: comm, command_line, uid, dest_ip, syscall. "
        "Identify lateral movement tradecraft. Output MITRE ATT&CK + containment."
    ),
    "azure_entraid": (
        "You are the Cloud Identity Expert. Analyze Azure AD / Entra ID events. "
        "Identify credential-based lateral movement. Output MITRE + containment."
    ),
}

VECTOR = {
    "sysmon_sensor":      "windows_math",
    "windows_deepsensor": "deepsensor_math",
    "network_tap":        "c2_math",
    "linux_sentinel":     "sentinel_math",
    "azure_entraid":      "cloud_flow",
}

def _ip_int():  return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
def _ip_ext():
    p = random.choice(["45.33","104.21","172.67","185.220"])
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"
def _host():    return f"{random.choice(['WS','SRV','DC','APP','SQL'])}-{random.randint(10,99)}"
def _user():    return random.choice(["jsmith","alee","tmorgan","schen","rbrown","lzhang"])
def _svc_name(): return f"Svc{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))}"
def _guid():
    return (f"{random.randint(0x10000000,0xFFFFFFFF):08X}-"
            f"{random.randint(0x1000,0xFFFF):04X}-{random.randint(0x1000,0xFFFF):04X}-"
            f"{random.randint(0x1000,0xFFFF):04X}-{random.randint(0x100000000000,0xFFFFFFFFFFFF):012X}")

def _cot(a1, a2, a3, conclusion, technique, action="contain"):
    verdict = "TRUE POSITIVE" if action == "contain" else "FALSE POSITIVE"
    return (f"<analysis>\n[AXIS 1] Benign Alternative Assessment:\n  {a1}\n"
            f"[AXIS 2] Behavioral Proof Assessment:\n  {a2}\n"
            f"[AXIS 3] Entity Coverage:\n  {a3}\n"
            f"[CONCLUSION] {conclusion}\n</analysis>\n"
            f"{verdict}. {technique}\nRECOMMENDED_ACTION: {action}")

def _record(tool_class, sensor, mitre, msgs, cls, event_id=None):
    import hashlib
    r = {"ttp_category": TTP_CAT, "tool_class": tool_class,
         "mitre_techniques": mitre, "source_type": sensor,
         "vector_name": VECTOR[sensor], "classification": cls,
         "messages": msgs}
    if event_id is not None:
        r["event_id"] = event_id
    elif sensor in ("sysmon_sensor", "windows_deepsensor", "linux_sentinel"):
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
# 1. SCMServiceHijack
#    Evidence: OpenSCManagerA → QueryServiceConfigA → ChangeServiceConfigA →
#              StartServiceA → RestoreServiceConfig (cleanup)
#              Service binary path temporarily replaced with attacker command
#    Sources: SCShell (C, Python), Invoke-SMBRemoting, SharpLateral (redexec)
#    Admin FP: SCCM deploying application service (signed binary, vendor path)
# ═══════════════════════════════════════════════════════════════════════════════

def _scm_tp(i):
    target = _host(); src = _host()
    svc = random.choice(["wuauserv","spooler","Netlogon","W32Time","nsi","lmhosts"])
    payload = random.choice([
        f"cmd.exe /c powershell.exe -enc {random.randint(10000,99999):x}",
        f"C:\\Windows\\Temp\\{random.randint(100,999)}.exe",
        f"cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt",
    ])
    p = {
        "src": src, "target": target, "svc": svc, "payload": payload,
        "api_seq": ["OpenSCManagerA(target, SC_MANAGER_ALL_ACCESS)",
                    f"OpenServiceA({svc})",
                    f"QueryServiceConfigA → saved original binary path",
                    f"ChangeServiceConfigA → binary_path_name='{payload[:40]}'",
                    f"StartServiceA({svc})",
                    "ChangeServiceConfigA → restored original path (cleanup)"],
        "event_7045": i%3==0,  # new service vs modifying existing
        "auth": random.choice(["NTLM","Kerberos","Pass-the-Hash"]),
    }
    prompt = (f"Windows Sysmon -- SCM Service Hijack for Lateral Execution.\n"
              f"Source: {p['src']} → Target: {p['target']}\n"
              f"  Service: {p['svc']}\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  authentication: {p['auth']}\n"
              f"  event_7045_new_service: {p['event_7045']}\n"
              f"  service_path_restored_after_exec=YES (cleanup)")
    cot = _cot(
        f"SCCM and software deployment tools create or configure services, but always with "
        f"signed binaries in C:\\Program Files\\, not cmd.exe or temporary executables. "
        f"Service binary path modification via ChangeServiceConfigA (not an installer) is not legitimate.",
        f"ChangeServiceConfigA sets {svc} binary to '{payload[:50]}' -- cmd.exe or temp-path payload. "
        f"QueryServiceConfigA first: attacker preserved original path for cleanup (anti-forensic). "
        f"StartServiceA immediately after modification -- one-shot execution, not persistent. "
        f"Path restored post-execution: confirms adversarial intent (not accidental misconfiguration). "
        f"Auth={p['auth']}: attacker used valid credentials for SCM access to {p['target']}.",
        f"Source {p['src']} executed code on {p['target']} via SCM service hijack. "
        "Attack is filelessly executed in the context of an existing service account. "
        "Network propagation via port 135 (RPC) -- no SMB 445 required.",
        "SCM service binary path hijack for remote code execution confirmed.",
        "MITRE T1021.002 (Remote Services: SMB/Windows Admin Shares) + T1543.003 (Windows Service). "
        "Isolate target, check for additional lateral movement, review affected service.",
    )
    return prompt, cot, "true_positive"

def _scm_fp(i):
    p = {"svc": "TenableNessusAgent", "path": r"C:\Program Files\Tenable\Nessus\nessusd.exe",
         "ticket": f"CHG-{random.randint(10000,99999)}", "via": "SCCM"}
    prompt = (f"Windows Sysmon -- Service Configuration Change.\n"
              f"  Service: {p['svc']}\n"
              f"  new_binary_path: {p['path']}\n"
              f"  changed_by: {p['via']}  ticket={p['ticket']}\n"
              f"  binary_signed=YES  path_in_program_files=YES  no_cleanup=YES")
    cot = _cot(
        "SCCM deploying Tenable agent -- signed binary in Program Files, change ticket, no cleanup.",
        f"path=C:\\Program Files (vendor). signed=YES. SCCM deployment. Ticket {p['ticket']}. No path restoration.",
        "Authorized software deployment -- vendor path, signed, no cleanup, SCCM.",
        "Authorized service deployment. No action.",
        "T1543.003 -- AUTHORIZED SERVICE DEPLOYMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. WMILateralExec
#    Evidence: WmiPrvSe.exe spawning unexpected child processes,
#              Win32_Process.Create via DCOM (port 135 + dynamic),
#              Event 4624 network logon + WmiPrvSe.exe process creation
#    Sources: Invoke-WMIRemoting, SharpLateral (RedWMI)
#    Admin FP: SCCM/management WMI (service account, scoped, scheduled)
# ═══════════════════════════════════════════════════════════════════════════════

def _wmi_tp(i):
    src = _host(); target = _host()
    payload = random.choice([
        f"powershell.exe -enc {random.randint(10000,99999):x}",
        f"cmd.exe /c net use \\\\{_ip_int()}\\C$ /user:domain\\admin P@ssw0rd",
        f"C:\\Windows\\Temp\\{random.randint(100,999)}.exe",
    ])
    p = {
        "src": src, "target": target, "payload": payload,
        "parent_proc": "WmiPrvSe.exe",
        "child_proc": payload.split(".exe")[0].split("\\")[-1] + ".exe",
        "network_logon_4624": True, "explicit_creds_4648": i%2==0,
        "rpc_port": 135,
    }
    prompt = (f"Windows Sysmon -- WMI Lateral Execution.\n"
              f"Source: {p['src']} → Target: {p['target']}\n"
              f"  Method: Win32_Process.Create via ManagementScope\n"
              f"  ParentProcess: {p['parent_proc']}\n"
              f"  ChildProcess: {p['child_proc']}\n"
              f"  CommandLine: {p['payload'][:70]}\n"
              f"  network_logon_event_4624=YES (type 3, from {p['src']})\n"
              + (f"  explicit_credential_use_4648=YES\n" if p['explicit_creds_4648'] else "")
              + f"  rpc_connection_to_port_135=YES")
    cot = _cot(
        "SCCM, Intune, and IT management tools use WMI for inventory and configuration, but "
        "these run from service accounts on scheduled cycles. "
        f"WmiPrvSe.exe spawning {p['child_proc']} directly without a prior scheduled task or "
        "maintenance event is not legitimate admin behavior.",
        f"ParentProcess=WmiPrvSe.exe spawning {p['child_proc']}: "
        "process launched via Win32_Process.Create (not a scheduled or persistent event). "
        f"Event 4624 network logon (type 3) from {p['src']} immediately before process creation. "
        + (f"Event 4648 explicit credential use: attacker supplied credentials. " if p['explicit_creds_4648'] else "")
        + f"Payload='{p['payload'][:50]}' (PowerShell/temp binary from WMI context).",
        f"Source {p['src']} executed arbitrary command on {p['target']} via WMI. "
        "Execution appears as WmiPrvSe.exe child process -- evades process-based blocking. "
        "Network channel: RPC port 135 + dynamic ports (no SMB 445 needed).",
        "WMI remote code execution via Win32_Process.Create confirmed.",
        "MITRE T1047 (Windows Management Instrumentation). "
        "Isolate target, check WmiPrvSe.exe process tree, audit WMI subscriptions.",
    )
    return prompt, cot, "true_positive"

def _wmi_fp(i):
    p = {"sa": "svc-sccm", "query": "Win32_LogicalDisk", "schedule": "hourly inventory"}
    prompt = (f"Windows Sysmon -- WMI Query from Management Service.\n"
              f"  Source: svc-sccm (service account)\n"
              f"  WMI_class: {p['query']}  operation=SELECT (read-only)\n"
              f"  schedule={p['schedule']}  no_process_creation=YES\n"
              f"  parent=SCCMAgent.exe")
    cot = _cot(
        "SCCM agent WMI inventory query -- read-only, service account, scheduled, no process creation.",
        f"class={p['query']} (read-only). no Win32_Process.Create. service account. SCCMAgent.exe parent.",
        "Authorized SCCM inventory via WMI -- no lateral execution.",
        "Authorized SCCM WMI inventory. No action.",
        "T1047 -- AUTHORIZED IT MANAGEMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ScheduledTaskLateral
#    Evidence: Remote task creation (Event 4698) + immediate execution trigger +
#              rapid task deletion (Event 4699) -- sub-minute create/exec/delete cycle
#    Sources: SharpLateral (schedule), Amnesiac (Suntour), Invoke-SMBRemoting -AsTask
#    Admin FP: IT deploying scheduled maintenance task (persists days/weeks)
# ═══════════════════════════════════════════════════════════════════════════════

def _stl_tp(i):
    target = _host(); src = _host()
    task_name = f"\\Microsoft\\Windows\\{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', k=10))}"
    payload = random.choice([
        "powershell.exe -enc JABhAGI=",
        f"cmd.exe /c {random.choice(['whoami','ipconfig','net user /domain'])} > C:\\Windows\\Temp\\o.txt",
    ])
    create_to_delete_s = random.randint(3, 30)
    p = {
        "src": src, "target": target, "task": task_name, "payload": payload,
        "trigger": "OnLogon (immediate)",
        "run_as": "SYSTEM",
        "create_to_delete_s": create_to_delete_s,
        "event_4698": True, "event_4699": True,
    }
    prompt = (f"Windows Sysmon -- Remote Scheduled Task Lateral Execution.\n"
              f"Source: {p['src']} → Target: {p['target']}\n"
              f"  TaskName: {p['task']}\n"
              f"  Trigger: {p['trigger']}\n"
              f"  Action: {p['payload']}\n"
              f"  RunAs: {p['run_as']}\n"
              f"  event_4698_task_created=YES  event_4699_task_deleted=YES\n"
              f"  create_to_delete_seconds={p['create_to_delete_s']}\n"
              f"  task_persisted=NO (anti-forensic deletion)")
    cot = _cot(
        "Legitimate remote task deployment leaves tasks in place for hours or days (maintenance, "
        "daily jobs). An IT-deployed task is named descriptively, targets a specific time window, "
        "and is not deleted within seconds of creation.",
        f"Task '{p['task']}' created (Event 4698) → executed → deleted (Event 4699) in "
        f"{p['create_to_delete_s']}s -- anti-forensic task lifecycle. "
        f"Trigger='OnLogon (immediate)': adversarial pattern (IT tasks use time-based triggers). "
        f"RunAs=SYSTEM (unnecessary for IT tasks on modern management). "
        f"Task name random characters masquerading as a system path.",
        f"Source {p['src']} executed code as SYSTEM on {p['target']} via ephemeral scheduled task. "
        "Task deleted after execution to reduce forensic evidence.",
        "Remote scheduled task for lateral execution confirmed -- anti-forensic lifecycle.",
        "MITRE T1053.005 (Scheduled Task/Job: Scheduled Task) + T1021 (Remote Services). "
        "Recover task execution artifacts from Windows Event Log before rollover.",
    )
    return prompt, cot, "true_positive"

def _stl_fp(i):
    p = {"task": "\\IT\\WeeklyPatchScan", "trigger": "Weekly Sunday 02:00",
         "action": r"C:\Program Files\Tenable\Nessus\nessus-agent.exe --scan",
         "sa": "svc-patchmgmt", "ticket": f"CHG-{random.randint(10000,99999)}",
         "persisted_days": 30}
    prompt = (f"Windows Sysmon -- IT Scheduled Task Deployment.\n"
              f"  TaskName: {p['task']}\n"
              f"  Trigger: {p['trigger']}\n"
              f"  Action: {p['action']}\n"
              f"  RunAs: {p['sa']}  ticket={p['ticket']}\n"
              f"  task_persisted_days={p['persisted_days']}  event_4699=NO")
    cot = _cot(
        "IT patch scan task -- service account, weekly trigger, vendor binary, persists 30 days, no deletion.",
        f"named=/IT/ (descriptive). Weekly trigger. action=C:\\Program Files (vendor). sa={p['sa']}. 30-day lifecycle.",
        "Authorized IT scheduled task -- service account, vendor path, time trigger, persistent.",
        "Authorized IT task deployment. No action.",
        "T1053.005 -- AUTHORIZED IT TASK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. DCOMHTAExecution
#    Evidence: CoCreateInstanceEx targeting HTA class via CLSCTX_REMOTE_SERVER,
#              HTTP GET for .hta file immediately after RPC 135 connection,
#              mshta.exe spawned from DCOM activation context on target
#    Sources: LethalHTA (Native, DotNet, CobaltStrike)
#    Admin FP: No legitimate admin FP -- mshta via DCOM from remote is always adversarial
# ═══════════════════════════════════════════════════════════════════════════════

def _dcom_hta_tp(i):
    src = _ip_int(); target = _ip_int()
    hta_url = f"http://{_ip_ext()}/{random.choice(['update','setup','install','payload'])}.hta"
    p = {
        "src": src, "target": target, "hta_url": hta_url,
        "clsid": "3050F4D8-98B5-11CF-BB82-00AA00BDCE0B",
        "interface": "IPersistMoniker.Load()",
        "rpc_first": True, "http_after_rpc_s": random.randint(1, 5),
        "mshta_parent": "svchost.exe",
    }
    prompt = (f"Network Tap + Sysmon -- DCOM HTA Lateral Execution.\n"
              f"Source: {p['src']} → Target: {p['target']}\n"
              f"  step1: RPC port 135 connection (DCOM object activation)\n"
              f"  step2: {p['interface']} on CLSID {p['clsid']}\n"
              f"  step3: HTTP GET {p['hta_url']} ({p['http_after_rpc_s']}s after RPC)\n"
              f"  step4: mshta.exe spawned on target (parent={p['mshta_parent']})\n"
              f"  mshta_spawned_without_user_interaction=YES")
    cot = _cot(
        "mshta.exe is legitimately launched by users clicking .hta files or by software "
        "installers. A remote system spawning mshta.exe via DCOM activation with "
        "parent=svchost.exe (the DCOM host) without user interaction has no legitimate analog.",
        f"RPC 135 connection → CLSID {p['clsid']} activation → CreateURLMonikerEx → "
        f"IPersistMoniker.Load({p['hta_url']}): HTTP GET to external URL triggered by COM activation. "
        f"mshta.exe spawned on {p['target']} {p['http_after_rpc_s']}s after RPC connection, "
        f"parent={p['mshta_parent']} (DCOM activation). "
        "RPC → HTTP → process creation in <5s = automated DCOM lateral movement pattern.",
        f"Source {p['src']} triggered mshta.exe execution on {p['target']} via DCOM. "
        "mshta.exe will load and execute the HTA payload from {p['hta_url']}. "
        "No user interaction required.",
        "DCOM HTA lateral execution confirmed -- CoCreateInstanceEx + IPersistMoniker.Load.",
        "MITRE T1021.003 (Remote Services: Distributed Component Object Model). "
        "Block HTA URL at perimeter, isolate target, check mshta.exe execution artifacts.",
    )
    return prompt, cot, "true_positive"

def _dcom_hta_fp(i):
    # Even legitimate HTA use is rare; there's no clean admin FP.
    # Best FP: authorized IT delivering HTA from internal server (not via DCOM from remote)
    p = {"src": "admin-ws-01", "hta_path": "\\\\it-server\\share\\setup.hta",
         "launch": "user double-click from file share", "ticket": f"IT-{random.randint(100,999)}"}
    prompt = (f"Windows Sysmon -- HTA File Execution.\n"
              f"  source={p['src']}  hta_path={p['hta_path']}\n"
              f"  launch_method={p['launch']}\n"
              f"  dcom_activation=NO  user_initiated=YES  ticket={p['ticket']}")
    cot = _cot(
        "User-initiated HTA from IT file share -- no DCOM remote activation, user interaction present.",
        f"user_initiated=YES. dcom_activation=NO. No RPC 135 precursor. Ticket {p['ticket']}.",
        "Authorized IT setup via user-initiated HTA -- no DCOM lateral movement.",
        "User-initiated HTA from IT share. Monitor for payload content.",
        "T1021.003 -- AUTHORIZED USER HTA. Monitor.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. DCOMMMCExecution
#    Evidence: MMC20.Application CLSID instantiated remotely, ExecuteShellCommand
#              called, mmc.exe spawned from svchost.exe (DCOM activation parent)
#    Sources: SharpLateral (DcomExec), writeup t1175
#    Admin FP: IT using MMC for remote management (mmc.exe parent is user, not svchost)
# ═══════════════════════════════════════════════════════════════════════════════

def _dcom_mmc_tp(i):
    src = _ip_int(); target = _ip_int()
    cmd = random.choice(["cmd.exe", "powershell.exe", "C:\\Windows\\Temp\\payload.exe"])
    p = {
        "src": src, "target": target,
        "clsid": "49B2791A-B1AE-4C90-9B8E-E860BA07F889",
        "progid": "MMC20.Application",
        "method": "ActiveView.ExecuteShellCommand()",
        "command": cmd,
        "mmc_parent": "svchost.exe",
    }
    prompt = (f"Sysmon -- DCOM MMC20.Application Lateral Execution.\n"
              f"Source: {p['src']} → Target: {p['target']}\n"
              f"  ProgID: {p['progid']}  CLSID: {p['clsid']}\n"
              f"  Method: {p['method']}\n"
              f"  Command: {p['command']}\n"
              f"  mmc.exe_parent_on_target: {p['mmc_parent']}\n"
              f"  activation_context: CLSCTX_REMOTE_SERVER")
    cot = _cot(
        "MMC is legitimately used by admins to manage remote systems, but it is launched "
        "by the user directly (parent = explorer.exe or terminal). When MMC is activated "
        "via DCOM from a remote host, the parent on the target is svchost.exe (the DCOM host), "
        "not an interactive session.",
        f"mmc.exe spawned with parent=svchost.exe (DCOM activation context) -- "
        "no user interaction on target. "
        f"CLSID {p['clsid']} instantiated from {p['src']} via CLSCTX_REMOTE_SERVER. "
        f"ExecuteShellCommand('{p['command']}'): command execution via MMC internal method, "
        "not via mmc.exe /s or snap-in interaction. "
        "RPC 135 → DCOM object → command execution in <2s.",
        f"Source {p['src']} executed '{p['command']}' on {p['target']} via DCOM MMC20.Application. "
        "Code runs under the SYSTEM-equivalent DCOM host context.",
        "DCOM MMC20.Application lateral execution confirmed.",
        "MITRE T1021.003 (DCOM). Isolate target, check mmc.exe children.",
    )
    return prompt, cot, "true_positive"

def _dcom_mmc_fp(i):
    p = {"user": "jsmith", "parent": "explorer.exe", "target": "remote-dc.corp.local"}
    prompt = (f"Sysmon -- MMC Administrative Connection.\n"
              f"  user={p['user']}  parent={p['parent']}\n"
              f"  target={p['target']}  mmc_parent_on_target=none\n"
              f"  dcom_activation=NO  user_initiated=YES")
    cot = _cot(
        "Admin launching MMC from their workstation via explorer.exe -- user-initiated, no DCOM activation.",
        f"parent=explorer.exe (user session). user_initiated=YES. No DCOM remote activation.",
        "Authorized admin MMC usage -- user session, explorer.exe parent.",
        "Authorized admin MMC. No action.",
        "T1021.003 -- AUTHORIZED MMC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. DCOMCOMHijackLateral
#    Evidence: Remote registry write to HKCU\...\CLSID\InProcServer32,
#              DLL dropped via SMB, then DCOM activation triggers DLL load
#              BaaUpdate.exe/SpeechRuntime.exe spawned with malicious DLL
#    Sources: BitlockMove, SpeechRuntimeMove
#    Admin FP: No legitimate admin FP -- remote HKCU COM hijack is always adversarial
# ═══════════════════════════════════════════════════════════════════════════════

def _dcom_hijack_tp(i):
    target = _host(); src = _host()
    if i % 2 == 0:
        hijacked_clsid = "A7A63E5C-3877-4840-8727-C1EA9D7A4D50"
        launcher = "BaaUpdate.exe"
        tool_note = "BDEUILauncher COM hijack"
    else:
        hijacked_clsid = "655D9BF9-3876-43D0-B6E8-C83C1224154C"
        launcher = "SpeechRuntime.exe"
        tool_note = "SpeechRuntime COM hijack"
    dll_path = f"C:\\Users\\{_user()}\\AppData\\Local\\Temp\\{random.randint(100,999)}.dll"
    p = {
        "src": src, "target": target, "clsid": hijacked_clsid,
        "launcher": launcher, "dll": dll_path, "note": tool_note,
        "registry_key": f"HKCU\\Software\\Classes\\CLSID\\{{{hijacked_clsid}}}\\InProcServer32",
        "smb_drop": True,
    }
    prompt = (f"Sysmon -- DCOM COM Hijack Lateral Execution ({p['note']}).\n"
              f"Source: {p['src']} → Target: {p['target']}\n"
              f"  step1: Remote registry write (via RemoteRegistry service)\n"
              f"    key={p['registry_key']}\n"
              f"    value_default={p['dll']}\n"
              f"  step2: DLL dropped via SMB → {p['dll']}\n"
              f"  step3: DCOM activation triggers {p['launcher']}\n"
              f"  step4: {p['launcher']} loads DLL from hijack path\n"
              f"  dll_signed=NO  dll_in_appdata=YES")
    cot = _cot(
        "Legitimate software does not modify HKCU\\...\\CLSID\\InProcServer32 from a remote "
        "context. COM hijacking via remote registry access followed by DLL delivery is an "
        "attack-specific multi-stage technique with no admin equivalent.",
        f"Remote registry write to {p['registry_key']}: overrides COM lookup for {p['clsid']}. "
        f"DLL dropped via SMB to AppData path (unsigned, non-vendor). "
        f"DCOM activation of a target CLSID triggers {p['launcher']}, "
        f"which loads the hijacked DLL from {p['dll']}. "
        "4-step sequence (registry → DLL drop → DCOM trigger → DLL load) is definitional COM hijack lateral movement.",
        f"Source {p['src']}: DLL executing in context of {p['launcher']} on {p['target']}. "
        "COM hijack grants code execution without creating a visible child process tree.",
        f"DCOM COM hijack lateral execution confirmed via {p['note']}.",
        "MITRE T1021.003 (DCOM) + T1574.001 (DLL Search Order Hijacking). "
        "Remove registry hijack, delete DLL, restart affected service.",
    )
    return prompt, cot, "true_positive"

def _dcom_hijack_fp(i):
    p = {"key": r"HKLM\Software\Classes\CLSID\{...}\InProcServer32",
         "via": "software_installer", "signed": True, "ticket": f"INST-{random.randint(100,999)}"}
    prompt = (f"Sysmon -- COM InProcServer32 Registration.\n"
              f"  registry_key={p['key']}  (HKLM, not HKCU)\n"
              f"  written_by={p['via']}  signed={p['signed']}  ticket={p['ticket']}\n"
              f"  remote_registry_access=NO  dll_in_vendor_dir=YES")
    cot = _cot(
        "Software installer registering COM class in HKLM via local installer -- not remote HKCU hijack.",
        f"HKLM (system-wide). local_installer. Signed DLL. Vendor directory. No remote registry.",
        "Authorized local COM class registration by installer.",
        "Authorized COM registration. No action.",
        "T1574.001 -- AUTHORIZED INSTALLER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. MSILateralExecution
#    Evidence: CoCreateInstanceEx targeting IMsiServer, SQLInstallDriverEx call,
#              ODBC DLL placed in registry + unexpected path, DLL loads in
#              MSI Server process (SYSTEM context) without msiexec user invocation
#    Sources: msi_lateral_mv (BOF + COM)
#    Admin FP: SCCM deploying MSI package (msiexec.exe, signed, change ticket)
# ═══════════════════════════════════════════════════════════════════════════════

def _msi_tp(i):
    target = _host(); src = _host()
    dll_path = random.choice([
        f"C:\\Windows\\Temp\\SQLDriver{random.randint(10,99)}.dll",
        f"C:\\ProgramData\\{random.randint(100,999)}.dll",
    ])
    p = {
        "src": src, "target": target, "dll": dll_path,
        "interface": "IMsiCustomAction::SQLInstallDriverEx()",
        "odbc_key": r"HKLM\SOFTWARE\ODBC\ODBCINST.INI\TestDriver",
        "msi_server_context": "NT AUTHORITY\\SYSTEM",
        "no_msiexec_parent": True,
    }
    prompt = (f"Sysmon -- MSI DCOM Lateral Execution.\n"
              f"Source: {p['src']} → Target: {p['target']}\n"
              f"  Interface: {p['interface']}\n"
              f"  DLL_path: {p['dll']}\n"
              f"  ODBC_registry_key: {p['odbc_key']}\n"
              f"  execution_context: {p['msi_server_context']}\n"
              f"  msiexec.exe_parent=NO (DCOM-activated, not user-launched)\n"
              f"  dll_signed=NO  dll_in_temp=YES")
    cot = _cot(
        "SCCM and Intune use msiexec.exe for package deployment, which produces an audit trail "
        "and runs under a deployment service account. SQLInstallDriverEx invoked via DCOM "
        "without a preceding msiexec.exe call is not package deployment behavior.",
        f"IMsiCustomAction.SQLInstallDriverEx via DCOM (no msiexec.exe parent): "
        "using MSI Server as a DCOM code execution primitive. "
        f"DLL placed at {p['dll']} (temp/ProgramData -- not an ODBC vendor path). "
        f"ODBC registry key created: {p['odbc_key']} (attacker-created ODBC entry). "
        f"DLL executes in MSI Server context ({p['msi_server_context']}) -- highest privilege, no visible process.",
        f"DLL running as SYSTEM in MSI Server on {p['target']}. "
        "No visible process creation -- in-process execution in existing MSI Server.",
        "MSI DCOM lateral execution via SQLInstallDriverEx confirmed.",
        "MITRE T1021.003 (DCOM). Remove ODBC registry entry, delete DLL, reboot MSI Server.",
    )
    return prompt, cot, "true_positive"

def _msi_fp(i):
    p = {"msiexec": "msiexec.exe", "pkg": "NessusAgent.msi",
         "ticket": f"CHG-{random.randint(10000,99999)}", "via": "SCCM"}
    prompt = (f"Sysmon -- MSI Package Installation.\n"
              f"  process={p['msiexec']}  package={p['pkg']}\n"
              f"  deployed_via={p['via']}  ticket={p['ticket']}\n"
              f"  dcom_activation=NO  signed=YES  standard_odbc_path=YES")
    cot = _cot(
        "SCCM deploying signed MSI via msiexec.exe -- standard path, not DCOM IMsiServer.",
        f"msiexec.exe (standard). Signed. SCCM. Ticket. Standard ODBC path.",
        "Authorized MSI package deployment. No action.",
        "Authorized SCCM MSI deployment. No action.",
        "T1021.003 -- AUTHORIZED MSI DEPLOYMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. NTLMRelayLateral
#    Evidence: Forced authentication to attacker (HTML img/UNC path),
#              same credential hash relayed to third-party target within 2-3s,
#              service creation on target following successful relay
#    Sources: lateral-movement-writeups/ntlm-relaying
#    Admin FP: No admin FP -- same hash on 2 hosts in <3s is definitionally adversarial
# ═══════════════════════════════════════════════════════════════════════════════

def _ntlm_relay_tp(i):
    victim = _ip_int(); attacker = _ip_int(); target = _ip_int()
    p = {
        "victim": victim, "attacker": attacker, "target": target,
        "trigger": random.choice(["UNC path in email attachment",
                                   "HTML img src=\\\\attacker\\share",
                                   "SCF file on shared drive"]),
        "relay_delay_ms": random.randint(200, 2000),
        "post_relay_action": random.choice(["service creation", "scheduled task", "file write to C$"]),
        "hash_type": "NTLMv2",
        "smb_signing_on_target": False,
    }
    prompt = (f"Network Tap -- NTLM Credential Relay Lateral Movement.\n"
              f"  Victim: {p['victim']}  Attacker relay: {p['attacker']}  Target: {p['target']}\n"
              f"  trigger: {p['trigger']}\n"
              f"  credential_captured: {p['hash_type']} hash from {p['victim']}\n"
              f"  relay_to_target_delay_ms={p['relay_delay_ms']}\n"
              f"  target_smb_signing={p['smb_signing_on_target']}\n"
              f"  post_relay_action: {p['post_relay_action']}\n"
              f"  same_session_id_reused=YES")
    cot = _cot(
        "A single account authenticating to two different hosts within seconds of each other "
        "does occur (SSO, distributed app), but SSO flows use Kerberos tickets (not NTLM), "
        "and the second authentication is to a known application server, not an arbitrary endpoint.",
        f"Victim {p['victim']} forced to authenticate to {p['attacker']} via {p['trigger']}. "
        f"Within {p['relay_delay_ms']}ms, same NTLMv2 authentication hash relayed to {p['target']}. "
        f"SMB signing disabled on {p['target']}: allows relay without hash validation. "
        f"Post-relay action '{p['post_relay_action']}' on {p['target']}: "
        "attacker used relayed credentials to execute code.",
        f"Account from {p['victim']} now has authenticated session on {p['target']} "
        "via relay -- lateral movement achieved without cracking hash.",
        "NTLM relay lateral movement confirmed.",
        "MITRE T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning) + T1021.002. "
        "Enable SMB signing on all hosts, isolate relay host, reset relayed account.",
    )
    return prompt, cot, "true_positive"

def _ntlm_relay_fp(i):
    # Near-FP: same account on two hosts but with 30+ seconds gap and known app
    p = {"acct": "svc-monitoring", "host1": _ip_int(), "host2": _ip_int(), "gap_s": 35}
    prompt = (f"Network Tap -- Account Auth on Two Hosts.\n"
              f"  account={p['acct']}  host1={p['host1']}  host2={p['host2']}\n"
              f"  gap_between_auths_s={p['gap_s']}  protocol=Kerberos\n"
              f"  both_hosts_in_approved_monitoring_targets=YES")
    cot = _cot(
        "Monitoring service account authenticating to two hosts 35s apart via Kerberos -- "
        "not NTLM relay (which happens in <3s and uses NTLM, not Kerberos).",
        f"Protocol=Kerberos (relay uses NTLM). gap={p['gap_s']}s (relay is <3s). Known monitoring account.",
        "Authorized monitoring agent -- Kerberos, >30s gap, known targets.",
        "Authorized monitoring service. No action.",
        "T1557.001 -- AUTHORIZED MONITORING AUTH. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. PassTheHashLateral
#    Evidence: LogonUser LOGON32_LOGON_NEW_CREDENTIALS (type 9) with hash,
#              ImpersonateLoggedOnUser then child process with different token,
#              network authentication without Event 4624 interactive logon
#    Sources: Amnesiac Token-Impersonation.ps1, Invoke-GrabTheHash, SCShell pass-hash
#    Admin FP: PsExec with service account (signed, change ticket, type-3 logon)
# ═══════════════════════════════════════════════════════════════════════════════

def _pth_tp(i):
    src = _host(); target = _ip_int()
    p = {
        "src": src, "target": target,
        "api_seq": ["LogonUser(domain\\admin, LOGON32_LOGON_NEW_CREDENTIALS=9, NTLM_hash)",
                    "ImpersonateLoggedOnUser(new_token)",
                    "Net use \\\\target\\C$ or RPC/SMB connection"],
        "logon_type": 9,
        "no_event_4624_interactive": True,
        "lateral_action": random.choice(["file copy to C$", "SCM service exec", "WMI process create"]),
        "event_4648": True,
    }
    prompt = (f"Windows Sysmon -- Pass-the-Hash Lateral Movement.\n"
              f"Source: {p['src']} → Target: {p['target']}\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  logon_type={p['logon_type']} (LOGON32_LOGON_NEW_CREDENTIALS)\n"
              f"  no_interactive_4624_for_target_account=YES\n"
              f"  event_4648_explicit_credential=YES\n"
              f"  lateral_action: {p['lateral_action']}")
    cot = _cot(
        "Legitimate credential use for remote access produces a type-3 network logon (Event 4624 "
        "type 3) from the authenticating host. Logon type 9 (LOGON32_LOGON_NEW_CREDENTIALS) "
        "creates a NEW credential context without an interactive logon event -- the defining "
        "signature of Pass-the-Hash.",
        f"LogonUser with LOGON32_LOGON_NEW_CREDENTIALS (type 9): "
        "creates token using existing NTLM hash without cleartext password. "
        "ImpersonateLoggedOnUser: current process takes on the hash-based identity. "
        "No Event 4624 interactive logon for the impersonated account on {p['src']}. "
        f"Event 4648 explicit credential: attacker supplied hash. "
        f"Subsequent {p['lateral_action']} to {p['target']} under impersonated identity.",
        f"Source {p['src']} is using a stolen NTLM hash to access {p['target']} "
        "without knowing the cleartext password. "
        "Network-level authentication appears legitimate.",
        "Pass-the-Hash lateral movement confirmed.",
        "MITRE T1550.002 (Use Alternate Authentication Material: Pass the Hash). "
        "Rotate account credentials, enable Credential Guard, isolate source host.",
    )
    return prompt, cot, "true_positive"

def _pth_fp(i):
    p = {"tool": "PsExec.exe", "acct": "svc-deploy", "ticket": f"CHG-{random.randint(10000,99999)}",
         "logon_type": 3}
    prompt = (f"Windows Sysmon -- Remote Process Execution.\n"
              f"  tool={p['tool']}  account={p['acct']}\n"
              f"  logon_type={p['logon_type']} (network logon)\n"
              f"  event_4624_type3=YES  change_ticket={p['ticket']}\n"
              f"  signed=YES  no_logon_type_9=YES")
    cot = _cot(
        "PsExec with type-3 network logon using service account -- not type-9 pass-the-hash.",
        f"logon_type=3 (normal network). No type-9 LOGON_NEW_CREDENTIALS. Signed PsExec. Ticket.",
        "Authorized remote execution via PsExec -- service account, type-3 logon, change ticket.",
        "Authorized PsExec deployment. No action.",
        "T1550.002 -- AUTHORIZED REMOTE EXEC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. LAPSCredentialExtract
#     Evidence: Unexpected RPC service binding on DC with custom UUID,
#               LDAP queries from DC context to LAPS schema (ms-Mcs-AdmPwd),
#               S4U2Self Kerberos requests from non-standard process
#     Sources: DecryptRecoveryLAPS_RPC (custom RPC backdoor)
#     Admin FP: Authorized IT using Microsoft LAPS PowerShell to retrieve password
# ═══════════════════════════════════════════════════════════════════════════════

def _laps_tp(i):
    dc = _host()
    custom_uuid = _guid()
    p = {
        "dc": dc, "custom_uuid": custom_uuid,
        "rpc_service_installed": True,
        "ldap_attr": "ms-Mcs-AdmPwd",
        "kerberos_s4u": i%2==0,
        "computers_queried": random.randint(5, 50),
    }
    prompt = (f"Windows Sysmon -- LAPS Credential Extraction via RPC Backdoor.\n"
              f"Domain Controller: {p['dc']}\n"
              f"  custom_rpc_service_installed=YES\n"
              f"  rpc_interface_uuid: {{{p['custom_uuid']}}}\n"
              f"  uuid_not_in_standard_windows_rpc_registry=YES\n"
              f"  ldap_attribute_queried: {p['ldap_attr']}\n"
              f"  computers_with_laps_queried={p['computers_queried']}\n"
              + (f"  kerberos_s4u2self_requests=YES (machine account impersonation)\n" if p['kerberos_s4u'] else ""))
    cot = _cot(
        "Authorized LAPS password retrieval uses Microsoft's Get-LAPSADPassword cmdlet "
        "or the LAPS UI tool, both of which run in the context of the IT admin's account "
        "and make standard LDAP queries. A custom RPC service on the DC with a non-Microsoft "
        "UUID providing LAPS decryption is not a Microsoft tool.",
        f"Custom RPC UUID {{{p['custom_uuid']}}}: not in standard Windows RPC endpoint map -- "
        "attacker-installed RPC service on DC. "
        f"LDAP queries to {p['ldap_attr']}: reading LAPS passwords for {p['computers_queried']} endpoints. "
        + (f"Kerberos S4U2Self: machine account token used to access LAPS data without user creds. " if p['kerberos_s4u'] else "")
        + "RPC backdoor on DC = attacker has privileged persistence on domain infrastructure.",
        f"DC {p['dc']}: LAPS passwords for {p['computers_queried']} computers have been extracted. "
        "Attacker now has local admin credentials for those endpoints -- "
        "domain-wide lateral movement is enabled.",
        "LAPS credential extraction via custom RPC backdoor confirmed.",
        "MITRE T1552.004 (Unsecured Credentials: Private Keys) + T1003 (Credential Dumping). "
        "Remove RPC backdoor service, rotate ALL LAPS passwords, audit DC for other backdoors.",
    )
    return prompt, cot, "true_positive"

def _laps_fp(i):
    p = {"tool": "Get-LAPSADPassword PowerShell", "acct": "svc-helpdesk",
         "target": "WS-47", "ticket": f"INC-{random.randint(10000,99999)}"}
    prompt = (f"Windows Sysmon -- LAPS Password Retrieval.\n"
              f"  tool={p['tool']}  account={p['acct']}\n"
              f"  target_computer={p['target']}  ticket={p['ticket']}\n"
              f"  custom_rpc_service=NO  standard_ldap_query=YES\n"
              f"  computers_queried=1  authorized_role=HelpDesk")
    cot = _cot(
        "Helpdesk using Microsoft LAPS PowerShell for single computer -- standard LDAP, authorized role.",
        f"Microsoft LAPS tool. Standard LDAP. 1 computer. HelpDesk role. Ticket {p['ticket']}.",
        "Authorized LAPS password retrieval by helpdesk.",
        "Authorized LAPS retrieval. No action.",
        "T1552 -- AUTHORIZED LAPS ACCESS. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. TGTPKINITExtract
#     Evidence: Certificate request to CA from endpoint (not certificate renewal),
#               Kerberos AS-REQ with PKINIT preauth from non-standard process,
#               UnPAC-the-Hash: TGT obtained without password → NTLM hash extracted
#     Sources: Amnesiac/Tools/Invoke-GrabTheHash.ps1, TGT_Monitor.ps1
#     Admin FP: Legitimate certificate enrollment (auto-enrollment, known template)
# ═══════════════════════════════════════════════════════════════════════════════

def _tgt_pkinit_tp(i):
    src = _host()
    p = {
        "src": src,
        "ca_server": f"ca.{random.choice(['corp','domain','internal'])}.local",
        "cert_template": random.choice(["User","Workstation","SubCA","DomainController"]),
        "pkinit_asreq": True,
        "unpac_hash": True,
        "tgt_stored_registry": i%2==0,
        "ldap_queries": random.randint(2, 8),
    }
    prompt = (f"Sysmon -- PKINIT TGT Extraction / UnPAC-the-Hash.\n"
              f"Host: {p['src']}\n"
              f"  step1: Certificate request to {p['ca_server']} (template={p['cert_template']})\n"
              f"  step2: Kerberos AS-REQ with PKINIT preauth (cert-based TGT request)\n"
              f"  step3: UnPAC-the-Hash -- TGT obtained, NTLM hash extracted without password\n"
              + (f"  tgt_stored_in_registry: HKLM\\SOFTWARE\\MONITOR=YES\n" if p['tgt_stored_registry'] else "")
              + f"  ldap_queries_to_ca={p['ldap_queries']}\n"
              f"  hash_extracted_without_cleartext=YES")
    cot = _cot(
        "Legitimate certificate enrollment happens through autoenrollment (scheduled, Windows "
        "Certificate Services) or user-requested renewal (certmgr.msc). "
        "Programmatic PKINIT TGT requests from non-standard processes for hash extraction "
        "have no legitimate analog.",
        f"Certificate request to {p['ca_server']} template={p['cert_template']} from non-CA-process: "
        "programmatic enrollment for attack (not autoenrollment). "
        "Kerberos AS-REQ with PKINIT preauth: certificate-based TGT request without password. "
        "UnPAC-the-Hash: TGT obtained → PAC structure parsed → NTLM hash extracted. "
        + (f"TGT stored in HKLM\\SOFTWARE\\MONITOR (attacker persistence store). " if p['tgt_stored_registry'] else "")
        + "Result: NTLM hash for domain account without knowing the password.",
        f"Host {p['src']}: NTLM hash for the enrolled account has been extracted via PKINIT. "
        "This hash enables Pass-the-Hash attacks to any host in the domain.",
        "PKINIT TGT/UnPAC-the-Hash credential extraction confirmed.",
        "MITRE T1649 (Steal or Forge Authentication Certificates) + T1550.002. "
        "Revoke enrolled certificate, reset account password, rotate NTLM hash (password change + netlogon restart).",
    )
    return prompt, cot, "true_positive"

def _tgt_pkinit_fp(i):
    p = {"proc": "certlm.msc", "template": "Workstation", "via": "autoenrollment",
         "schedule": "configured group policy"}
    prompt = (f"Sysmon -- Certificate Autoenrollment.\n"
              f"  process={p['proc']}  template={p['template']}\n"
              f"  via={p['via']}  schedule={p['schedule']}\n"
              f"  pkinit_for_hash_extraction=NO  registry_store=NO")
    cot = _cot(
        "Windows autoenrollment via certlm.msc -- group policy scheduled, no hash extraction.",
        f"certlm.msc (standard). autoenrollment. GPO scheduled. No UnPAC-the-Hash. No registry store.",
        "Authorized certificate autoenrollment via GPO.",
        "Authorized autoenrollment. No action.",
        "T1649 -- AUTHORIZED AUTOENROLLMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. RDPSessionHijack
#     Evidence: tscon.exe executed from SYSTEM-context process,
#               target session disconnected (Event 4779) then reconnected (Event 4778)
#               by attacker-controlled session, no user-initiated reconnect
#     Sources: SessionExec, lateral-movement-writeups/rdp-hijacking
#     Admin FP: Admin reconnecting to their own disconnected session
# ═══════════════════════════════════════════════════════════════════════════════

def _rdp_hijack_tp(i):
    victim_user = _user(); attacker = _host()
    victim_session = random.randint(1, 10)
    p = {
        "victim": victim_user, "attacker": attacker,
        "session_id": victim_session,
        "tscon_parent": "SYSTEM",
        "api_seq": ["WTSEnumerateSessions() -- listed all sessions",
                    f"WTSQuerySessionInformation(session {victim_session}) -- found disconnected session",
                    f"tscon.exe {victim_session} /dest:console -- hijacked to attacker session"],
        "event_4778": True, "event_4779": True,
        "same_user_reconnect": False,
    }
    prompt = (f"Windows Sysmon -- RDP Session Hijack.\n"
              f"Attacker Host: {p['attacker']}\n"
              f"  victim_account: {p['victim']}\n"
              f"  target_session_id={p['session_id']} (previously disconnected)\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  tscon_parent_context: {p['tscon_parent']}\n"
              f"  event_4779_victim_disconnected=YES\n"
              f"  event_4778_session_reconnected=YES\n"
              f"  reconnecting_user_differs_from_session_owner=YES")
    cot = _cot(
        "Legitimate RDP session reconnection is user-initiated (user clicks 'Connect' in Remote "
        "Desktop or MRC). When a user reconnects, Event 4778 shows the SAME account reconnecting "
        "to their own session. tscon.exe is only used by admins for specific troubleshooting.",
        f"tscon.exe with parent=SYSTEM: automated session hijack, not user action. "
        f"WTSEnumerateSessions: attacker enumerated all sessions to find {p['victim']}'s disconnected one. "
        f"Event 4779 (disconnect) followed by 4778 (reconnect) for {p['victim']}'s session -- "
        f"but reconnecting account is the attacker, not {p['victim']}. "
        "Attacker now has full access to victim's desktop, files, and running applications.",
        f"Host {p['attacker']}: attacker has hijacked {p['victim']}'s RDP session (session {p['session_id']}). "
        "All victim's data, credentials, and applications are accessible.",
        "RDP session hijack confirmed.",
        "MITRE T1563.002 (Remote Service Session Hijacking: RDP Hijacking). "
        "Terminate hijacked session, change victim's password, enable NLA.",
    )
    return prompt, cot, "true_positive"

def _rdp_hijack_fp(i):
    p = {"user": _user(), "session": random.randint(1,5), "reason": "reconnecting own session"}
    prompt = (f"Windows Sysmon -- RDP Session Reconnect.\n"
              f"  user={p['user']}  session_id={p['session']}\n"
              f"  reason={p['reason']}\n"
              f"  reconnecting_user_matches_session_owner=YES  tscon=NO  user_initiated=YES")
    cot = _cot(
        "User reconnecting to their own RDP session -- same account, user-initiated, no tscon.exe.",
        f"reconnecting_user=session_owner. user_initiated=YES. No tscon.exe.",
        "Authorized user self-reconnect to own RDP session.",
        "Authorized RDP session reconnect. No action.",
        "T1563.002 -- AUTHORIZED SELF-RECONNECT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. WinRMLateral
#     Evidence: Inbound WinRM connection (port 5985/5986) from non-admin source,
#               wsmprovhost.exe spawning unexpected child processes,
#               PowerShell remoting session without prior IT authorization
#     Sources: lateral-movement-writeups/t1028-winrm, Amnesiac Invoke-WMIRemoting
#     Admin FP: Authorized IT remote management (IT SA, change ticket, known source)
# ═══════════════════════════════════════════════════════════════════════════════

def _winrm_tp(i):
    src = _ip_int(); target = _ip_int()
    p = {
        "src": src, "target": target,
        "port": random.choice([5985, 5986]),
        "child_proc": random.choice(["cmd.exe","powershell.exe","net.exe","whoami.exe"]),
        "wsmprovhost_parent": True,
        "hours": random.choice([2, 3, 23, 0, 1]),  # off-hours
    }
    prompt = (f"Network Tap + Sysmon -- WinRM Lateral Movement.\n"
              f"Source: {p['src']} → Target: {p['target']}:{p['port']}\n"
              f"  protocol={'HTTP' if p['port']==5985 else 'HTTPS'} WinRM\n"
              f"  wsmprovhost.exe_spawned=YES\n"
              f"  child_process: {p['child_proc']} (parent=wsmprovhost.exe)\n"
              f"  source_in_it_admin_group=NO\n"
              f"  time_of_connection={p['hours']:02d}:xx (off-hours)")
    cot = _cot(
        "WinRM is used by IT for remote management, but from known management workstations in "
        "the IT admin group, during business hours, with change tickets for production systems.",
        f"Source {p['src']} not in IT admin group: WinRM from unauthorized host. "
        f"Off-hours ({p['hours']:02d}:xx). "
        f"wsmprovhost.exe spawning {p['child_proc']}: commands executed via remoting. "
        f"No change ticket correlated with this connection.",
        f"Source {p['src']} has authenticated WinRM session to {p['target']}. "
        "All commands appear as wsmprovhost.exe children -- bypasses some process-based rules.",
        "Unauthorized WinRM lateral movement confirmed.",
        "MITRE T1021.006 (Remote Services: Windows Remote Management). "
        "Block WinRM from non-IT sources, review commands in wsmprovhost.exe process tree.",
    )
    return prompt, cot, "true_positive"

def _winrm_fp(i):
    p = {"src": "mgmt-ws-01", "group": "IT_Admins", "ticket": f"CHG-{random.randint(10000,99999)}", "hour": random.randint(9,16)}
    prompt = (f"Network Tap -- WinRM Remote Management.\n"
              f"  source=mgmt-ws-01  source_group={p['group']}\n"
              f"  ticket={p['ticket']}  hour={p['hour']}:xx (business hours)\n"
              f"  source_in_approved_mgmt_list=YES")
    cot = _cot(
        "IT admin WinRM from approved management workstation during business hours with ticket.",
        f"IT_Admins group. Business hours. Ticket {p['ticket']}. Approved source.",
        "Authorized IT WinRM management. No action.",
        "Authorized WinRM from IT admin. No action.",
        "T1021.006 -- AUTHORIZED IT WINRM. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 14. NamedPipeShellLateral
#     Evidence: Service creation with PowerShell-based binary path,
#               named pipe creation immediately after service start,
#               reverse shell back to attacker via named pipe
#     Sources: Invoke-SMBRemoting named pipe mode, Amnesiac Invoke-SMBRemoting
#     Admin FP: SQL Server named pipe (vendor format, service account)
# ═══════════════════════════════════════════════════════════════════════════════

def _npipe_tp(i):
    target = _host(); src = _host()
    svc = _svc_name()
    pipe = f"pipe_{random.randint(100000,999999)}"
    payload = f"cmd.exe /c powershell.exe -nop -w hidden -enc {''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=40))}"
    p = {
        "src": src, "target": target, "svc": svc, "pipe": pipe,
        "service_binary_path": payload,
        "event_7045": True, "event_7034": True,  # service created + terminated
        "pipe_callback_to_src": True,
    }
    prompt = (f"Windows Sysmon -- Named Pipe Shell via Service Lateral.\n"
              f"Source: {p['src']} → Target: {p['target']}\n"
              f"  service_created: {p['svc']} (Event 7045)\n"
              f"  service_binary_path: {p['service_binary_path'][:70]}\n"
              f"  named_pipe_created: \\\\.\\pipe\\{p['pipe']}\n"
              f"  pipe_connects_back_to: {p['src']}\n"
              f"  service_terminated_after_exec=YES (Event 7034)\n"
              f"  interactive_shell_via_pipe=YES")
    cot = _cot(
        "SQL Server and other legitimate applications create named pipes, but they follow "
        "vendor-format naming (\\\\MSSQL$<instance>\\sql\\query) and are associated with "
        "long-running services. A service with a PowerShell binary path that creates a "
        "randomly-named pipe connecting back to the attacker is not any vendor service.",
        f"Service '{p['svc']}' created with binary_path=cmd.exe /c powershell.exe -enc (not a service binary). "
        f"Named pipe \\\\.\\pipe\\{p['pipe']} created immediately after service start. "
        f"Pipe connects back to {p['src']}: reverse shell channel. "
        "Service terminates after establishing pipe -- one-shot execution, not persistent. "
        "Pattern: service creates pipe → pipe provides interactive shell → attacker controls target.",
        f"Target {p['target']}: interactive shell available to source {p['src']} via named pipe. "
        "Attacker has full command execution through the pipe.",
        "Named pipe reverse shell via service lateral movement confirmed.",
        "MITRE T1021.002 (SMB/Windows Admin Shares) + T1059.001 (PowerShell). "
        "Kill service, block named pipe connection, isolate target.",
    )
    return prompt, cot, "true_positive"

def _npipe_fp(i):
    p = {"pipe": "MSSQL$PROD\\sql\\query", "svc": "MSSQLSERVER", "sa": "NT SERVICE\\MSSQLSERVER"}
    prompt = (f"Sysmon -- SQL Server Named Pipe.\n"
              f"  pipe_name: \\\\.\\pipe\\{p['pipe']}\n"
              f"  service={p['svc']}  service_account={p['sa']}\n"
              f"  vendor_pipe_format=YES  service_binary_in_program_files=YES")
    cot = _cot(
        "SQL Server named pipe -- vendor format, MSSQL service account, program files binary.",
        f"pipe=MSSQL$ (vendor format). sa={p['sa']}. program_files binary.",
        "Authorized SQL Server named pipe. No action.",
        "Authorized SQL Server named pipe. No action.",
        "T1021.002 -- AUTHORIZED SQL SERVER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 15. PassiveNetworkDiscovery
#     Evidence: Packet capture on network interface without sending any traffic,
#               device fingerprinting from broadcast protocols (DHCP, SSDP, mDNS),
#               no outbound connections from the sniffing process
#     Sources: passive_sensor (Go -- listens to broadcast protocols)
#     Admin FP: Authorized network performance monitoring (known tool, CMDB)
# ═══════════════════════════════════════════════════════════════════════════════

def _passive_net_tp(i):
    sniffer_ip = _ip_int()
    protocols = random.sample(["DHCP:67/68","SSDP:1900","mDNS:5353","NetBIOS:137/138",
                                "WS-Discovery:3702","LLDP:multicast"], k=random.randint(3,5))
    p = {
        "host": sniffer_ip,
        "protocols": protocols,
        "devices_discovered": random.randint(10, 150),
        "no_outbound_connections": True,
        "promiscuous_mode": False,  # passive_sensor uses multicast listeners
        "duration_h": round(random.uniform(0.5, 8.0), 1),
    }
    prompt = (f"Network Tap -- Passive Network Discovery Sensor.\n"
              f"Sniffer Host: {p['host']}\n"
              f"  protocols_monitored: {', '.join(p['protocols'])}\n"
              f"  devices_fingerprinted={p['devices_discovered']}\n"
              f"  outbound_connections_from_sniffer=0\n"
              f"  promiscuous_mode={p['promiscuous_mode']}\n"
              f"  observation_duration_h={p['duration_h']}\n"
              f"  data_includes: MAC/OUI vendor, hostnames, IP, OS hints")
    cot = _cot(
        "Network monitoring tools (SNMP, Nagios, Zabbix) actively poll devices and are "
        "registered in the CMDB with known source IPs and scheduled operation windows. "
        "A process silently listening to all broadcast protocols from an unregistered host "
        "without sending any traffic is not an authorized monitoring tool.",
        f"Sniffer listening to {len(p['protocols'])} broadcast protocols (DHCP/SSDP/mDNS/NetBIOS): "
        "building a passive device inventory without announcing itself. "
        f"{p['devices_discovered']} devices fingerprinted from MAC/OUI + hostname announcements. "
        "zero outbound connections: completely silent to IDS/network detection. "
        f"Running for {p['duration_h']}h: sustained intelligence gathering operation.",
        f"Host {p['host']} has built a passive network map including device types, "
        "hostnames, and OS hints for {p['devices_discovered']} devices. "
        "This intelligence enables targeted lateral movement to specific device types.",
        "Passive network discovery confirmed -- silent broadcast protocol monitoring.",
        "MITRE T1018 (Remote System Discovery) + T1040 (Network Sniffing). "
        "Identify sniffer host, audit what data was captured, isolate if unauthorized.",
    )
    return prompt, cot, "true_positive"

def _passive_net_fp(i):
    p = {"tool": "Zabbix passive checks", "source": "monitoring.corp.local",
         "cmdb": "YES", "schedule": "every 60s"}
    prompt = (f"Network Tap -- Monitoring System Passive Checks.\n"
              f"  tool={p['tool']}  source={p['source']}\n"
              f"  cmdb_registered={p['cmdb']}  schedule={p['schedule']}\n"
              f"  source_in_approved_monitoring_list=YES")
    cot = _cot(
        "Zabbix passive monitoring from CMDB-registered source -- authorized, scheduled.",
        f"CMDB registered. Known source. Scheduled. Authorized monitoring.",
        "Authorized network monitoring. No action.",
        "Authorized monitoring. No action.",
        "T1040 -- AUTHORIZED MONITORING. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 16. ReachableHostScan
#     Evidence: TCP connect scan from compromised host to internal subnet,
#               rapid fan-out to multiple internal hosts on service ports,
#               CheckReachableHosts.ps1 / NBTScan pattern
#     Sources: CheckReachableHosts.ps1, NBTScan.txt
#     Admin FP: IT asset scan (bounded ports, business hours, IT SA, change ticket)
# ═══════════════════════════════════════════════════════════════════════════════

def _reach_host_tp(i):
    src = _ip_int()
    ports_scanned = random.sample([22,80,443,445,3389,5985,135,139,21,23], k=random.randint(4,8))
    p = {
        "src": src,
        "subnet": f"{'.'.join(_ip_int().split('.')[:3])}.0/24",
        "hosts_probed": random.randint(50, 254),
        "ports": ports_scanned,
        "reachable_found": random.randint(10, 60),
        "cv": round(random.uniform(0.0, 0.08), 4),
        "nbtstat_queries": i%2==0,
    }
    prompt = (f"Network Tap -- Internal Reachability Scan from Compromised Host.\n"
              f"Source: {p['src']} → Subnet: {p['subnet']}\n"
              f"  hosts_probed={p['hosts_probed']}  reachable_found={p['reachable_found']}\n"
              f"  ports_tested={p['ports']}\n"
              f"  inter_probe_cv={p['cv']:.4f} (machine-generated)\n"
              + (f"  netbios_stat_queries=YES (hostname resolution)\n" if p['nbtstat_queries'] else "")
              + f"  source_in_it_asset_inventory=NO")
    cot = _cot(
        "IT asset discovery uses bounded port lists during business hours from known management "
        "workstations registered in the CMDB. A compromised workstation performing subnet-wide "
        "TCP connect scans on lateral movement-relevant ports (SMB:445, RDP:3389, WinRM:5985) "
        "at machine-generated timing is not authorized IT activity.",
        f"Fan-out to {p['hosts_probed']} hosts across {p['subnet']} testing {len(p['ports'])} ports: "
        f"{p['ports']}. "
        f"cv={p['cv']:.4f} (machine-generated sweep, not human browsing). "
        f"Ports include lateral movement vectors: SMB(445), RDP(3389), WinRM(5985), SCM(135). "
        + (f"NetBIOS stat queries: attacker mapping hostnames to IPs for targeting. " if p['nbtstat_queries'] else "")
        + f"Source {p['src']} not in IT asset inventory.",
        f"Source {p['src']} is mapping {p['hosts_probed']} internal hosts for lateral movement targets. "
        f"Found {p['reachable_found']} reachable hosts with open lateral movement ports.",
        "Internal reachability scan from compromised host confirmed.",
        "MITRE T1018 (Remote System Discovery) + T1046 (Network Service Discovery). "
        "Isolate source, review which hosts were found reachable -- likely next lateral movement targets.",
    )
    return prompt, cot, "true_positive"

def _reach_host_fp(i):
    p = {"src": "nessus-scanner-01", "ports": "22,80,443", "ticket": f"SEC-{random.randint(100,999)}",
         "hour": random.randint(9,16)}
    prompt = (f"Network Tap -- Authorized Vulnerability Scan.\n"
              f"  source=nessus-scanner-01  ports={p['ports']}\n"
              f"  ticket={p['ticket']}  hour={p['hour']}:xx\n"
              f"  scanner_in_cmdb=YES  scope_approved=YES")
    cot = _cot(
        "Nessus scanner from CMDB-registered source, bounded ports, approved scope, ticket.",
        f"CMDB registered. Approved scope. Ticket {p['ticket']}. Business hours.",
        "Authorized vulnerability scan. No action.",
        "Authorized Nessus scan. No action.",
        "T1046 -- AUTHORIZED VULN SCAN. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. SSHSnakePivoting
#     Evidence: Recursive SSH connections forming A→B→C chain,
#               key discovery and use in sequence, no script files on disk,
#               bash receiving SSH-Snake script via stdin
#     Sources: ssh-snake/Snake.sh
#     Admin FP: Ansible playbook SSH (known source, bounded, service account)
# ═══════════════════════════════════════════════════════════════════════════════

def _ssh_snake_tp(i):
    hop1 = _ip_int(); hop2 = _ip_int(); hop3 = _ip_int()
    p = {
        "hop1": hop1, "hop2": hop2, "hop3": hop3,
        "ssh_chain_depth": random.randint(3, 8),
        "keys_discovered": random.randint(2, 15),
        "no_files_on_disk": True,
        "script_via_stdin": True,
        "bash_cmdline": "bash -c 'bash <(base64 -d <<<...)'",
        "hosts_enumerated": random.randint(10, 100),
    }
    prompt = (f"Linux Sentinel -- SSH Snake Recursive Pivoting.\n"
              f"Chain: {p['hop1']} → {p['hop2']} → {p['hop3']} → ...\n"
              f"  ssh_chain_depth={p['ssh_chain_depth']}\n"
              f"  private_keys_discovered={p['keys_discovered']}\n"
              f"  script_on_disk=NO (delivered via stdin)\n"
              f"  bash_invocation: {p['bash_cmdline']}\n"
              f"  hosts_in_known_hosts_enumerated={p['hosts_enumerated']}\n"
              f"  ssh_parent=sshd  bash_child_of_sshd=YES")
    cot = _cot(
        "Ansible and legitimate SSH automation use bounded playbooks from known source IPs, "
        "connect to specific hosts, and do not recursively discover and pivot from each "
        "compromised host to all its known_hosts.",
        f"SSH chain depth={p['ssh_chain_depth']}: each compromised host discovers and connects "
        "to all its known_hosts -- recursive lateral movement. "
        f"Private keys discovered: {p['keys_discovered']} keys used for pivoting without password. "
        "Script delivered via stdin (no disk file): forensically clean, no file artifacts. "
        f"bash child of sshd: script running inside SSH session with no file on disk. "
        f"Hosts enumerated from known_hosts: {p['hosts_enumerated']} potential pivot targets.",
        f"SSH Snake active with {p['ssh_chain_depth']}-hop chain. "
        f"{p['hosts_enumerated']} hosts being recursively compromised. "
        "Attack spreads automatically to any host with trusted SSH keys.",
        "SSH recursive lateral movement (SSH Snake) confirmed.",
        "MITRE T1021.004 (Remote Services: SSH) + T1552.004 (Private Keys). "
        "Audit all hosts in known_hosts chain, rotate SSH keys network-wide.",
    )
    return prompt, cot, "true_positive"

def _ssh_snake_fp(i):
    p = {"tool": "Ansible", "source": "ansible-controller.corp.local",
         "playbook": "deploy_updates.yml", "sa": "svc-ansible", "hosts": "production group"}
    prompt = (f"Linux Sentinel -- Ansible SSH Automation.\n"
              f"  source={p['source']}  tool={p['tool']}\n"
              f"  playbook={p['playbook']}  account={p['sa']}\n"
              f"  hosts={p['hosts']}  depth=1 (no recursive pivot)\n"
              f"  script_file_on_disk=YES  bounded_targets=YES")
    cot = _cot(
        "Ansible from known controller -- bounded targets, service account, script on disk, no recursion.",
        f"Known source. Bounded target group. Service account. Script file on disk. Depth=1.",
        "Authorized Ansible automation. No action.",
        "Authorized Ansible SSH. No action.",
        "T1021.004 -- AUTHORIZED ANSIBLE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. FailoverClusterLateral
#     Evidence: DCERPC bindings to cluster service UUID from non-cluster admin,
#               ApiGetClusterName + ApiCreateEnum calls enumerating nodes/resources,
#               HKLM\Cluster registry reads for VCO credential extraction
#     Sources: fustercluck.py
#     Admin FP: Cluster admin using Failover Cluster Manager (authorized role)
# ═══════════════════════════════════════════════════════════════════════════════

def _cluster_tp(i):
    cluster_node = _host()
    src = _ip_int()
    p = {
        "src": src, "cluster_node": cluster_node,
        "rpc_calls": ["ApiGetClusterName (opnum 3) -- cluster name + node",
                      "ApiCreateEnum(CLUSTER_ENUM_NODE) -- list all nodes",
                      "ApiCreateEnum(CLUSTER_ENUM_RESOURCE) -- list all resources",
                      "ApiCreateEnum(CLUSTER_ENUM_GROUP) -- list cluster groups",
                      "ApiCreateEnum(CLUSTER_ENUM_NETWORK) -- list networks"],
        "registry_access": r"HKLM\Cluster\ResourceData",
        "vco_creds_targeted": True,
        "s4u_kerberos": True,
    }
    prompt = (f"Network Tap + Sysmon -- Windows Failover Cluster Lateral Movement.\n"
              f"Source: {p['src']} → Cluster Node: {p['cluster_node']}\n"
              f"  RPC_calls:\n    " + "\n    ".join(p['rpc_calls']) + "\n"
              f"  registry_access: {p['registry_access']}\n"
              f"  vco_credential_extraction_targeted=YES\n"
              f"  kerberos_s4u2self=YES (virtual computer object auth)\n"
              f"  source_in_cluster_admin_group=NO")
    cot = _cot(
        "Windows Failover Cluster Manager uses these same API calls for legitimate cluster "
        "management, but the tool runs as a cluster administrator from known management "
        "workstations. These API calls from a non-cluster-admin account via a port-135 "
        "connection indicate unauthorized cluster reconnaissance.",
        f"DCERPC bindings to cluster service UUID from {p['src']}: "
        "ApiGetClusterName + ApiCreateEnum for all resource types = full cluster enumeration. "
        f"HKLM\\Cluster\\ResourceData access: targeting VCO (Virtual Computer Object) encrypted credentials. "
        "Kerberos S4U2Self: machine account used to obtain service tickets for cluster resources. "
        "Source not in cluster admin group: unauthorized access.",
        f"Cluster {p['cluster_node']}: full infrastructure map obtained including all nodes, "
        "resources, groups, and networks. VCO credentials enable authenticated access to "
        "all cluster-hosted workloads.",
        "Windows Failover Cluster lateral movement/credential extraction confirmed.",
        "MITRE T1018 (Remote System Discovery) + T1078 (Valid Accounts via VCO creds). "
        "Audit cluster access, rotate VCO passwords, restrict cluster RPC access.",
    )
    return prompt, cot, "true_positive"

def _cluster_fp(i):
    p = {"acct": "svc-cluster-admin", "tool": "Failover Cluster Manager",
         "ticket": f"OPS-{random.randint(100,999)}"}
    prompt = (f"Network Tap -- Cluster Management Access.\n"
              f"  account={p['acct']}  tool={p['tool']}\n"
              f"  ticket={p['ticket']}  source_in_cluster_admin_group=YES\n"
              f"  authorized_maintenance_window=YES")
    cot = _cot(
        "Cluster admin using Failover Cluster Manager -- authorized role, maintenance window, ticket.",
        f"cluster_admin_group=YES. FCM tool. Ticket {p['ticket']}. Maintenance window.",
        "Authorized cluster management. No action.",
        "Authorized cluster management. No action.",
        "T1018 -- AUTHORIZED CLUSTER MGMT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. AmnesiacHiveDump
#     Evidence: Registry hive mounting + raw read of SAM/SYSTEM/SECURITY hives,
#               Invoke-GrabTheHash: shadow copy access for offline hive extraction,
#               HiveDump.ps1: in-memory reg.exe shadow output parsing
#     Sources: Amnesiac/Tools/HiveDump.ps1, Invoke-GrabTheHash.ps1
#     Admin FP: Authorized DFIR registry hive backup (signed tool, IR ticket)
# ═══════════════════════════════════════════════════════════════════════════════

def _hive_tp(i):
    target = _host()
    method = random.choice([
        "reg save HKLM\\SAM + HKLM\\SYSTEM + HKLM\\SECURITY to temp",
        "shadow copy mount + direct .hiv file copy",
        "NtSaveKeyEx (native API) to bypass VSS requirement",
    ])
    p = {
        "host": target,
        "method": method,
        "hives": ["SAM","SYSTEM","SECURITY"],
        "parent": random.choice(["powershell.exe","wscript.exe","cmd.exe"]),
        "output_path": f"C:\\Windows\\Temp\\{random.randint(100,999)}",
        "event_4656": True,
    }
    prompt = (f"Windows Sysmon -- Registry Hive Dump (Credential Extraction).\n"
              f"Host: {p['host']}\n"
              f"  method: {p['method']}\n"
              f"  hives_targeted: {', '.join(p['hives'])}\n"
              f"  parent_process: {p['parent']}\n"
              f"  output_path: {p['output_path']}\n"
              f"  event_4656_object_access_SAM=YES\n"
              f"  output_in_temp=YES")
    cot = _cot(
        "Authorized registry hive backups for DR or forensics are performed with signed tools "
        "(Windows Backup, NTBackup) under dedicated service accounts, not interactively from "
        "PowerShell or wscript.exe, and are not stored in %TEMP%.",
        f"Hives targeted: {', '.join(p['hives'])} -- the credential store triad for local hash extraction. "
        f"Method: {p['method']}. "
        f"Parent={p['parent']} (not a backup tool). "
        f"Output to {p['output_path']} (temp path for staging/exfil). "
        "Event 4656 SAM object access confirms credential store read.",
        f"Host {p['host']}: SAM/SYSTEM/SECURITY hives extracted. "
        "These three files together enable offline extraction of all local account NTLM hashes.",
        "Registry hive dump for credential extraction confirmed.",
        "MITRE T1003.002 (OS Credential Dumping: Security Account Manager). "
        "Delete hive files from temp, change all local account passwords, isolate host.",
    )
    return prompt, cot, "true_positive"

def _hive_fp(i):
    p = {"tool": "ntbackup.exe", "sa": "svc-backup", "ticket": f"IR-{random.randint(100,999)}",
         "dest": r"\\backup-server\share\registry"}
    prompt = (f"Windows Sysmon -- Registry Backup.\n"
              f"  tool={p['tool']}  account={p['sa']}\n"
              f"  destination={p['dest']}  ticket={p['ticket']}\n"
              f"  signed=YES  authorized_role=backup_operator")
    cot = _cot(
        "Authorized registry backup using ntbackup -- service account, backup destination, IR ticket.",
        f"ntbackup.exe (signed). svc-backup. Network backup destination (not temp). Ticket.",
        "Authorized registry backup by backup operator.",
        "Authorized registry backup. No action.",
        "T1003.002 -- AUTHORIZED BACKUP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 20. SMBSigningAbuse
#     Evidence: SMB traffic without Message Signing (Signature=0/disabled),
#               relay of captured credential to third host within 3s,
#               service/file creation on relay target with relayed credentials
#     Sources: lateral-movement-writeups/smb-relaying
#     Admin FP: No admin FP -- relaying without signing to a third host is always adversarial
# ═══════════════════════════════════════════════════════════════════════════════

def _smb_sign_tp(i):
    victim = _ip_int(); relay = _ip_int(); target = _ip_int()
    p = {
        "victim": victim, "relay": relay, "target": target,
        "smb_signing_on_target": False,
        "relay_delay_ms": random.randint(100, 2500),
        "post_relay": random.choice(["file write to C$", "service creation + execution", "registry modification"]),
        "relay_tool_indicator": "NTLMSSP negotiation flags: signing=NOT_REQUIRED",
    }
    prompt = (f"Network Tap -- SMB Relay via Signing Bypass.\n"
              f"Victim: {p['victim']}  Relay: {p['relay']}  Target: {p['target']}\n"
              f"  smb_signing_required_on_target=NO\n"
              f"  ntlmssp_flags: SIGNING_NOT_REQUIRED\n"
              f"  credential_capture_to_relay_ms={p['relay_delay_ms']}\n"
              f"  post_relay_action: {p['post_relay']}\n"
              f"  relay_indicator: {p['relay_tool_indicator']}")
    cot = _cot(
        "SMB without signing is a misconfiguration, but by itself is not an attack. "
        "The attack is the relay: capturing credentials from one host and using them against "
        "a third host within milliseconds.",
        f"SMB signing disabled on {p['target']}: relay is possible. "
        f"Credential captured from {p['victim']} relayed to {p['target']} in {p['relay_delay_ms']}ms. "
        f"NTLMSSP SIGNING_NOT_REQUIRED flag: relay tool actively downgrading signing. "
        f"Post-relay action '{p['post_relay']}' on {p['target']}: code/file execution with relayed credentials.",
        f"Target {p['target']}: attacker authenticated using {p['victim']}'s credentials. "
        f"Any resource accessible to {p['victim']} is now accessible to attacker on {p['target']}.",
        "SMB relay via signing bypass confirmed.",
        "MITRE T1557.001 (Adversary-in-the-Middle) + T1021.002 (SMB/Admin Shares). "
        "Enable SMB signing globally, isolate relay host, reset credentials.",
    )
    return prompt, cot, "true_positive"

def _smb_sign_fp(i):
    p = {"host": _ip_int(), "reason": "legacy application compatibility",
         "signing": "not_required (not disabled)", "ticket": f"NET-{random.randint(100,999)}"}
    prompt = (f"Network Tap -- SMB Without Required Signing.\n"
              f"  host={p['host']}  smb_signing={p['signing']}\n"
              f"  reason={p['reason']}  no_relay_detected=YES\n"
              f"  exception_ticket={p['ticket']}")
    cot = _cot(
        "SMB signing not required on legacy app host -- misconfiguration, no active relay observed.",
        f"signing=not_required (not disabled). No relay observed. Legacy exception. Ticket {p['ticket']}.",
        "SMB misconfiguration on legacy host -- no active relay. Remediate signing.",
        "SMB signing misconfiguration. Remediate.",
        "T1557 -- MISCONFIGURATION, NOT ACTIVE RELAY. Enforce signing.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# WormSelfPropagation (from Framework-Botnet/NetworkSpreader.cpp)
#   Evidence: infected host immediately scans adjacent subnets after initial
#             compromise, identical payload binary pushed to each new host via
#             SMB/WMI/SSH, each new host repeats the same scan/push cycle --
#             exponential fan-out with correlated payload hashes
#   Admin FP: SCCM/Ansible push-deployment to known host list (bounded, service
#             account, change ticket, no scan fan-out from target hosts)
# ═══════════════════════════════════════════════════════════════════════════════

def _wsp_tp(i):
    proto      = random.choice(["SMB","WMI","SSH","WinRM"])
    port       = {"SMB":445,"WMI":135,"SSH":22,"WinRM":5985}[proto]
    gen0       = _ip_int()
    gen1_count = random.randint(3, 12)
    gen2_count = gen1_count * random.randint(2, 5)
    payload_hash = "".join(random.choices("0123456789abcdef", k=16))
    scan_range = f"{'.'.join(gen0.split('.')[:3])}.0/24"
    latency_s  = random.randint(5, 60)
    host       = _host()

    prompt = (f"Network Tap -- Worm Self-Propagation Pattern.\n"
              f"Source (gen0): {gen0} ({host})\n"
              f"  phase_1_scan: subnet_scanned={scan_range}  port={port} ({proto})\n"
              f"  phase_2_push: payload_pushed_to={gen1_count} hosts  protocol={proto}\n"
              f"    payload_hash_all_copies={payload_hash}  (identical binary on each)\n"
              f"    latency_compromise_to_scan_s={latency_s}  (new host scans immediately)\n"
              f"  gen1_hosts_now_scanning=YES  ({gen1_count} hosts each scanning /24)\n"
              f"  gen2_projected_infections={gen2_count}\n"
              f"  no_operator_interaction=YES  (fully automated spread)\n"
              f"  scan_originates_from_target=YES  (target becomes scanner after infection)")

    cot = _cot(
        f"SCCM and Ansible deployments push to a pre-defined bounded host list -- targets "
        "never become scanners themselves. No legitimate deployment tool copies itself to "
        f"{gen1_count} hosts and then has each of those hosts begin scanning their own /24 "
        f"subnet within {latency_s} seconds.",
        f"Identical payload hash ({payload_hash}) on all {gen1_count} targets = same binary pushed. "
        f"Latency from compromise to scan={latency_s}s (automated -- no human interaction). "
        f"Each gen1 host immediately begins scanning its own /24 subnet (self-replication confirmed). "
        f"gen2 projected infections: {gen2_count} hosts from this single gen0 origin.",
        f"Worm outbreak initiated from {gen0}. Propagation is exponential -- gen1={gen1_count}, "
        f"gen2≈{gen2_count}. Every infected host becomes an additional propagation source.",
        "Worm self-propagation confirmed -- fan-out scan + identical payload + infected hosts become scanners.",
        "MITRE T1210 + T1570 (Exploit Remote Services + Lateral Tool Transfer). "
        "Emergency network segmentation -- isolate affected subnets, block scan ports at switches, "
        "enumerate all hosts with payload hash via EDR.",
    )
    return prompt, cot, "true_positive"

def _wsp_fp(i):
    host_count = random.randint(10, 200)
    prompt = (f"Network Tap -- Software Deployment Push.\n"
              f"  source=SCCM-SRV-01  account=svc-sccm  protocol=SMB\n"
              f"  targets={host_count}  (pre-defined host list from CMDB)\n"
              f"  payload_hash=consistent  payload_signed=YES  vendor_cert=corp-pki\n"
              f"  targets_scan_after_install=NO  automated_spread=NO\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}  maintenance_window=YES")
    cot = _cot(
        f"SCCM deployment to {host_count} pre-defined hosts from CMDB: signed payload, "
        "change ticket, no scan fan-out from targets after deployment.",
        f"Source=SCCM-SRV-01 (known deployment server). Targets pre-defined (CMDB list). "
        "Payload signed by corp PKI. targets_scan_after_install=NO. Change ticket. Maintenance window.",
        "Authorized SCCM software deployment -- bounded targets, no propagation from targets.",
        f"SCCM push to {host_count} CMDB hosts -- signed, change ticket, no target-initiated spread.",
        "T1570 -- AUTHORIZED SCCM DEPLOYMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# -- Extension: 3 additional lateral movement classes -------------------------

def _bhood_tp(i):
    host  = _host(); dc = f"DC{random.randint(1,3):02d}"
    hosts = [f"{random.choice(['WS','SRV'])}-{random.randint(10,99)}" for _ in range(random.randint(3,8))]
    user  = random.choice(["jsmith","alee","tmorgan"])
    prompt = (f"Windows Host Telemetry -- BloodHound-Discovered Attack Path Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1_enum: rapid LDAP queries to {dc}\n"
              f"    query_rate=200/min  objects_queried=GenericWrite,AdminTo,MemberOf\n"
              f"    SharpHound_IOC=YES  (ACL + session + group + trust enumeration)\n"
              f"  stage_2_exploit_path (automated, <120s after enum):\n"
              f"    EventID=5136 (AD object change): user added to group (GenericWrite)\n"
              f"    EventID=4624 (lateral login): new admin sessions to: {', '.join(hosts[:3])}\n"
              f"    lateral_spread_velocity=HIGH  time_from_enum_to_lateral=45s\n"
              f"    (humans take hours to manually exploit BloodHound paths -- this is automated)")
    cot = _cot(
        "IT admins query LDAP for directory management. Legitimate changes: "
        "slow, one at a time, with change tickets, spread over hours/days.",
        "LDAP query rate 200/min + SharpHound ACL patterns = automated BloodHound collection. "
        "AD group modification + lateral logins within 45 seconds = automated path exploitation "
        "(not humanly possible to manually chain this quickly). "
        f"Spread to {len(hosts)} hosts in <2 minutes.",
        f"Host {host} ({user}): BloodHound path exploited -- AD object modified, lateral spread "
        f"to {len(hosts)} hosts in <120s.",
        "BloodHound automated attack path confirmed -- rapid enum + AD change + lateral.",
        "MITRE T1069.002 + T1078.003. Reset affected accounts. Review AD ACL changes. "
        "Scope lateral spread on all reached hosts.",
    )
    return prompt, cot, "true_positive"

def _bhood_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized IT Directory Audit.\n"
              f"  LDAP query rate=3/min  context=quarterly_AD_audit\n"
              f"  user=svc-directory-audit  (read-only service account)\n"
              f"  no_AD_object_changes=YES  no_lateral_logins=YES\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "Authorized quarterly AD audit -- read-only, slow, change ticket, no object changes.",
        "Read-only. Slow rate. No object changes. No lateral logins. Change ticket.",
        "Authorized AD audit -- read-only, slow, no changes.",
        "AD audit -- read-only service account, slow, no changes.",
        "T1069.002 -- AUTHORIZED AUDIT. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _scm_supply_tp(i):
    host = _host(); user = _user()
    svc  = random.choice(["SplunkForwarder","NessusAgent","SnortAgent","SolarWindsAgent"])
    dll  = f"C:\\Program Files\\{svc}\\{''.join(random.choices('abcdef',k=6))}.dll"
    prompt = (f"Windows Host Telemetry -- Software Supply Chain SCM Lateral Movement.\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1_hijack: EventID=7 (ImageLoaded)\n"
              f"    Image: {svc}.exe  ImageLoaded: {dll}\n"
              f"    Signed: false  (replaced legitimate DLL with malicious copy)\n"
              f"  stage_2_service_restart: EventID=7045 or Service stop/start\n"
              f"    {svc} service restarted -- loads malicious DLL\n"
              f"  stage_3_lateral: EventID=3 (Network Connection)\n"
              f"    Image: {svc}.exe  DestinationIp={_ip_int()}  DestinationPort=4444\n"
              f"    (legitimate software agent making C2 connection -- hard to detect)\n"
              f"  EventID=1: cmd.exe child of {svc}.exe (unexpected for monitoring agent)")
    cot = _cot(
        f"{svc} is a legitimate monitoring/security agent with network access. "
        "Legitimate operation: connects to vendor infrastructure, loads signed DLLs.",
        f"Unsigned DLL loaded by {svc}.exe from its installation dir = DLL replacement "
        f"(signed DLL replaced by attacker). {svc} service then connects to internal IP "
        "on non-standard port = malicious lateral movement using trusted agent's "
        "network access. cmd.exe child from monitoring agent = DLL payload executed.",
        f"Host {host}: {svc} agent hijacked -- unsigned DLL → C2 connection via trusted agent.",
        f"SCM supply chain lateral confirmed -- {svc} DLL replaced + C2.",
        "MITRE T1543.003 + T1021.002. Reinstall {svc}, rotate service credentials, "
        "audit all hosts running {svc} for same DLL modification.",
    )
    return prompt, cot, "true_positive"

def _scm_supply_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized Agent Update.\n"
              f"  EventID=7  Image: SplunkForwarder.exe\n"
              f"    ImageLoaded: C:\\Program Files\\SplunkUniversalForwarder\\libcrypto-3-x64.dll\n"
              f"    Signed=true  SignatureIssuer=Splunk Inc.\n"
              f"  update_triggered_by=SplunkForwarder_autoupdate\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "Splunk auto-update loading signed DLL -- normal agent update behavior.",
        "Signed by Splunk. Auto-update trigger. Change ticket. No cmd child.",
        "Authorized agent update -- signed DLL, Splunk, change ticket.",
        "Splunk update -- signed DLL, auto-update, change ticket.",
        "T1543.003 -- AUTHORIZED AGENT UPDATE. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _oauth_lateral_tp(i):
    host = _host(); user = _user()
    prompt = (f"Windows Host Telemetry -- OAuth/MSAL Token Theft for Cloud Lateral Movement.\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1_theft: EventID=10 (ProcessAccess)\n"
              f"    SourceImage: implant.exe  TargetImage: msedge.exe\n"
              f"    GrantedAccess=0x1F0FFF  (full process access)\n"
              f"  stage_2_extract: MSAL token cache read\n"
              f"    path: %LOCALAPPDATA%\\Microsoft\\TokenBroker\\Cache\\*.cache\n"
              f"    refresh_tokens_extracted=YES  scope=Mail.ReadWrite+User.Read.All\n"
              f"  stage_3_lateral: Azure/M365 API calls from non-browser process\n"
              f"    https://graph.microsoft.com/v1.0/users  from implant.exe (not msedge.exe)\n"
              f"    tokens_replayed_outside_browser=YES  (impossible for legit browser tokens)")
    cot = _cot(
        "MSAL tokens are stored by browsers for OAuth2/OIDC sessions. Legitimate browser "
        "access: tokens used only by the browser process they were issued to.",
        "GrantedAccess=0x1F0FFF on Edge process = full memory access to extract tokens. "
        "MSAL cache files read by non-browser process = token theft. "
        "Graph API calls from implant.exe = stolen refresh tokens replayed for "
        "lateral movement to M365/Azure without password.",
        f"Host {host} ({user}): MSAL OAuth tokens stolen from Edge, replayed to Graph API. "
        "Cloud lateral movement confirmed without credentials.",
        "OAuth token theft + M365 lateral confirmed -- token replay from non-browser.",
        "MITRE T1550.001 + T1528. Revoke all refresh tokens for {user}. "
        "Force re-authentication. Audit Graph API activity.",
    )
    return prompt, cot, "true_positive"

def _oauth_lateral_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized SSO Token Refresh.\n"
              f"  EventID=10  TargetImage: msedge.exe  GrantedAccess=0x1000\n"
              f"    SourceImage: WindowsBrokerHost.exe  (Token Broker -- authorized)\n"
              f"  no_MSAL_cache_file_access_by_non_broker=YES\n"
              f"  Graph_API_calls_from=msedge.exe  (token used by issuing browser only)")
    cot = _cot(
        "Token Broker (WindowsBrokerHost) refreshing token for browser -- authorized SSO flow.",
        "Token Broker source. Limited access. Browser uses own tokens. No cross-process replay.",
        "Authorized SSO token refresh -- Token Broker, browser keeps own tokens.",
        "SSO refresh -- Token Broker, limited access, no token theft.",
        "T1550.001 -- AUTHORIZED SSO FLOW. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Add on (2026-06-05)
# ═══════════════════════════════════════════════════════════════════════════════

def _mssql_lateral_tp(i):
    src = _ip_int(); dst = _ip_int()
    method = random.choice([
        ("xp_cmdshell", "OS command execution via SQL Server"),
        ("SQL Agent Job", "Persistent job created for code execution"),
        ("Linked Server", "Lateral movement via SQL Server trust chain"),
        ("CLR Assembly", "Custom .NET assembly loaded for code execution"),
    ])
    p = {"src": src, "dst": dst, "method": method[0], "desc": method[1],
         "auth": random.choice(["SA account","Windows auth via PTH","SQL login brute"]),
         "cmd": random.choice(["whoami","net user backdoor P@ss1 /add","powershell.exe -enc JAB"])}
    prompt = (f"Network Tap + Sysmon -- MSSQL Lateral Execution.\n"
              f"Source: {p['src']} → MSSQL {p['dst']}:1433\n"
              f"  method={p['method']} ({p['desc']})\n"
              f"  command_executed={p['cmd'][:50]}\n"
              f"  authentication={p['auth']}\n"
              f"  sqlservr_spawns_child=YES")
    cot = _cot(
        "DBAs use SQL Agent jobs for scheduled maintenance. xp_cmdshell is disabled by default "
        "and only enabled by sysadmins for specific automation. "
        f"Running '{p['cmd'][:40]}' via {p['method']} from {p['src']} is not DBA work.",
        f"method={p['method']}: well-known MSSQL lateral movement technique. "
        f"auth={p['auth']}: credential abuse for MSSQL access. "
        f"cmd='{p['cmd'][:40]}': OS-level command execution via SQL Server. "
        "sqlservr.exe spawning child process: MSSQL code execution confirmed.",
        f"MSSQL server {p['dst']}: OS command execution achieved from {p['src']}.",
        "MSSQL lateral execution confirmed.",
        "MITRE T1021.002 (Remote Services via MSSQL). "
        "Disable xp_cmdshell, rotate SA password, audit SQL Agent jobs.",
    )
    return prompt, cot, "true_positive"

def _mssql_lateral_fp(i):
    p = {"job": "nightly_maintenance", "cmd": "DBCC CHECKDB", "sa": "svc-dba"}
    prompt = (f"Sysmon -- SQL Agent Maintenance Job.\n"
              f"  job={p['job']}  command={p['cmd']}\n"
              f"  account={p['sa']}  scheduled=YES")
    cot = _cot(
        "Nightly DBA maintenance job -- database integrity check, service account, scheduled.",
        f"Scheduled DBA job. DBCC command (DB maintenance). svc-dba.",
        "Authorized SQL Agent maintenance. No action.",
        "Authorized MSSQL job. No action.",
        "T1021 -- AUTHORIZED DBA JOB. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _entra_token_tp(i):
    p = {"src": _ip_ext(),
         "token_type": random.choice(["refresh_token","access_token","PRT"]),
         "original_service": random.choice(["Graph API","Teams","OneDrive","SharePoint"]),
         "pivoted_to": random.sample(["Azure Management","Key Vault","Storage","DevOps","Email"], k=random.randint(2,4)),
         "different_ip": True,
         "token_age_h": round(random.uniform(0.1, 23.9), 1)}
    prompt = (f"Azure AD -- OAuth Token Theft and Pivot.\n"
              f"Source IP: {p['src']}\n"
              f"  token_type={p['token_type']}\n"
              f"  originally_issued_to={p['original_service']}\n"
              f"  now_used_for: {', '.join(p['pivoted_to'])}\n"
              f"  original_ip_differs_from_current=YES\n"
              f"  token_age_hours={p['token_age_h']}")
    cot = _cot(
        "Token reuse from a single device across services is normal SSO behavior. "
        f"A {p['token_type']} from {p['original_service']} being used from a different IP "
        f"to access {', '.join(p['pivoted_to'][:2])} is token theft and pivoting.",
        f"token_type={p['token_type']}: long-lived credential enabling cross-service access. "
        f"different_ip=YES: token used from IP not matching original authentication. "
        f"pivoted_to={p['pivoted_to']}: lateral movement across Azure services. "
        "Token theft survives password reset -- must be explicitly revoked.",
        f"Stolen {p['token_type']} enabling lateral movement across "
        f"{len(p['pivoted_to'])} Azure services from {p['src']}.",
        "Entra ID token theft and cross-service lateral movement confirmed.",
        "MITRE T1528 (Steal Application Access Token) + T1021. "
        "Revoke all sessions for user, rotate credentials, audit accessed resources.",
    )
    return prompt, cot, "true_positive"

def _entra_token_fp(i):
    p = {"service": "Teams → SharePoint", "ip": "same corporate egress", "sso": True}
    prompt = (f"Azure AD -- SSO Token Reuse.\n"
              f"  services={p['service']}  same_corporate_ip=YES\n"
              f"  sso_flow=YES  token_valid=YES")
    cot = _cot(
        "Normal SSO token reuse across Microsoft 365 services from same corporate IP.",
        "Same IP. SSO flow. Expected service chain.",
        "Authorized SSO token reuse. No action.",
        "Authorized SSO. No action.",
        "T1528 -- AUTHORIZED SSO. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _paexec_tp(i):
    src = _ip_int(); dst = _ip_int()
    target_host = _host()
    payload = random.choice(["beacon.exe","loader.exe","agent.exe","stage2.exe"])
    pkt_count = random.randint(50, 300)
    prompt = (f"Network + Sysmon -- PAExec Remote Service Lateral Movement.\n"
              f"  src={src}  dst={dst}  target_host={target_host}\n"
              f"  phase_1_smb: dst_port=445  is_internal_dst=true  packets_src={pkt_count}\n"
              f"  phase_2_service: EventID=13\n"
              f"    TargetObject=HKLM\\SYSTEM\\CurrentControlSet\\Services\\PAEXECSVC\n"
              f"    Details=C:\\Windows\\PAEXECSVC.EXE\n"
              f"  phase_3_exec: EventID=1\n"
              f"    ParentImage: PAEXECSVC.EXE  Image: {payload}\n"
              f"    User=NT AUTHORITY\\SYSTEM  IntegrityLevel=System\n"
              f"  phase_4_cleanup: service_deleted_after_run=YES  no_change_ticket=YES")
    cot = _cot(
        "PAExec and PsExec are legitimate remote admin tools. "
        "The discriminators are: non-admin-tool source, payload dropped to C:\\Windows\\ root "
        "(not a vendor path), and service deleted immediately after execution "
        "(ephemeral lateral movement pattern rather than persistent service install).",
        f"phase_1: SMB (445) with {pkt_count} packets to internal host {dst} = service install traffic. "
        "phase_2: PAEXECSVC registry key = PAExec remote service installed via admin share. "
        f"phase_3: PAEXECSVC.EXE spawning {payload} as SYSTEM = payload executed via remote service. "
        "phase_4: service_deleted + no_change_ticket = attacker cleanup, not authorized ops.",
        f"Lateral movement from {src} to {dst} ({target_host}) via PAExec. "
        f"Payload {payload} executed as SYSTEM.",
        "PAExec lateral movement with ephemeral PAEXECSVC service confirmed.",
        "MITRE T1021.002 (SMB/Admin Shares) + T1543.003 (Create Service) + T1070.001. "
        "Block workstation-to-workstation SMB, isolate both endpoints, audit admin share access.",
    )
    return prompt, cot, "true_positive"

def _paexec_fp(i):
    p = {"sa": "svc-remoteops", "dst": _ip_int(), "ticket": f"CHG-{random.randint(1000,9999)}", "cmd": "ipconfig /all"}
    prompt = (f"Network -- Authorized IT Remote Execution (PAExec).\n"
              f"  src_account={p['sa']}  dst={p['dst']}\n"
              f"  ticket={p['ticket']}  maintenance_window=YES\n"
              f"  command={p['cmd']}  cmdb_registered_target=YES")
    cot = _cot(
        f"Authorized IT remote execution by svc-remoteops during maintenance window -- read-only command, CMDB target.",
        f"sa=svc-remoteops. Ticket {p['ticket']}. Maintenance window. ipconfig. CMDB-registered.",
        "Authorized admin remote execution. No action.",
        "Authorized PAExec admin use. No action.",
        "T1021.002 -- AUTHORIZED REMOTE ADMIN. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _sccmhunter_tp(i):
    src = _ip_int()
    mp_host = f"CM0{random.randint(1,3)}.{random.choice(['corp','prod'])}.local"
    payload = random.choice(["implant.exe","loader.dll","stage2.ps1","beacon.bat"])
    method  = random.choice(["AdminService RCE","CMScript deployment","PXE bootstrap abuse"])
    count   = random.randint(50, 5000)
    prompt = (f"Network Tap -- SCCM/ConfigMgr Lateral Movement.\n"
              f"  src={src}  management_point={mp_host}\n"
              f"  method={method}\n"
              f"  phase_1_enum: http_uri LIKE /AdminService/v1.0/Device OR /SMS_MP/.sms_aut\n"
              f"    http_method=GET  http_useragent=python-requests\n"
              f"    devices_enumerated={count}\n"
              f"  phase_2_deploy: http_method=POST  http_uri LIKE /AdminService/\n"
              f"    payload={payload}  target_collection=All_Systems\n"
              f"  phase_3_exec: remote_exec_via_sccm_client=YES  lateral_scope=ALL_ENDPOINTS")
    cot = _cot(
        "SCCM management points serve legitimate software deployment from authorized CM servers. "
        "The discriminator is: enumeration from a non-CM account from a non-CM host, "
        "target collection is All_Systems (maximum blast radius), "
        "and deployed payload is not registered in the CM console.",
        f"method={method}: not standard CM admin -- python-requests UA from non-CM host. "
        f"devices_enumerated={count}: full scope recon. "
        f"POST to AdminService with payload={payload} targeting All_Systems: "
        "SCCM used as lateral movement infrastructure for enterprise-wide execution. "
        "No change ticket, off-hours, non-IT-admin source.",
        f"Source {src}: payload {payload} deployed to all {count} SCCM-managed endpoints "
        f"via {method}. Enterprise-wide execution achieved.",
        "SCCM/ConfigMgr lateral movement for enterprise-wide execution confirmed.",
        "MITRE T1072 (Software Deployment Tools) + T1021. "
        "Revoke CM admin, remove deployed packages, audit CM event logs.",
    )
    return prompt, cot, "true_positive"

def _sccmhunter_fp(i):
    p = {"sa": "svc-sccm-deploy", "pkg": "ChromeUpdate", "ticket": f"PKG-{random.randint(1000,9999)}", "col": "Workstations-Wave2"}
    prompt = (f"Network -- Authorized SCCM Software Deployment.\n"
              f"  account={p['sa']}  package={p['pkg']}\n"
              f"  collection={p['col']}  ticket={p['ticket']}\n"
              f"  source_is_sccm_server=YES  package_signed=YES")
    cot = _cot(
        f"SCCM service account deploying signed package to bounded workstation collection with change ticket.",
        f"sa=svc-sccm-deploy. Signed. Bounded collection. Ticket {p['ticket']}. CM server source.",
        "Authorized SCCM deployment. No action.",
        "Authorized CM deployment. No action.",
        "T1072 -- AUTHORIZED CM DEPLOYMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Registry + S3 Query Patterns + Main
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_CLASSES = {
    "SCMServiceHijack":       ("sysmon_sensor",    ["T1021.002","T1543.003"],  _scm_tp,          _scm_fp),
    "WMILateralExec":         ("sysmon_sensor",    ["T1047"],                  _wmi_tp,          _wmi_fp),
    "ScheduledTaskLateral":   ("sysmon_sensor",    ["T1053.005","T1021"],      _stl_tp,          _stl_fp),
    "DCOMHTAExecution":       ("network_tap",      ["T1021.003"],              _dcom_hta_tp,     _dcom_hta_fp),
    "DCOMMMCExecution":       ("sysmon_sensor",    ["T1021.003"],              _dcom_mmc_tp,     _dcom_mmc_fp),
    "DCOMCOMHijackLateral":   ("sysmon_sensor",    ["T1021.003","T1574.001"],  _dcom_hijack_tp,  _dcom_hijack_fp),
    "MSILateralExecution":    ("sysmon_sensor",    ["T1021.003"],              _msi_tp,          _msi_fp),
    "NTLMRelayLateral":       ("network_tap",      ["T1557.001","T1021.002"],  _ntlm_relay_tp,   _ntlm_relay_fp),
    "PassTheHashLateral":     ("sysmon_sensor",    ["T1550.002","T1021"],      _pth_tp,          _pth_fp),
    "LAPSCredentialExtract":  ("sysmon_sensor",    ["T1552.004","T1003"],      _laps_tp,         _laps_fp),
    "TGTPKINITExtract":       ("sysmon_sensor",    ["T1649","T1550.002"],      _tgt_pkinit_tp,   _tgt_pkinit_fp),
    "RDPSessionHijack":       ("sysmon_sensor",    ["T1563.002"],              _rdp_hijack_tp,   _rdp_hijack_fp),
    "WinRMLateral":           ("network_tap",      ["T1021.006"],              _winrm_tp,        _winrm_fp),
    "NamedPipeShellLateral":  ("sysmon_sensor",    ["T1021.002","T1059.001"],  _npipe_tp,        _npipe_fp),
    "PassiveNetworkDiscovery":("network_tap",      ["T1018","T1040"],          _passive_net_tp,  _passive_net_fp),
    "ReachableHostScan":      ("network_tap",      ["T1018","T1046"],          _reach_host_tp,   _reach_host_fp),
    "SSHSnakePivoting":       ("linux_sentinel",   ["T1021.004","T1552.004"],  _ssh_snake_tp,    _ssh_snake_fp),
    "FailoverClusterLateral": ("network_tap",      ["T1018","T1078"],          _cluster_tp,      _cluster_fp),
    "AmnesiacHiveDump":       ("sysmon_sensor",    ["T1003.002"],              _hive_tp,         _hive_fp),
    "SMBSigningAbuse":        ("network_tap",      ["T1557.001","T1021.002"],  _smb_sign_tp,     _smb_sign_fp),
    "WormSelfPropagation":    ("network_tap",      ["T1210","T1570"],          _wsp_tp,           _wsp_fp),
    "BloodHoundAttackPath":   ("sysmon_sensor",    ["T1069.002","T1078.003"],  _bhood_tp,         _bhood_fp),
    "SCMSupplyChainLateral":  ("sysmon_sensor",    ["T1543.003","T1021.002"],  _scm_supply_tp,    _scm_supply_fp),
    "MaliciousOAuthLateral":  ("sysmon_sensor",    ["T1550.001","T1528"],      _oauth_lateral_tp, _oauth_lateral_fp),
    "MSSQLLateral":           ("network_tap",      ["T1021.002"],              _mssql_lateral_tp, _mssql_lateral_fp),
    "EntraTokenHijack":       ("azure_entraid",    ["T1528","T1021"],          _entra_token_tp,   _entra_token_fp),
    "PAExecLateral":          ("network_tap",      ["T1021.002","T1543.003"],  _paexec_tp,        _paexec_fp),
    "SCCMHunterLateral":      ("network_tap",      ["T1072","T1021"],          _sccmhunter_tp,    _sccmhunter_fp),
}

S3_QUERIES = {
    "SCMServiceHijack":       {"sensor":"sysmon_sensor", "where":"sysmon_event_id = 13 AND TargetObject LIKE '%ControlSet%Services%ImagePath%' AND Image NOT LIKE 'C:\\\\Program Files%'"},
    "WMILateralExec":         {"sensor":"sysmon_sensor", "where":"sysmon_event_id = 1 AND ParentImage LIKE '%WmiPrvSe.exe%' AND Image NOT LIKE '%svchost%'"},
    "ScheduledTaskLateral":   {"sensor":"sysmon_sensor", "where":"sysmon_event_id = 1 AND (CommandLine LIKE '%Register-ScheduledTask%' OR CommandLine LIKE '%schtasks%/create%') AND (CommandLine LIKE '%/xml%' OR CommandLine LIKE '%-enc%')"},
    "NTLMRelayLateral":       {"sensor":"network_tap",   "where":"dst_port = 445 AND protocol_name = 'SMB' AND is_internal_dst = true GROUP BY src_ip, dst_ip HAVING COUNT(*) > 5 AND MIN(timestamp) - MAX(timestamp) < 3"},
    "RDPSessionHijack":       {"sensor":"sysmon_sensor", "where":"sysmon_event_id = 1 AND Image LIKE '%tscon.exe%' AND User LIKE '%SYSTEM%'"},
    "WinRMLateral":           {"sensor":"network_tap",   "where":"dst_port IN (5985,5986) AND is_internal_dst = true"},
    "PassiveNetworkDiscovery":{"sensor":"network_tap",   "where":"dst_port IN (67,68,1900,5353,137,138,3702) AND protocol_name = 'UDP' "},
    "ReachableHostScan":      {"sensor":"network_tap",   "where":"dst_port IN (22,445,3389,5985,135) GROUP BY src_ip HAVING COUNT(DISTINCT dst_ip) > 20 AND AVG(session_duration_ms) < 1000"},
    "SSHSnakePivoting":       {"sensor":"linux_sentinel", "where":"comm = 'ssh' AND command_line LIKE '%ssh -i%' AND dest_ip IS NOT NULL"},
    "AmnesiacHiveDump":       {"sensor":"sysmon_sensor", "where":"sysmon_event_id = 1 AND CommandLine LIKE '%reg save%' AND (CommandLine LIKE '%SAM%' OR CommandLine LIKE '%SYSTEM%' OR CommandLine LIKE '%SECURITY%')"},
    "WormSelfPropagation":    {"sensor":"network_tap",   "where":"dst_port IN (445,135,22,5985) AND is_internal_dst = true GROUP BY src_ip HAVING COUNT(DISTINCT dst_ip) > 10 AND AVG(session_duration_ms) < 2000"},
    "BloodHoundAttackPath":   {"sensor":"sysmon_sensor", "where":"sysmon_event_id=13 AND TargetObject LIKE '%memberOf%'"},
    "SCMSupplyChainLateral":  {"sensor":"sysmon_sensor", "where":"sysmon_event_id=7 AND Signed='false' AND Image LIKE '%SplunkForwarder%' OR Image LIKE '%NessusAgent%' OR Image LIKE '%SolarWinds%'"},
    "MaliciousOAuthLateral":  {"sensor":"sysmon_sensor", "where":"sysmon_event_id=10 AND TargetImage LIKE '%msedge%' OR TargetImage LIKE '%chrome%' AND GrantedAccess='0x1f0fff'"},
    "MSSQLLateral":           {"sensor":"network_tap","where":"dst_port = 1433 AND is_internal_dst = true GROUP BY src_ip HAVING COUNT(*) > 5"},
    "EntraTokenHijack":       {"sensor":"azure_entraid", "where":"operation_name LIKE '%token%' OR (result_type = 'Success' AND conditional_access_status = 'NotApplied' AND auth_method_detail = 'Password')"},
    "PAExecLateral":          {"sensor":"network_tap","where":"dst_port = 445 AND is_internal_dst = true AND packets_src > 50"},
    "SCCMHunterLateral":      {"sensor":"network_tap","where":"http_uri LIKE '%/SMS_MP%' OR http_uri LIKE '%/AdminService/%' AND http_method IS NOT NULL"},
    "DCOMHTAExecution":       {"sensor":"network_tap","where":"dst_port = 135 AND is_internal_dst = true AND avg_inter_arrival < 5.0"},
    "DCOMMMCExecution":       {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND ParentImage LIKE '%mmc.exe%' AND Image NOT LIKE '%mmc.exe%' AND User NOT LIKE '%SYSTEM%'"},
    "DCOMCOMHijackLateral":   {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%HKCU%Classes%CLSID%' AND Image NOT LIKE '%msiexec%' AND Image NOT LIKE '%regsvr32%'"},
    "MSILateralExecution":    {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND Image LIKE '%msiexec%' AND CommandLine LIKE '%/i%' AND CommandLine LIKE '%\\\\\\\\%'"},
    "PassTheHashLateral":     {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND CommandLine LIKE '%LogonUser%' OR CommandLine LIKE '%sekurlsa%' AND ParentImage NOT LIKE '%services.exe%'"},
    "LAPSCredentialExtract":  {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND (CommandLine LIKE '%ms-Mcs-AdmPwd%' OR CommandLine LIKE '%Get-LapsADPassword%' OR CommandLine LIKE '%Get-AdmPwdPassword%')"},
    "TGTPKINITExtract":       {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND (CommandLine LIKE '%PKINIT%' OR CommandLine LIKE '%asktgt%' OR CommandLine LIKE '%Rubeus%ptt%' OR CommandLine LIKE '%Kerberos%ptt%')"},
    "NamedPipeShellLateral":  {"sensor":"sysmon_sensor","where":"sysmon_event_id IN (17,18) AND PipeName NOT LIKE 'MSSQL$%' AND PipeName NOT LIKE 'spoolss%' AND Image NOT LIKE 'C:\\\\Windows%'"},
    "FailoverClusterLateral": {"sensor":"network_tap","where":"dst_port = 135 AND is_internal_dst = true AND avg_inter_arrival < 2.0 AND variance_inter_arrival < 0.15"},
    "SMBSigningAbuse":        {"sensor":"network_tap","where":"dst_port = 445 AND is_internal_dst = true AND avg_inter_arrival < 3.0 AND variance_inter_arrival < 0.10"},
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
