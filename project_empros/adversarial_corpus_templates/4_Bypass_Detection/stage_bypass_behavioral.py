"""
stage_bypass_behavioral.py -- Comprehensive Bypass Detection TTP Behavioral Dataset

Detection philosophy: behavioral evidence only -- API sequences, kernel structures,
WFP events, registry changes, memory patterns. No tool names in detection logic.
Every class has admin FP variants.

Output:
  data/staging/bypass_behavioral_v1.jsonl
  data/staging/bypass_query_index.json

Usage:
    python stage_bypass_behavioral.py
    python stage_bypass_behavioral.py --records-per-class 15 --admin-fps-per-class 3
    python stage_bypass_behavioral.py --tool-filter AMSIInProcessPatch,WFPEDRNetworkBlock
"""

import json
import random
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("stage-bypass")
random.seed(17)

OUTPUT_DIR  = Path("../data/staging")
OUTPUT_FILE = OUTPUT_DIR / "bypass_behavioral_v1.jsonl"
INDEX_FILE  = OUTPUT_DIR / "bypass_query_index.json"

SYS = {
    "sysmon_sensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 4D windows_math. Source: Sysmon event stream. "
        "Schema: sysmon_event_id, Image, CommandLine, ParentImage, User, IntegrityLevel, "
        "TargetImage, GrantedAccess, TargetObject, Details, ImageLoaded, Signed, "
        "SignatureStatus, TargetFilename, TamperingType, EventType_reg. "
        "Identify defense evasion tradecraft. Output MITRE ATT&CK + containment."
    ),
    "windows_deepsensor": (
        "You are the Host Forensics Expert. Target OS: Windows. "
        "Vector Space: 4D windows_math. Schema: Image, CommandLine, ParentProcessName, "
        "APISequence, MemoryPattern, RegistryPath, KernelEvent. "
        "Identify defense evasion tradecraft. Output MITRE ATT&CK + containment."
    ),
    "linux_sentinel": (
        "You are the Host Forensics Expert. Target OS: Linux/Unix. "
        "Vector Space: 5D sentinel_math. Schema: comm, command_line, uid, syscall, file_path. "
        "Identify defense evasion tradecraft. Output MITRE ATT&CK + containment."
    ),
    "network_tap": (
        "You are the Network Tap Forensics Expert. Analyze the session window "
        "using pre-computed behavioral fields. "
        "Attribute to MITRE ATT&CK and recommend containment."
    ),
}

VECTOR = {
    "sysmon_sensor":      "windows_math",
    "windows_deepsensor": "deepsensor_math",
    "linux_sentinel":     "sentinel_math",
    "network_tap":        "c2_math",
}

TTP_CAT = "BypassDetection"  # ttp_category field in every record

def _ip_int():  return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
def _ip_ext():
    p = random.choice(["45.33","104.21","172.67","185.220"])
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"
def _host():    return f"{random.choice(['WS','SRV','APP','DC'])}-{random.randint(10,99)}"
def _user():    return random.choice(["jsmith","alee","tmorgan","schen","rbrown"])
def _pid():     return random.randint(1000, 30000)
def _guid():
    return (f"{{{random.randint(0x10000000,0xFFFFFFFF):08X}-"
            f"{random.randint(0x1000,0xFFFF):04X}-"
            f"{random.randint(0x1000,0xFFFF):04X}-"
            f"{random.randint(0x1000,0xFFFF):04X}-"
            f"{random.randint(0x100000000000,0xFFFFFFFFFFFF):012X}}})")

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
# 1. AMSIInProcessPatch
#    Evidence: PowerShell process writing to amsi.dll .text section,
#              VirtualProtect RX→RW→RX on amsi.dll pages,
#              obfuscated snippet execution before other commands
#    Sources: AMSI.fail, EByte-Pattern-AmsiPatch
#    Admin FP: Windows Defender scanning amsi.dll (read-only)
# ═══════════════════════════════════════════════════════════════════════════════

_AMSI_PATCH_METHODS = [
    ("xor eax,eax; ret prologue replacement", "AMSI_SCAN_FUNC_START pattern match"),
    ("cmp eax,0xFF patch (AMSI_RESULT_CLEAN→-1)", "pattern: 83 F8 00 → 83 F8 FF"),
    ("conditional jump NOP/JMP patch", "AMSI_TEST_JZ: 85 C0 74 → 85 C0 EB"),
]

def _amsi_ip_tp(i):
    proc   = random.choice(["powershell.exe","pwsh.exe","csc.exe","wscript.exe"])
    method, pattern = _AMSI_PATCH_METHODS[i % len(_AMSI_PATCH_METHODS)]
    p = {
        "host": _host(), "user": _user(), "proc": proc, "pid": _pid(),
        "method": method, "pattern": pattern,
        "vprotect_seq": "PAGE_EXECUTE_READ → PAGE_EXECUTE_READWRITE → PAGE_EXECUTE_READ",
        "target_func": "amsi.dll!AmsiScanBuffer",
        "obfuscated_snippet": i % 2 == 0,
        "write_bytes": random.choice(["0x31 0xC0 0xC3", "0xC3", "0xEB 0x00"]),
        "write_count": random.randint(2, 8),
        "loaded_before_commands": True,
    }
    prompt = (f"Windows Host -- AMSI In-Process Memory Patch.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  Process: {p['proc']} (PID {p['pid']})\n"
              f"  target_function: {p['target_func']}\n"
              f"  patch_method: {p['method']}\n"
              f"  patch_pattern: {p['pattern']}\n"
              f"  patch_bytes: {p['write_bytes']}\n"
              f"  VirtualProtect_sequence: {p['vprotect_seq']}\n"
              f"  write_operations_to_amsi_text_section={p['write_count']}\n"
              + (f"  obfuscated_snippet_loaded_before_commands=YES\n" if p['obfuscated_snippet'] else ""))
    cot = _cot(
        f"Windows Defender and security vendors read amsi.dll for scanning but never "
        f"write to its .text section at runtime. A {p['proc']} process modifying "
        "AmsiScanBuffer instruction bytes has no legitimate use case.",
        f"VirtualProtect sequence on amsi.dll .text: RX→RW (write enabled) → patch written → RX (restored). "
        f"Patch bytes {p['write_bytes']} at AmsiScanBuffer: "
        + ("XOR EAX,EAX; RET = function immediately returns 0 (clean). " if "xor" in p['write_bytes'].lower() else
           "RET = function returns without scanning. " if p['write_bytes'] == "0xC3" else
           "JMP = skip scan logic. ")
        + f"Method: {p['method']}. "
        + (f"Obfuscated bypass snippet executed before main script -- covers tracks. " if p['obfuscated_snippet'] else ""),
        f"Host {p['host']}: AMSI is disabled for all scripts in the {p['proc']} session. "
        "Malicious PowerShell/CLR code can now execute without AMSI scanning. "
        "Any malware loaded after this bypass runs without detection.",
        "In-process AMSI memory patch confirmed.",
        "MITRE T1562.001 (Disable or Modify Tools: AMSI bypass). "
        "Kill process, restore amsi.dll integrity, escalate to IR.",
    )
    return prompt, cot, "true_positive"

def _amsi_ip_fp(i):
    p = {"proc": "MsMpEng.exe", "op": "READ_ONLY memory scan",
         "signed": True, "api": "AmsiScanBuffer (called by Defender, not patched)"}
    prompt = (f"Windows Host -- Defender AMSI Read Access.\n"
              f"  Process: {p['proc']}\n"
              f"  operation={p['op']}  no_VirtualProtect_write=YES\n"
              f"  signed={p['signed']}  amsi_dll_integrity=INTACT")
    cot = _cot(
        "MsMpEng.exe reading amsi.dll for scanning -- read-only access, no .text modification.",
        "No VirtualProtect write sequence. amsi.dll .text section unchanged. Defender read-only.",
        "Authorized Defender AMSI scanning -- read-only, signed.",
        "Authorized Defender AMSI usage. No action.",
        "T1562.001 -- AUTHORIZED DEFENDER OPERATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. AMSIRemotePatch
#    Evidence: PROCESS_ALL_ACCESS handle to target process,
#              EnumProcessModules to find amsi.dll in remote process,
#              ReadProcessMemory (export table parse), VirtualProtectEx + WriteProcessMemory
#    Sources: EByte-Remote-AMSI-Bypass (B8 00 00 00 00 C3 patch)
#    Admin FP: EDR reading LSASS (different -- read-only, no write)
# ═══════════════════════════════════════════════════════════════════════════════

def _amsi_rp_tp(i):
    src_proc  = random.choice(["powershell.exe","cmd.exe","unknown.exe"])
    tgt_proc  = random.choice(["powershell.exe","pwsh.exe","mshta.exe","wscript.exe"])
    patch_b   = random.choice(["B8 00 00 00 00 C3 (mov eax,0; ret)", "31 C0 C3 (xor eax,eax; ret)"])
    p = {
        "host": _host(), "src": src_proc, "tgt": tgt_proc,
        "pid": _pid(), "patch": patch_b,
        "api_seq": ["OpenProcess(PROCESS_ALL_ACCESS)",
                    "EnumProcessModules (locate amsi.dll)",
                    "ReadProcessMemory (parse export table)",
                    "VirtualProtectEx (RX→RW)",
                    "WriteProcessMemory (AmsiScanBuffer patch)",
                    "VirtualProtectEx (RW→RX)"],
    }
    prompt = (f"Windows Host -- Cross-Process AMSI Patch.\n"
              f"Host: {p['host']}\n"
              f"  SourceProcess: {p['src']}\n"
              f"  TargetProcess: {p['tgt']} (PID {p['pid']})\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  patch_bytes_written: {p['patch']}\n"
              f"  target_function: AmsiScanBuffer in remote amsi.dll")
    cot = _cot(
        "No administrative tool requires cross-process memory write to amsi.dll. "
        f"EDR agents read remote process memory (PROCESS_VM_READ) but never write patch bytes "
        "to security DLL functions in other processes.",
        f"PROCESS_ALL_ACCESS on {p['tgt']}: all cross-process operations enabled. "
        f"EnumProcessModules + ReadProcessMemory: locating amsi.dll in remote process. "
        f"VirtualProtectEx RX→RW: enabling write on amsi.dll .text. "
        f"WriteProcessMemory: writing {p['patch']} to AmsiScanBuffer -- disables scan in target. "
        "VirtualProtectEx RW→RX: restoring protection to hide patch.",
        f"Host {p['host']}: AMSI disabled in {p['tgt']} (PID {p['pid']}). "
        "From this moment, any malicious code loaded into that process runs without scanning.",
        "Cross-process AMSI patch confirmed.",
        "MITRE T1562.001 (AMSI bypass via remote process memory write). "
        "Kill both processes, restore amsi.dll, investigate what ran in target process.",
    )
    return prompt, cot, "true_positive"

def _amsi_rp_fp(i):
    p = {"src": "CrowdStrike-CSAgent.exe", "tgt": "lsass.exe",
         "access": "PROCESS_VM_READ", "no_write": True}
    prompt = (f"Windows Host -- EDR Memory Read.\n"
              f"  Source: {p['src']} → Target: {p['tgt']}\n"
              f"  access={p['access']}  WriteProcessMemory=NO\n"
              f"  VirtualProtectEx=NO  amsi_dll_unaffected=YES")
    cot = _cot(
        "EDR agent reading lsass for credential monitoring -- read-only, no amsi.dll write.",
        "PROCESS_VM_READ only. No VirtualProtectEx. No WriteProcessMemory. amsi.dll intact.",
        "Authorized EDR memory read -- no AMSI patching.",
        "Authorized EDR LSASS monitoring. No action.",
        "T1562.001 -- AUTHORIZED EDR READ. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. AMSIThreadRedirect
#    Evidence: NtSuspendThread on all threads in target process,
#              VirtualAllocEx for proxy function,
#              WriteProcessMemory (proxy stub + JMP at AmsiScanBuffer),
#              NtResumeThread
#    Sources: Ebyte-AMSI-ProxyInjector (NT API thread suspend + proxy redirect)
#    Admin FP: Legitimate debugger breakpoint (single thread, debug session)
# ═══════════════════════════════════════════════════════════════════════════════

def _amsi_tr_tp(i):
    tgt  = random.choice(["powershell.exe","pwsh.exe","wscript.exe"])
    p = {
        "host": _host(), "tgt": tgt, "pid": _pid(),
        "api_seq": [
            "NtSuspendThread (all threads in target)",
            "VirtualAllocEx (proxy function memory)",
            "WriteProcessMemory (proxy stub: preserve regs, return 0)",
            "WriteProcessMemory (JMP at AmsiScanBuffer → proxy)",
            "NtResumeThread (all threads)"
        ],
        "threads_suspended": random.randint(3, 12),
        "proxy_bytes": "55 48 89 E5 31 C0 5D C3 (proxy: push/save, xor eax, pop, ret)",
        "jmp_bytes": f"FF 25 {random.randint(0x00, 0xFF):02X} {random.randint(0x00, 0xFF):02X} 00 00 (indirect JMP to proxy)",
    }
    prompt = (f"Windows Host -- AMSI Thread-Suspend Redirect.\n"
              f"Host: {p['host']}  Target: {p['tgt']} (PID {p['pid']})\n"
              f"  threads_suspended={p['threads_suspended']}\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  proxy_function_bytes: {p['proxy_bytes']}\n"
              f"  amsi_jump_bytes: {p['jmp_bytes']}")
    cot = _cot(
        "Debuggers suspend individual threads for breakpoints, not all threads. "
        "Suspending ALL threads + allocating a proxy function + writing a JMP instruction "
        "to AmsiScanBuffer is not any debugger workflow.",
        f"NtSuspendThread on ALL {p['threads_suspended']} threads: atomic operation to prevent race condition during patch. "
        "VirtualAllocEx: proxy stub allocated in target process. "
        "WriteProcessMemory → proxy: stub always returns 0 (AMSI_RESULT_CLEAN). "
        f"JMP at AmsiScanBuffer ({p['jmp_bytes']}): redirects every scan call to the always-clean proxy. "
        "NtResumeThread: restores normal execution with bypass in place.",
        f"Host {p['host']}: AmsiScanBuffer in {p['tgt']} permanently redirected to a no-op proxy. "
        "All scanning in that session returns clean regardless of content.",
        "AMSI thread-suspend redirect bypass confirmed.",
        "MITRE T1562.001. Kill process, audit execution logs for commands run after bypass.",
    )
    return prompt, cot, "true_positive"

def _amsi_tr_fp(i):
    p = {"tool": "WinDbg.exe", "threads": 1, "purpose": "breakpoint at single function"}
    prompt = (f"Windows Host -- Debugger Thread Suspend.\n"
              f"  Tool: {p['tool']}  threads_suspended={p['threads']} (one thread)\n"
              f"  debug_session_active=YES  no_JMP_write=YES  no_proxy_alloc=YES")
    cot = _cot(
        "WinDbg suspending single thread for breakpoint -- no JMP write, no proxy allocation.",
        "Single thread suspended. Debug session active. No VirtualAllocEx proxy. No JMP write.",
        "Authorized debugger breakpoint -- single thread, no memory modification.",
        "Authorized debugger session. No action.",
        "T1562.001 -- AUTHORIZED DEBUGGER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. WFPEDRNetworkBlock
#    Evidence: WFP filter added targeting EDR process AppID,
#              FWPM_LAYER_ALE_AUTH_CONNECT_V4/_RECV_ACCEPT_V4 for EDR processes,
#              FwpmGetAppIdFromFileName0 call on EDR binary path,
#              EDR outbound connections suddenly drop to zero
#    Sources: EDRSilencer, SilentButDeadly
#    Admin FP: Windows Firewall GPO policy blocking specific application
# ═══════════════════════════════════════════════════════════════════════════════

_EDR_PROCS = ["MsMpEng.exe","SentinelAgent.exe","CrowdStrike-CSAgent.exe",
               "elastic-endpoint.exe","cb.exe","CylanceSvc.exe"]

def _wfp_tp(i):
    edr_procs = random.sample(_EDR_PROCS, k=random.randint(1, 4))
    p = {
        "host": _host(), "actor": random.choice(["cmd.exe","powershell.exe","unknown.exe"]),
        "edrs": edr_procs, "filter_count": len(edr_procs) * 2,
        "provider_guid": _guid(),
        "sublayer_weight": "0x7FFF (maximum priority)",
        "layers": ["FWPM_LAYER_ALE_AUTH_CONNECT_V4 (outbound)",
                   "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 (inbound)"],
        "session_type": random.choice(["dynamic (in-memory)", "persistent (survive reboot)"]),
        "FwpmGetAppId_calls": len(edr_procs),
        "CreateFileW_bypass": i % 2 == 0,
    }
    prompt = (f"Windows Host -- WFP Filter Blocking EDR Network Communication.\n"
              f"Host: {p['host']}  Actor: {p['actor']}\n"
              f"  edrs_targeted: {', '.join(p['edrs'])}\n"
              f"  wfp_provider_guid: {p['provider_guid']}\n"
              f"  sublayer_weight: {p['sublayer_weight']}\n"
              f"  filters_added: {p['filter_count']} ({len(p['edrs'])} EDR × 2 directions)\n"
              f"  layers: {', '.join(p['layers'])}\n"
              f"  session_type: {p['session_type']}\n"
              f"  FwpmGetAppIdFromFileName0_calls={p['FwpmGetAppId_calls']}\n"
              + (f"  custom_FwpmGetAppId_to_bypass_CreateFileW_block=YES\n" if p['CreateFileW_bypass'] else ""))
    cot = _cot(
        "IT admins add WFP firewall rules via Group Policy to block specific application categories, "
        "but these rules are deployed from management systems, target known application classes, "
        "and are documented in change management. A non-admin process dynamically adding WFP filters "
        "specifically targeting security products by process image path is not GPO behavior.",
        f"WFP provider + sublayer with weight 0x7FFF (max priority -- overrides other rules). "
        f"FwpmGetAppIdFromFileName0 calls: {p['FwpmGetAppId_calls']} -- attacker resolving AppIDs of EDR binaries by name. "
        f"Filters added to {', '.join(p['layers'])}: "
        "both inbound and outbound blocked for each EDR. "
        f"Session={p['session_type']}: "
        + ("filters survive reboot -- persistent sabotage." if "persistent" in p['session_type'] else "filters active until process exits.")
        + (f"\ncustom FwpmGetAppIdFromFileName0 implementation: bypasses EDR's own CreateFileW block -- attacker aware of countermeasures." if p['CreateFileW_bypass'] else ""),
        f"Host {p['host']}: EDR processes {', '.join(p['edrs'])} can no longer send telemetry, "
        "receive updates, or communicate with cloud consoles. EDR is operationally blind.",
        "WFP-based EDR network isolation confirmed.",
        "MITRE T1562.004 (Disable or Modify System Firewall) + T1562.001 (Impair Defenses). "
        "Remove WFP filters, restore EDR connectivity, investigate what ran during blind period.",
    )
    return prompt, cot, "true_positive"

def _wfp_fp(i):
    p = {"app": "zoom.exe", "rule": "Corporate Bandwidth Policy",
         "deployed_by": "GPO", "ticket": f"NET-{random.randint(100,999)}"}
    prompt = (f"Windows Host -- WFP Application Filter (GPO).\n"
              f"  application={p['app']}  rule={p['rule']}\n"
              f"  deployed_by={p['deployed_by']}  ticket={p['ticket']}\n"
              f"  targets_security_product=NO  sublayer_weight=normal")
    cot = _cot(
        "Corporate bandwidth policy GPO blocking Zoom -- normal application, normal sublayer weight, GPO-deployed.",
        f"GPO-deployed. targets={p['app']} (not a security product). Normal weight. Ticket.",
        "Authorized corporate network policy -- GPO, bandwidth management, non-security target.",
        "Authorized GPO network filter. No action.",
        "T1562.004 -- AUTHORIZED GPO FILTER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. EDRProcessSuspend
#    Evidence: WerFaultSecure vulnerability abuse -- creating a WER report job
#              targeting EDR process PID, process enters suspended state,
#              no BYOVD driver loaded, user-mode operation only
#    Sources: edr-freeze (WerFaultSecure exploit to suspend EDR)
#    Admin FP: Legitimate WER crash report for application debugging
# ═══════════════════════════════════════════════════════════════════════════════

def _edr_freeze_tp(i):
    edr_proc = random.choice(_EDR_PROCS)
    sleep_ms  = random.randint(5000, 120000)
    p = {
        "host": _host(), "actor": random.choice(["cmd.exe","powershell.exe","unknown.exe"]),
        "target": edr_proc, "pid": _pid(),
        "sleep_ms": sleep_ms, "wer_service_abused": True,
        "driver_loaded": False,
        "target_state": "SUSPENDED",
        "method": "WerFaultSecure vulnerability (user-mode, no kernel required)",
        "windows_version": "Windows 11 24H2",
    }
    prompt = (f"Windows Host -- EDR Process Suspension via WerFaultSecure.\n"
              f"Host: {p['host']}  Actor: {p['actor']}\n"
              f"  target_process: {p['target']} (PID {p['pid']})\n"
              f"  method: {p['method']}\n"
              f"  target_state_after: {p['target_state']}\n"
              f"  suspend_duration_ms={p['sleep_ms']}\n"
              f"  vulnerable_driver_loaded=NO (user-mode only)\n"
              f"  WerFaultSecure_service_interaction=YES")
    cot = _cot(
        "Windows Error Reporting (WER) creates reports for crashing applications -- this is legitimate. "
        "However, WerFaultSecure is not designed for intentionally suspending healthy security processes. "
        "A non-crash process deliberately targeting an EDR's PID via WER has no legitimate purpose.",
        f"Actor {p['actor']} abusing WerFaultSecure vulnerability to suspend {p['target']} (PID {p['pid']}). "
        f"No kernel driver required -- user-mode exploitation. "
        f"Target transitions to SUSPENDED state for {p['sleep_ms']}ms. "
        "During this window, the EDR cannot detect process creation, file access, "
        "network connections, or memory operations. "
        "Requires no Administrator-level operations beyond what's available to standard users.",
        f"Host {p['host']}: EDR {p['target']} suspended for {p['sleep_ms']/1000:.0f} seconds. "
        "Attacker has a detection-free window for any operation. "
        "User-mode technique works on fully patched Windows -- no driver or exploit chain needed.",
        "EDR process suspension via WerFaultSecure confirmed.",
        "MITRE T1562.001 (Impair Defenses: Disable or Modify Tools). "
        "Investigate activity during suspension window, patch WerFaultSecure vulnerability.",
    )
    return prompt, cot, "true_positive"

def _edr_freeze_fp(i):
    p = {"app": "notepad.exe", "pid": _pid(), "reason": "application crash dump",
         "initiated_by": "user double-click crash dialog"}
    prompt = (f"Windows Host -- WER Crash Report.\n"
              f"  crashed_process={p['app']} (PID {p['pid']})\n"
              f"  reason={p['reason']}\n"
              f"  initiated_by={p['initiated_by']}\n"
              f"  target_is_security_product=NO")
    cot = _cot(
        "WER handling notepad crash -- legitimate crash report, user-initiated, non-security target.",
        "target=notepad.exe (not security product). User-initiated from crash dialog.",
        "Authorized WER crash report for non-security application.",
        "Authorized WER crash report. No action.",
        "T1562.001 -- AUTHORIZED WER CRASH REPORT. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. BindFilterDLLRedirect
#    Evidence: bindfltapi.dll loaded, BfSetupFilter called (CreateBindLink),
#              virtual path maps EDR installation directory → attacker-controlled path,
#              EDR DLLs now load from fake/corrupt location,
#              EDRStartupHinder: service monitors EDR PID and applies link on start
#    Sources: edr-redir, edr_startup_hinder
#    Admin FP: Windows SDK test root certificate for application testing
# ═══════════════════════════════════════════════════════════════════════════════

def _bfdr_tp(i):
    edr_path  = random.choice([
        "C:\\Program Files\\CrowdStrike\\",
        "C:\\Program Files\\SentinelOne\\Sentinel Agent\\",
        "C:\\Program Files\\Elastic\\Endpoint\\",
    ])
    fake_path = random.choice(["C:\\Windows\\Temp\\fake\\", "C:\\ProgramData\\update\\",
                                "C:\\Users\\Public\\lib\\"])
    p = {
        "host": _host(), "actor": random.choice(["cmd.exe","powershell.exe","svchost.exe"]),
        "virtual_path": edr_path,
        "backing_path": fake_path,
        "api": "BfSetupFilter (bindfltapi.dll!BfSetupFilter)",
        "service_mode": i % 2 == 0,
        "edrs_affected": [edr_path.split("\\")[-2]],
    }
    prompt = (f"Windows Host -- Bind Filter DLL Redirect (EDR Sabotage).\n"
              f"Host: {p['host']}  Actor: {p['actor']}\n"
              f"  API_called: {p['api']}\n"
              f"  virtual_path (EDR install): {p['virtual_path']}\n"
              f"  backing_path (fake/corrupt): {p['backing_path']}\n"
              f"  effect: EDR loads DLLs from {p['backing_path']} instead of real install\n"
              + (f"  service_mode=YES (monitors EDR PID, applies link on each start)\n" if p['service_mode'] else ""))
    cot = _cot(
        "Windows bind filter (bindflt.sys) is used for application compatibility and container isolation. "
        "Legitimate uses redirect user-writable paths for sandboxing, not redirect vendor security "
        "product installations to attacker-controlled directories.",
        f"BfSetupFilter: creates virtual path binding -- all file accesses to {p['virtual_path']} "
        f"are transparently redirected to {p['backing_path']}. "
        "EDR loads its own DLLs from the fake directory -- they can be empty, corrupt, or replaced. "
        + (f"Service mode: attacker monitors EDR process start (PID poll) and re-applies redirect -- "
           "persistent even after EDR restart. " if p['service_mode'] else "")
        + f"No BYOVD required -- bindflt.sys is a legitimate signed Windows driver.",
        f"Host {p['host']}: EDR installation directory transparently replaced. "
        "EDR starts but loads non-functional or attacker-modified components. "
        "Behavioral monitoring, signature scanning, and cloud connectivity may all be impaired.",
        "EDR DLL redirect via bind filter confirmed.",
        "MITRE T1562.001 (Impair Defenses). "
        "Remove bind link (BfRemoveMapping), verify EDR DLL integrity, restart EDR.",
    )
    return prompt, cot, "true_positive"

def _bfdr_fp(i):
    p = {"api": "BfSetupFilter", "src": "C:\\TestApp\\", "dst": "C:\\TestEnv\\sandbox\\",
         "purpose": "application sandbox testing", "ticket": f"DEV-{random.randint(100,999)}"}
    prompt = (f"Windows Host -- Bind Filter for Dev Sandbox.\n"
              f"  API: {p['api']}\n"
              f"  virtual_path={p['src']}  backing_path={p['dst']}\n"
              f"  purpose={p['purpose']}  ticket={p['ticket']}\n"
              f"  target_is_security_product=NO")
    cot = _cot(
        "Developer sandboxing non-security application for testing -- documented, ticketed, non-EDR target.",
        f"target={p['src']} (non-security app). Ticket {p['ticket']}. Dev environment.",
        "Authorized sandbox bind filter -- non-security target, developer environment.",
        "Authorized dev sandbox bind filter. No action.",
        "T1562.001 -- AUTHORIZED DEV SANDBOX. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. AppLockerEDRDenyRule
#    Evidence: AppLocker policy written with EDR executable paths in deny list,
#              NtQuerySystemInformation to resolve process image paths,
#              WLDP/AppLocker policy registry keys modified,
#              EDR fails to start on next reboot
#    Sources: EDR-GhostLocker
#    Admin FP: Corporate AppLocker blocking unapproved applications
# ═══════════════════════════════════════════════════════════════════════════════

def _applocker_tp(i):
    edr_list = random.sample(_EDR_PROCS, k=random.randint(2, 5))
    p = {
        "host": _host(), "actor": random.choice(["cmd.exe","powershell.exe"]),
        "edrs_targeted": edr_list,
        "api_seq": ["CreateToolhelp32Snapshot (enumerate running processes)",
                    "NtQuerySystemInformation(SystemProcessIdInformation) (resolve full image paths)",
                    "AppLocker deny rule created (path-based, hash-based)"],
        "policy_location": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Exe\\",
        "rule_type": "deny",
        "effect": "EDR executables blocked from launching after reboot",
    }
    prompt = (f"Windows Host -- AppLocker Deny Rules Targeting EDR.\n"
              f"Host: {p['host']}  Actor: {p['actor']}\n"
              f"  EDRs_targeted: {', '.join(p['edrs_targeted'])}\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  policy_registry: {p['policy_location']}\n"
              f"  rule_type: {p['rule_type']}\n"
              f"  effect: {p['effect']}")
    cot = _cot(
        "IT security teams use AppLocker to block unapproved applications -- "
        "but these policies are deployed via GPO from domain controllers and target "
        "user-installable software, not security products. A process dynamically "
        f"enumerating running processes, resolving their full paths via NtQuerySystemInformation, "
        "and creating deny rules specifically for security products is not IT AppLocker management.",
        f"Process enumeration + NtQuerySystemInformation(SystemProcessIdInformation): "
        "resolving exact binary paths of running EDR processes -- not enumerating user apps. "
        f"Policy written to {p['policy_location']}: deny rules for {', '.join(p['edrs_targeted'][:2])}. "
        "Actor={p['actor']} (interactive session, not GPO management tool or domain controller). "
        "Effect: EDR executables blocked on reboot -- persistent EDR shutdown.",
        f"Host {p['host']}: AppLocker deny rules will prevent all targeted EDRs from starting "
        "after the next reboot. This persists across sessions and reconfigurations.",
        "AppLocker-based EDR blocking confirmed.",
        "MITRE T1562.001 (Impair Defenses). "
        "Remove AppLocker deny rules, investigate how attacker gained policy write access.",
    )
    return prompt, cot, "true_positive"

def _applocker_fp(i):
    p = {"rule": "deny unapproved EXEs in user AppData",
         "deployed_by": "GPO from SCCM", "ticket": f"SEC-{random.randint(100,999)}"}
    prompt = (f"Windows Host -- AppLocker Policy Update.\n"
              f"  rule={p['rule']}\n"
              f"  deployed_by={p['deployed_by']}  ticket={p['ticket']}\n"
              f"  target_is_security_product=NO  gpo_deployed=YES")
    cot = _cot(
        "GPO-deployed AppLocker blocking user AppData executables -- standard security hardening.",
        f"GPO-deployed from SCCM. Target=AppData EXEs (not security products). Ticket {p['ticket']}.",
        "Authorized AppLocker security hardening policy.",
        "Authorized AppLocker GPO policy. No action.",
        "T1562.001 -- AUTHORIZED APPLOCKER GPO. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. BYOVDKernelBypass
#    Evidence: Known vulnerable driver loaded (iqvw64e.sys, gmer.sys, etc.),
#              arbitrary kernel read/write via driver IOCTL,
#              EDR kernel callbacks zeroed in PspCreate*NotifyRoutine arrays,
#              ObRegisterCallbacks entries removed
#    Sources: edrsandblast (PspCreateProcessNotifyRoutine), sharp-blackout (gmer)
#    Admin FP: Legitimate enterprise tool using an approved kernel driver
# ═══════════════════════════════════════════════════════════════════════════════

_VULN_DRIVERS = [
    ("iqvw64e.sys", "Intel NIC driver", "CVE-2015-2291"),
    ("gmer.sys", "GMER rootkit scanner", "arbitrary kernel r/w"),
    ("aswArPot.sys", "Avast Anti-Rootkit", "CVE-2022-26522"),
    ("RTCore64.sys", "MSI Afterburner", "CVE-2019-16098"),
]

def _byovd_tp(i):
    drv_file, drv_name, cve = _VULN_DRIVERS[i % len(_VULN_DRIVERS)]
    callbacks_removed = random.randint(2, 8)
    p = {
        "host": _host(), "driver": drv_file, "drv_name": drv_name, "cve": cve,
        "loaded_by": random.choice(["cmd.exe","powershell.exe","unknown.exe"]),
        "kernel_read_write": True,
        "callbacks_zeroed": random.sample(
            ["PspCreateProcessNotifyRoutine", "PspCreateThreadNotifyRoutine",
             "PspLoadImageNotifyRoutine", "ObRegisterCallbacks"], k=min(callbacks_removed, 4)),
        "lsass_dump_after": i % 3 == 0,
        "driver_deleted_after": i % 2 == 0,
    }
    prompt = (f"Windows Host -- BYOVD Kernel Bypass.\n"
              f"Host: {p['host']}  Actor: {p['loaded_by']}\n"
              f"  vulnerable_driver_loaded: {p['driver']} ({p['drv_name']} / {p['cve']})\n"
              f"  kernel_arbitrary_read_write=YES\n"
              f"  kernel_callbacks_zeroed: {', '.join(p['callbacks_zeroed'])}\n"
              f"  edr_callback_count_removed={len(p['callbacks_zeroed'])}\n"
              + (f"  lsass_dump_immediately_after=YES\n" if p['lsass_dump_after'] else "")
              + (f"  driver_deleted_after_use=YES (cleanup)\n" if p['driver_deleted_after'] else ""))
    cot = _cot(
        "Enterprise security tools occasionally use signed kernel drivers for elevated access. "
        f"However, {p['drv_name']} ({p['cve']}) is a known vulnerable driver on "
        "Microsoft's recommended driver block list -- no enterprise vendor ships it as a current product.",
        f"Driver {p['driver']} ({p['cve']}): well-known BYOVD target with arbitrary kernel r/w capability. "
        f"Kernel callbacks zeroed: {', '.join(p['callbacks_zeroed'])}. "
        "These callbacks are how EDRs receive process/thread/image creation notifications -- "
        "zeroing them makes the EDR blind to all new process and DLL load activity. "
        + (f"LSASS dumped immediately after callback removal: credential theft while EDR is blind. " if p['lsass_dump_after'] else "")
        + (f"Driver deleted after use: covering BYOVD evidence." if p['driver_deleted_after'] else ""),
        f"Host {p['host']}: kernel-level EDR telemetry completely disabled. "
        "Process creation, thread creation, and image load events are no longer delivered to EDR. "
        "Attacker has full kernel visibility; defenders are blind.",
        "BYOVD kernel callback removal confirmed.",
        "MITRE T1562.001 + T1014 (Rootkit via kernel callback manipulation). "
        "Full host reimaging required -- kernel integrity cannot be trusted.",
    )
    return prompt, cot, "true_positive"

def _byovd_fp(i):
    p = {"driver": "BEDaisy.sys", "product": "BattlEye Anti-Cheat",
         "signed": True, "approved_blocklist": False, "purpose": "anti-cheat kernel driver"}
    prompt = (f"Windows Host -- Approved Kernel Driver Load.\n"
              f"  driver={p['driver']}  product={p['product']}\n"
              f"  signed={p['signed']}  on_ms_driver_blocklist=NO\n"
              f"  purpose={p['purpose']}  callbacks_modified=NO")
    cot = _cot(
        "BattlEye anti-cheat driver -- signed, not on blocklist, does not zero EDR callbacks.",
        f"Signed by developer. Not on MS driver blocklist. No callback modification.",
        "Authorized anti-cheat kernel driver -- signed, approved, no callback tampering.",
        "Authorized game anti-cheat driver. No action.",
        "T1562.001 -- AUTHORIZED KERNEL DRIVER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. UnsignedKernelDriverMap
#    Evidence: Known vulnerable signed driver (iqvw64e.sys/similar) loaded,
#              NtLoadDriver for unsigned driver using vulnerable driver as proxy,
#              unsigned .sys file created in temp/system path,
#              kernel code execution without code signing enforcement bypass
#    Sources: kurasagi/kdmapper
#    Admin FP: Developer loading test-signed driver in test mode
# ═══════════════════════════════════════════════════════════════════════════════

def _ukdm_tp(i):
    mapper_drivers = [
        ("iqvw64e.sys", "Intel NIC diagnostic driver (expired cert)"),
        ("rtcore64.sys", "MSI Afterburner GPU monitor"),
        ("AsrDrv106.sys", "ASRock motherboard driver"),
    ]
    signed_drv, desc = mapper_drivers[i % len(mapper_drivers)]
    p = {
        "host": _host(),
        "signed_driver": signed_drv, "signed_desc": desc,
        "payload_driver": f"payload_{random.randint(100,999)}.sys",
        "payload_path": random.choice([rf"C:\Windows\Temp\{random.randint(100,999)}.sys",
                                        rf"C:\ProgramData\{random.randint(100,999)}.sys"]),
        "ci_disabled_in_kernel": True,
        "payload_mapped_to": f"0x{random.randint(0xFFFFF80000000000, 0xFFFFFFFFFFFFFFFF):016X}",
    }
    prompt = (f"Windows Host -- Unsigned Kernel Driver Mapping.\n"
              f"Host: {p['host']}\n"
              f"  step1_signed_driver_loaded: {p['signed_driver']} ({p['signed_desc']})\n"
              f"  step2_unsigned_driver_file: {p['payload_driver']} at {p['payload_path']}\n"
              f"  step3_CI_bypass_in_kernel=YES (code integrity enforcement bypassed)\n"
              f"  step4_unsigned_driver_mapped_to: {p['payload_mapped_to']}\n"
              f"  driver_not_in_services_registry=YES (mapped without registration)")
    cot = _cot(
        "Legitimate kernel driver loading uses NtLoadDriver with an HKLM\\System\\CurrentControlSet\\Services "
        "registry entry and requires a valid code signature in production mode. "
        f"Loading {p['signed_driver']} (expired/vulnerable cert) as a proxy to bypass CI "
        "and map an unsigned .sys to a kernel address has no legitimate admin analog.",
        f"Step 1: {p['signed_driver']} loaded -- known BYOVD carrier with kernel r/w capability. "
        "Step 2: unsigned payload at non-standard path -- not DKMS, not OEM, not PKG-installed. "
        "Step 3: CI (Driver Signature Enforcement) bypassed via kernel write primitive. "
        f"Step 4: unsigned driver mapped to kernel address {p['payload_mapped_to']} -- "
        "executing arbitrary ring-0 code without DSE. "
        "Not registered in Services -- hides from standard driver enumeration.",
        f"Host {p['host']}: attacker has arbitrary ring-0 code execution. "
        "Kernel integrity is fully compromised -- all security assumptions are invalidated.",
        "Unsigned kernel driver mapping via BYOVD confirmed.",
        "MITRE T1014 (Rootkit) + T1547.006 (Kernel Modules). Full reimaging required.",
    )
    return prompt, cot, "true_positive"

def _ukdm_fp(i):
    p = {"driver": "WdBoot.sys", "desc": "Windows Defender early launch anti-malware driver",
         "signed": "Microsoft", "dsekibuilt": True}
    prompt = (f"Windows Host -- Signed Microsoft Driver Load.\n"
              f"  driver={p['driver']}  desc={p['desc']}\n"
              f"  signed_by={p['signed']}  in_services_registry=YES\n"
              f"  DSE_enforced=YES  no_BYOVD=YES")
    cot = _cot(
        "Windows Defender ELAM driver -- signed by Microsoft, in Services registry, DSE enforced.",
        "Microsoft-signed. Services registered. No BYOVD. DSE enforced.",
        "Authorized Windows Defender kernel driver.",
        "Authorized Windows Defender ELAM driver. No action.",
        "T1547.006 -- AUTHORIZED MICROSOFT DRIVER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. KernelNotifyCallbackRemoval
#     Evidence: Arbitrary kernel memory write to PspCreateProcessNotifyRoutine
#               array, callback entries nulled for specific driver addresses,
#               ETW TI (Threat Intelligence) provider disabled
#     Sources: edrsandblast (kernel callback array manipulation)
#     Admin FP: No legitimate use case -- callback arrays are kernel-internal
# ═══════════════════════════════════════════════════════════════════════════════

def _kncr_tp(i):
    arrays = random.sample(["PspCreateProcessNotifyRoutine",
                             "PspCreateThreadNotifyRoutine",
                             "PspLoadImageNotifyRoutine"], k=random.randint(2, 3))
    p = {
        "host": _host(),
        "arrays_modified": arrays,
        "callbacks_removed": random.randint(2, 8),
        "etw_ti_disabled": i % 2 == 0,
        "object_callbacks_removed": i % 3 == 0,
        "method": "arbitrary kernel write via vulnerable driver IOCTL",
        "offsets_source": random.choice(["hardcoded", "PDB symbol lookup", "ntoskrnl scan"]),
    }
    prompt = (f"Windows Host (Kernel Telemetry) -- Callback Array Manipulation.\n"
              f"Host: {p['host']}\n"
              f"  method: {p['method']}\n"
              f"  arrays_modified: {', '.join(p['arrays_modified'])}\n"
              f"  callbacks_nulled={p['callbacks_removed']} (EDR driver pointers zeroed)\n"
              f"  offsets_resolved_via={p['offsets_source']}\n"
              + (f"  ETW_TI_provider_disabled=YES (kernel telemetry events suppressed)\n" if p['etw_ti_disabled'] else "")
              + (f"  ObRegisterCallbacks_entries_removed=YES (handle operation callbacks)\n" if p['object_callbacks_removed'] else ""))
    cot = _cot(
        "Kernel callback arrays are internal kernel structures with no documented API for "
        "external zeroing. Even security vendors add callbacks via PsSetCreateProcessNotifyRoutine "
        "-- they never directly modify the arrays themselves.",
        f"Direct kernel write to {', '.join(p['arrays_modified'])}: "
        f"{p['callbacks_removed']} EDR driver callback pointers zeroed -- those drivers receive NO process/thread/image notifications. "
        f"Offset resolution via {p['offsets_source']}: attacker computed kernel structure addresses "
        "for this specific Windows build. "
        + ("ETW TI provider disabled: Microsoft-Windows-Threat-Intelligence ETW events (process hollowing, APC injection detection) suppressed. " if p['etw_ti_disabled'] else "")
        + ("ObRegisterCallbacks removed: EDR can no longer block handle operations on LSASS or other protected processes. " if p['object_callbacks_removed'] else ""),
        f"Host {p['host']}: kernel-level detection is completely disabled. "
        "EDR receives zero notifications from the kernel about process activity. "
        "This is the most comprehensive bypass possible short of full kernel replacement.",
        "Kernel notification callback removal confirmed -- complete EDR blindness.",
        "MITRE T1562.001 + T1014. Full reimaging required -- kernel cannot be trusted.",
    )
    return prompt, cot, "true_positive"

def _kncr_fp(i):
    p = {"proc": "ntoskrnl.exe", "op": "PsSetCreateProcessNotifyRoutine (ADD, not remove)",
         "driver": "WdFilter.sys", "signed": "Microsoft"}
    prompt = (f"Windows Kernel -- Callback Registration.\n"
              f"  operation={p['op']}\n"
              f"  registering_driver={p['driver']}  signed={p['signed']}\n"
              f"  modification_type=ADD (not nulling)")
    cot = _cot(
        "Defender registering a process notification callback -- adding, not removing, via official API.",
        "Uses PsSetCreateProcessNotifyRoutine (add). Signed Microsoft driver. Official API.",
        "Authorized EDR callback registration via Microsoft API.",
        "Authorized callback registration. No action.",
        "T1562.001 -- AUTHORIZED CALLBACK REGISTRATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. IoUringSyscallEvasion (Linux)
#     Evidence: io_uring ring buffer operations replacing read/recv/send/connect,
#               C2 communication without triggering standard syscall hooks,
#               SQPOLL kernel thread for polling (no per-op syscall)
#     Sources: ringreaper (io_uring-based C2 avoiding syscall EDR hooks)
#     Admin FP: High-performance I/O application (nginx, PostgreSQL using io_uring)
# ═══════════════════════════════════════════════════════════════════════════════

def _iouring_tp(i):
    p = {
        "host": _host().lower(), "user": _user(), "uid": random.choice([0, 1000, 1001]),
        "proc": random.choice(["unknown","./agent","./runner","./helper"]),
        "io_uring_setup_calls": 1,
        "io_uring_enter_calls": random.randint(20, 500),
        "sqpoll_thread": i % 2 == 0,
        "syscalls_replaced": ["read","recv","send","connect","write"],
        "traditional_syscall_count": random.randint(0, 3),
        "c2_connection": _ip_ext(),
        "bytes_transferred": random.randint(1000, 50000),
    }
    prompt = (f"Linux Sentinel -- io_uring Syscall Evasion.\n"
              f"Host: {p['host']}  User: {p['user']} (uid={p['uid']})\n"
              f"  process: {p['proc']}\n"
              f"  io_uring_setup()_calls={p['io_uring_setup_calls']}\n"
              f"  io_uring_enter()_calls={p['io_uring_enter_calls']}\n"
              f"  sqpoll_kernel_thread={'YES (zero syscalls for polling)' if p['sqpoll_thread'] else 'NO'}\n"
              f"  replaced_syscalls: {', '.join(p['syscalls_replaced'])}\n"
              f"  traditional_syscall_count={p['traditional_syscall_count']} (near zero)\n"
              f"  outbound_connection: {p['c2_connection']}\n"
              f"  bytes_transferred={p['bytes_transferred']:,}")
    cot = _cot(
        "High-performance applications (nginx, PostgreSQL, io_uring benchmarks) use io_uring for I/O, "
        "but they are packaged binaries with known paths. An unknown process replacing ALL network "
        f"syscalls (read/recv/send/connect) with io_uring ops while connecting to {p['c2_connection']} "
        "is not a performance-oriented server application.",
        f"io_uring setup + {p['io_uring_enter_calls']} io_uring_enter calls: "
        "all network I/O submitted as ring buffer operations -- standard syscall hooks see nothing. "
        f"traditional_syscall_count={p['traditional_syscall_count']}: "
        "near-zero traditional syscalls for a process doing network I/O = io_uring bypass in use. "
        + ("SQPOLL thread: kernel polls ring without any syscall overhead -- complete stealth. " if p['sqpoll_thread'] else "")
        + f"Outbound to {p['c2_connection']}: network activity invisible to auditd/seccomp/eBPF syscall hooks.",
        f"Host {p['host']}: C2 agent {p['proc']} communicates without triggering any syscall-level EDR hook. "
        "Traditional auditd, seccomp filters, and eBPF tracepoints on read/recv/send see no events.",
        "io_uring-based syscall evasion for C2 communication confirmed.",
        "MITRE T1562.006 (Indicator Blocking) + T1071 (C2 via io_uring). "
        "Add io_uring_enter to monitored syscalls, kernel-level process inspection.",
    )
    return prompt, cot, "true_positive"

def _iouring_fp(i):
    p = {"proc": "nginx", "io_enters": random.randint(500, 5000),
         "path": "/usr/sbin/nginx", "purpose": "production web server async I/O"}
    prompt = (f"Linux Sentinel -- nginx io_uring Usage.\n"
              f"  process={p['proc']}  path={p['path']}\n"
              f"  io_uring_enter_calls={p['io_enters']}\n"
              f"  purpose={p['purpose']}  package_installed=YES  signed=YES")
    cot = _cot(
        "nginx using io_uring for web serving -- installed package, known binary, production web server.",
        f"path=/usr/sbin/nginx (package). Known web server binary. No C2 destination.",
        "Authorized nginx io_uring high-performance I/O.",
        "Authorized nginx io_uring usage. No action.",
        "T1562.006 -- AUTHORIZED NGINX IO_URING. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. UACRegistryBypass
#     Evidence: Registry key written to HKCU\...\ms-settings or similar COM
#               elevation moniker path, auto-elevation exploit, process created
#               with high integrity without UAC prompt
#     Admin FP: Legitimate MSI installer requesting elevation via manifest
# ═══════════════════════════════════════════════════════════════════════════════

def _uac_tp(i):
    techniques = [
        ("fodhelper.exe", r"HKCU\Software\Classes\ms-settings\Shell\Open\command",
         "auto-elevate binary shell handler hijack"),
        ("eventvwr.exe",  r"HKCU\Software\Classes\mscfile\Shell\Open\command",
         "MMC snap-in COM launch hijack"),
        ("computerdefaults.exe", r"HKCU\Software\Classes\ms-settings\Shell\Open\command",
         "Settings COM handler hijack"),
        ("sdclt.exe",     r"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe",
         "Control Panel auto-elevation hijack"),
    ]
    auto_elev, reg_key, desc = techniques[i % len(techniques)]
    payload = random.choice([r"cmd.exe /c powershell.exe -enc JABhAGI=",
                              r"C:\Windows\Temp\payload.exe",
                              r"powershell.exe -w hidden -c IEX(...)"])
    p = {
        "host": _host(), "user": _user(),
        "auto_elevate_binary": auto_elev, "registry_key": reg_key,
        "payload": payload, "description": desc,
        "high_integrity_spawned": True, "uac_prompt_shown": False,
    }
    prompt = (f"Windows Host -- UAC Bypass via Registry Hijack.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  technique: {p['description']}\n"
              f"  registry_key_written: {p['registry_key']}\n"
              f"  payload_value: {p['payload']}\n"
              f"  auto_elevate_binary: {p['auto_elevate_binary']}\n"
              f"  high_integrity_process_spawned={p['high_integrity_spawned']}\n"
              f"  uac_prompt_displayed={p['uac_prompt_shown']}")
    cot = _cot(
        f"Legitimate elevation requests trigger a UAC consent dialog. {p['auto_elevate_binary']} "
        "is an auto-elevate binary that bypasses the dialog when invoked -- but writing a custom "
        "shell handler under HKCU to redirect its COM lookup to a malicious payload is not "
        "a software installer pattern.",
        f"Registry write to {p['registry_key']}: overrides COM lookup for {p['auto_elevate_binary']}. "
        f"When {p['auto_elevate_binary']} auto-elevates, it invokes the HKCU COM handler instead of the system one. "
        f"Payload '{p['payload'][:60]}' runs with HIGH integrity token. "
        f"uac_prompt=False: privilege escalation without user notification -- "
        "definitional UAC bypass signature.",
        f"Host {p['host']}: attacker escalated from medium to HIGH integrity without UAC prompt. "
        "All subsequent commands run with administrator-equivalent privileges.",
        "UAC bypass via auto-elevate binary hijack confirmed.",
        "MITRE T1548.002 (Abuse Elevation Control Mechanism: UAC Bypass). "
        "Remove HKCU registry key, kill high-integrity process, investigate what ran.",
    )
    return prompt, cot, "true_positive"

def _uac_fp(i):
    p = {"installer": "setup.exe", "manifest": "requireAdministrator", "prompt": "YES",
         "signed": True}
    prompt = (f"Windows Host -- UAC Elevation Request.\n"
              f"  installer={p['installer']}  manifest={p['manifest']}\n"
              f"  uac_prompt_shown={p['prompt']}  binary_signed={p['signed']}\n"
              f"  no_registry_hijack=YES")
    cot = _cot(
        "Signed installer requesting elevation via manifest -- UAC dialog shown, no registry hijack.",
        f"Signed binary. requireAdministrator manifest. UAC dialog shown. No HKCU COM key.",
        "Authorized elevation via UAC dialog -- signed, manifest-declared.",
        "Authorized installer elevation. No action.",
        "T1548.002 -- AUTHORIZED INSTALLER ELEVATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. PPLTokenRace
#     Evidence: WMI filter+consumer created for early-boot execution before svchost,
#               SYSTEM privilege process pausing anti-malware service startup,
#               token replacement on suspended PPL child process,
#               deprivileged token injected before PPL process resumes
#     Sources: collection/PPL-0day (race condition token replacement)
#     Admin FP: CreateProcessAsPPL (testing PPL -- needs kernel debugger or KPP bypass)
# ═══════════════════════════════════════════════════════════════════════════════

def _ppl_tp(i):
    target_svc = random.choice(["WinDefend","SentinelAgent","CSFalconService","MsMpSvc"])
    p = {
        "host": _host(),
        "wmi_filter": "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'",
        "wmi_consumer": "CommandLineEventConsumer → payload runs as SYSTEM before svchost",
        "target_service": target_svc,
        "technique": "Race condition: service starts SUSPENDED → token replaced → service resumes",
        "token_replaced_with": "deprivileged security context",
        "result": "Anti-malware service starts with near-zero privileges",
    }
    prompt = (f"Windows Host -- PPL Token Race Condition.\n"
              f"Host: {p['host']}\n"
              f"  wmi_filter_created: {p['wmi_filter']}\n"
              f"  wmi_consumer: {p['wmi_consumer']}\n"
              f"  target_service: {p['target_service']}\n"
              f"  technique: {p['technique']}\n"
              f"  token_replaced_with: {p['token_replaced_with']}\n"
              f"  result: {p['result']}")
    cot = _cot(
        "Protected Process Light is designed to prevent any non-PPL process from interfering "
        "with anti-malware services. A WMI early-boot subscription running as SYSTEM before "
        "svchost to catch and deprivilege a service startup has no authorized use.",
        "WMI EventFilter + CommandLineEventConsumer: runs payload as SYSTEM before most services start. "
        f"Race window: {p['target_service']} starts SUSPENDED (AttachConsole pause). "
        "NtOpenProcessToken + NtSetInformationToken on SUSPENDED PPL child: replaces token before resume. "
        f"Result: {p['target_service']} resumes with {p['token_replaced_with']} -- "
        "PPL protection bypassed without BYOVD or kernel exploit.",
        f"Host {p['host']}: {p['target_service']} starts with minimal privileges. "
        "Anti-malware scanning, behavioral monitoring, and cloud connectivity are all impaired.",
        "PPL token race condition bypass confirmed.",
        "MITRE T1562.001 (Impair Defenses: Bypass PPL). "
        "Remove WMI subscription, restart service, investigate early-boot activity.",
    )
    return prompt, cot, "true_positive"

def _ppl_fp(i):
    p = {"tool": "CreateProcessAsPPL.exe", "purpose": "testing PPL levels in dev env",
         "kernel_debug": "YES", "mode": "PROTECTION_LEVEL_ANTIMALWARE_LIGHT"}
    prompt = (f"Windows Host -- PPL Test in Dev Environment.\n"
              f"  tool={p['tool']}  kernel_debugger_attached={p['kernel_debug']}\n"
              f"  mode={p['mode']}  test_machine=YES  production=NO")
    cot = _cot(
        "PPL test tool in dev environment with kernel debugger -- authorized testing.",
        f"Kernel debugger attached. Dev machine. Not production. Tool={p['tool']}.",
        "Authorized PPL level testing in development environment.",
        "Authorized dev PPL test. No action.",
        "T1562.001 -- AUTHORIZED DEV PPL TEST. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 14. LSASSForkDump
#     Evidence: NtCreateProcessEx called to clone lsass.exe,
#               MiniDumpWriteDump on the cloned process (not the original),
#               .dmp file written to disk,
#               no direct OpenProcess on lsass.exe PID
#     Sources: collection/Bypass-EDR (LSASS forked dump vs CrowdStrike)
#     Admin FP: ProcDump with EDR exclusion (direct lsass access)
# ═══════════════════════════════════════════════════════════════════════════════

def _lsass_fork_tp(i):
    dump_path = random.choice([r"C:\Users\Public\forked_lsass.dmp",
                                r"C:\Windows\Temp\mem.dmp",
                                r"C:\ProgramData\update.dmp"])
    p = {
        "host": _host(), "user": _user(),
        "actor": random.choice(["powershell.exe","cmd.exe","unknown.exe"]),
        "api_seq": [
            "OpenProcess(lsass.exe) -- PROCESS_CREATE_PROCESS right only",
            "NtCreateProcessEx(ParentProcess=lsass) -- CLONE lsass to new PID",
            "MiniDumpWriteDump(cloned_lsass_PID, dump_file)",
        ],
        "dump_path": dump_path,
        "direct_lsass_access": False,
        "clone_pid": _pid(),
    }
    prompt = (f"Windows Host -- LSASS Fork Dump (EDR Bypass).\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  actor: {p['actor']}\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  dump_written_to: {p['dump_path']}\n"
              f"  direct_OpenProcess_on_lsass=NO (clone, not original)\n"
              f"  clone_process_pid={p['clone_pid']}")
    cot = _cot(
        "ProcDump and other memory analysis tools open lsass directly with PROCESS_ALL_ACCESS. "
        "NtCreateProcessEx to CLONE lsass creates a child inheriting all memory without "
        "directly opening lsass.exe -- EDRs that monitor OpenProcess(lsass) see nothing.",
        f"NtCreateProcessEx(ParentProcess=lsass): creates a process inheriting lsass address space. "
        f"MiniDumpWriteDump targets clone PID {p['clone_pid']} (not lsass PID): "
        "most EDRs only monitor direct lsass handle creation -- the clone is unmonitored. "
        f"Dump written to {p['dump_path']}: full LSASS memory dump contains NTLM hashes, Kerberos tickets, cleartext credentials. "
        "direct_OpenProcess_on_lsass=NO: bypasses behavioral rule 'MiniDumpWriteDump on lsass'.",
        f"Host {p['host']}: full LSASS credential dump achieved without triggering lsass-specific EDR alerts. "
        "NTLM hashes and Kerberos tickets for all logged-in users are at {p['dump_path']}.",
        "LSASS fork dump confirmed -- credential dump via process clone evading EDR.",
        "MITRE T1003.001 (OS Credential Dumping: LSASS Memory). "
        "Delete dump file, rotate all credentials, investigate exfiltration of dump.",
    )
    return prompt, cot, "true_positive"

def _lsass_fork_fp(i):
    p = {"tool": "procdump.exe", "exclusion": "approved EDR exclusion for IR",
         "ticket": f"IR-{random.randint(100,999)}", "direct": True}
    prompt = (f"Windows Host -- ProcDump LSASS Dump.\n"
              f"  tool=procdump.exe  method=direct OpenProcess\n"
              f"  edr_exclusion={p['exclusion']}  ticket={p['ticket']}\n"
              f"  signed=YES  ir_response=YES")
    cot = _cot(
        "ProcDump with approved EDR exclusion for IR -- direct access, signed, IR ticket.",
        f"Signed ProcDump. EDR exclusion approved. IR ticket {p['ticket']}. Direct access (not fork bypass).",
        "Authorized IR credential collection -- signed tool, EDR exclusion, IR ticket.",
        "Authorized IR ProcDump with EDR exclusion. No action.",
        "T1003.001 -- AUTHORIZED IR DUMP. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 15. APCQueueInjection
#     Evidence: QueueUserAPC / NtQueueApcThread on alertable thread in target,
#               shellcode pointed to by APC routine,
#               target process enters alertable wait state
#     Sources: collection/APC-Injection
#     Admin FP: Legitimate async I/O completion routines (bounded, documented)
# ═══════════════════════════════════════════════════════════════════════════════

def _apc_tp(i):
    targets = ["explorer.exe","svchost.exe","notepad.exe","RuntimeBroker.exe","spoolsv.exe"]
    p = {
        "host": _host(),
        "src": random.choice(["powershell.exe","cmd.exe","wscript.exe"]),
        "target": random.choice(targets), "pid": _pid(),
        "api_seq": ["OpenThread(THREAD_SET_CONTEXT + THREAD_GET_CONTEXT)",
                    "VirtualAllocEx(target, PAGE_EXECUTE_READWRITE)",
                    "WriteProcessMemory (shellcode)",
                    "NtQueueApcThread (APC_ROUTINE = shellcode_address)"],
        "alertable_thread_found": True,
        "shellcode_size_kb": random.randint(4, 256),
    }
    prompt = (f"Windows Host -- APC Queue Shellcode Injection.\n"
              f"Host: {p['host']}\n"
              f"  SourceProcess: {p['src']}\n"
              f"  TargetProcess: {p['target']} (PID {p['pid']})\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  alertable_thread_identified=YES\n"
              f"  shellcode_size_kb={p['shellcode_size_kb']}")
    cot = _cot(
        "Async I/O completion routines (ReadFileEx, WriteFileEx) use APCs legitimately, "
        "but these are used within the same process via documented I/O APIs. "
        "NtQueueApcThread from a foreign process with a shellcode address is not async I/O.",
        f"OpenThread to locate alertable thread in {p['target']}. "
        "VirtualAllocEx(RWX) + WriteProcessMemory: shellcode planted in remote process. "
        f"NtQueueApcThread: APC_ROUTINE = shellcode address -- when thread calls SleepEx/WaitForSingleObjectEx "
        "in alertable mode, shellcode executes. "
        f"shellcode_size={p['shellcode_size_kb']}KB (full payload). "
        "Execution occurs in the context of the target process thread -- appears as {p['target']} activity.",
        f"Host {p['host']}: shellcode executing in {p['target']}. "
        "C2 activity appears to originate from {p['target']} process.",
        "APC queue shellcode injection confirmed.",
        "MITRE T1055.004 (Process Injection: Asynchronous Procedure Call). "
        "Kill target process, memory forensics, isolate host.",
    )
    return prompt, cot, "true_positive"

def _apc_fp(i):
    p = {"proc": "MSSQL Server", "api": "ReadFileEx completion routine",
         "apc_context": "same-process async I/O", "foreign_process_write": False}
    prompt = (f"Windows Host -- SQL Server Async I/O APC.\n"
              f"  process=sqlservr.exe  api={p['api']}\n"
              f"  apc_context={p['apc_context']}\n"
              f"  foreign_process_write=NO  no_VirtualAllocEx_remote=YES")
    cot = _cot(
        "SQL Server async I/O completion via ReadFileEx -- same-process APC, no remote write.",
        "Same-process APC. ReadFileEx completion (standard API). No remote VirtualAllocEx.",
        "Authorized SQL Server async I/O completion.",
        "Authorized SQL Server APC. No action.",
        "T1055.004 -- AUTHORIZED ASYNC I/O APC. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 16. ShellcodeRuntimeEncrypt
#     Evidence: Anti-sandbox checks before decrypt (sleep timing, VM detection),
#               XOR/AES key rotation per build, encrypted payload in binary,
#               msfvenom-style shellcode detected after decryption in memory
#     Sources: GenEDRBypass (XOR + dynamic key rotation), Shellcode-Mutator
#     Admin FP: Legitimate encrypted software license (anti-tamper, bounded)
# ═══════════════════════════════════════════════════════════════════════════════

def _shellcode_enc_tp(i):
    enc_types = [("XOR with rotating key", "0xAB"), ("AES-256-CBC", "dynamic IV"),
                 ("RC4 with per-build seed", "computed at runtime")]
    enc_name, key_note = enc_types[i % len(enc_types)]
    p = {
        "host": _host(), "user": _user(),
        "proc": random.choice(["powershell.exe","dotnet.exe","unknown.exe"]),
        "encryption": enc_name, "key": key_note,
        "anti_sandbox": random.sample(["timing check (sleep 5s then verify 5s elapsed)",
                                        "VM artifact check (vmtoolsd.exe)",
                                        "user interaction check (cursor movement)",
                                        "domain join check"], k=random.randint(1, 3)),
        "payload_entropy_on_disk": round(random.uniform(3.8, 5.5), 3),
        "payload_entropy_in_mem": round(random.uniform(3.5, 5.5), 3),
        "decrypted_shellcode_entropy": round(random.uniform(3.0, 5.0), 3),
        "alloc_rwx": True,
    }
    prompt = (f"Windows Host -- Runtime-Decrypted Shellcode Execution.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  Process: {p['proc']}\n"
              f"  encryption: {p['encryption']}  key: {p['key']}\n"
              f"  anti_sandbox_checks: {'; '.join(p['anti_sandbox'])}\n"
              f"  payload_entropy_on_disk={p['payload_entropy_on_disk']:.3f}\n"
              f"  decrypted_shellcode_in_mem=YES  alloc_PAGE_EXECUTE_READWRITE=YES\n"
              f"  decrypted_entropy={p['decrypted_shellcode_entropy']:.3f}")
    cot = _cot(
        "Commercial software uses code encryption (anti-tamper, licensing) but with "
        "trusted certificates, predictable decryption patterns, and no VM/timing evasion checks. "
        "Anti-sandbox timing checks + VM artifact detection before decryption is not software protection.",
        f"Anti-sandbox checks before decryption: {'; '.join(p['anti_sandbox'][:2])} -- "
        "malware avoiding analysis environments. "
        f"Encryption: {p['encryption']} ({p['key']}): per-build key makes signature detection impossible. "
        f"Payload entropy on disk={p['payload_entropy_on_disk']:.3f} (encrypted blob -- no AV signature). "
        "RWX allocation + decrypt + execute: classic shellcode execution pattern. "
        f"Decrypted entropy={p['decrypted_shellcode_entropy']:.3f} (shellcode byte distribution).",
        f"Host {p['host']}: encrypted shellcode successfully decrypted and executing in {p['proc']}. "
        "Anti-sandbox checks confirm attacker was aware of analysis environment detection.",
        "Runtime-encrypted shellcode execution confirmed.",
        "MITRE T1027.002 (Obfuscated Files: Software Packing) + T1027.007 (Dynamic API Resolution). "
        "Kill process, memory dump, isolate host.",
    )
    return prompt, cot, "true_positive"

def _shellcode_enc_fp(i):
    p = {"app": "DRM-protected game", "enc": "Denuvo anti-tamper",
         "anti_sandbox": "NO", "signed": True, "cert": "game publisher EV cert"}
    prompt = (f"Windows Host -- DRM-Protected Executable.\n"
              f"  application={p['app']}  protection={p['enc']}\n"
              f"  anti_sandbox_checks={p['anti_sandbox']}\n"
              f"  signed={p['signed']}  publisher_cert={p['cert']}\n"
              f"  no_network_C2_after_decrypt=YES")
    cot = _cot(
        "Denuvo DRM -- signed by game publisher EV cert, no anti-sandbox checks, no C2 after decrypt.",
        f"Signed EV cert. No anti-sandbox. No RWX C2 shellcode. No outbound C2.",
        "Authorized DRM-protected game executable.",
        "Authorized DRM protection. No action.",
        "T1027.002 -- AUTHORIZED DRM. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. SmartScreenBypass
#     Evidence: DLL sideload targeting auto-elevated binary,
#               shellcode in DLL evades SmartScreen MOTW check,
#               process launched without SmartScreen warning,
#               unsigned DLL + signed host binary combination
#     Sources: collection/Bypass-Smartscreen (DLL sideload + shellcode encryption)
#     Admin FP: Vendor app with bundled DLL (signed, vendor directory)
# ═══════════════════════════════════════════════════════════════════════════════

def _ss_tp(i):
    host_apps = [("OneDrive.exe", "version.dll"), ("Teams.exe", "dbghelp.dll"),
                 ("zoom.exe", "winmm.dll"), ("chrome_proxy.exe", "msvcp140.dll")]
    app, dll = host_apps[i % len(host_apps)]
    p = {
        "host_binary": app, "sideloaded_dll": dll,
        "dll_location": rf"C:\Users\{_user()}\AppData\Local\{app.split('.')[0]}\{dll}",
        "dll_signed": False,
        "host_signed": True,
        "smartscreen_bypassed": True,
        "shellcode_in_dll": True,
        "dll_exports_forward": True,
    }
    prompt = (f"Windows Host -- SmartScreen Bypass via DLL Sideload.\n"
              f"  host_binary: {p['host_binary']} (signed = {p['host_signed']})\n"
              f"  sideloaded_dll: {p['sideloaded_dll']} at {p['dll_location']}\n"
              f"  dll_signed: {p['dll_signed']}\n"
              f"  dll_exports_forward_to_system_dll: {p['dll_exports_forward']}\n"
              f"  shellcode_in_dll_dllmain: {p['shellcode_in_dll']}\n"
              f"  smartscreen_check_skipped: {p['smartscreen_bypassed']}\n"
              f"  execution_context: {p['host_binary']} process")
    cot = _cot(
        f"{p['host_binary']} is a signed Microsoft/vendor binary -- SmartScreen trusts it. "
        f"But {p['sideloaded_dll']} in the application directory is unsigned and not "
        "part of the vendor installation. The DLL sideload creates a trust chain: "
        "signed launcher → unsigned payload → shellcode execution.",
        f"Sideloaded {p['sideloaded_dll']} from {p['dll_location']}: "
        f"unsigned, not in system DLL path, not from vendor package. "
        f"Exports forward to legitimate system {p['sideloaded_dll']}: "
        "application functions normally while shellcode runs. "
        "DllMain shellcode: executes on process startup in the context of trusted {p['host_binary']}. "
        "SmartScreen check skipped: SmartScreen only evaluates the launching binary -- "
        "it doesn't recursively validate all DLLs loaded by a signed executable.",
        f"Host: {p['host_binary']} process is executing attacker shellcode. "
        "Traffic, process operations, and file access appear to originate from a trusted binary.",
        "SmartScreen bypass via DLL sideload confirmed.",
        "MITRE T1574.002 (DLL Sideloading) + T1553.005 (SmartScreen bypass). "
        "Remove sideloaded DLL, block execution from AppData paths.",
    )
    return prompt, cot, "true_positive"

def _ss_fp(i):
    p = {"app": "AutoCAD.exe", "dll": "acadRes.dll",
         "path": r"C:\Program Files\Autodesk\AutoCAD 2024\acadRes.dll",
         "signed": "Autodesk", "in_vendor_dir": True}
    prompt = (f"Windows Host -- Vendor DLL Load.\n"
              f"  host_binary=AutoCAD.exe  dll={p['dll']}\n"
              f"  dll_path={p['path']}\n"
              f"  signed_by={p['signed']}  in_vendor_directory={p['in_vendor_dir']}")
    cot = _cot(
        "AutoCAD vendor DLL in Program Files, signed by Autodesk -- legitimate application bundle.",
        f"Signed by {p['signed']}. In vendor install directory. Part of official installation.",
        "Authorized vendor DLL in application directory.",
        "Authorized vendor DLL load. No action.",
        "T1574.002 -- AUTHORIZED VENDOR DLL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 18. DefenderExclusionAdd
#     Evidence: Registry write to HKLM\...\Windows Defender\Exclusions\Paths
#               or Processes or Extensions, exclusion added for attacker payload
#               path or process, Defender stops scanning that location
#     Admin FP: IT adding exclusion for known high-false-positive application
# ═══════════════════════════════════════════════════════════════════════════════

_EXCL_PATHS = [r"C:\Windows\Temp", r"C:\ProgramData\Update",
               r"C:\Users\Public", r"C:\Temp\payload"]
_EXCL_PROCS = ["svchost32.exe", "update.exe", "helper.bat", "run.ps1"]

def _defender_excl_tp(i):
    excl_type = random.choice(["Path", "Process", "Extension"])
    if excl_type == "Path":
        excl_val = random.choice(_EXCL_PATHS)
        reg_key  = rf"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\{excl_val}"
    elif excl_type == "Process":
        excl_val = random.choice(_EXCL_PROCS)
        reg_key  = rf"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\{excl_val}"
    else:
        excl_val = random.choice([".hta",".sct",".vbs",".ps1"])
        reg_key  = rf"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\{excl_val}"
    p = {
        "host": _host(), "user": _user(),
        "actor": random.choice(["cmd.exe","powershell.exe","reg.exe"]),
        "exclusion_type": excl_type, "exclusion_value": excl_val,
        "registry_key": reg_key,
        "payload_already_at_path": i % 2 == 0,
    }
    prompt = (f"Windows Host -- Windows Defender Exclusion Added.\n"
              f"Host: {p['host']}  User: {p['user']}\n"
              f"  actor: {p['actor']}\n"
              f"  exclusion_type: {p['excl_type'] if hasattr(p, 'excl_type') else p['exclusion_type']}\n"
              f"  exclusion_value: {p['exclusion_value']}\n"
              f"  registry_key: {p['registry_key']}\n"
              + (f"  payload_file_already_present_at_path=YES\n" if p['payload_already_at_path'] else ""))
    cot = _cot(
        "IT teams add Defender exclusions for known false-positive applications -- "
        "these are scoped to specific vendor paths (C:\\Program Files\\<Vendor>\\), "
        "deployed via GPO, and documented in change management. "
        f"A {p['actor']} process adding an exclusion for {p['exclusion_value']} "
        "(temp/public path or script extension) is not IT exclusion management.",
        f"Exclusion type={p['exclusion_type']}, value={p['exclusion_value']}: "
        + (f"path {p['exclusion_value']} is a writable staging location -- attacker dropping payloads there. " if p['exclusion_type'] == "Path" else
           f"process {p['exclusion_value']} is an unsigned binary -- attacker's payload executable. " if p['exclusion_type'] == "Process" else
           f"extension {p['exclusion_value']} is a script type -- all scripts of this type now run unscanned. ")
        + f"Registry write by {p['actor']} (interactive session, not GPO). "
        + (f"Payload already present at excluded path: exclusion was added specifically to enable payload execution." if p['payload_already_at_path'] else ""),
        f"Host {p['host']}: Windows Defender will no longer scan {p['exclusion_value']}. "
        "Any malware placed in/at that path or process executes without AV detection.",
        "Windows Defender exclusion added for adversarial path/process/extension.",
        "MITRE T1562.001 (Disable or Modify Tools: Defender Exclusion). "
        "Remove exclusion, re-scan excluded path, investigate what was placed there.",
    )
    return prompt, cot, "true_positive"

def _defender_excl_fp(i):
    p = {"path": r"C:\Program Files\Tenable\Nessus",
         "reason": "false positive on Nessus scanner binaries",
         "ticket": f"SEC-{random.randint(100,999)}", "via": "GPO"}
    prompt = (f"Windows Host -- Defender Exclusion (GPO-deployed).\n"
              f"  exclusion_path={p['path']}\n"
              f"  reason={p['reason']}  ticket={p['ticket']}\n"
              f"  deployed_via={p['via']}  vendor_path=YES")
    cot = _cot(
        "GPO-deployed Defender exclusion for known security scanner false positive -- vendor path, ticket.",
        f"path={p['path']} (vendor install). GPO deployed. Ticket {p['ticket']}. Known FP.",
        "Authorized Defender exclusion for known scanner false positive.",
        "Authorized Defender exclusion via GPO. No action.",
        "T1562.001 -- AUTHORIZED DEFENDER EXCLUSION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 19. LinuxLibcHookEvasion
#     Evidence: LD_PRELOAD / /etc/ld.so.preload writing + libcext.so.2 dropped,
#               hooked functions filtering /proc/net/tcp entries,
#               /etc/ld.so.preload itself hidden by hook (unlink/stat/access blocked),
#               network connections invisible in /proc/net/tcp
#     Sources: collection/Auto-Color (LD_PRELOAD + /proc/net/tcp hiding)
#     Admin FP: Performance profiling library (no /proc hiding)
# ═══════════════════════════════════════════════════════════════════════════════

def _linux_libc_tp(i):
    lib_names = ["libcext.so.2", "libssl.so.1.1", "libpthread.so.999", "libsystem.so.0"]
    p = {
        "host": _host().lower(), "user": _user(), "uid": random.choice([0, 1000]),
        "lib": random.choice(lib_names),
        "preload_file": "/etc/ld.so.preload",
        "hooked_functions": random.sample(
            ["open","openat","fopen","stat","lstat","readdir","unlink","rename","access"], k=5),
        "proc_net_tcp_filtered": True,
        "preload_self_protected": True,
        "c2_hidden": True,
    }
    prompt = (f"Linux Sentinel -- Libc Hook Evasion (LD_PRELOAD Backdoor).\n"
              f"Host: {p['host']}  User: {p['user']} (uid={p['uid']})\n"
              f"  library_dropped: {p['lib']}\n"
              f"  /etc/ld.so.preload_written=YES\n"
              f"  hooked_libc_functions: {', '.join(p['hooked_functions'])}\n"
              f"  /proc/net/tcp_entries_filtered=YES (C2 connection invisible)\n"
              f"  /etc/ld.so.preload_self_protected=YES (unlink/stat/access blocked)")
    cot = _cot(
        "Performance profiling libraries (gperftools, valgrind) use LD_PRELOAD legitimately "
        "but do not filter /proc/net/tcp entries or protect /etc/ld.so.preload from deletion. "
        "A library that hides both itself and network connections is designed for concealment.",
        f"Library {p['lib']} written to non-package-manager path. "
        f"/etc/ld.so.preload modified: loads {p['lib']} into every process. "
        f"Hooked functions: {', '.join(p['hooked_functions'][:3])} -- "
        "intercepts file/directory operations to filter attacker artifacts from output. "
        "/proc/net/tcp filtered: C2 network connections absent from standard network tools (ss, netstat). "
        "/etc/ld.so.preload self-protected: unlink/stat/access calls on preload file return errors "
        "-- attacker cannot easily remove the hook.",
        f"Host {p['host']}: C2 connections and attacker files are invisible to standard admin tools. "
        "Standard system commands return false data.",
        "Libc hook evasion via LD_PRELOAD confirmed -- C2 connections hidden from /proc/net/tcp.",
        "MITRE T1574.006 (Dynamic Linker Hijacking) + T1014 (Rootkit). "
        "Boot from live media -- infected processes cannot be trusted.",
    )
    return prompt, cot, "true_positive"

def _linux_libc_fp(i):
    p = {"lib": "/usr/lib/x86_64-linux-gnu/libasan.so.5",
         "purpose": "AddressSanitizer for dev build",
         "proc_filter": False, "package": "libasan5"}
    prompt = (f"Linux Sentinel -- LD_PRELOAD Dev Tool.\n"
              f"  library={p['lib']}\n"
              f"  purpose={p['purpose']}  package={p['package']}\n"
              f"  proc_net_tcp_filtered=NO  self_protected=NO")
    cot = _cot(
        "AddressSanitizer LD_PRELOAD from package -- no /proc filtering, no self-protection.",
        f"lib={p['lib']} (packaged). No /proc/net/tcp filter. No self-protection.",
        "Authorized AddressSanitizer dev instrumentation.",
        "Authorized ASan dev tool. No action.",
        "T1574.006 -- AUTHORIZED DEV TOOL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# 20. RPCInterfaceRace
#     Evidence: Scheduled task or WMI consumer executing at boot before services,
#               RPC endpoint registration on StorSvc-like interface GUID,
#               NTLMv2 machine account hash capture from relay target,
#               delivery optimization service makes RPC call to attacker endpoint
#     Sources: rpc-racer (StorSvc RPC race for NTLM relay)
#     Admin FP: No admin FP -- masquerading as system service RPC interface is never legitimate
# ═══════════════════════════════════════════════════════════════════════════════

def _rpc_race_tp(i):
    relay_ip = _ip_int()
    p = {
        "host": _host(),
        "technique": "RPC interface registration before legitimate service starts",
        "target_interface": "StorSvc RPC (Storage Service) -- SvcRebootToFlashingMode method",
        "rpc_endpoint": _guid(),
        "scheduled_task": f"\\Microsoft\\Windows\\RPC-Race-{random.randint(100,999)}",
        "wmi_trigger": i % 2 == 0,
        "relay_ip": relay_ip,
        "ntlm_captured": True,
        "machine_account_hash": True,
    }
    prompt = (f"Windows Host -- RPC Interface Race Condition.\n"
              f"Host: {p['host']}\n"
              f"  technique: {p['technique']}\n"
              f"  registered_rpc_interface: {p['rpc_endpoint']}\n"
              f"  mimics_interface: {p['target_interface']}\n"
              f"  persistence_via: {'WMI consumer (boot-time)' if p['wmi_trigger'] else 'Scheduled task: ' + p['scheduled_task']}\n"
              f"  relay_server: {p['relay_ip']}\n"
              f"  ntlm_machine_account_hash_captured={p['ntlm_captured']}\n"
              f"  can_relay_for_ldap_rbcd=YES")
    cot = _cot(
        "System services legitimately register RPC interfaces -- but they do so as part of "
        "their service initialization, under their service account. A scheduled task or WMI consumer "
        "registering an RPC interface before the legitimate service starts to intercept its first "
        "caller has no authorized use case.",
        f"Boot-time execution via {'WMI consumer' if p['wmi_trigger'] else 'scheduled task'}: "
        "attacker registers RPC endpoint before StorSvc starts. "
        f"Mimics {p['target_interface']}: Delivery Optimization Service calls SvcRebootToFlashingMode "
        "and receives attacker's response containing a UNC path. "
        "DoSvc authenticates to the UNC path → machine account NTLMv2 hash sent. "
        f"Relay to {p['relay_ip']}: machine account hash relayed to {relay_ip} for LDAP RBCD or SMB auth.",
        f"Host {p['host']}: machine account hash captured and relayable. "
        "Attacker can relay to LDAP to configure RBCD or to SMB for lateral movement.",
        "RPC interface race condition for NTLM relay confirmed.",
        "MITRE T1557.001 (Adversary-in-the-Middle) + T1187 (Forced Authentication). "
        "Remove scheduled task/WMI consumer, rotate machine account password (reset NTLM hash).",
    )
    return prompt, cot, "true_positive"

def _rpc_race_fp(i):
    p = {"service": "WinRM", "endpoint": "Windows Remote Management",
         "startup": "automatic at boot", "account": "NT AUTHORITY\\NetworkService"}
    prompt = (f"Windows Host -- System Service RPC Registration.\n"
              f"  service={p['service']}  endpoint={p['endpoint']}\n"
              f"  startup={p['startup']}  account={p['account']}\n"
              f"  registered_before_DoSvc=NO  no_scheduled_task=YES")
    cot = _cot(
        "WinRM registering its own RPC endpoint at service startup -- legitimate system service.",
        f"service=WinRM (legitimate). account=NetworkService. No scheduled task race.",
        "Authorized system service RPC registration at startup.",
        "Authorized WinRM RPC registration. No action.",
        "T1557 -- AUTHORIZED SYSTEM SERVICE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# CallbackShellcodeExecution (from code_snippets/CallbackShellcode/)
#   Evidence: VirtualAlloc RWX in own process + callback registration pointing
#             into the alloc region (CreateTimerQueueTimer, EnumChildWindows,
#             SetWindowsHookEx, CreateFiber) -- no CreateRemoteThread/WriteProcessMemory
#   Admin FP: Legitimate UI timer / accessibility tool (bounded, signed, known path)
# ═══════════════════════════════════════════════════════════════════════════════

def _cbs_tp(i):
    callbacks = [
        ("CreateTimerQueueTimer",  "timer callback fires shellcode in pool thread",    "T1055.004"),
        ("EnumChildWindows",       "window enumeration callback used as shellcode stub","T1055.004"),
        ("SetWindowsHookEx",       "WH_KEYBOARD_LL hook procedure points to RWX alloc","T1056.001"),
        ("CreateFiber",            "fiber execution context redirected to alloc region","T1055.004"),
        ("CreateThreadpoolWait",   "threadpool wait callback fires on signalled event", "T1055.004"),
        ("EnumSystemLocales",      "locale enumeration callback as shellcode trampoline","T1055.004"),
    ]
    cb_api, cb_desc, technique = callbacks[i % len(callbacks)]
    alloc_addr = f"0x{random.randint(0x10000000, 0x7FFFFFFF):08x}"
    alloc_size = random.randint(4096, 131072)
    host  = _host()
    user  = _user()
    src   = random.choice(["powershell.exe","rundll32.exe","mshta.exe","wscript.exe","dllhost.exe"])

    prompt = (f"Windows Host Telemetry -- Callback-Based Shellcode Execution.\n"
              f"Host: {host}  User: {user}\n"
              f"  Image: {src}\n"
              f"  VirtualAlloc_RWX=YES  addr={alloc_addr}  size={alloc_size}\n"
              f"  callback_api={cb_api}  callback_addr={alloc_addr}  ({cb_desc})\n"
              f"  CreateRemoteThread=NO  WriteProcessMemory=NO  no_remote_process=YES\n"
              f"  shellcode_in_own_process=YES  no_new_file_on_disk=YES\n"
              f"  alloc_entropy={round(random.uniform(0.88, 0.99), 3)}")

    cot = _cot(
        f"Legitimate applications register {cb_api} callbacks to their own functions -- not to "
        "a freshly VirtualAlloc'd RWX memory region. UI timers, window hooks, and fiber contexts "
        "all reference code in loaded modules (DLL exports), never in anonymous heap allocations.",
        f"VirtualAlloc(RWX) at {alloc_addr} ({alloc_size} bytes) with no corresponding loaded module. "
        f"{cb_api} callback registered to {alloc_addr} (inside RWX alloc, not a DLL export). "
        f"No CreateRemoteThread / WriteProcessMemory = clean evasion of injection API monitors. "
        f"High entropy in alloc region ({round(random.uniform(0.88,0.99),3)}) = encrypted/packed shellcode.",
        f"Host {host} ({user}): {src} is executing shellcode via {cb_api} callback mechanism. "
        "No disk artifact. Shellcode runs in the context of a trusted Windows process.",
        f"Callback-based shellcode execution confirmed via {cb_api}.",
        f"MITRE {technique} (Callback-Based Injection). Dump process memory at {alloc_addr}, "
        "isolate host, trace parent chain to initial stager.",
    )
    return prompt, cot, "true_positive"

def _cbs_fp(i):
    app = random.choice(["Accessibility Insights","NVDA Screen Reader","AutoHotKey"])
    api = random.choice(["SetWindowsHookEx","CreateTimerQueueTimer"])
    prompt = (f"Windows Host Telemetry -- UI Callback Registration.\n"
              f"  Image: {app.lower().replace(' ','')}.exe\n"
              f"  {api}_registered=YES  callback_addr=IN_LOADED_MODULE\n"
              f"  VirtualAlloc_RWX=NO  CreateRemoteThread=NO\n"
              f"  code_signed=YES  vendor={app}  target=own_process\n"
              f"  cmdb_installed=YES")
    cot = _cot(
        f"{app} legitimately registers {api} callbacks to handle UI events. "
        "Callback address is inside a loaded signed DLL -- not an RWX heap allocation.",
        f"callback_addr=IN_LOADED_MODULE (DLL export, not anonymous alloc). VirtualAlloc_RWX=NO. "
        f"Signed binary. CMDB-registered installation.",
        f"Authorized {app} UI callback -- no shellcode indicators.",
        f"{app} {api} callback in loaded module -- no RWX alloc, signed, CMDB registered.",
        f"T1055.004 -- AUTHORIZED UI FRAMEWORK. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# DSEDriverSignatureBypass (from BYOVD/DSERemover/)
#   Evidence: BYOVD driver load + IOCTL targeting ci.dll g_CiOptions kernel var
#             → subsequent unsigned driver loads successfully (EventID 6 Signed=false
#             without test-signing boot config)
#   Admin FP: IT-authorized test-signing mode on developer machine (bcdedit shows
#             TESTSIGNING=On, change ticket, DEV CMDB tag)
# ═══════════════════════════════════════════════════════════════════════════════

def _dse_tp(i):
    vuln_drivers = ["RTCore64.sys","WinRing0x64.sys","mhyprot2.sys","ene.sys","gdrv.sys"]
    vuln_driver  = random.choice(vuln_drivers)
    unsigned_drv = f"payload{random.randint(100,999)}.sys"
    host = _host()

    prompt = (f"Windows Host Telemetry -- Driver Signature Enforcement Bypass.\n"
              f"Host: {host}\n"
              f"  phase_1: sysmon_event_id=6 (DriverLoaded)  driver={vuln_driver}\n"
              f"    Signed=true  SignatureStatus=Valid  (known-vulnerable BYOVD stepping stone)\n"
              f"  phase_2: DeviceIoControl_to_{vuln_driver.replace('.sys','')}=YES\n"
              f"    ioctl_target=ci.dll_g_CiOptions  operation=patch_to_0\n"
              f"    effect=DSE_DISABLED  (kernel no longer validates driver signatures)\n"
              f"  phase_3: sysmon_event_id=6 (DriverLoaded)  driver={unsigned_drv}\n"
              f"    Signed=false  SignatureStatus=Unsigned\n"
              f"    load_succeeded=YES  (normally blocked by DSE)\n"
              f"  testsigning_boot_config=NO  (not test-signing mode)")

    cot = _cot(
        "Unsigned drivers are blocked by Windows Code Integrity unless test-signing mode is "
        "enabled (bcdedit /set testsigning on) and the system was rebooted. An unsigned driver "
        "loading WITHOUT test-signing enabled means DSE was patched at runtime via kernel exploit.",
        f"Phase 1: {vuln_driver} (known-vulnerable driver) loaded to obtain kernel write primitive. "
        f"Phase 2: IOCTL patches ci.dll g_CiOptions to 0 -- DSE disabled at kernel level. "
        f"Phase 3: {unsigned_drv} loads despite Signed=false and no test-signing boot config. "
        "This three-phase sequence is definitional BYOVD-based DSE bypass.",
        f"Host {host}: DSE disabled -- attacker can now load arbitrary unsigned kernel drivers. "
        "All kernel-level defensive controls (EDR minifilters, callback arrays) are at risk.",
        "DSE bypass via BYOVD confirmed -- ci.dll patch + unsigned driver load without test-signing.",
        "MITRE T1562.001 + T1014 (Impair Defenses + Rootkit). Re-image host immediately; "
        "DSE patch persists until reboot but unsigned drivers may have installed persistent rootkit.",
    )
    return prompt, cot, "true_positive"

def _dse_fp(i):
    host = f"DEV-{random.randint(10,99)}"
    prompt = (f"Windows Host Telemetry -- Test-Signing Mode Driver Load.\n"
              f"  Host: {host}  cmdb_tag=DEV_WORKSTATION\n"
              f"  sysmon_event_id=6  driver=testdriver_{random.randint(100,999)}.sys\n"
              f"  Signed=false  SignatureStatus=Unsigned\n"
              f"  testsigning_boot_config=YES  (bcdedit shows TESTSIGNING=On)\n"
              f"  boot_config_change_ticket=CHG-{random.randint(10000,99999)}\n"
              f"  no_byovd_driver_load=YES  no_ci_patch_ioctl=YES\n"
              f"  executing_account=svc-devops  driver_path=C:\\dev\\drivers\\")
    cot = _cot(
        "TESTSIGNING mode explicitly enabled via bcdedit on a CMDB-tagged DEV workstation "
        "with a change ticket -- developer loading test-signed driver for development.",
        "testsigning_boot_config=YES (legitimate -- not runtime ci.dll patch). "
        "No BYOVD stepping-stone driver. No IOCTL to ci.dll. "
        "DEV workstation with change ticket. Driver path is development directory.",
        "Authorized test driver load on development machine -- no DSE bypass exploit.",
        "Test-signing mode with change ticket on DEV workstation -- no BYOVD or ci.dll patch.",
        "T1562.001 -- AUTHORIZED TEST SIGNING ON DEV MACHINE. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# KernelETWTIProviderRemoval (from BYOVD/ETwTiRemover/)
#   Evidence: BYOVD driver load + IOCTL that patches EtwThreatIntelProvider
#             in kernel → ETW-TI events (ImageLoad, ProcessCreate, NetworkConnect)
#             disappear from EDR telemetry stream; gap confirmed by event sequence
#             analysis showing event IDs vanishing post-IOCTL
#   Admin FP: NONE -- removing kernel ETW threat intel providers has no authorized use
# ═══════════════════════════════════════════════════════════════════════════════

def _etw_ki_tp(i):
    vuln_driver   = random.choice(["RTCore64.sys","WinRing0x64.sys","mhyprot2.sys","HW64.sys"])
    provider_name = random.choice(["EtwThreatIntelProvider","Microsoft-Windows-Threat-Intelligence",
                                   "Microsoft-Windows-Security-Auditing-TI"])
    gap_start_s   = random.randint(5, 60)
    host          = _host()
    events_before = random.randint(80, 500)

    prompt = (f"Windows Host Telemetry -- Kernel ETW Provider Removal.\n"
              f"Host: {host}\n"
              f"  phase_1: sysmon_event_id=6  driver={vuln_driver}  (BYOVD loader)\n"
              f"  phase_2: DeviceIoControl_to_{vuln_driver.replace('.sys','')}=YES\n"
              f"    ioctl_operation=patch_etw_provider_array\n"
              f"    target_provider={provider_name}\n"
              f"  phase_3: etw_ti_event_gap_detected=YES\n"
              f"    events_per_min_before={events_before}  events_per_min_after=0\n"
              f"    gap_started_s_after_ioctl={gap_start_s}\n"
              f"    affected_event_types=ImageLoad,ProcessCreate,NetworkConnect,AllocVM\n"
              f"  sysmon_events_unaffected=YES  (user-mode Sysmon still running)\n"
              f"  edr_kernel_telemetry_blind=YES")

    cot = _cot(
        f"No production software, driver update, or IT tool removes ETW threat intelligence "
        f"providers ({provider_name}) from kernel memory. These providers feed directly into "
        "EDR kernel callbacks; their removal is exclusively a defensive-capability attack.",
        f"BYOVD {vuln_driver} loaded as kernel write primitive. "
        f"IOCTL patches EtwThreatIntelProvider array in kernel -- removes ETW-TI from provider list. "
        f"Telemetry gap: {events_before} events/min → 0 within {gap_start_s}s of IOCTL. "
        "EDR kernel telemetry (ImageLoad, ProcessCreate, AllocVM) now blind -- "
        "attacker can execute payloads without kernel-level observation.",
        f"Host {host}: kernel ETW threat intel provider removed. "
        "All subsequent process injection, shellcode allocation, and network connections "
        "are invisible to EDR kernel hooks. Sysmon (user-mode) may still log some events.",
        "Kernel ETW-TI provider removal confirmed -- BYOVD + IOCTL + telemetry gap.",
        "MITRE T1562.006 + T1014 (ETW Tampering + Rootkit). "
        "Reboot immediately to restore ETW-TI, collect memory forensics before reboot, "
        "treat all activity on this host post-IOCTL as unobserved.",
    )
    return prompt, cot, "true_positive"

def _etw_ki_fp(i):
    prompt = (f"Windows Host Telemetry -- ETW Session Configuration Change.\n"
              f"  operation=ETW_session_stop  session_name=Microsoft-Windows-Win32k\n"
              f"  changed_by=svc-monitoring  method=ControlTrace_API\n"
              f"  kernel_provider_array_modified=NO  byovd_driver_load=NO\n"
              f"  ticket=MON-{random.randint(1000,9999)}  reason=reduce_noise_high_freq_events")
    cot = _cot(
        "Stopping a user-mode ETW session via ControlTrace API to reduce telemetry noise "
        "is a legitimate monitoring configuration change -- it does not patch kernel memory.",
        "kernel_provider_array_modified=NO (no kernel patch). byovd_driver_load=NO. "
        "ControlTrace API (user-mode, authorized). Service account with ticket.",
        "Authorized ETW session configuration -- no kernel modification.",
        "ETW session stop via ControlTrace -- user-mode, no kernel patch, change ticket.",
        "T1562.006 -- AUTHORIZED MONITORING CONFIGURATION. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ── Extension: 5 additional bypass/evasion classes ───────────────────────────

def _cgbypass_tp(i):
    host = _host(); user = _user()
    variants = [
        ("patch lsaiso.exe memory to disable VBS isolation guard pages → dump protected secrets",
         "lsaiso.exe  GrantedAccess=0x1FFFFF  from low-IL process"),
        ("load vulnerable driver → read lsaiso kernel object → decrypt VBS-sealed credentials",
         "RTCore64.sys loaded → kernel read of lsaiso context → credential exposure"),
    ]
    desc, indicator = variants[i % len(variants)]
    prompt = (f"Windows Host Telemetry -- Credential Guard VBS Bypass.\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1_bypass: {indicator}\n"
              f"  stage_2_patch: EventID=10 (ProcessAccess)\n"
              f"    TargetImage: lsaiso.exe  GrantedAccess=0x1FFFFF\n"
              f"    caller_IntegrityLevel=Medium  (requires kernel exploit to achieve)\n"
              f"  stage_3_read: protected_credential_material_extracted=YES\n"
              f"    ntlm_hashes_from_VBS_protected_memory=YES\n"
              f"  technique: {desc}")
    cot = _cot(
        "lsaiso.exe (LSA Isolated) runs inside VBS (Virtualization-Based Security) and holds "
        "protected credential material. Legitimate access: none from user-mode processes. "
        "PROCESS_ALL_ACCESS on lsaiso.exe requires defeating VBS isolation = kernel exploit.",
        f"PROCESS_ALL_ACCESS (0x1FFFFF) on lsaiso.exe from Medium-IL process -- "
        "impossible without VBS bypass. {desc}. Credential material extracted from "
        "VBS-protected memory = Credential Guard bypassed.",
        f"Host {host} ({user}): Credential Guard VBS isolation bypassed. "
        "Protected credential material exposed.",
        "Credential Guard bypass confirmed -- VBS isolation defeated.",
        "MITRE T1556.002 + T1068. Isolate host. Full credential rotation required. "
        "Assume all credentials on this host compromised.",
    )
    return prompt, cot, "true_positive"

def _cgbypass_fp(i):
    prompt = (f"Windows Host Telemetry -- VBS System Health Query.\n"
              f"  EventID=10  TargetImage: lsaiso.exe\n"
              f"    GrantedAccess=0x1000  (PROCESS_QUERY_LIMITED_INFORMATION only)\n"
              f"    SourceImage: SecurityHealthService.exe  IntegrityLevel=SYSTEM\n"
              f"  no_memory_read=YES  no_credential_extraction=YES")
    cot = _cot(
        "SecurityHealthService querying lsaiso health status -- limited access only.",
        "SYSTEM source. 0x1000 (limited). No memory read. Security health check.",
        "Authorized VBS health query -- limited access, SYSTEM source.",
        "VBS health check -- 0x1000, SecurityHealthService.",
        "T1556.002 -- AUTHORIZED HEALTH QUERY. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _fiber_tp(i):
    host = _host(); user = _user()
    pid = _pid()
    prompt = (f"Windows Host Telemetry -- Fiber-Based Shellcode Execution (Thread Hook Evasion).\n"
              f"Host: {host}  User: {user}  PID={pid}\n"
              f"  memory_alloc: VirtualAlloc(PAGE_EXECUTE_READWRITE)  size=4096  (shellcode)\n"
              f"  fiber_api_sequence:\n"
              f"    ConvertThreadToFiber(NULL) → CreateFiber(0, shellcode_addr, NULL)\n"
              f"    → SwitchToFiber(fiber_handle)  (executes shellcode in fiber context)\n"
              f"  no_NtCreateThread=YES  no_CreateRemoteThread=YES\n"
              f"    (evades NtCreateThread EDR hooks -- no thread creation event)\n"
              f"  ETW_gap: no_thread_start_event=YES  memory_entropy=7.9\n"
              f"  subsequent: outbound_C2_connection=YES  new_process_created=YES")
    cot = _cot(
        "Fiber APIs (CreateFiber/SwitchToFiber) are used by some game engines, "
        "cooperative multitasking systems, and fiber-based coroutine libraries. "
        "Legitimate use: fibers have identifiable calling context and no RWX memory.",
        "ConvertThreadToFiber + CreateFiber(RWX shellcode addr) + SwitchToFiber = "
        "shellcode execution without any thread creation event (NtCreateThread/EventID 8). "
        "Evades EDR hooks on thread creation. RWX allocation + fiber entry point = "
        "shellcode execution via fiber scheduling. ETW gap in thread events confirms.",
        f"Host {host} PID={pid}: Shellcode executed via fiber API -- no thread event, "
        "bypasses thread-creation EDR hooks.",
        "Fiber-based shellcode execution confirmed -- RWX + fiber + no thread event.",
        "MITRE T1055 (Process Injection). Kill PID={pid}, dump memory for forensics.",
    )
    return prompt, cot, "true_positive"

def _fiber_fp(i):
    prompt = (f"Windows Host Telemetry -- Legitimate Fiber Usage (Game Engine).\n"
              f"  Image: GameEngine.exe  fibers_used=YES\n"
              f"    ConvertThreadToFiber + CreateFiber (many, for game task scheduling)\n"
              f"  no_RWX_allocation=YES  (fibers use normal stack memory)\n"
              f"  no_shellcode_pattern=YES  no_outbound_C2=YES\n"
              f"  binary_signed=YES  vendor=UnrealEngine")
    cot = _cot(
        "Game engine using fibers for cooperative multitasking -- signed, no RWX shellcode, no C2.",
        "Signed game engine. No RWX. No shellcode entropy. No C2. Normal fiber scheduling.",
        "Authorized fiber use -- game engine, signed, no RWX shellcode.",
        "Game engine fibers -- signed, no RWX, no C2.",
        "T1055 -- AUTHORIZED FIBER USE. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _pplkill_tp(i):
    host = _host(); user = _user()
    edr_proc = random.choice(["MsMpEng.exe","CSFalconService.exe","SentinelAgent.exe","CylanceProtect.exe"])
    vuln_drv  = random.choice(["RTCore64.sys","gdrv.sys","cpuz141_x64.sys","iqvw64e.sys"])
    prompt = (f"Windows Host Telemetry -- PPL Process Killer (Protected EDR Termination).\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1_load: EventID=6 (DriverLoad)\n"
              f"    Image: {vuln_drv}  Signed: true  SignatureStatus=Expired\n"
              f"    driver_is_known_LOLDRIVER=YES  PPL_bypass_tool_loaded=YES\n"
              f"  stage_2_exploit: EventID=10 (ProcessAccess)\n"
              f"    TargetImage: {edr_proc}  GrantedAccess=0x1FFFFF\n"
              f"    (PPL protection bypassed via kernel handle manipulation)\n"
              f"  stage_3_kill: EventID=4689 (ProcessTermination)\n"
              f"    TerminatedProcess: {edr_proc}  TerminatedBy: attacker_tool\n"
              f"    EDR_telemetry_gap_begins_at_termination_time=YES")
    cot = _cot(
        f"{edr_proc} is Protected Process Light (PPL) -- standard user-mode processes "
        "cannot open it with PROCESS_ALL_ACCESS, let alone terminate it. "
        "Legitimate driver loads: signed and not expired, from vendor update channels.",
        f"Known LOLDRIVER ({vuln_drv}) with expired signature loaded = BYOVD technique "
        f"to gain kernel R/W. PROCESS_ALL_ACCESS on PPL {edr_proc} = protection level "
        "bypassed via kernel EPROCESS manipulation. Termination of PPL EDR = "
        "blind spot created for subsequent attack phases.",
        f"Host {host} ({user}): PPL EDR {edr_proc} killed via BYOVD kernel exploit. "
        "Security telemetry gap begins. Assume attacker operating undetected.",
        f"PPL killer confirmed -- {vuln_drv} → PROCESS_ALL_ACCESS on {edr_proc} → killed.",
        "MITRE T1562.001 + T1068. CRITICAL: EDR blind spot. "
        f"Check for subsequent activity after {edr_proc} termination. Restart EDR, isolate host.",
    )
    return prompt, cot, "true_positive"

def _pplkill_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized EDR Update.\n"
              f"  EventID=6  Image: CrowdStrike_new_sensor.sys  Signed=true  SignatureStatus=Valid\n"
              f"    loaded_by=CsAgentService  (vendor's own service)\n"
              f"  no_PPL_bypass=YES  no_PROCESS_ALL_ACCESS_on_EDR=YES\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}")
    cot = _cot(
        "Vendor EDR loading its own signed driver via its own service -- normal update.",
        "Valid signature. Vendor service parent. No PPL bypass. Change ticket.",
        "Authorized EDR driver update -- valid signature, vendor service.",
        "EDR driver update -- vendor signed, no PPL bypass.",
        "T1562.001 -- AUTHORIZED EDR UPDATE. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _patchguard_tp(i):
    host = _host(); user = _user()
    prompt = (f"Windows Host Telemetry -- PatchGuard Subversion Attempt.\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1: bcdedit /set testsigning on  (requires admin + reboot)\n"
              f"  stage_2: EventID=6 (DriverLoad)\n"
              f"    Image: patchguard_disabler.sys  Signed=false\n"
              f"    (test signing allows loading of unsigned drivers)\n"
              f"  stage_3: kernel_function_hooks_detected=YES\n"
              f"    KiSystemServiceUser_patched=YES  (SSDT hook)\n"
              f"    PgContext_randomization_bypass=YES\n"
              f"  EventID=13: HKLM...BCD...testsigning=Yes  (BCD modification)")
    cot = _cot(
        "Test signing (bcdedit /set testsigning on) is used by kernel developers "
        "for driver development. Production systems never have test signing enabled.",
        "bcdedit enabling test signing = pre-requisite for unsigned kernel code. "
        "Unsigned driver loading with SSDT hooks = PatchGuard bypass (loads before "
        "PatchGuard's next integrity check timer fires). "
        "KiSystemServiceUser patch = full kernel control -- all syscalls interceptable.",
        f"Host {host}: PatchGuard subverted -- test signing enabled, unsigned driver loaded, "
        "SSDT hooks installed. Full kernel compromise.",
        "PatchGuard bypass confirmed -- test signing + unsigned driver + SSDT hooks.",
        "MITRE T1068 + T1014. Isolate host. Full reinstall required -- kernel is untrusted.",
    )
    return prompt, cot, "true_positive"

def _patchguard_fp(i):
    prompt = (f"Windows Host Telemetry -- Developer Test Environment.\n"
              f"  EventID=13: HKLM...BCD...testsigning=Yes\n"
              f"  machine_tag=DEV-KERNEL-TEST  domain=DEVLAB (isolated network)\n"
              f"  user_group=KernelEngineering  ITSEC_approved=YES\n"
              f"  no_malicious_kernel_hooks=YES  known_test_driver=YES")
    cot = _cot(
        "Approved kernel dev environment -- isolated dev lab, kernel engineering group, "
        "ITSEC approved, test driver only.",
        "DEVLAB domain (isolated). KernelEngineering group. ITSEC approved. "
        "Known test driver. No malicious hooks.",
        "Authorized kernel dev test environment -- isolated, approved, known driver.",
        "Kernel dev test env -- isolated lab, approved, no malicious hooks.",
        "T1068 -- AUTHORIZED DEV ENVIRONMENT. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


def _etwconsumer_tp(i):
    host = _host(); user = _user()
    provider = random.choice([
        "Microsoft-Windows-Threat-Intelligence",
        "Microsoft-Windows-Security-Auditing",
        "Microsoft-Windows-Kernel-Process",
    ])
    prompt = (f"Windows Host Telemetry -- ETW Threat Intelligence Provider Disabled.\n"
              f"Host: {host}  User: {user}\n"
              f"  stage_1_patch: ntdll.dll!EtwEventWrite patched in-process\n"
              f"    (NOP sled replacing event write -- silences ETW from this process)\n"
              f"  stage_2_consumer: EventID=12 (RegistryDelete)\n"
              f"    TargetObject: HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\"
              f"EventLog-Security\\{{{provider}}}\n"
              f"    (ETW consumer registration deleted -- no more event delivery)\n"
              f"  stage_3_gap: ETW_telemetry_gap_from_provider={provider}\n"
              f"    subsequent_activity_invisible_to_consumers=YES")
    cot = _cot(
        "ETW consumer registrations are modified by logging infrastructure (SIEM agents, "
        "WEF configuration). Legitimate changes: by SYSTEM from signed logging agents "
        "with change tickets.",
        f"In-process ntdll!EtwEventWrite NOP patch = per-process ETW silence. "
        f"Registry deletion of {provider} consumer key = system-wide ETW gap. "
        "Combines process-level and system-level ETW blindness. "
        "Subsequent activity invisible to SOC ETW consumers.",
        f"Host {host} ({user}): ETW provider {provider} disabled at both process and "
        "system level. Telemetry gap created.",
        f"ETW consumer kill confirmed -- {provider} disabled.",
        "MITRE T1562.006 (Impair Defenses: Indicator Blocking). "
        "Re-enable ETW provider, audit all activity during gap period.",
    )
    return prompt, cot, "true_positive"

def _etwconsumer_fp(i):
    prompt = (f"Windows Host Telemetry -- Authorized ETW Configuration.\n"
              f"  EventID=12  TargetObject: HKLM...WMI\\Autologger\\...\n"
              f"    modification_by=WEFClient.exe  (Windows Event Forwarding)\n"
              f"    IntegrityLevel=SYSTEM  signed_binary=YES\n"
              f"  change_ticket=CHG-{random.randint(10000,99999)}  gpo_deployed=YES")
    cot = _cot(
        "WEF agent (SYSTEM, signed) reconfiguring ETW consumer -- authorized GPO change.",
        "WEFClient.exe (signed). SYSTEM. GPO deployed. Change ticket.",
        "Authorized ETW consumer reconfiguration -- WEF, SYSTEM, GPO.",
        "WEF ETW config -- SYSTEM, signed, GPO, change ticket.",
        "T1562.006 -- AUTHORIZED ETW CONFIG. No action.", action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Add on (2026-06-05)
# ═══════════════════════════════════════════════════════════════════════════════

# ── PoolPartyInjection (bypass/poolparty + waiting_thread_hijacking) ──
def _poolparty_tp(i):
    target = random.choice(["svchost.exe","RuntimeBroker.exe","dllhost.exe","notepad.exe"])
    p = {"src": random.choice(["powershell.exe","cmd.exe","unknown.exe"]),
         "target": target,
         "api_seq": ["OpenProcess(PROCESS_ALL_ACCESS)",
                     "VirtualAllocEx(RWX)",
                     "WriteProcessMemory (shellcode)",
                     "TpAllocWork / SubmitThreadpoolWork (thread pool callback to shellcode)"],
         "no_ntcreatethreadex": True,
         "shellcode_entropy": round(random.uniform(3.5, 5.5), 3)}
    prompt = (f"Windows Sysmon -- Thread Pool Code Injection.\n"
              f"  SourceProcess: {p['src']}\n"
              f"  TargetProcess: {p['target']}\n"
              f"  API_sequence:\n    " + "\n    ".join(p['api_seq']) + "\n"
              f"  NtCreateThreadEx_or_CreateRemoteThread=NO\n"
              f"  shellcode_entropy_in_alloc={p['shellcode_entropy']:.3f}")
    cot = _cot(
        "Thread pool APIs are used by Windows services for async work. "
        "No legitimate admin tool allocates RWX memory in a remote process and submits "
        "a thread pool work item pointing to that region.",
        f"TpAllocWork/SubmitThreadpoolWork to shellcode at RWX region: "
        "thread pool injection bypasses EDR hooks on NtCreateThreadEx. "
        f"shellcode_entropy={p['shellcode_entropy']:.3f} (encrypted payload). "
        "No conventional thread creation visible -- EDR stack unwind shows worker thread.",
        f"Host: {p['target']} running attacker shellcode via thread pool worker.",
        "Thread pool code injection confirmed.",
        "MITRE T1055 (Process Injection via Thread Pool). Isolate, memory dump.",
    )
    return prompt, cot, "true_positive"

def _poolparty_fp(i):
    p = {"proc": "sqlservr.exe", "api": "SubmitThreadpoolWork (async query)", "legitimate": True}
    prompt = (f"Windows Sysmon -- SQL Server Thread Pool.\n"
              f"  process={p['proc']}  api={p['api']}\n"
              f"  no_remote_process=YES  no_VirtualAllocEx=YES")
    cot = _cot(
        "SQL Server using thread pool for async query execution -- same-process, no remote alloc.",
        "No remote process. No VirtualAllocEx. SQL Server context.",
        "Authorized SQL Server thread pool usage. No action.",
        "Authorized SQL Server async. No action.",
        "T1055 -- AUTHORIZED SQL SERVER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ── EDRLogWipe (microsoft/edraser + event log deletion) ──
def _edrlogwipe_tp(i):
    logs = random.sample(["Security","System","Microsoft-Windows-Sysmon/Operational",
                           "Microsoft-Windows-Windows Defender/Operational","Application"], k=random.randint(3,5))
    p = {"actor": random.choice(["cmd.exe","powershell.exe","wevtutil.exe"]),
         "logs_cleared": logs,
         "event_1102": True,
         "method": random.choice(["wevtutil cl","ClearEventLog API","EventLog service interaction"])}
    prompt = (f"Windows Sysmon -- Event Log Wipe.\n"
              f"  actor={p['actor']}\n"
              f"  method={p['method']}\n"
              f"  logs_cleared: {', '.join(p['logs_cleared'])}\n"
              f"  event_1102_generated=YES  event_104_generated=YES\n"
              f"  includes_sysmon_log={'Sysmon' in ' '.join(p['logs_cleared'])}")
    cot = _cot(
        "Log rotation and archival are performed by Windows Event Log service automatically. "
        f"Manually clearing {len(p['logs_cleared'])} event logs including Security and Sysmon "
        "immediately after operational activity has no administrative justification.",
        f"method={p['method']}: deliberate manual clearing. "
        f"Logs cleared: {', '.join(p['logs_cleared'][:2])}... -- primary forensic evidence sources. "
        "Includes Sysmon: eliminates process creation and network connection history. "
        "Event 1102 + 104: confirms successful log destruction.",
        "Forensic evidence destroyed. Attack timeline reconstruction impaired.",
        "Event log wipe confirmed -- evidence destruction post-compromise.",
        "MITRE T1070.001 (Indicator Removal: Clear Windows Event Logs). "
        "Check backup logs, audit who ran the wipe, review period before wipe.",
    )
    return prompt, cot, "true_positive"

def _edrlogwipe_fp(i):
    p = {"sa": "svc-log-archiver", "log": "Application", "ticket": f"OPS-{random.randint(100,999)}"}
    prompt = (f"Windows Sysmon -- Scheduled Log Archival.\n"
              f"  account={p['sa']}  log_cleared={p['log']}\n"
              f"  ticket={p['ticket']}  schedule=monthly\n"
              f"  archive_created_first=YES  only_application_log=YES")
    cot = _cot(
        "Monthly application log archival by service account -- bounded, scheduled, archival-first.",
        f"Service account. Monthly. Application log only. Archive created first. Ticket {p['ticket']}.",
        "Authorized log archival. No action.",
        "Authorized log archival. No action.",
        "T1070.001 -- AUTHORIZED ARCHIVAL. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ── ProcessImpersonationEDR (i_am_antimalware / defender_write/InjectDLL) ──
def _proc_impersonate_tp(i):
    edr_names = ["MsMpEng.exe","SentinelAgent.exe","CSFalconService.exe","elastic-agent.exe"]
    fake_name = random.choice(edr_names)
    p = {"fake_proc": fake_name,
         "actual_path": f"C:\\Users\\{_user()}\\AppData\\Local\\Temp\\{fake_name}",
         "signed": False,
         "parent": random.choice(["cmd.exe","powershell.exe","wscript.exe"]),
         "event_log_spoofed": i%2==0}
    prompt = (f"Windows Sysmon -- Security Product Process Impersonation.\n"
              f"  process_name={p['fake_proc']}\n"
              f"  actual_path={p['actual_path']}\n"
              f"  binary_signed=NO\n"
              f"  parent={p['parent']}\n"
              f"  path_not_vendor_directory=YES\n"
              + (f"  spoofed_event_log_entries=YES (fake Defender events)\n" if p['event_log_spoofed'] else ""))
    cot = _cot(
        f"Legitimate {fake_name} resides in a vendor-specific directory (C:\\Program Files\\, "
        "C:\\ProgramData\\) and is signed by the vendor. An unsigned copy in %APPDATA%\\Temp "
        "launched from a script host is not the real security agent.",
        f"path={p['actual_path']} (Temp -- not vendor dir). "
        f"signed=NO ({fake_name} is always vendor-signed). "
        f"parent={p['parent']} (security agents are launched by SCM, not script hosts). "
        + (f"Spoofed event log: fake Defender detections to confuse IR timeline. " if p['event_log_spoofed'] else ""),
        f"Fake {fake_name} running from temp path -- masquerading as security product "
        "to blend into process listings.",
        "Security product process impersonation confirmed.",
        "MITRE T1036.005 (Masquerading: Match Legitimate Name). "
        "Kill fake process, check for DLL injection into real AV process.",
    )
    return prompt, cot, "true_positive"

def _proc_impersonate_fp(i):
    p = {"proc": "MsMpEng.exe", "path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
         "signed": True}
    prompt = (f"Windows Sysmon -- Defender Process.\n"
              f"  process={p['proc']}  path={p['path']}\n"
              f"  signed={p['signed']}  vendor_directory=YES")
    cot = _cot(
        "Genuine MsMpEng.exe in Defender platform directory -- signed, vendor path.",
        f"Signed. Vendor directory. Microsoft cert.",
        "Authorized Defender process. No action.",
        "Authorized Defender. No action.",
        "T1036.005 -- LEGITIMATE AV PROCESS. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ── EDRStartupHinder (microsoft/EDRStartupHinder -- IFEO / service disable) ──
def _edr_startup_hinder_tp(i):
    edrs = ["MsMpEng.exe","SentinelAgent.exe","CSFalconService.exe",
            "CylanceSvc.exe","elastic-agent.exe","cb.exe","ds_agent.exe"]
    target = edrs[i % len(edrs)]
    method = random.choice(["IFEO Debugger redirect","Service Start=Disabled","GlobalFlag=0x200"])
    host = _host(); user = _user()
    ifeo_detail = (
        f"  EventID=13 (RegistrySet):\n"
        f"    TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        f"\\Image File Execution Options\\{target}\\Debugger\n"
        f"    Details=C:\\Windows\\System32\\svchost.exe\n"
    ) if "IFEO" in method else (
        f"  EventID=13 (RegistrySet):\n"
        f"    TargetObject=HKLM\\SYSTEM\\CurrentControlSet\\Services\\{target.replace('.exe','')}\\Start\n"
        f"    Details=DWORD (0x00000004) → SERVICE_DISABLED\n"
    )
    prompt = (f"Windows Sysmon -- EDR Startup Blocker.\n"
              f"Host: {host}  User: {user}  IntegrityLevel=High\n"
              f"  target_binary={target}  method={method}\n"
              f"{ifeo_detail}"
              f"  edr_gap_after_next_reboot=YES  no_crash_visible=YES")
    cot = _cot(
        f"IFEO debugger keys are used by developers to attach debuggers on startup. "
        f"Redirecting a security product ({target}) to svchost.exe is not development -- "
        "it suppresses the security process without generating a crash or log entry.",
        f"method={method}: targets {target} -- a security binary, not a developer target. "
        "HKLM write (admin required): foothold already established. "
        "IFEO redirect to svchost.exe = startup suppression, not debugging. "
        "Impact: EDR offline after next reboot -- persistent blind spot.",
        f"Host {host}: EDR binary {target} blocked from starting via {method}. "
        "Host will operate without endpoint protection after reboot.",
        f"EDR startup suppression via {method} confirmed.",
        "MITRE T1562.001 (Impair Defenses: Disable or Modify Tools). "
        "Restore EDR service config, remove IFEO key, enforce EDR tamper protection.",
    )
    return prompt, cot, "true_positive"

def _edr_startup_hinder_fp(i):
    p = {"target": "notepad.exe", "debugger": "devenv.exe", "ticket": f"DEV-{random.randint(100,999)}"}
    prompt = (f"Windows Sysmon -- Developer IFEO Debugger Attachment.\n"
              f"  target={p['target']}  debugger={p['debugger']}\n"
              f"  ticket={p['ticket']}  developer_workstation=YES  not_security_product=YES")
    cot = _cot(
        "Developer attaching VS debugger to notepad.exe via IFEO -- standard practice.",
        f"target=notepad.exe (not security product). devenv.exe. Dev workstation. Ticket {p['ticket']}.",
        "Authorized developer IFEO. No action.",
        "Authorized developer debugging. No action.",
        "T1562.001 -- AUTHORIZED DEVELOPER DEBUGGING. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ── SignatureStealer (microsoft/SignatureStealer -- authenticode signature theft) ──
def _sig_stealer_tp(i):
    legit_src = random.choice(["chrome.exe","explorer.exe","Teams.exe","OneDrive.exe","MsMpEng.exe"])
    target_name = "".join(random.choices("abcdefghijklmnop", k=random.randint(6,9))) + ".exe"
    host = _host(); user = _user()
    prompt = (f"Windows Sysmon -- Authenticode Signature Theft.\n"
              f"Host: {host}  User: {user}\n"
              f"  phase_1_read: EventID=1\n"
              f"    Image: sig-grab.exe  IntegrityLevel=High\n"
              f"    CommandLine: --source {legit_src} --target {target_name}\n"
              f"  phase_2_write: EventID=11\n"
              f"    TargetFilename: %TEMP%\\{target_name}\n"
              f"    signature_block_appended=YES\n"
              f"  phase_3_result: Signed=true  SignatureIssuer={legit_src}_cert\n"
              f"    path_mismatch=YES (issuer path ≠ file location)\n"
              f"    pe_modified_after_signing=YES  (signature technically invalid)")
    cot = _cot(
        f"Code signing is legitimate. The discriminator is that {legit_src} signature belongs to "
        "the vendor and should only appear on vendor binaries in vendor paths. "
        "Copying it to an unrelated binary in %TEMP% creates a visually convincing but invalid signature "
        "that deceives tools checking only the Signed flag.",
        f"sig-grab.exe: tool name indicates malicious intent -- not a Windows or vendor utility. "
        f"Source={legit_src} (vendor-signed). Target=%TEMP%\\{target_name} (no vendor dir). "
        "pe_modified_after_signing: signature is detached copy -- WinVerifyTrust would fail on deep check "
        "but many EDRs check Signed=true without chain validation. "
        "SignatureStealer bypasses allowlisting tools relying on code signature presence alone.",
        f"Host {host}: malicious {target_name} disguised with stolen {legit_src} signature. "
        "Signature-based EDR allowlisting is bypassed.",
        "Authenticode signature theft for binary masquerading confirmed.",
        "MITRE T1036.001 (Invalid Code Signature) + T1553.002. "
        "Hash-verify all signed binaries against vendor baseline, isolate host.",
    )
    return prompt, cot, "true_positive"

def _sig_stealer_fp(i):
    vendor = random.choice(["Microsoft","Google","Adobe"])
    product = random.choice(["Teams","Chrome","Acrobat"])
    prompt = (f"Windows Sysmon -- Vendor Installer Writing Signed Binary.\n"
              f"  installer=MsiExec.exe  vendor={vendor}\n"
              f"  target_path=C:\\Program Files\\{vendor}\\{product}\n"
              f"  Signed=true  SignatureStatus=Valid  signer={vendor} Corporation")
    cot = _cot(
        f"MsiExec.exe installing {vendor} {product} to Program Files -- signed, valid cert, standard path.",
        f"MsiExec parent. Program Files. {vendor} cert. SignatureStatus=Valid.",
        "Authorized vendor install. No action.",
        "Authorized vendor installer. No action.",
        "T1036.001 -- AUTHORIZED VENDOR INSTALLER. No action.",
        action="dismiss",
    )
    return prompt, cot, "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# Registry + Main
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_CLASSES = {
    "AMSIInProcessPatch":          ("sysmon_sensor",            ["T1562.001"],             _amsi_ip_tp,   _amsi_ip_fp),
    "AMSIRemotePatch":             ("sysmon_sensor",            ["T1562.001"],             _amsi_rp_tp,   _amsi_rp_fp),
    "AMSIThreadRedirect":          ("sysmon_sensor",            ["T1562.001"],             _amsi_tr_tp,   _amsi_tr_fp),
    "WFPEDRNetworkBlock":          ("windows_deepsensor",       ["T1562.004","T1562.001"], _wfp_tp,       _wfp_fp),
    "EDRProcessSuspend":           ("windows_deepsensor",       ["T1562.001"],             _edr_freeze_tp,_edr_freeze_fp),
    "BindFilterDLLRedirect":       ("windows_deepsensor",       ["T1562.001"],             _bfdr_tp,      _bfdr_fp),
    "AppLockerEDRDenyRule":        ("sysmon_sensor",            ["T1562.001"],             _applocker_tp, _applocker_fp),
    "BYOVDKernelBypass":           ("sysmon_sensor",            ["T1562.001","T1014"],     _byovd_tp,     _byovd_fp),
    "UnsignedKernelDriverMap":     ("sysmon_sensor",            ["T1014","T1547.006"],     _ukdm_tp,      _ukdm_fp),
    "KernelNotifyCallbackRemoval": ("windows_deepsensor",       ["T1562.001","T1014"],     _kncr_tp,      _kncr_fp),
    "IoUringSyscallEvasion":       ("linux_sentinel",           ["T1562.006","T1071"],     _iouring_tp,   _iouring_fp),
    "UACRegistryBypass":           ("sysmon_sensor",            ["T1548.002"],             _uac_tp,       _uac_fp),
    "PPLTokenRace":                ("windows_deepsensor",       ["T1562.001"],             _ppl_tp,       _ppl_fp),
    "LSASSForkDump":               ("sysmon_sensor",            ["T1003.001"],             _lsass_fork_tp,_lsass_fork_fp),
    "APCQueueInjection":           ("sysmon_sensor",            ["T1055.004"],             _apc_tp,       _apc_fp),
    "ShellcodeRuntimeEncrypt":     ("windows_deepsensor",       ["T1027.002","T1027.007"], _shellcode_enc_tp, _shellcode_enc_fp),
    "SmartScreenBypass":           ("sysmon_sensor",            ["T1574.002","T1553.005"], _ss_tp,     _ss_fp),
    "DefenderExclusionAdd":        ("sysmon_sensor",            ["T1562.001"],             _defender_excl_tp, _defender_excl_fp),
    "LinuxLibcHookEvasion":        ("linux_sentinel",           ["T1574.006","T1014"],     _linux_libc_tp,_linux_libc_fp),
    "RPCInterfaceRace":            ("windows_deepsensor",       ["T1557.001","T1187"],     _rpc_race_tp,  _rpc_race_fp),
    "CallbackShellcodeExecution":  ("sysmon_sensor",            ["T1055.004","T1027.002"], _cbs_tp,       _cbs_fp),
    "DSEDriverSignatureBypass":    ("sysmon_sensor",            ["T1562.001","T1014"],     _dse_tp,       _dse_fp),
    "KernelETWTIProviderRemoval":  ("windows_deepsensor",       ["T1562.006","T1014"],     _etw_ki_tp,    _etw_ki_fp),
    "CredGuardVBSBypass":          ("sysmon_sensor",            ["T1556.002","T1068"],     _cgbypass_tp,  _cgbypass_fp),
    "FiberBasedShellcode":         ("sysmon_sensor",            ["T1055"],                 _fiber_tp,     _fiber_fp),
    "PPLKillerPrivesc":            ("sysmon_sensor",            ["T1562.001","T1068"],     _pplkill_tp,   _pplkill_fp),
    "PatchGuardSubversion":        ("sysmon_sensor",            ["T1068","T1014"],         _patchguard_tp,_patchguard_fp),
    "ETWConsumerKill":             ("sysmon_sensor",            ["T1562.006"],             _etwconsumer_tp,_etwconsumer_fp),
    "PoolPartyInjection":          ("sysmon_sensor",            ["T1055"],                 _poolparty_tp,        _poolparty_fp),
    "EDRLogWipe":                  ("sysmon_sensor",            ["T1070.001"],             _edrlogwipe_tp,       _edrlogwipe_fp),
    "ProcessImpersonationEDR":     ("sysmon_sensor",            ["T1036.005"],             _proc_impersonate_tp, _proc_impersonate_fp),
    "EDRStartupHinder":            ("sysmon_sensor",            ["T1562.001","T1547"],     _edr_startup_hinder_tp,_edr_startup_hinder_fp),
    "SignatureStealer":            ("sysmon_sensor",            ["T1036.001","T1553.002"], _sig_stealer_tp,      _sig_stealer_fp),
}

S3_QUERIES = {
    "AMSIInProcessPatch":       {"sensor":"sysmon_sensor","where":"sysmon_event_id = 7 AND ImageLoaded LIKE '%amsi.dll%'"},
    "WFPEDRNetworkBlock":       {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%SYSTEM%CurrentControlSet%Services%BFE%'"},
    "BYOVDKernelBypass":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 6 AND (ImageLoaded LIKE '%iqvw64e.sys%' OR ImageLoaded LIKE '%gmer.sys%' OR ImageLoaded LIKE '%RTCore64.sys%' OR ImageLoaded LIKE '%aswArPot.sys%')"},
    "UACRegistryBypass":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND (TargetObject LIKE '%ms-settings%' OR TargetObject LIKE '%mscfile%')"},
    "LSASSForkDump":            {"sensor":"sysmon_sensor","where":"sysmon_event_id = 10 AND TargetImage LIKE '%lsass%' AND GrantedAccess = '0x1fffff'"},
    "DefenderExclusionAdd":     {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%Windows Defender%Exclusions%' AND Image NOT LIKE '%MsMpEng%' AND Image NOT LIKE '%SecurityCenter%'"},
    "IoUringSyscallEvasion":    {"sensor":"linux_sentinel","where":"anomaly_score > 0.7 AND uid > 0 AND dest_port IS NOT NULL"},
    "LinuxLibcHookEvasion":     {"sensor":"linux_sentinel","where":"target_file='/etc/ld.so.preload' AND uid > 0"},
    "AppLockerEDRDenyRule":     {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%SrpV2%Exe%' AND (Details LIKE '%MsMpEng%' OR Details LIKE '%Sentinel%')"},
    "KernelNotifyCallbackRemoval": {"sensor":"sysmon_sensor","where":"sysmon_event_id = 6 AND Signed = 'false' AND ImageLoaded NOT LIKE 'C:\\Windows\\%'"},
    "CallbackShellcodeExecution":  {"sensor":"sysmon_sensor","where":"sysmon_event_id=1 AND (CommandLine LIKE '%CreateTimerQueueTimer%' OR CommandLine LIKE '%EnumChildWindows%' OR CommandLine LIKE '%CreateFiber%')"},
    "DSEDriverSignatureBypass":    {"sensor":"sysmon_sensor","where":"sysmon_event_id=6 AND Signed='false' AND TargetObject LIKE '%BCD%testsigning%'"},
    "KernelETWTIProviderRemoval":  {"sensor":"windows_deepsensor","where":"event_type LIKE '%etw%' AND signature_name LIKE '%ThreatIntel%'"},
    "CredGuardVBSBypass":       {"sensor":"sysmon_sensor","where":"sysmon_event_id=10 AND TargetImage LIKE '%lsaiso%' AND GrantedAccess='0x1fffff'"},
    "FiberBasedShellcode":      {"sensor":"sysmon_sensor","where":"sysmon_event_id=10 AND GrantedAccess LIKE '%0x1f0fff%' AND Image NOT LIKE '%MsMpEng%'"},
    "PPLKillerPrivesc":         {"sensor":"sysmon_sensor","where":"sysmon_event_id=6 AND Signed='true' AND SignatureStatus='Expired' AND ImageLoaded IN ('RTCore64.sys','gdrv.sys','iqvw64e.sys','cpuz141_x64.sys')"},
    "PatchGuardSubversion":     {"sensor":"sysmon_sensor","where":"sysmon_event_id=13 AND TargetObject LIKE '%BCD%testsigning%' AND Details='Yes'"},
    "ETWConsumerKill":          {"sensor":"sysmon_sensor","where":"sysmon_event_id=12 AND TargetObject LIKE '%WMI%Autologger%EventLog-Security%' AND Image NOT LIKE '%WEFClient%'"},
    "PoolPartyInjection":       {"sensor":"sysmon_sensor","where":"sysmon_event_id = 8 AND TargetImage NOT LIKE '%svchost%' AND SourceImage NOT LIKE 'C:\\\\Windows%'"},
    "EDRLogWipe":               {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND CommandLine LIKE '%wevtutil%cl%' OR CommandLine LIKE '%Clear-EventLog%'"},
    "ProcessImpersonationEDR":  {"sensor":"sysmon_sensor","where":"sysmon_event_id = 1 AND Image LIKE '%MsMpEng%' AND Image NOT LIKE 'C:\\\\ProgramData%' AND Image NOT LIKE 'C:\\\\Program Files%'"},
    "EDRStartupHinder":         {"sensor":"sysmon_sensor","where":"sysmon_event_id = 13 AND TargetObject LIKE '%Image File Execution Options%Debugger%' AND Image NOT LIKE '%msiexec%' AND Image NOT LIKE '%devenv%'"},
    "SignatureStealer":         {"sensor":"sysmon_sensor","where":"sysmon_event_id = 11 AND TargetFilename LIKE '%.exe' AND Image LIKE '%Temp%' AND Image NOT LIKE '%MsiExec%'"},
    "AMSIRemotePatch":          {"sensor":"sysmon_sensor","where":"sysmon_event_id = 10 AND TargetImage LIKE '%powershell%' AND GrantedAccess = '0x1fffff' AND Image NOT LIKE '%MsMpEng%' AND Image NOT LIKE '%CrowdStrike%'"},
    "AMSIThreadRedirect":       {"sensor":"sysmon_sensor","where":"sysmon_event_id = 8 AND TargetImage LIKE '%powershell%' AND SourceImage NOT LIKE 'C:\\\\Windows\\\\System32%' AND SourceImage NOT LIKE 'C:\\\\Program Files%'"},
    "EDRProcessSuspend":        {"sensor":"windows_deepsensor","where":"path LIKE '%WerFaultSecure%' AND command_line LIKE '%edr%' OR command_line LIKE '%Sentinel%' OR command_line LIKE '%CrowdStrike%'"},
    "BindFilterDLLRedirect":    {"sensor":"windows_deepsensor","where":"path LIKE '%bindfltapi%' AND command_line NOT LIKE '%System32%' AND command_line NOT LIKE '%SysWOW64%'"},
    "UnsignedKernelDriverMap":  {"sensor":"sysmon_sensor","where":"sysmon_event_id = 6 AND Signed = 'false' AND ImageLoaded LIKE '%Temp%' OR ImageLoaded LIKE '%ProgramData%'"},
    "PPLTokenRace":             {"sensor":"windows_deepsensor","where":"event_count > 5 AND path LIKE '%WerFaultSecure%' AND score > 0.7"},
    "APCQueueInjection":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 8 AND TargetImage LIKE '%explorer%' OR TargetImage LIKE '%svchost%' AND SourceImage NOT LIKE 'C:\\\\Windows%' AND SourceImage NOT LIKE 'C:\\\\Program Files%'"},
    "ShellcodeRuntimeEncrypt":  {"sensor":"windows_deepsensor","where":"score > 0.8 AND command_line LIKE '%sleep%' AND event_count > 3 AND path NOT LIKE 'C:\\\\Program Files%'"},
    "SmartScreenBypass":        {"sensor":"sysmon_sensor","where":"sysmon_event_id = 7 AND Signed = 'false' AND Image LIKE '%AppData%' AND ImageLoaded LIKE '%version.dll%' OR ImageLoaded LIKE '%dbghelp.dll%' OR ImageLoaded LIKE '%winmm.dll%'"},
    "RPCInterfaceRace":         {"sensor":"windows_deepsensor","where":"event_count > 10 AND command_line LIKE '%schtasks%' AND score > 0.7 AND path NOT LIKE 'C:\\\\Windows%'"},
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
        "ttp_category": "BypassDetection",
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
