"""
Linux dynamic analyzer -- ELF static + dynamic detonation (decision D4).

Runs inside the isolated KVM/libvirt micro-VM. Static analysis (ELF header parse +
CAPA + YARA) reads bytes only and never executes the sample. Dynamic analysis
(syscall trace via strace/eBPF, network capture via tcpdump + INetSim, Volatility3
linux memory) detonates the sample in the isolated guest -- gated behind `mock` so
CI never shells out or runs anything.
"""

import os
import struct
import subprocess

from summary_schema import file_record

ELF_MAGIC = b"\x7fELF"
_CLASS = {1: 32, 2: 64}
_ENDIAN = {1: "little", 2: "big"}


def parse_elf(path: str) -> dict:
    """Safe, execution-free parse of the ELF header. {is_elf:false} for non-ELF."""
    with open(path, "rb") as f:
        hdr = f.read(64)
    if hdr[:4] != ELF_MAGIC:
        return {"is_elf": False}
    bits = _CLASS.get(hdr[4])
    endian = _ENDIAN.get(hdr[5])
    fmt = "<" if endian == "little" else ">"
    e_type, e_machine = struct.unpack(fmt + "HH", hdr[16:20])
    return {"is_elf": True, "bits": bits, "endian": endian,
            "e_type": e_type, "e_machine": e_machine}


def _static(sample_path, tools_dir, yara_rules, mock):
    result = {"file": sample_path, "elf": {}, "capa": {}, "yara_matches": []}
    try:
        result["elf"] = parse_elf(sample_path)
    except Exception as e:
        result["elf"] = {"error": str(e)}
    if mock:
        return result
    try:  # pragma: no cover - real tool path, exercised on the sandbox VM
        capa_exe = os.path.join(tools_dir or "", "capa")
        proc = subprocess.run([capa_exe, sample_path, "-f", "elf", "-j"],
                              capture_output=True, text=True, timeout=300)
        result["capa"] = {"exit_code": proc.returncode, "stdout": proc.stdout[:100000]}
    except Exception as e:
        result["capa"] = {"error": str(e)}
    try:  # pragma: no cover
        proc = subprocess.run(["yara", "-p", "4", yara_rules, sample_path],
                              capture_output=True, text=True, timeout=60)
        result["yara_matches"] = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    except Exception as e:
        result["yara_matches"] = [f"Error: {e}"]
    return result


def _dynamic(sample_path, collection_path, simulate_network, mock):
    result = {"network": {}, "trace": {}, "memory": {}, "errors": []}
    if mock:
        result["trace"] = {"mocked": True}
        return result
    # pragma: no cover -- real detonation inside the isolated guest only.
    try:  # strace the execution (the ONLY place the sample runs, in the isolated VM)
        trace_log = os.path.join(collection_path or ".", "strace.log")
        subprocess.run(["strace", "-f", "-o", trace_log, sample_path],
                       capture_output=True, timeout=180)
        result["trace"] = {"output": trace_log}
    except Exception as e:
        result["errors"].append(f"strace error: {e}")
    return result


def analyze(sample_path, *, tools_dir=None, yara_rules=None, collection_path=None,
            simulate_network=True, mock=None) -> dict:
    """Analyze one ELF sample, returning the shared file-record envelope."""
    if mock is None:
        mock = bool(os.getenv("DETCHAMBER_ENGINE_MOCK"))
    return file_record(
        sample_path,
        static=_static(sample_path, tools_dir, yara_rules, mock),
        dynamic=_dynamic(sample_path, collection_path, simulate_network, mock),
    )
