"""
Lab det_chamber -- Phase 3: Linux dynamic analyzer.

Full Linux detonation (decision D4): ELF samples get static (ELF header + CAPA +
YARA) and dynamic (syscall trace + network + memory) analysis, emitting the SAME
summary envelope as the Windows engine so everything downstream is os-agnostic.

The sample is never executed in CI -- static ELF parsing reads bytes only, and the
dynamic phase is mock-gated (DETCHAMBER_ENGINE_MOCK / mock=True). Fixtures are
synthetic benign ELF headers, never live malware.
"""

import struct
import sys
from pathlib import Path

import pytest

ENGINE = Path(__file__).resolve().parents[2] / "det_chamber" / "engine"
sys.path.insert(0, str(ENGINE))

import summary_schema as schema   # noqa: E402
import linux_analyzer as la       # noqa: E402


def _elf64(tmp_path, e_type=2, e_machine=0x3E):
    # Minimal valid ELF64 LE header: magic, EI_CLASS=2(64), EI_DATA=1(LE), then
    # e_type / e_machine at offset 16. Enough for the safe header parse.
    hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 + struct.pack("<HH", e_type, e_machine)
    hdr += b"\x00" * (64 - len(hdr))
    p = tmp_path / "sample.elf"
    p.write_bytes(hdr)
    return str(p)


# --- ELF static parse (no execution) -----------------------------------------
def test_parse_elf_reads_class_and_machine(tmp_path):
    info = la.parse_elf(_elf64(tmp_path))
    assert info["is_elf"] is True
    assert info["bits"] == 64
    assert info["endian"] == "little"
    assert info["e_machine"] == 0x3E  # x86-64


def test_parse_elf_rejects_non_elf(tmp_path):
    p = tmp_path / "notelf.bin"
    p.write_bytes(b"MZ this is not an elf")
    assert la.parse_elf(str(p))["is_elf"] is False


# --- analyze() envelope ------------------------------------------------------
def test_analyze_returns_uniform_file_record(tmp_path):
    rec = la.analyze(_elf64(tmp_path), mock=True)
    assert set(rec) == set(schema.FILE_RECORD_KEYS)        # file/static/dynamic
    assert rec["static"]["elf"]["is_elf"] is True
    for k in ("elf", "capa", "yara_matches"):
        assert k in rec["static"]
    for k in ("network", "trace", "memory", "errors"):
        assert k in rec["dynamic"]


def test_analyze_does_not_execute_sample(tmp_path, monkeypatch):
    # If the analyzer ever tried to run the sample, Popen/run would be invoked.
    import subprocess
    calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError("executed sample")))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError("ran subprocess in mock")))
    la.analyze(_elf64(tmp_path), mock=True)   # mock must not shell out at all
    assert calls == []
