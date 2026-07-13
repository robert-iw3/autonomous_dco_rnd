"""
Shared detonation-summary envelope -- the single shape every analyzer emits.

Windows (malware_sandbox.py) and Linux (linux_analyzer.py) produce different
platform-specific detail under `static`/`dynamic`, but the OUTER envelope is
identical so everything downstream (intake result, swarm enrichment) is
os-agnostic. Both sides build their records through these helpers.
"""

FILE_RECORD_KEYS = ("file", "static", "dynamic")
SUMMARY_KEYS = ("timestamp", "host_ip", "files")


def file_record(name: str, static: dict = None, dynamic: dict = None) -> dict:
    """One analyzed artifact: {file, static, dynamic}."""
    return {"file": name, "static": static or {}, "dynamic": dynamic or {}}


def build_summary(timestamp, host_ip, files) -> dict:
    """The run-level summary.json shape shared by both platforms."""
    return {"timestamp": timestamp, "host_ip": host_ip, "files": list(files)}


def is_file_record(rec: dict) -> bool:
    return isinstance(rec, dict) and set(rec) == set(FILE_RECORD_KEYS)
