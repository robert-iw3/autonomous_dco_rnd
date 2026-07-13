"""
Det Chamber configuration -- the single, testable source of every path and tunable.

Before this, the engine hard-coded `E:\\Tools\\Windows`, `E:\\YARA`, `C:\\Logs`,
`C:\\Collections` etc. across the Python, the Dockerfile and docker-compose
(finding F2), so re-homing or running the chamber anywhere else meant editing code.
Now everything resolves through `load_config()` with a clear precedence:

    built-in defaults  <  [detchamber] table in a TOML file  <  DETCHAMBER_* env vars

Env wins last so container/orchestration deployments can override without a rebuild.
Pure stdlib (tomllib) so it imports and unit-tests on any OS, no win32 needed.
"""

import os
import tomllib
from dataclasses import dataclass, replace
from typing import List, Mapping, Optional


@dataclass(frozen=True)
class SandboxConfig:
    # ── Paths (Windows hosts are the default analysis target) ──
    tools_dir: str = "E:\\Tools\\Windows"
    malware_dir: str = "C:\\Malware"            # intake dir scanned for samples
    detonation_dir: str = "C:\\Users\\Public\\Desktop"  # where a sample is copied + run
    collection_dir: str = "C:\\Collections"
    log_dir: str = "C:\\Logs"
    inetsim_dir: str = "E:\\Tools\\Windows\\inetsim"
    yara_rules: str = "E:\\YARA\\windows_x64_rules.compiled"
    procmon_config: str = "E:\\Tools\\Windows\\malw.pmc"
    # ── Detonation tunables ──
    pcap_time: int = 180
    parallel: int = 4
    simulate_network: bool = False
    evidence_tool: str = "magnet"               # 'magnet' | 'cuckoo'
    cuckoo_url: str = "http://192.168.56.10:8090"
    volatility_plugins: List[str] = None        # set in __post_init__-style default

    def __post_init__(self):
        if self.volatility_plugins is None:
            object.__setattr__(self, "volatility_plugins", ["windows.pslist", "windows.netscan"])


# Maps a config field -> (env var, coercion). Absent from env => not overridden.
_ENV: Mapping[str, str] = {
    "tools_dir":          "DETCHAMBER_TOOLS_DIR",
    "malware_dir":        "DETCHAMBER_MALWARE_DIR",
    "detonation_dir":     "DETCHAMBER_DETONATION_DIR",
    "collection_dir":     "DETCHAMBER_COLLECTION_DIR",
    "log_dir":            "DETCHAMBER_LOG_DIR",
    "inetsim_dir":        "DETCHAMBER_INETSIM_DIR",
    "yara_rules":         "DETCHAMBER_YARA_RULES",
    "procmon_config":     "DETCHAMBER_PROCMON_CONFIG",
    "pcap_time":          "DETCHAMBER_PCAP_TIME",
    "parallel":           "DETCHAMBER_PARALLEL",
    "simulate_network":   "DETCHAMBER_SIMULATE_NETWORK",
    "evidence_tool":      "DETCHAMBER_EVIDENCE_TOOL",
    "cuckoo_url":         "DETCHAMBER_CUCKOO_URL",
    "volatility_plugins": "DETCHAMBER_VOLATILITY_PLUGINS",
}
_INT_FIELDS = {"pcap_time", "parallel"}
_BOOL_FIELDS = {"simulate_network"}
_LIST_FIELDS = {"volatility_plugins"}


def _coerce(field: str, raw: str):
    if field in _INT_FIELDS:
        return int(raw)
    if field in _BOOL_FIELDS:
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    if field in _LIST_FIELDS:
        return [p.strip() for p in raw.split(",") if p.strip()]
    return raw


def load_config(config_path: Optional[str] = None,
                env: Optional[Mapping[str, str]] = None) -> SandboxConfig:
    """Resolve config as defaults < TOML([detchamber]) < env(DETCHAMBER_*)."""
    env = os.environ if env is None else env
    cfg = SandboxConfig()

    # Layer 1: TOML file (operator-provided, e.g. det_chamber/config/detchamber.toml)
    if config_path:
        with open(config_path, "rb") as fh:
            table = tomllib.load(fh).get("detchamber", {})
        overrides = {}
        for field, value in table.items():
            if hasattr(cfg, field):
                overrides[field] = value
        cfg = replace(cfg, **overrides)

    # Layer 2: environment (highest precedence)
    env_overrides = {}
    for field, var in _ENV.items():
        if var in env and env[var] != "":
            env_overrides[field] = _coerce(field, env[var])
    if env_overrides:
        cfg = replace(cfg, **env_overrides)

    return cfg
