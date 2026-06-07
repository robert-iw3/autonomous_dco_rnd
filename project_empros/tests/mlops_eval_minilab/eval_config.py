"""
eval_config.py -- Eval MiniLab configuration.

Reads from .env file (or environment variables) and exposes typed config to the
eval pipeline. Deliberately has no external imports beyond stdlib + dotenv.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the same directory as this file (eval_minilab/.env)
_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE)
else:
    load_dotenv(Path(__file__).parent / ".env.example")

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT     = Path(__file__).parents[2]   # project_empros/
STAGING_DIR   = REPO_ROOT / "mlops" / "data" / "staging"
LOG_DIR       = Path(os.getenv("EVAL_LOG_DIR", str(REPO_ROOT / "logs")))

# ── Ollama ────────────────────────────────────────────────────────────────────
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
EVAL_MODEL      = os.getenv("EVAL_MODEL", "llama3.2:3b")

# ── Eval parameters ───────────────────────────────────────────────────────────
EVAL_RECORDS_PER_CORPUS = int(os.getenv("EVAL_RECORDS_PER_CORPUS", "12"))
EVAL_TEMPERATURE        = float(os.getenv("EVAL_TEMPERATURE", "0.1"))
EVAL_MAX_TOKENS         = int(os.getenv("EVAL_MAX_TOKENS", "800"))
EVAL_REPORT_FILE        = os.getenv("EVAL_REPORT_FILE", "eval_minilab_report.json")

_filter_raw = os.getenv("EVAL_CORPUS_FILTER", "").strip()
EVAL_CORPUS_FILTER: list[str] = (
    [f.strip() for f in _filter_raw.split(",") if f.strip()]
    if _filter_raw else []
)

# ── Corpus discovery ──────────────────────────────────────────────────────────
ALL_CORPUS_FILES = sorted(STAGING_DIR.glob("*_behavioral_v1.jsonl"))

def get_corpus_files() -> list[Path]:
    if EVAL_CORPUS_FILTER:
        return [f for f in ALL_CORPUS_FILES if f.name in EVAL_CORPUS_FILTER]
    return ALL_CORPUS_FILES

# ── Expected vector spaces (must match projector.py VECTOR_DIMS) ──────────────
# Some source types can legitimately use multiple vector spaces depending on context:
#   network_tap → "network_tap" for L7 flow forensics
#   network_tap → "c2_math"    for AD/LDAP/protocol attack analysis (stage_active_directory uses this)
# The check below allows the set of valid spaces per source_type.
EXPECTED_VECTOR_SPACES: dict[str, set[str]] = {
    "sysmon_sensor":      {"windows_math"},
    "windows_deepsensor": {"deepsensor_math"},
    "trellix_ens":        {"trellix_math"},
    "linux_sentinel":     {"sentinel_math"},
    "linux_c2":           {"c2_math"},
    "windows_c2":         {"c2_math"},
    "network_tap":        {"network_tap", "c2_math"},   # AD/LDAP attacks use c2_math (flow stats)
    "aws_cloudtrail":     {"cloud_flow"},
    "azure_entraid":      {"cloud_flow"},
    "gcp_audit":          {"cloud_flow"},
    "macos_sensor":       {"windows_math"},
    "suricata_eve":       {"c2_math"},
}

# Recommended laptop models by tier (for README / --help output)
MODEL_TIERS = {
    "cpu_minimal":  "llama3.2:1b",    # <2GB RAM, very fast, lower accuracy
    "cpu_default":  "llama3.2:3b",    # 2-4GB RAM, recommended default
    "cpu_quality":  "phi3:mini",      # 3-4GB RAM, strong reasoning
    "gpu_fast":     "llama3.1:8b-instruct-q4_0",  # 5GB VRAM
    "gpu_quality":  "deepseek-r1:7b", # 5GB VRAM, chain-of-thought
}
