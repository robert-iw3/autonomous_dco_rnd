"""
ueba_engine.py -- UEBA/ML for Trellix ENS SQL transmission pipeline.

Persistence: SQLite WAL at ueba_state/state.db tracks the frequency counter
across container restarts so novelty is consistent across batches.

Adapted from:  windows/prototypes/edr_sensor/archived/OsAnomalyML.py
               windows/prototypes/c2_beacon/BeaconML.py
"""

from __future__ import annotations

import math
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest

_DB_PATH = Path(__file__).parent / "ueba_state" / "state.db"

# Patterns to strip before hashing (GUIDs, hex tokens, temps, timestamps)
_STRIP_RE = re.compile(
    r"[{(]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[)}]?"
    r"|0x[0-9a-fA-F]+"
    r"|\b\d{4}-\d{2}-\d{2}[T_]\d{2}:\d{2}:\d{2}"
    r"|\\Temp\\[^\\\s]+"
    r"|\\AppData\\Local\\Temp\\[^\\\s]+",
    re.IGNORECASE,
)

# Max samples to keep in the rolling window for IsolationForest refit
_MAX_WINDOW = 5000
_ENTROPY_MAX = 4.0   # practical max for 8-bit chars over short strings

class TrellixUEBAEngine:
    """Stateful UEBA engine. One instance per process; thread-safe via GIL."""

    def __init__(
        self,
        db_path: Path = _DB_PATH,
        n_estimators: int = 50,
        contamination: float = 0.01,
        refit_interval: int = 500,
    ) -> None:
        self._db_path = db_path
        self._refit_interval = refit_interval
        self._processed = 0

        self._clf = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
        )
        self._clf_fitted = False

        # Rolling feature window for periodic refit
        self._feature_window: list[list[float]] = []

        # In-memory frequency counter -- persisted to SQLite on each refit
        self._freq: Counter = Counter()

        # SQLite for frequency persistence across restarts
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(db_path), check_same_thread=False)
        # Maximum uptime WAL settings: durability without sacrificing throughput
        self._con.execute("PRAGMA journal_mode=WAL;")
        self._con.execute("PRAGMA synchronous=NORMAL;")       # safe in WAL mode
        self._con.execute("PRAGMA wal_autocheckpoint=1000;")  # checkpoint every 1000 pages
        self._con.execute("PRAGMA busy_timeout=5000;")        # 5s wait on lock contention
        self._con.execute("PRAGMA cache_size=-65536;")        # 64 MB page cache
        self._con.execute("PRAGMA mmap_size=268435456;")      # 256 MB memory-mapped I/O
        self._con.execute("PRAGMA temp_store=MEMORY;")
        self._con.execute(
            "CREATE TABLE IF NOT EXISTS threat_freq "
            "(key TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 1);"
        )
        self._con.commit()
        self._load_freq()

    # -- Public API ------------------------------------------------------------

    def score_event(
        self,
        threat_name: Optional[str],
        threat_type: Optional[str],
        file_path: Optional[str],
        process_name: Optional[str],
        severity: Optional[int],
        action_taken: Optional[str],
    ) -> tuple[float, float, float]:
        """Return (anomaly_score, entropy_score, frequency_score) in [0,1]."""

        entropy = self._entropy_score(file_path, process_name)
        frequency = self._frequency_score(threat_name, threat_type)
        features = self._build_features(severity, action_taken, entropy, frequency)

        self._feature_window.append(features)
        if len(self._feature_window) > _MAX_WINDOW:
            self._feature_window.pop(0)

        self._processed += 1
        if self._processed % self._refit_interval == 0 and len(self._feature_window) >= 10:
            self._refit()

        anomaly = self._anomaly_score(features)

        return anomaly, entropy, frequency

    def flush(self) -> None:
        """Persist frequency counter to SQLite (call before shutdown)."""
        self._save_freq()

    # -- Feature computation ---------------------------------------------------

    def _entropy_score(self, file_path: Optional[str], process_name: Optional[str]) -> float:
        """Shannon entropy of combined FilePath + ProcessName, normalised to [0,1]."""
        combined = (file_path or "") + (process_name or "")
        if not combined:
            return 0.0
        raw = _shannon_entropy(combined)
        return min(raw / _ENTROPY_MAX, 1.0)

    def _frequency_score(
        self, threat_name: Optional[str], threat_type: Optional[str]
    ) -> float:
        """Inverse novelty: rare threat+type combos score closer to 1.0."""
        key = _normalise_threat_key(threat_name, threat_type)
        self._freq[key] += 1
        count = self._freq[key]
        total = sum(self._freq.values()) or 1
        freq_ratio = count / total
        # Invert: low frequency → high risk score
        return float(np.clip(1.0 - freq_ratio, 0.0, 1.0))

    def _build_features(
        self,
        severity: Optional[int],
        action_taken: Optional[str],
        entropy: float,
        frequency: float,
    ) -> list[float]:
        return [
            _severity_to_float(severity),
            _action_to_float(action_taken),
            entropy,
            frequency,
        ]

    def _anomaly_score(self, features: list[float]) -> float:
        """IsolationForest anomaly score, remapped to [0,1] (1 = most anomalous)."""
        if not self._clf_fitted:
            return 0.5  # fallback until enough samples for first fit

        raw = self._clf.score_samples(np.array([features]))[0]
        # score_samples returns negative values; more negative = more anomalous
        # remap: score ∈ [-0.5, 0] typically → [0, 1]
        return float(np.clip(-raw * 2.0, 0.0, 1.0))

    def _refit(self) -> None:
        X = np.array(self._feature_window)
        self._clf.fit(X)
        self._clf_fitted = True
        self._save_freq()

    # -- Persistence -----------------------------------------------------------

    def _load_freq(self) -> None:
        rows = self._con.execute("SELECT key, count FROM threat_freq").fetchall()
        self._freq = Counter({k: v for k, v in rows})

    def _save_freq(self) -> None:
        with self._con:
            for key, count in self._freq.items():
                self._con.execute(
                    "INSERT INTO threat_freq (key, count) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET count = excluded.count;",
                    (key, count),
                )

# -- Module-level helpers (used by tests) -------------------------------------

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    probs = [v / len(data) for v in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def _normalise_threat_key(threat_name: Optional[str], threat_type: Optional[str]) -> str:
    """Strip volatile tokens (GUIDs, hex, timestamps) for stable frequency counting."""
    raw = f"{threat_name or ''}|{threat_type or ''}"
    return _STRIP_RE.sub("", raw).strip().lower()

def _severity_to_float(severity: Optional[int]) -> float:
    """Map EPO ThreatSeverity 1-5 to [0.2, 1.0]."""
    if severity is None:
        return 0.0
    return float(np.clip(severity / 5.0, 0.0, 1.0))

def _action_to_float(action: Optional[str]) -> float:
    """Map ActionTaken string to a risk weight."""
    if not action:
        return 0.0
    a = action.lower()
    if "block" in a:
        return 1.0
    if "quarantin" in a:
        return 0.75
    if "clean" in a:
        return 0.5
    if "detect" in a:
        return 0.25
    return 0.1