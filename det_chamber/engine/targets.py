"""
Detonation target selection -- pure stdlib, OS-agnostic, unit-testable.

The engine historically scanned the whole malware directory and detonated every
file in it. The live-acquisition workflow needs the opposite: hand the chamber a
single acquired artifact (or an explicit short list) and detonate exactly that.
`--malware` / docker-compose already advertised this, but `main()` never honoured
it (finding F4). This module is the single source of truth for "what gets
detonated", isolated here so it can be tested without win32/pefile/psutil.
"""

import os
from typing import List, Optional


def select_targets(malware_dir: str, malware: Optional[str] = None) -> List[str]:
    """Return the basenames to detonate, relative to ``malware_dir``.

    * ``malware`` is None/empty -> every regular file in the directory (legacy
      batch behaviour), directories ignored.
    * ``malware`` is a name or comma-separated list -> exactly those files, after
      verifying each exists as a regular file in ``malware_dir``. A missing entry
      raises ``FileNotFoundError`` so a single-artifact detonation fails loudly
      instead of silently detonating nothing.
    """
    if malware:
        names = [n.strip() for n in malware.split(",") if n.strip()]
        missing = [n for n in names if not os.path.isfile(os.path.join(malware_dir, n))]
        if missing:
            raise FileNotFoundError(
                f"requested artifact(s) not found in {malware_dir}: {', '.join(missing)}"
            )
        return names

    return [
        f for f in os.listdir(malware_dir)
        if os.path.isfile(os.path.join(malware_dir, f))
    ]
