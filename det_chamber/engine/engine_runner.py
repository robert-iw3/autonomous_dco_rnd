"""
Engine runner -- the single dispatch point from an analyzer label to a detonation.

The intake service calls `detonate_single` as its run_engine. It writes the verified
artifact bytes to a temp file (NEVER executes them here) and routes to the analyzer:
  linux_sandbox  -> linux_analyzer.analyze (local, in the isolated Linux guest)
  windows_engine -> the Windows engine on the Windows VM pool
"""

import os
import tempfile

import summary_schema as schema


def _run_linux(path, manifest, mock):
    import linux_analyzer
    return linux_analyzer.analyze(path, mock=mock)


def _run_windows(path, manifest, mock):
    if mock:
        # Mirror the Windows engine's envelope without a Windows host (CI).
        return schema.file_record(
            path,
            static={"pefile": {"mocked": True}, "capa": {}, "yara_matches": []},
            dynamic={"procmon": {"mocked": True}, "network": {}, "evidence": {},
                     "memory": {}, "errors": []},
        )
    # Real Windows detonation runs on the Windows VM pool (submitted by the deploy
    # layer, Phase 6). The Linux intake host does not detonate Windows samples itself.
    raise NotImplementedError("windows detonation runs on the Windows VM pool")


_DISPATCH = {"linux_sandbox": _run_linux, "windows_engine": _run_windows}


def detonate_single(data: bytes, manifest, analyzer: str, *, mock=None) -> dict:
    if analyzer not in _DISPATCH:
        raise ValueError(f"unknown analyzer: {analyzer!r}")
    if mock is None:
        mock = bool(os.getenv("DETCHAMBER_ENGINE_MOCK"))
    with tempfile.TemporaryDirectory(prefix="detchamber-") as d:
        path = os.path.join(d, os.path.basename(manifest.filename))
        with open(path, "wb") as f:      # write only -- the sample is never executed here
            f.write(data)
        return _DISPATCH[analyzer](path, manifest, mock)
