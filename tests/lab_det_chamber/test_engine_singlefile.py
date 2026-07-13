"""
Lab det_chamber -- Phase 1: re-home + config-drive + single-file detonation mode.

  1. SINGLE-FILE MODE -- `targets.select_targets()` returns exactly the requested
     file(s) under `--malware`, or the whole directory otherwise. This closes the
     flag-drift bug (F4) where docker-compose passed `--malware`/`--filetypes` that
     `main()` never implemented, so a single-artifact detonation was impossible.
  2. CONFIG-DRIVEN PATHS -- `sandbox_config.load_config()` centralises every path
     and tunable (was hard-coded `E:\\`/`C:\\` literals scattered through the code,
     the Dockerfile and compose -- finding F2). Defaults < toml file < env override.
  3. LINUX-IMPORTABLE ENGINE -- the engine module no longer imports win32/pefile/
     psutil/requests at module scope and no longer creates `C:\\Logs` at import time,
     so it can be imported (and its pure logic unit-tested) on the Linux CI box.
     Verified by AST inspection -- no heavy deps needed to run this lab.

Run:
    pytest tests/lab_det_chamber/test_engine_singlefile.py -v
"""

import ast
import sys
from pathlib import Path

import pytest

ENGINE_DIR = Path(__file__).resolve().parent.parent.parent / "det_chamber" / "engine"
SANDBOX_SRC = ENGINE_DIR / "malware_sandbox.py"
sys.path.insert(0, str(ENGINE_DIR))

# Pure-stdlib engine modules (no win32/pefile/psutil) -- importable on Linux CI.
import sandbox_config  # noqa: E402
import targets         # noqa: E402


# --- 1. Single-file / directory target selection -----------------------------
def _touch(d: Path, *names):
    for n in names:
        (d / n).write_bytes(b"\x00benign-fixture")


def test_select_all_files_when_no_filter(tmp_path):
    _touch(tmp_path, "a.bin", "b.exe", "c.dat")
    (tmp_path / "subdir").mkdir()  # directories must be ignored
    assert sorted(targets.select_targets(str(tmp_path))) == ["a.bin", "b.exe", "c.dat"]


def test_select_single_named_file(tmp_path):
    _touch(tmp_path, "evil.exe", "other.exe")
    assert targets.select_targets(str(tmp_path), malware="evil.exe") == ["evil.exe"]


def test_select_explicit_comma_list(tmp_path):
    _touch(tmp_path, "a.bin", "b.bin", "c.bin")
    assert sorted(targets.select_targets(str(tmp_path), malware="a.bin,c.bin")) == ["a.bin", "c.bin"]


def test_select_missing_single_file_raises(tmp_path):
    _touch(tmp_path, "present.bin")
    with pytest.raises(FileNotFoundError):
        targets.select_targets(str(tmp_path), malware="absent.bin")


def test_select_ignores_subdirectories(tmp_path):
    (tmp_path / "only_a_dir").mkdir()
    assert targets.select_targets(str(tmp_path)) == []


# --- 2. Config loader: defaults < toml < env ---------------------------------
def test_config_defaults_present():
    cfg = sandbox_config.load_config(env={})
    # Every path/tunable the engine needs must resolve to a documented default.
    for field in ("tools_dir", "malware_dir", "collection_dir", "log_dir",
                  "yara_rules", "procmon_config", "pcap_time", "parallel",
                  "evidence_tool", "cuckoo_url", "simulate_network",
                  "volatility_plugins"):
        assert hasattr(cfg, field), f"config missing field: {field}"
    assert isinstance(cfg.pcap_time, int)
    assert isinstance(cfg.parallel, int)
    assert isinstance(cfg.simulate_network, bool)
    assert isinstance(cfg.volatility_plugins, (list, tuple))


def test_config_toml_overrides_default(tmp_path):
    toml = tmp_path / "detchamber.toml"
    toml.write_text('[detchamber]\ntools_dir = "/opt/tools"\npcap_time = 42\n')
    cfg = sandbox_config.load_config(config_path=str(toml), env={})
    assert cfg.tools_dir == "/opt/tools"
    assert cfg.pcap_time == 42


def test_config_env_overrides_toml(tmp_path):
    toml = tmp_path / "detchamber.toml"
    toml.write_text('[detchamber]\ntools_dir = "/from/toml"\n')
    cfg = sandbox_config.load_config(
        config_path=str(toml),
        env={"DETCHAMBER_TOOLS_DIR": "/from/env"},
    )
    assert cfg.tools_dir == "/from/env"  # env wins (container override precedence)


def test_config_env_type_coercion():
    cfg = sandbox_config.load_config(env={
        "DETCHAMBER_PCAP_TIME": "60",
        "DETCHAMBER_PARALLEL": "8",
        "DETCHAMBER_SIMULATE_NETWORK": "true",
    })
    assert cfg.pcap_time == 60 and cfg.parallel == 8
    assert cfg.simulate_network is True


def test_shipped_config_file_parses():
    """The committed config/detchamber.toml must load and carry a [detchamber] table."""
    cfg_file = ENGINE_DIR.parent / "config" / "detchamber.toml"
    assert cfg_file.exists(), "det_chamber/config/detchamber.toml must exist"
    cfg = sandbox_config.load_config(config_path=str(cfg_file), env={})
    assert cfg.tools_dir and cfg.collection_dir  # populated from the file


# --- 3. Engine is Linux-importable + config-driven (AST, no heavy deps) -------
def _engine_tree():
    return ast.parse(SANDBOX_SRC.read_text())


def _module_level_imports(tree):
    names = set()
    for node in tree.body:  # only top-level statements
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("heavy", ["win32api", "win32con", "pefile", "psutil", "requests"])
def test_no_module_level_heavy_imports(heavy):
    # These must be imported lazily (inside the functions that use them) so the
    # module imports cleanly on the Linux CI box and on a Windows host alike.
    assert heavy not in _module_level_imports(_engine_tree()), \
        f"{heavy} is imported at module scope; make it lazy/function-local"


def test_no_dir_creation_at_import():
    # Creating the log dir at import time crashes import on Linux and is a side
    # effect. Only statements that RUN at import matter -- code inside def/class
    # bodies (setup_logging, main) is fine. So inspect top-level executable
    # statements, skipping function/class defs and imports, and assert none of
    # them call makedirs/mkdir.
    tree = _engine_tree()
    import_time_stmts = [
        n for n in tree.body
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                              ast.Import, ast.ImportFrom))
    ]
    for stmt in import_time_stmts:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                assert sub.func.attr not in ("makedirs", "mkdir"), \
                    "no os.makedirs/mkdir at module scope; defer to a setup function"


def test_argparser_supports_malware_and_config():
    src = SANDBOX_SRC.read_text()
    assert "--malware" in src, "engine must accept --malware (single-file mode)"
    assert "--config" in src, "engine must accept --config (path to detchamber.toml)"


def test_no_hardcoded_windows_paths_in_engine():
    # All E:\ / C:\ defaults belong in sandbox_config.py, never scattered in the
    # engine logic. Catches regressions back to finding F2.
    src = SANDBOX_SRC.read_text()
    assert "E:\\" not in src and "C:\\" not in src, \
        "hard-coded Windows path literal in malware_sandbox.py; move it to sandbox_config.py"
