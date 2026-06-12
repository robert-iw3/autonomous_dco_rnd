"""
PCAP retention (72h) — behavioural + contract.

The Arkime sensor's durable product is SPI METADATA (OpenSearch + the ML gateway);
raw PCAPs are transient and purged on a 72h rolling window so disk use stays
bounded. These tests EXECUTE the real `pcap_retention.sh` against synthetic files
with controlled mtimes — so a wrong threshold/units or an unsafe glob fails here —
and pin that SPI in OpenSearch is RETAINED, not deleted.
"""

import os
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.tier0


def _make(dirpath: Path, name: str, age_hours: float) -> Path:
    f = dirpath / name
    f.write_bytes(b"\xd4\xc3\xb2\xa1pcap")        # pcap magic-ish payload
    when = time.time() - age_hours * 3600
    os.utime(f, (when, when))
    return f


def _run(script: Path, pcap_dir: Path, hours=72, dry_run=False):
    env = {**os.environ, "PCAP_DIR": str(pcap_dir),
           "PCAP_RETENTION_HOURS": str(hours), "DRY_RUN": "true" if dry_run else "false"}
    return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)


# -- behavioural: the real script purges only what's past the window ----------
def test_purges_only_pcaps_older_than_72h(tmp_path, paths):
    old = _make(tmp_path, "old-073h.pcap", 73)
    boundary = _make(tmp_path, "old-100h.pcap", 100)
    fresh = _make(tmp_path, "fresh-071h.pcap", 71)
    very_fresh = _make(tmp_path, "fresh-001h.pcap", 1)

    r = _run(paths["pcap_retention"], tmp_path)
    assert r.returncode == 0, r.stderr

    assert not old.exists() and not boundary.exists(), "PCAPs older than 72h must be purged"
    assert fresh.exists() and very_fresh.exists(), "PCAPs within 72h must be kept"


def test_dry_run_deletes_nothing(tmp_path, paths):
    old = _make(tmp_path, "old.pcap", 200)
    r = _run(paths["pcap_retention"], tmp_path, dry_run=True)
    assert r.returncode == 0
    assert old.exists(), "DRY_RUN must not delete"
    assert "WOULD delete" in r.stdout


def test_only_pcap_files_touched(tmp_path, paths):
    # SPI/sidecar artefacts and non-pcap files are never removed
    keep = _make(tmp_path, "sessions.json", 500); keep.write_text("{}")
    os.utime(keep, (time.time() - 500 * 3600,) * 2)
    old_pcap = _make(tmp_path, "ancient.pcap", 500)
    _run(paths["pcap_retention"], tmp_path)
    assert keep.exists(), "non-pcap files must never be deleted"
    assert not old_pcap.exists()


def test_refuses_zero_retention(tmp_path, paths):
    # a misconfigured 0 would wipe everything -- the script must refuse
    f = _make(tmp_path, "x.pcap", 999)
    r = _run(paths["pcap_retention"], tmp_path, hours=0)
    assert r.returncode != 0, "retention of 0h must be refused"
    assert f.exists()


def test_missing_dir_is_noop(tmp_path, paths):
    r = _run(paths["pcap_retention"], tmp_path / "does-not-exist")
    assert r.returncode == 0


# -- contract: retention is actually wired + bounded --------------------------
def test_retention_loop_wired_into_startarkime(paths):
    s = paths["startarkime"].read_text()
    assert "pcap_retention.sh" in s, "the sensor must run the retention loop"
    assert "PCAP_RETENTION_HOURS" in s
    assert "RETENTION_PID" in s and "kill -TERM \"${RETENTION_PID" in s, "loop must be cleaned up on shutdown"


def test_retention_window_is_72h(paths):
    assert 'PCAP_RETENTION_HOURS:-72' in paths["pcap_retention"].read_text()
    assert 'PCAP_RETENTION_HOURS:-72' in paths["startarkime"].read_text()


def test_size_safety_net_present(paths):
    ini = paths["arkime_ini"].read_text()
    assert "freeSpaceG" in ini, "Arkime freeSpaceG is the size-based safety net between purges"


def test_pcap_dir_is_dedicated_mount(paths):
    # pcaps land on a dedicated bind mount, not the OS/metadata disks
    compose = paths["compose"].read_text()
    assert "/mnt/pcap_storage:/data/pcap" in compose


# -- the key invariant: SPI METADATA is RETAINED for historical analysis ------
def test_ism_retains_spi_no_delete_state(paths):
    import json
    policy = json.loads(paths["ism"].read_text())["policy"]
    state_names = {s["name"] for s in policy["states"]}
    assert "delete" not in state_names, \
        "SPI must be RETAINED for historical analysis -- the ISM must NOT delete session indices"
    # no state may carry a delete action either
    for s in policy["states"]:
        assert all("delete" not in a for a in s["actions"]), f"state {s['name']} must not delete"
    # archive to S3 is the durable historical copy
    assert any(any("snapshot" in a for a in s["actions"]) for s in policy["states"]), \
        "SPI should be archived to S3 cold storage for historical retention"


def test_retention_split_is_documented(paths):
    # the script itself states the split so an operator can't misread the intent
    t = paths["pcap_retention"].read_text().lower()
    assert "spi" in t and "retain" in t and "72h" in t
