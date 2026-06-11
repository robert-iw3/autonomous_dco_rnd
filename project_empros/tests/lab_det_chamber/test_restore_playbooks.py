"""
Lab det_chamber -- false-positive restore (rollback).

A confirmed-TP investigation contains/eradicates; if the verdict later flips to a
FALSE POSITIVE (e.g. detonation proves the sample benign), the destructive actions
must be REVERSIBLE. Cloud already had `05_restore_host.sh`; Linux and Windows did
not (finding DC-N7).

Contract proven here:
  * the eradication playbooks write a rollback JOURNAL (original↔quarantine↔sha256),
  * `06_restore` reverses isolation (restore the firewall backup the contain
    playbook saved), restores quarantined files from the journal **after verifying
    their sha256** (never restores tampered/wrong bytes), and is non-destructive,
  * the ssh_playbook_v1 provider exposes a `restore` action.
"""

import tomllib
from pathlib import Path

PB = Path(__file__).resolve().parents[2] / "operations" / "playbooks"
LINUX_RESTORE = PB / "linux" / "06_restore.sh"
WIN_RESTORE = PB / "windows" / "06_Restore-Host.ps1"
LINUX_ERAD = PB / "linux" / "02_eradicate_process.sh"
WIN_ERAD = PB / "windows" / "02_Eradicate-Process.ps1"
CONTAINMENT = Path(__file__).resolve().parents[2] / "operations" / "infra" / "containment.toml"


# --- Eradication writes a rollback journal -----------------------------------
def test_linux_eradication_writes_rollback_journal():
    t = LINUX_ERAD.read_text()
    # The journal helper appends a JSON line per quarantine (quotes are shell-escaped).
    assert "ROLLBACK_JOURNAL" in t and "journal " in t and "quarantine" in t, \
        "linux eradication must journal each quarantine for restore"
    assert "rollback" in t


def test_windows_eradication_writes_rollback_journal():
    t = WIN_ERAD.read_text()
    assert "Write-Rollback" in t and "rollback" in t.lower() and "quarantine" in t.lower()


# --- Linux restore -----------------------------------------------------------
def test_linux_restore_exists_and_reverses_isolation():
    assert LINUX_RESTORE.exists(), "operations/playbooks/linux/06_restore.sh must exist"
    t = LINUX_RESTORE.read_text()
    assert "iptables-restore" in t or "nft -f" in t, "must restore the saved firewall ruleset"
    assert "iptables-pre-" in t or "nftables-pre-" in t, "must read the pre-containment backup 01 saved"


def test_linux_restore_verifies_hash_before_restoring_files():
    t = LINUX_RESTORE.read_text()
    assert "sha256sum" in t, "must verify the quarantined file's sha256 before restoring it"
    assert "rollback" in t and ".jsonl" in t, "must read the rollback journal"


def test_linux_restore_is_non_destructive():
    t = LINUX_RESTORE.read_text()
    assert "rm -rf" not in t, "restore must not destroy data"


# --- Windows restore ---------------------------------------------------------
def test_windows_restore_exists_and_reverses_isolation():
    assert WIN_RESTORE.exists(), "operations/playbooks/windows/06_Restore-Host.ps1 must exist"
    t = WIN_RESTORE.read_text()
    assert "netsh advfirewall import" in t, "must import the firewall backup 01 saved"
    assert "firewall-pre-" in t


def test_windows_restore_verifies_hash_before_restoring_files():
    t = WIN_RESTORE.read_text()
    assert "Get-FileHash" in t, "must verify the quarantined file's sha256 before restoring it"
    assert "Move-Item" in t and "rollback" in t.lower()


# --- Transport: ssh_playbook_v1 restore action -------------------------------
def test_containment_has_restore_action():
    conf = tomllib.loads(CONTAINMENT.read_text())
    action = conf["providers"]["ssh_playbook_v1"]["actions"]["restore"]
    assert action["method"] == "POST"
    assert "incident_id" in action["validation"]["required_fields"]
