"""
Lab det_chamber -- Phase 4: on-endpoint acquisition agents + transport wiring.

The agents are delivered to endpoints via the existing ssh_playbook_v1 executor
(SSH for Linux, WinRM for Windows) as operations playbooks, matching the 00-04
forensics/containment playbooks. They must hash + zip + manifest the file and
NEVER execute it. Asserted structurally here (the bash/PS can't run in this lab),
plus the containment provider action that routes them.
"""

import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LINUX = REPO / "operations" / "playbooks" / "linux" / "05_acquire_artifact.sh"
WIN = REPO / "operations" / "playbooks" / "windows" / "05_Acquire-Artifact.ps1"
CONTAINMENT = REPO / "operations" / "infra" / "containment.toml"


# --- Linux agent (bash, delivered over SSH) ----------------------------------
def test_linux_agent_hashes_zips_manifests():
    t = LINUX.read_text()
    assert "sha256sum" in t, "must compute SHA256 for chain of custody"
    assert "zip" in t.lower(), "must package the artifact"
    assert "manifest" in t.lower(), "must write a manifest"
    assert "NEXUS_INCIDENT_ID" in t, "must take incident context like the other playbooks"


def test_linux_agent_never_executes_sample():
    t = LINUX.read_text()
    # no chmod +x / direct invocation / sourcing of the acquired file
    for bad in ("chmod +x", "./\"$", "bash \"$FILE", "source \"$FILE", "eval "):
        assert bad not in t, f"linux agent must never execute the sample ({bad!r})"


def test_linux_agent_guards_path_and_size():
    t = LINUX.read_text()
    assert "/etc/shadow" in t, "must carry an OS-critical deny-list"
    assert "MAX" in t.upper(), "must enforce a size cap"


# --- Windows agent (PowerShell, delivered over WinRM) ------------------------
def test_windows_agent_hashes_zips_manifests():
    t = WIN.read_text()
    assert "Get-FileHash" in t and "SHA256" in t
    assert "Compress-Archive" in t
    assert "manifest" in t.lower()
    assert "NEXUS_INCIDENT_ID" in t or "IncidentId" in t


def test_windows_agent_never_executes_sample():
    t = WIN.read_text()
    for bad in ("Start-Process", "Invoke-Expression", "iex "):
        assert bad not in t, f"windows agent must never execute the sample ({bad!r})"


def test_windows_agent_guards_path_and_size():
    t = WIN.read_text().lower()
    assert "system32\\config" in t or "ntds.dit" in t, "must carry an OS-critical deny-list"
    assert "max" in t, "must enforce a size cap"


# --- Transport: ssh_playbook_v1 acquire_artifact action ----------------------
def test_containment_has_acquire_artifact_action():
    conf = tomllib.loads(CONTAINMENT.read_text())
    action = conf["providers"]["ssh_playbook_v1"]["actions"]["acquire_artifact"]
    assert action["method"] == "POST"
    assert "fallback-containment" in action["endpoint"], "routes to the playbook executor webhook"
    required = action["validation"]["required_fields"]
    assert "file_path" in required and "incident_id" in required
