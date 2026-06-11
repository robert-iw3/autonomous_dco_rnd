"""
Sensor-side -- SOAR response execution capability on the endpoint agents.

Validates (source-contract; Rust/C# aren't compiled here) what each on-host agent
brings to running a Nexus-determined response playbook outbound (DC-N11), and pins
the integration gaps so they don't silently regress.

  windows/windows_xdr_dev : local response executor (ActiveDefenseModule) + the
                            nexus_integrity HMAC + the Nexus task channel
                            (ResponseChannel: poll → verify → fixed playbook).
  linux/sentinel          : outbound telemetry (bearer JWT + HMAC) + the response
                            module (src/response: poller + verify + executor).
DC-N11 logic is now present on both agents; these pin the contract so it can't
regress to a stub.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]      # project_empros
ROOT = REPO.parent                              # git root (linux/, windows/)

WIN_DEFENSE = ROOT / "windows" / "windows_xdr_dev" / "agent" / "ActiveDefenseModule.cs"
WIN_INTEGRITY = ROOT / "windows" / "windows_xdr_dev" / "nexus_integrity" / "src" / "lib.rs"
WIN_FORWARDER = ROOT / "windows" / "windows_xdr_dev" / "agent" / "NexusForwarder.cs"
WIN_RESPONSE = ROOT / "windows" / "windows_xdr_dev" / "agent" / "ResponseChannel.cs"
WIN_PROTOCOL = ROOT / "windows" / "windows_xdr_dev" / "agent" / "ResponseProtocol.cs"
WIN_DOTNET_TEST = ROOT / "windows" / "windows_xdr_dev" / "tests" / "dotnet" / "ResponseProtocolTests.cs"
WIN_PROGRAM = ROOT / "windows" / "windows_xdr_dev" / "agent" / "Program.cs"
SYSMON_RESPONSE = ROOT / "windows" / "sysmon_sensor" / "response_channel.py"
LINUX_TX = ROOT / "linux" / "sentinel" / "src" / "siem" / "parquet_transmitter.rs"
PLAYBOOKS = REPO / "operations" / "playbooks"


# -- Windows XDR: local response executor present (SOAR-mappable primitives) ---
def test_windows_agent_has_local_response_primitives():
    t = WIN_DEFENSE.read_text()
    assert "ExecuteMitigationAsync" in t, "the agent must have a local mitigation entrypoint"
    assert "Process" in t and "Kill" in t, "process termination (→ eradicate)"
    assert "netsh" in t and "block" in t.lower(), "host firewall block (→ block_ip / isolate)"
    assert "ReleaseQuarantine" in t, "rollback primitive (→ restore / false positive)"


def test_windows_agent_has_integrity_hmac_for_task_auth():
    # The same HMAC headers used for outbound telemetry will authenticate the
    # task channel (verify a Nexus task) and the outcome report.
    assert "HDR_BATCH_HMAC" in WIN_INTEGRITY.read_text()


def test_windows_agent_transmits_outbound():
    # NexusForwarder is the outbound channel the task-poller + outcome-report reuse.
    assert WIN_FORWARDER.exists()


def test_windows_response_protocol_implements_contract():
    # DC-N11: the pure protocol (HMAC verify, fixed playbook, NEXUS_* env). This is
    # the part the xunit test actually EXECUTES (cross-platform), so it isn't just a
    # grep guard -- behaviour is proven by tests/dotnet, this only pins structure.
    assert WIN_PROTOCOL.exists(), "DC-N11: windows must have agent/ResponseProtocol.cs"
    t = WIN_PROTOCOL.read_text()
    assert "HMACSHA256" in t and "FixedTimeEquals" in t, "constant-time HMAC verify"
    assert "WinPlaybook" in t and "01_Contain-Host.ps1" in t, "fixed playbook allowlist"
    assert "NEXUS_INCIDENT_ID" in t, "NEXUS_* env contract"
    assert "GoldenSig" in t and "GoldenCanonical" in t, "carries the golden vector"


def test_windows_response_protocol_has_executed_test():
    # The gap is CLOSED: a real xunit test compiles ResponseProtocol.cs on Linux and
    # runs the golden-vector assertion (tier2 `dotnet test`). Not a grep proxy.
    assert WIN_DOTNET_TEST.exists(), "ResponseProtocol must have an executed xunit test"
    t = WIN_DOTNET_TEST.read_text()
    assert "Verify_accepts_python_signature" in t, "must assert C# accepts a Python signature"
    assert "[Fact]" in t or "[Theory]" in t, "must be runnable xunit tests"


def test_windows_response_channel_is_transport_only():
    # ResponseChannel is the BackgroundService transport; it delegates the protocol.
    t = WIN_RESPONSE.read_text()
    assert "/api/v1/tasks" in t and "Bearer" in t, "outbound poll (no inbound reach)"
    assert "ResponseProtocol." in t, "must delegate to the tested protocol class"


def test_windows_response_channel_wired_into_program():
    assert "ResponseChannel" in WIN_PROGRAM.read_text(), \
        "ResponseChannel must be registered as a hosted service"


def test_sysmon_sensor_has_response_channel():
    # A Sysmon-only endpoint still gets a response mechanism (behaviour proven in
    # windows/sysmon_sensor/test/tier0/test_response_channel.py, which signs with
    # the real platform signer). This pins the wiring.
    assert SYSMON_RESPONSE.exists(), "sysmon sensor must have response_channel.py"
    t = SYSMON_RESPONSE.read_text()
    assert "def verify_task" in t and "hmac" in t, "verifies the Nexus HMAC"
    assert "WIN_PLAYBOOK" in t and "01_Contain-Host.ps1" in t, "fixed windows playbooks"
    assert "/api/v1/tasks" in t, "outbound poll"
    assert "NEXUS_ENABLE_RESPONSE" in (ROOT / "windows" / "sysmon_sensor" / "SysmonSensor.py").read_text(), \
        "the sensor must opt-in start the response channel"


# -- Linux sentinel: outbound transport + auth exist (poller will reuse them) --
def test_linux_sentinel_has_outbound_authed_transport():
    t = LINUX_TX.read_text()
    assert "bearer_auth" in t, "JWT bearer auth — reused by the response poller"
    assert "HDR_BATCH_HMAC" in t, "HMAC integrity — reused for tasks + outcome reports"


def test_linux_sentinel_response_executor_implements_contract():
    # DC-N11: Verify a signed task (HMAC), select a FIXED playbook by action (no task-supplied path),
    # build NEXUS_* env, pull tasks OUTBOUND, report outcome. Pinned so it can't
    # silently regress to a stub.
    mod = ROOT / "linux" / "sentinel" / "src" / "response" / "mod.rs"
    assert mod.exists(), "DC-N11: sentinel must have src/response/mod.rs"
    t = mod.read_text()
    assert "fn verify_task" in t and "Hmac" in t, "must verify the task HMAC"
    assert "LINUX_PLAYBOOK" in t and "01_contain_host.sh" in t, "fixed playbook allowlist"
    assert "fn select_playbook" in t, "action → fixed playbook (never a task path)"
    assert "NEXUS_INCIDENT_ID" in t and "fn build_env" in t, "NEXUS_* env contract"
    assert "fn run_poller" in t and "/api/v1/tasks" in t and "bearer_auth" in t, \
        "outbound poll of the ingress task endpoint (no inbound reach)"
    # the golden cross-language vector pins Rust↔Python signing parity (runs in CI)
    assert "canonical_matches_python_golden" in t, "must carry the golden-vector parity test"


def test_linux_sentinel_wires_response_poller_into_main():
    main = (ROOT / "linux" / "sentinel" / "src" / "main.rs").read_text()
    assert "mod response;" in main, "response module must be compiled into the binary"
    assert "run_poller" in main, "the poller must actually be spawned at startup"


# -- Both agents run the SAME fixed operations playbooks ----------------------
@pytest.mark.parametrize("sub,fname", [
    ("linux", "01_contain_host.sh"), ("linux", "04_block_c2.sh"),
    ("linux", "06_restore.sh"), ("windows", "01_Contain-Host.ps1"),
    ("windows", "04_Block-C2.ps1"), ("windows", "06_Restore-Host.ps1"),
])
def test_response_playbooks_exist_for_both_os(sub, fname):
    assert (PLAYBOOKS / sub / fname).exists()
