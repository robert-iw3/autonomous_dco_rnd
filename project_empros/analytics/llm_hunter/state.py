import os
import operator
from typing import TypedDict, Annotated, List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, field_validator, constr
from langchain_core.messages import BaseMessage, RemoveMessage

# ─── Global "Do Not Pivot" set (Blast-Radius defense, Enhancement 2) ──
# Public resolvers, broadcast/loopback, link-local metadata. Defined here so the
# entity reducer can drop them at MERGE time -- meaning they can never enter the
# blast radius in the first place, rather than relying on a router mutation that
# LangGraph discards (the previous, ineffective location).
GLOBAL_DO_NOT_PIVOT = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "255.255.255.255", "0.0.0.0", "127.0.0.1", "169.254.169.254",
}
MAX_ENTITIES = 10  # hard cap on simultaneously tracked entities per investigation

# ─── Deep-Analysis Loop Gates ──────────────────────────────────────
# FP_CONFIDENCE_GATE is the single confidence threshold for the False Positive
# review/memory contract: an FP verdict BELOW the gate is routed through the
# adversarial review board before the response agent (it cannot be dismissed unreviewed),
# and only an FP verdict AT/ABOVE the gate with a complete blast radius may be
# stored as immunity-eligible RAG memory. This closes the self-poisoning loop
# where one lazy FP verdict granted permanent auto-dismissal of its signature.
FP_CONFIDENCE_GATE = float(os.getenv("NEXUS_FP_CONFIDENCE_GATE", "0.80"))

# Maximum number of times the supervisor's deterministic thoroughness gate may
# reject a FINISH that left entities unresolved before escalating to manual
# review (prevents an infinite supervisor↔expert ping-pong on a stuck entity).
MAX_GATE_OVERRIDES = int(os.getenv("NEXUS_MAX_GATE_OVERRIDES", "2"))

def route_for_source_type(source_type: str) -> str:
    """
    Deterministic source_type → expert routing. Single source of truth shared by
    the orchestrator's first-hop route and the supervisor's thoroughness-gate
    re-route (importing the orchestrator from an agent would be circular).
    """
    if (source_type.startswith("aws_") or source_type.startswith("azure_")
            or source_type.startswith("gcp_") or source_type.startswith("vmware_")):
        return "cloud_expert"
    if source_type == "network_tap":
        return "nettap_expert"
    if source_type == "suricata_eve" or "c2" in source_type:
        return "net_expert"
    # Endpoint sensors: sysmon_sensor, windows_deepsensor, linux_sentinel,
    # macos_sensor, trellix_ens → host_expert
    return "host_expert"

# ─── Alert Schema (Strictly Typed) ─────────────────────────────────
class UnifiedAlertSchema(BaseModel):
    event_id: str = Field(description="The unique UUID of the triggering event.")
    timestamp: float = Field(description="Epoch timestamp of the anomaly.")
    sensor_id: str = Field(description="The hostname or IP of the endpoint.")
    # Forced Enum for routing safety. 'qdrant_vector' is the generic Layer-1
    # isolation-forest source emitted by worker_qdrant when no finer space is set.
    # NOTE: source_type must match what worker_qdrant writes to Qdrant payload
    # (source_type field set in transmit_batch). Any omission here causes the
    # orchestrator to term() those alerts as validation errors -- permanently dropped.
    source_type: Literal[
        # Endpoint -- Windows
        'sysmon_sensor',        # Sysmon driver (windows_math 6D)
        'windows_deepsensor',   # Windows EDR ML sensor (deepsensor_math 4D)
        'windows_c2',           # Windows C2 beacon detector (c2_math 8D)
        'trellix_ens',          # Trellix ENS AV/EDR (trellix_math 6D post ENS-3)
        # Endpoint -- Linux / macOS
        'linux_sentinel',       # Linux eBPF sentinel (sentinel_math 5D)
        'linux_c2',             # Linux C2 beacon detector (c2_math 8D)
        'macos_sensor',         # macOS persistence sensor (windows_math 6D proxy)
        # Network
        'network_tap',          # Arkime network tap (network_tap 8D)
        'suricata_eve',         # Suricata IDS EVE JSON
        # Cloud -- AWS
        'aws_vpc', 'aws_cloudtrail', 'aws_guardduty',
        # Cloud -- Azure
        'azure_nsg', 'azure_activity', 'azure_entraid',
        # Cloud -- GCP / VMware
        'gcp_audit', 'gcp_scc', 'gcp_vpc_flow',
        'vmware_syslog',
        # Generic fallback
        'qdrant_vector'
    ]
    vector_name: str = Field(description="The mathematical vector space that triggered the alert.")
    anomaly_score: float = Field(ge=0.0, le=1.0, description="The mathematical deviation score (0.0 to 1.0).")
    raw_event: Dict[str, Any] = Field(default_factory=dict, description="The fat payload of narrative context.")

# ─── Final Verdict Schema (Strictly Typed) ─────────────────────────
class VerdictSchema(BaseModel):
    is_true_positive: bool = Field(description="True if this is a genuine threat, False if benign/administrative.")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0.")
    justification: str = Field(description="A concise, technical explanation of why this verdict was reached.")
    recommended_action: Literal['contain', 'monitor', 'dismiss'] = Field(description="The final action to take.")

# ─── SOAR Execution Schema (Strictly Typed) ────────────────────────
class SoarExecutionSchema(BaseModel):
    """
    OWASP LLM07 & LLM08: Restricts the LLM's agency to a mathematically verifiable
    set of allowed API contracts. Prevents hallucinated plugin execution.

    NOTE: this contract is now FIELD-ALIGNED with the payload produced by
    response.py. Previously the producer emitted {action, target_sensor,
    justification, ...} while this schema demanded {action_type, targets,
    reason, incident_id}, so EVERY containment failed validation in the
    orchestrator and was silently dropped. The two are now reconciled.

    `targets` was also relaxed from IPvAnyAddress to str: SOAR targets are
    routinely hostnames ('dc-prod-01') or pipe-delimited cloud sensor IDs, which
    an IP-only validator rejected. The resource-exhaustion cap (max 5) -- the
    actual ATLAS AML.T0016 control -- is retained.
    """
    incident_id: str
    action_type: Literal[
        "isolate_host", "block_ip", "monitor_subnet", "manual_review_required",
        # "restore" reverses containment/eradication when a detonation flips the
        # verdict to benign (false positive) -- routes to the ssh_playbook_v1
        # `restore` action (06_restore.{sh,ps1}).
        "restore",
    ] = Field(
        description="The exact functional capability requested."
    )
    target_sensor: str = Field(description="Primary sensor/host the action targets.")
    targets: List[str] = Field(
        default_factory=list,
        description="List of target identifiers (IPs or hostnames).",
        max_length=5,  # ATLAS AML.T0016: prevent resource exhaustion / mass shutdown
    )
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    reason: constr(max_length=200) = Field(description="Brief justification for the audit log.")

    @field_validator("targets")
    @classmethod
    def _strip_blanks(cls, v: List[str]) -> List[str]:
        return [t for t in v if t and str(t).strip()]

# ─── Live Acquisition Request (host_expert → Det Chamber) ──────────
class AcquisitionRequestSchema(BaseModel):
    """The validated request the host_expert's acquire_and_detonate tool emits on
    nexus.acquire.request. First-line path safety lives here (the deterministic
    worker_acquire re-validates with the full OS-critical deny-list before it
    ever reaches an endpoint). OWASP LLM07/08: the LLM only emits this schema."""
    incident_id: str
    host: str
    file_path: str
    os_family: Literal["windows", "linux"]
    confidence: float = Field(ge=0.0, le=1.0)
    reason: constr(max_length=200)

    @field_validator("file_path")
    @classmethod
    def _safe_path(cls, v: str) -> str:
        import re
        if not v or any(c in v for c in "*?"):
            raise ValueError("file_path is empty or contains a wildcard")
        if ".." in re.split(r"[\\/]+", v):
            raise ValueError("file_path contains path traversal")
        return v

# ─── RAG Immunity Signature ────────────────────────────────────────
def build_memory_signature(sensor_id: str, source_type: str, vector_name: str) -> str:
    """
    Canonical text embedded for RAG-driven immunity.

    This MUST be byte-identical on the WRITE path (response.py, when a verdict is
    persisted) and the READ path (supervisor.py, when recalling). The original
    code embedded different strings on each side -- write used
    'Action: {action}\\nReport: {full_report}', read used a fixed
    'Action: manual_review_required\\nReport: ' -- so the cosine similarity could
    never approach the 0.95 gate and immunity never fired. The signature is keyed
    only on the stable identity of the alert pattern, not on the variable verdict
    or free-text report.
    """
    return f"sensor:{sensor_id}|source_type:{source_type}|vector:{vector_name}"

# ─── Entity State Machine ──────────────────────────────────────────
class EntityTracking(BaseModel):
    # "file" tracks a confirmed-TP artifact (path in notes) the host_expert can
    # hand to the Det Chamber for live acquisition + detonation.
    type: Literal["ip", "domain", "pid", "hash", "user", "file"]
    status: Literal["pending", "investigating", "cleared", "malicious"] = "pending"
    notes: str = ""

def merge_entities(left: Dict[str, dict], right: Dict[str, dict]):
    """
    Intelligently updates entity status. If an entity is already 'malicious',
    it cannot be downgraded. Public resolvers / broadcast addresses in
    GLOBAL_DO_NOT_PIVOT are dropped at merge time so the blast radius can never
    explode through them (the "8.8.8.8 problem").
    """
    merged = {k: v for k, v in left.items() if str(k) not in GLOBAL_DO_NOT_PIVOT}

    # Severity hierarchy to prevent accidental downgrades.
    status_weights = {"pending": 0, "investigating": 1, "cleared": 2, "malicious": 3}

    for entity_id, new_data in right.items():
        if str(entity_id) in GLOBAL_DO_NOT_PIVOT:
            continue  # never track public infrastructure
        if entity_id not in merged:
            # Ensure a 'type' is always present so EntityTracking stays valid.
            merged[entity_id] = {"type": new_data.get("type", "ip"), **new_data}
        else:
            old_weight = status_weights.get(merged[entity_id].get("status", "pending"), 0)
            new_weight = status_weights.get(new_data.get("status", "pending"), 0)
            if new_weight > old_weight:
                merged[entity_id]["status"] = new_data["status"]
            if new_data.get("notes"):
                combined = f"{merged[entity_id].get('notes', '')} | {new_data['notes']}".strip(" |")
                # Bound note growth across many turns.
                merged[entity_id]["notes"] = combined[-800:]

    return merged

# ─── Context Window Manager ────────────────────────────────────────
def manage_messages(left: list[BaseMessage], right: list[BaseMessage]):
    """
    Appends new messages, honouring RemoveMessage tombstones so callers can
    prune specific message IDs from state. Experts now yield a single condensed
    summary message rather than their full ReAct transcript, which is the primary
    context-budget control (see agents/expert_base.py).
    """
    removals = {m.id for m in right if isinstance(m, RemoveMessage)}
    kept = [m for m in left if getattr(m, "id", None) not in removals]
    additions = [m for m in right if not isinstance(m, RemoveMessage)]
    return kept + additions

class InvestigativeState(TypedDict):
    alert: Dict[str, Any]
    messages: Annotated[List[BaseMessage], manage_messages]
    entities_of_interest: Annotated[Dict[str, dict], merge_entities]
    next_agent: Literal[
        "host_expert", "net_expert", "cloud_expert", "nettap_expert",
        "review_board", "response_agent", "FINISH",
    ]
    verdict: Optional[Dict[str, Any]]
    action_payload: Optional[Dict[str, Any]]
    incident_report: Optional[str]
    canary: Optional[str]  # OWASP LLM01 prompt-leak tripwire (injected into agent system prompts)
    # ── Deep-analysis loop bookkeeping ──
    # Number of times the supervisor's deterministic thoroughness gate rejected a
    # FINISH that left unresolved entities (bounded by MAX_GATE_OVERRIDES).
    gate_overrides: int
    # False when the verdict was accepted with an unresolved blast radius (gate
    # exhausted, blast-radius cap, or total provider failure). Such verdicts are
    # review-board-reviewed, surfaced as manual_review_required, and never mint
    # immunity-eligible RAG memory.
    analysis_complete: Optional[bool]