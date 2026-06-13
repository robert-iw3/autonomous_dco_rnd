# SEC-OUTPUT-SCHEMA — Strict SOAR output-contract enforcement

*Implementation: `analytics/llm_hunter/state.py`*

**Execution chain:** Logic → Invocation → Execution

**1. Logic** — SOAR actions must satisfy a strict Pydantic contract (enumerated action, blast-radius-capped validated targets).

`analytics/llm_hunter/state.py:L94-L129`

```python
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
```

**2. Invocation** — The dispatch path is the single egress for any containment action.

`analytics/llm_hunter/orchestrator.py:L294-L295`

```python
async def _dispatch_soar(alert: UnifiedAlertSchema, action: dict, js_client):
    """Validate the field-aligned SOAR payload and publish it to JetStream."""
```

**3. Execution** — Before publish, the action is re-validated against the schema; an off-contract payload raises ValidationError and is dropped rather than executed.

`analytics/llm_hunter/orchestrator.py:L324-L331`

```python
        validated = SoarExecutionSchema(
            incident_id=action.get("incident_id", alert.event_id),
            action_type=action_type,
            target_sensor=action.get("target_sensor", alert.sensor_id),
            targets=action.get("targets", []),
            confidence=float(action.get("confidence", 0.0)),
            reason=action.get("reason", "")[:200],
        )
```
