# SEC-OUTPUT-SCHEMA — Strict SOAR output-contract enforcement

*Implementation: `analytics/llm_hunter/state.py`*

SOAR actions must satisfy a strict Pydantic contract (enumerated action, validated targets) before any response is dispatched.

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
