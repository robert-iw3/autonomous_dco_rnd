# SEC-CANARY — Canary token prompt-leak tripwire

*Implementation: `analytics/llm_hunter/tools/sanitizer.py`*

Per-investigation canary token minted and embedded in the system context; its later appearance on any outbound surface is the prompt-leak tripwire.

`analytics/llm_hunter/tools/sanitizer.py:L49-L58`

```python
    def generate_canary() -> str:
        """
        OWASP LLM01: Advanced Prompt Injection Defense.
        Generates a unique canary token to inject into the System Prompt.
        If the model outputs this token, an adversary successfully executed a 'jailbreak'
        to read internal instructions.
        """
        return f"CANARY_{uuid.uuid4().hex[:12]}"

    @staticmethod
```

Orchestrator mints the canary at swarm start…

`analytics/llm_hunter/orchestrator.py:L197-L197`

```python
            canary = CognitiveSanitizer.generate_canary()
```

…and verifies it never leaked into any outbound surface before the verdict is released.

`analytics/llm_hunter/orchestrator.py:L258-L261`

```python
            # OWASP LLM01: verify the canary did not leak into any outbound surface.
            report = final_state.get("incident_report", "") or ""
            action = final_state.get("action_payload", {}) or {}
            if canary in report or canary in json.dumps(action):
```
