# SEC-CANARY — Canary token prompt-leak tripwire

*Implementation: `analytics/llm_hunter/tools/sanitizer.py`*

**Execution chain:** Invocation → Logic → Execution

**1. Invocation** — At swarm start the orchestrator mints a per-investigation canary token and seeds it into the agents' system context.

`analytics/llm_hunter/orchestrator.py:L197-L197`

```python
            canary = CognitiveSanitizer.generate_canary()
```

**2. Logic** — The canary is a unique UUID tripwire — its only legitimate place is the system prompt, so any later appearance downstream is proof of a prompt leak.

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

**3. Execution** — Before any verdict is released the orchestrator verifies the canary never leaked onto an outbound surface; a leak halts the SOAR pipeline.

`analytics/llm_hunter/orchestrator.py:L258-L261`

```python
            # OWASP LLM01: verify the canary did not leak into any outbound surface.
            report = final_state.get("incident_report", "") or ""
            action = final_state.get("action_payload", {}) or {}
            if canary in report or canary in json.dumps(action):
```
