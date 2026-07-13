# SEC-SANITIZER — Cognitive boundary isolation & untrusted-payload wrapping

*Implementation: `analytics/llm_hunter/tools/sanitizer.py`*

**Execution chain:** Logic → Logic → Execution

**1. Logic** — Untrusted text is stripped of control characters and prompt-injection delimiters and HTML-escaped before it can reach an LLM context.

`analytics/llm_hunter/tools/sanitizer.py:L24-L48`

```python
    def neutralize_string(text: Any) -> str:
        """
        Defangs prompt injection tokens and escapes HTML to prevent
        adversaries from breaking out of the XML boundaries.
        """
        if not isinstance(text, str):
            text = str(text)

        # TOKEN STUFFING DEFENSE: Truncate BEFORE any processing to bound
        # CPU cost of regex passes and guarantee the XML closing tag is
        # never pushed out of the context window.
        if len(text) > CognitiveSanitizer.MAX_FIELD_LENGTH:
            text = text[:CognitiveSanitizer.MAX_FIELD_LENGTH] + " ...[TRUNCATED_BY_SANITIZER]"

        # Strip system control tokens (e.g., <|im_start|>, [INST])
        safe_text = re.sub(r'<\|.*?\|>', '[DEFANGED_TOKEN]', text)
        safe_text = re.sub(r'\[/?INST\]', '[DEFANGED_TOKEN]', safe_text, flags=re.IGNORECASE)

        # Defang role-play injection attempts
        safe_text = re.sub(r'\b(System|Human|Assistant|User):\s*', 'EntityData: ', safe_text, flags=re.IGNORECASE)

        # Escape HTML to neutralize </untrusted_payload> breakout attempts
        return html.escape(safe_text)

    @staticmethod
```

**2. Logic** — All untrusted payloads are wrapped inside an explicit, randomised cognitive boundary so the model treats them as data, not instructions.

`analytics/llm_hunter/tools/sanitizer.py:L88-L96`

```python
    def wrap_untrusted(cls, text: Any) -> str:
        """
        Wrap a single already-fetched external/historical string in the
        canonical <untrusted_payload> envelope AFTER neutralization.

        Used by tools that surface adversary-influenced data (DuckDB cells,
        Qdrant historical payloads, external Threat-Intel responses) so every
        data path uses the SAME hardened neutralizer rather than ad-hoc wrapping.
        """
```

**3. Execution** — Wired into every expert: entity notes pulled into the shared board are neutralised before being rendered into the agent prompt.

`analytics/llm_hunter/agents/expert_base.py:L83-L84`

```python
            safe_notes = CognitiveSanitizer.neutralize_string(str(data.get("notes", "")))[:160]
            unresolved_lines.append(f"- {entity_id} [{status}]: {safe_notes}")
```
