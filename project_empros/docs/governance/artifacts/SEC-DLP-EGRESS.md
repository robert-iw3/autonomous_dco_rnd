# SEC-DLP-EGRESS — Outbound DLP / sovereign data isolation

*Implementation: `analytics/llm_hunter/tools/sanitizer.py`*

Outbound text is DLP-scrubbed (secrets/PII patterns) before egress, enforcing sovereign data isolation.

`analytics/llm_hunter/tools/sanitizer.py:L59-L73`

```python
    def scrub_outbound_dlp(text: str) -> str:
        """
        OWASP LLM06: Sensitive Information Disclosure Defense.
        Prevents internal IPv4/IPv6 ranges or obvious secrets from leaking
        to external Frontier Models (Anthropic/Azure).
        """
        if not isinstance(text, str): return text

        # Mask RFC 1918 internal IPs before they leave the sovereign enclave
        internal_ips = re.compile(r'(^|\s)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})')
        text = internal_ips.sub(r'\1[REDACTED_INTERNAL_IP]', text)

        return text

    @classmethod
```
