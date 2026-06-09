"""
VMware-specific HCL parsing helpers for tier2 tests.

All functions accept raw source text (str) and return structured data.
"""
import re
from typing import Optional

def _find_block_end(src: str, start: int) -> int:
    """
    Walk src from `start` (position just after the opening '{') and return
    the index one past the matching closing '}', counting brace depth.

    Correctly skips '${...}' interpolation sequences so their inner '{' and
    '}' characters do not interfere with block-boundary detection.
    """
    depth = 1
    i = start
    while i < len(src) and depth > 0:
        ch = src[i]
        if ch == "$" and i + 1 < len(src) and src[i + 1] == "{":
            # Skip interpolation: advance past the entire ${...} token.
            i += 2
            inner = 1
            while i < len(src) and inner > 0:
                if src[i] == "{":
                    inner += 1
                elif src[i] == "}":
                    inner -= 1
                i += 1
        elif ch == "{":
            depth += 1
            i += 1
        elif ch == "}":
            depth -= 1
            i += 1
        else:
            i += 1
    return i

def resource_body(src: str, resource_type: str, resource_name: str) -> Optional[str]:
    """Extract the content inside `resource "TYPE" "NAME" { ... }`, handling ${...}."""
    m = re.search(
        rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{',
        src,
    )
    if not m:
        return None
    end = _find_block_end(src, m.end())
    return src[m.end(): end - 1]

def provider_body(src: str, provider_name: str) -> Optional[str]:
    """Extract the content inside `provider "NAME" { ... }`, handling ${...}."""
    m = re.search(rf'provider\s+"{re.escape(provider_name)}"\s*\{{', src)
    if not m:
        return None
    end = _find_block_end(src, m.end())
    return src[m.end(): end - 1]

def variable_body(src: str, varname: str) -> Optional[str]:
    """Extract the content inside `variable "NAME" { ... }`."""
    m = re.search(rf'variable\s+"{re.escape(varname)}"\s*\{{', src)
    if not m:
        return None
    end = _find_block_end(src, m.end())
    return src[m.end(): end - 1]

def output_value(src: str, output_name: str) -> Optional[str]:
    """Extract the `value = ...` string from an output block."""
    m = re.search(rf'output\s+"{re.escape(output_name)}"\s*\{{', src)
    if not m:
        return None
    block_start = m.end()
    block_end = _find_block_end(src, block_start)
    block = src[block_start: block_end - 1]
    v = re.search(r'value\s*=\s*(.+)', block)
    return v.group(1).strip() if v else None

def scalar(src: str, key: str) -> Optional[str]:
    """Return the string value of `key = "value"` (handles escaped quotes)."""
    m = re.search(
        rf'{re.escape(key)}\s*=\s*"((?:[^"\\]|\\.)*)"',
        src,
    )
    return m.group(1) if m else None

def has_explicit_backend(src: str, backend_type: str = "local") -> bool:
    """Return True if `backend "TYPE" {}` is declared in src."""
    return bool(re.search(rf'backend\s+"{re.escape(backend_type)}"\s*\{{', src))

def has_variable(src: str, varname: str) -> bool:
    """Return True if a `variable "NAME"` block exists in src."""
    return bool(re.search(rf'variable\s+"{re.escape(varname)}"\s*\{{', src))

def required_provider_version(src: str, provider_source: str) -> Optional[str]:
    """
    Extract the version constraint for a required_providers entry by its source.
    """
    m = re.search(
        r'\{[^{}]*source\s*=\s*"' + re.escape(provider_source) + r'"[^{}]*\}',
        src,
        re.DOTALL,
    )
    if not m:
        return None
    block = m.group(0)
    v = re.search(r'version\s*=\s*"([^"]+)"', block)
    return v.group(1) if v else None

def has_resource(src: str, resource_type: str, resource_name: str) -> bool:
    """Return True if `resource "TYPE" "NAME"` is declared in src."""
    return bool(
        re.search(
            rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{',
            src,
        )
    )

def attr_value(src: str, key: str) -> Optional[str]:
    """Extract the raw value of `key = VALUE` (unquoted or quoted)."""
    m = re.search(rf'\b{re.escape(key)}\s*=\s*([^\n]+)', src)
    return m.group(1).strip().rstrip(",") if m else None