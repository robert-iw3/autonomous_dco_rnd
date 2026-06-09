"""
Tier-2 parsing helpers for GCP deploy/ IaC.
"""
import os
import re

def read_tf(tf_dir):
    """Concatenate every *.tf in a deploy dir into one searchable blob."""
    parts = []
    for fn in sorted(os.listdir(tf_dir)):
        if fn.endswith(".tf"):
            with open(os.path.join(tf_dir, fn)) as fh:
                parts.append(fh.read())
    return "\n".join(parts)

def iter_resources(src, rtype):
    """Yield (name, body) for every `resource "<rtype>" "<name>" { ... }`.

    Matches up to the first column-0 closing brace.
    """
    for m in re.finditer(
        rf'resource\s+"{re.escape(rtype)}"\s+"([A-Za-z0-9_]+)"\s*\{{(.*?)\n\}}',
        src, re.DOTALL,
    ):
        yield m.group(1), m.group(2)

def resource_addresses(src):
    """Set of every defined `rtype.name` address in the stack."""
    return {
        f"{rt}.{name}"
        for rt, name in re.findall(
            r'resource\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_]+)"', src
        )
    }

def scalar(block_text, key):
    """Read a `key = "value"` or `key = bareword` scalar out of block text.

    Handles HCL escape sequences (e.g. `\"` inside string values) by matching
    `(?:[^"\\]|\\.)*` instead of the naive `[^"]+`.
    """
    m = re.search(rf'{re.escape(key)}\s*=\s*"((?:[^"\\]|\\.)*)"', block_text)
    if m:
        return m.group(1)
    m = re.search(rf'{re.escape(key)}\s*=\s*(true|false|\d+)', block_text)
    return m.group(1) if m else None

def has_block(block_text, block_name):
    """Return True if a nested block with the given name exists in block_text."""
    return bool(re.search(rf'\b{re.escape(block_name)}\s*\{{', block_text))

def block_body(block_text, block_name):
    """Return the text body of the first occurrence of a named nested block."""
    m = re.search(
        rf'\b{re.escape(block_name)}\s*\{{(.*?)\n\s*\}}',
        block_text, re.DOTALL,
    )
    return m.group(1) if m else None

def ref_scalar(block_text, attr):
    """Extract a google_xxx.yyy resource reference from an attribute value."""
    m = re.search(
        re.escape(attr) + r'\s*=\s*(google_[A-Za-z0-9_]+\.[A-Za-z0-9_]+)',
        block_text,
    )
    return m.group(1) if m else None

def output_names(src):
    """Return the set of output names declared across all .tf files."""
    return set(re.findall(r'output\s+"([A-Za-z0-9_]+)"', src))

def output_ref(src, output_name):
    """Return the full resource reference (e.g. google_pubsub_subscription.scc_sub.name)
    from an output's value attribute."""
    pattern = (
        r'output\s+"' + re.escape(output_name) +
        r'"\s*\{[^}]*?value\s*=\s*(google_[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)'
    )
    m = re.search(pattern, src, re.DOTALL)
    return m.group(1) if m else None

def has_gcs_backend(src):
    """Return True if the terraform block declares a backend "gcs" block."""
    return bool(re.search(r'backend\s+"gcs"\s*\{', src))

def has_variable(src, varname):
    """Return True if `variable "varname"` is declared in the source."""
    return bool(re.search(r'variable\s+"' + re.escape(varname) + r'"\s*\{', src))