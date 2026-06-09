"""
Tier-2 parsing helpers for Azure deploy/ IaC.
"""
import os
import re

# ---------------------------------------------------------------------------
# Terraform (.tf) text extraction
# ---------------------------------------------------------------------------

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

    Matches up to the first column-0 closing brace, which is sufficient for
    the indented HCL style used throughout these deploy stacks.
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
    """Read a `key = "value"` or `key = bareword` scalar out of block text."""
    m = re.search(rf'{re.escape(key)}\s*=\s*"([^"]+)"', block_text)
    if m:
        return m.group(1)
    m = re.search(rf'{re.escape(key)}\s*=\s*(true|false|\d+)', block_text)
    return m.group(1) if m else None

# ---------------------------------------------------------------------------
# Azure-specific extraction helpers
# ---------------------------------------------------------------------------

def diagnostic_log_categories(src, resource_type):
    """Return the set of enabled_log category values for resources of a given type.

    Works for both azurerm_monitor_diagnostic_setting (activity) and
    azurerm_monitor_aad_diagnostic_setting (entraid).
    """
    categories = set()
    for _name, body in iter_resources(src, resource_type):
        for cat in re.findall(
            r'enabled_log\s*\{[^}]*?category\s*=\s*"([^"]+)"',
            body, re.DOTALL,
        ):
            categories.add(cat)
    return categories

def auth_rule_scalar(src, tf_resource_name, flag):
    """Return the boolean scalar for a named azurerm_eventhub_authorization_rule.

    tf_resource_name is the Terraform resource label (e.g. "listen", "send").
    flag is one of "listen", "send", "manage".
    Returns the string "true"/"false" or None if not found.
    """
    for name, body in iter_resources(src, "azurerm_eventhub_authorization_rule"):
        if name == tf_resource_name:
            return scalar(body, flag)
    return None

def ref_scalar(block_text, attr):
    """Extract the resource address (rtype.name) from a Terraform reference attribute.

    Given a block body containing:
        eventhub_authorization_rule_id = azurerm_eventhub_authorization_rule.send.id
    ref_scalar(body, "eventhub_authorization_rule_id")
        -> "azurerm_eventhub_authorization_rule.send"

    Returns None if the attribute is absent or is not a recognised azurerm reference.
    """
    m = re.search(
        re.escape(attr) + r'\s*=\s*(azurerm_[A-Za-z0-9_]+\.[A-Za-z0-9_]+)',
        block_text,
    )
    return m.group(1) if m else None

def output_names(src):
    """Return the set of output names declared across all .tf files."""
    return set(re.findall(r'output\s+"([A-Za-z0-9_]+)"', src))

def output_ref(src, output_name):
    """Return the resource address referenced by an output's value attribute.

    output "eventhub_connection_string" {
      value = azurerm_eventhub_authorization_rule.listen.primary_connection_string
    }
    output_ref(src, "eventhub_connection_string")
        -> "azurerm_eventhub_authorization_rule.listen"
    """
    pattern = (
        r'output\s+"' + re.escape(output_name) +
        r'"\s*\{[^}]*?value\s*=\s*(azurerm_[A-Za-z0-9_]+\.[A-Za-z0-9_]+)'
    )
    m = re.search(pattern, src, re.DOTALL)
    return m.group(1) if m else None