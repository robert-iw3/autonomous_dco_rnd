"""
Tier-2 parsing helpers for the deploy/ IaC.
"""
import os
import re
import yaml

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

def resource_block(src, rtype, name):
    """Return the body text of `resource "<rtype>" "<name>" { ... }`.

    Matches up to the first column-0 closing brace, which is sufficient for the
    flat, one-resource-per-block style used throughout these deploy stacks.
    """
    m = re.search(
        rf'resource\s+"{re.escape(rtype)}"\s+"{re.escape(name)}"\s*\{{(.*?)\n\}}',
        src, re.DOTALL,
    )
    return m.group(1) if m else None

def iam_policy_statements(src, policy_name):
    """Extract (actions, resource_ref) tuples from a jsonencode()'d
    aws_iam_policy. Returns [] if the policy isn't found.

    actions  -> list like ["sqs:ReceiveMessage", ...]
    resource -> the symbolic terraform ref, e.g. "aws_sqs_queue.flow_logs_queue.arn"
    """
    m = re.search(
        rf'resource\s+"aws_iam_policy"\s+"{re.escape(policy_name)}".*?'
        r'policy\s*=\s*jsonencode\(\{(.*?)\n\s*\}\)',
        src, re.DOTALL,
    )
    if not m:
        return []
    block = m.group(1)
    out = []
    # Tolerant of both single-line ({ Effect = .., Action = [..], Resource = .. })
    # and multi-line statement styles. Resource may be a single value or a list.
    for sm in re.finditer(
        r'Action\s*=\s*\[(.*?)\]'           # Action list
        r'[\s,]*Resource\s*=\s*'            # ... up to Resource
        r'(\[[^\]]*\]|"[^"]*"|[^\s,}]+)',   # list | quoted string | bareword ref
        block, re.DOTALL,
    ):
        # Concrete actions, service wildcards ("s3:*"), and bare "*" -- wildcards
        # MUST stay visible to the drift guard.
        actions = re.findall(r'"([a-zA-Z0-9]+:[A-Za-z*]+|\*)"', sm.group(1))
        raw = sm.group(2).strip()
        if raw.startswith("["):
            resources = [
                r.strip().strip('"')
                for r in re.findall(r'("[^"]*"|[A-Za-z0-9_][\w.${}/*-]*)', raw)
            ]
        else:
            resources = [raw.strip('"')]
        out.append((actions, resources))
    return out

def iam_allowed_actions(src, policy_name):
    """Flat set of every Allow-ed action across all statements."""
    return {a for actions, _ in iam_policy_statements(src, policy_name) for a in actions}

def scalar(block_text, key):
    """Read a `key = "value"` or `key = bareword` scalar out of a block body."""
    m = re.search(rf'{re.escape(key)}\s*=\s*"([^"]+)"', block_text)
    if m:
        return m.group(1)
    m = re.search(rf'{re.escape(key)}\s*=\s*(true|false|\d+)', block_text)
    return m.group(1) if m else None

# ---------------------------------------------------------------------------
# CloudFormation (.yaml) parsing -- intrinsic-function aware
# ---------------------------------------------------------------------------

class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation short-form intrinsics
    (!Ref, !Sub, !GetAtt, !NoValue, ...) instead of dying on the unknown tag.
    Each !Tag value becomes {"Tag": value} so the document loads losslessly
    enough for structural assertions."""

def _cfn_multi(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node)}
    return {tag_suffix: loader.construct_mapping(node)}

_CfnLoader.add_multi_constructor("!", _cfn_multi)

def load_cfn(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=_CfnLoader)

def cfn_resources_of_type(doc, cfn_type):
    """Return {logical_id: properties} for every resource of a given Type."""
    out = {}
    for logical_id, res in (doc.get("Resources") or {}).items():
        if res.get("Type") == cfn_type:
            out[logical_id] = res.get("Properties", {})
    return out

# ---------------------------------------------------------------------------
# Type-based discovery (name-independent) -- added so tier2 generalizes across
# the three *heterogeneous* deploy stacks (vpc/cloudtrail/guardduty use
# different resource names, buckets, queues, tables, and source formats).
# ---------------------------------------------------------------------------

def iter_resources(src, rtype):
    """Yield (name, body) for every `resource "<rtype>" "<name>" { ... }`."""
    for m in re.finditer(
        rf'resource\s+"{re.escape(rtype)}"\s+"([A-Za-z0-9_]+)"\s*\{{(.*?)\n\}}',
        src, re.DOTALL,
    ):
        yield m.group(1), m.group(2)

def resource_addresses(src):
    """Set of every defined `rtype.name` address in the stack (for verifying
    IAM statements are scoped to resources this stack actually owns)."""
    return {
        f"{rt}.{name}"
        for rt, name in re.findall(
            r'resource\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_]+)"', src
        )
    }

def ref_to_address(resource_ref):
    """Reduce an IAM Resource expression to its `rtype.name` address.
    'aws_sqs_queue.q.arn' -> 'aws_sqs_queue.q'
    '${aws_s3_bucket.b.arn}/*' -> 'aws_s3_bucket.b'
    Returns None for '*' or unrecognised shapes."""
    if resource_ref == "*":
        return None
    cleaned = resource_ref.strip().lstrip("${").rstrip("}")
    m = re.match(r'(aws_[A-Za-z0-9_]+\.[A-Za-z0-9_]+)', cleaned)
    return m.group(1) if m else None

def s3_notification_suffix(src):
    """The first filter_suffix on any aws_s3_bucket_notification, or None."""
    for _name, body in iter_resources(src, "aws_s3_bucket_notification"):
        s = scalar(body, "filter_suffix")
        if s:
            return s
    return None