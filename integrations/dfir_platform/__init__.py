"""
The boundary with the DFIR platform.

The platform collects, seals, stores and adjudicates memory evidence; this stack consumes
what that produces and does none of it. Everything crossing that line is described by
[PROJECTION-CONTRACT.md](PROJECTION-CONTRACT.md) and enforced by `contract`.

The package name is the same here and inside the worker image, so an import reads the same
in a test and in production.
"""
from dfir_platform.contract import (  # noqa: F401
    CONTRACT,
    VERSION,
    VERDICTS,
    ProjectionError,
    accept,
    bundle_id,
    canonical,
    decode,
    descriptor,
    seal_value,
    to_status,
    to_toolkit_findings,
    validate,
    verify_seal,
)
from dfir_platform.transport import (  # noqa: F401
    DirectorySource,
    DispatcherSource,
    TransportError,
    from_env,
)

__all__ = [
    "CONTRACT", "VERSION", "VERDICTS", "ProjectionError",
    "accept", "bundle_id", "canonical", "decode", "descriptor", "seal_value",
    "to_status", "to_toolkit_findings", "validate", "verify_seal",
    "DirectorySource", "DispatcherSource", "TransportError", "from_env",
]
