"""
SiemAnalysisRequest — the typed contract every standalone analysis starts from.

An operator, an API call, a schedule, or a detection hit hands the swarm one of
these; nothing else enters the standalone path. Credentials are referenced
(vault path), never embedded. The query itself is validated read-only + bounded
by the pivot runner, not here — the schema only pins shape and provenance.

Pure stdlib + pydantic so it is unit-tested deterministically.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field, model_validator

# Dialects the pivot runner can execute today (mirrors tools/siem_query adapters);
# the future backends degrade to an honest SIEM_BACKEND_NOT_IMPLEMENTED signal.
SUPPORTED_DIALECTS = ("spl", "esql", "kql")

# The product/logsource of the detection decides which canonical source_type the
# synthesized seed carries, so routing and containment reuse the existing maps
# (an unknown product falls back to the generic qdrant_vector class).
PRODUCT_SOURCE_TYPE = {
    "windows": "sysmon_sensor",
    "linux": "linux_sentinel",
    "macos": "macos_sensor",
    "aws": "aws_cloudtrail",
    "azure": "azure_activity",
    "gcp": "gcp_audit",
    "m365": "azure_entraid",
    "identity": "azure_entraid",
    "network": "suricata_eve",
}


class SiemAnalysisRequest(BaseModel):
    """One standalone SIEM analysis: which SIEM, what to run, and how bounded."""

    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    requested_at: float = Field(default_factory=time.time)

    backend: str = Field(description="Configured SIEM backend name, e.g. 'splunk' or 'elastic'.")
    dialect: Literal["spl", "esql", "kql"] = Field(
        description="Query dialect of the backend (SPL / ES|QL / KQL-on-ES).")

    # Exactly one of: a native read-only query, or a detection id resolved
    # against the backend's saved detections.
    query: str = Field(default="", description="Native read-only query to run.")
    detection_id: str = Field(default="", description="Saved detection to run instead of a raw query.")

    detection_name: str = Field(default="", description="Human name for the report header.")
    product: str = Field(default="", description="Detection logsource product (windows/linux/aws/...).")

    window_hours: int = Field(default=24, ge=1, le=720,
                              description="Time window the pivot enforces on the query.")
    max_rows: int = Field(default=200, ge=1, le=5000,
                          description="Row cap the pivot enforces on the query.")
    scope_indexes: list = Field(default_factory=list,
                                description="Optional narrowing of the backend's index allowlist.")

    read_creds_ref: str = Field(default="",
                                description="Vault reference for read credentials — never the secret itself.")

    entry_point: Literal["operator", "api", "detection", "schedule"] = "operator"
    requested_by: str = Field(default="", description="Operator/service identity for the audit trail.")

    include_coverage_report: bool = Field(
        default=False, description="Also produce the coverage/gap + environment profile artifacts.")

    context: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _query_or_detection(self):
        if bool(self.query.strip()) == bool(self.detection_id.strip()):
            raise ValueError("exactly one of 'query' or 'detection_id' is required")
        return self

    def source_type(self) -> str:
        """Canonical seed source_type for this detection's product."""
        return PRODUCT_SOURCE_TYPE.get(self.product.strip().lower(), "qdrant_vector")
