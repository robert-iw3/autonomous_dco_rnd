"""Standalone agentic SIEM analysis (WS-J).

Point the swarm at an existing SIEM — no Nexus sensor alert required — and get
an incident report plus a tailored, gated containment course of action, or an
environment-level coverage/gap report. Read-only, fail-open, and every query +
verdict is appended to the tamper-evident verdict ledger.

Modules:
    request           SiemAnalysisRequest — the typed entry contract
    entity_extractor  CIM/ECS result rows -> the swarm's typed entities
    pivot             standalone read-only SIEM pivot (SiemQueryTool guards)
    seed              SIEM hit -> UnifiedAlertSchema-shaped investigation seed
    standalone        the end-to-end analysis run (report + ContainmentProtocol)
    coverage          coverage/gap report + environment profile (sensorless value)
    entry             operator CLI + nexus.siem.analyze consumer
"""
