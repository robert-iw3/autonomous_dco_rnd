# GRC as Code Documentation — Sentinel Nexus

Professional governance artifacts for the platform's NIST AI 600-1 (GenAI Profile),
NIST CSF 2.0, and SP 800-53 posture. Each document is authored in Markdown and built to
**PDF** with `./build_pdfs.sh` (pandoc + xelatex). Regenerate the PDFs after editing any
source.

| Document | PDF | Addresses |
|---|---|---|
| System Security Plan | `system_security_plan.pdf` | SP 800-53 families · CSF 2.0 functions · AI RMF; IaC hardening; secure ingestion/transmission path |
| AI System Inventory | `ai_system_inventory.pdf` | GV-1.6 (Models A–D + swarm + frontier) |
| GAI Risk-Tier Statement | `gai_risk_tier_statement.pdf` | GV-1.3 (Tier 1 — autonomous/consequential) |
| AI Incident Response Plan + After-Action template | `ai_incident_response_plan.pdf` | GV-1.5-002, MG-4.3, GV-4.3-002 |
| Applicability Determinations | `applicability_determinations.pdf` | GV-1.3-003 (CBRN/CSAM/violent/IP = N-A) |
| Data Retention & Decommissioning Policy | `data_retention_decommission_policy.pdf` | GV-1.7-002, MS-2.10-001 (NC-4) |
| Environmental Impact Estimate | `environmental_impact_estimate.pdf` | MS-2.12 (NC-6) |

**Authoritative, test-linked control status:** `../nist_ai_600_1_control_tracker.md` and
`../security_controls.md`. These governance docs are the human-readable policy layer;
the tracker is the implementation-status layer (with proving tests).

## Building

```bash
./build_pdfs.sh    # rebuilds every *.pdf from its *.md
```
