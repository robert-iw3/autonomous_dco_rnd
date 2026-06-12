# GRC-as-Code Documentation — Sentinel Nexus

Professional governance artifacts for the platform's NIST AI 600-1 (GenAI Profile),
NIST CSF 2.0, and SP 800-53 posture. Each document is authored in Markdown and built to
**PDF** with `./build_pdfs.sh` (pandoc + xelatex).

## Single source of truth — the controls manifest

Three machine-readable inputs drive the generated docs:

- **`controls_manifest.yaml`** — every control once, with its implementing module, proving
  tests, and its mappings across **all** the disparate taxonomies (OWASP Top 10 for LLM,
  MITRE ATLAS, NIST AI 600-1, NIST SP 800-53 Rev. 5, NIST CSF 2.0).
- **`frameworks_reference.yaml`** — the OWASP / ATLAS enumerations with applicability +
  remediation, used to compute coverage vs. gaps.
- **`_oscal_sp800-53_rev5.json`** — authoritative SP 800-53 control titles cached from
  [NIST OSCAL v1.4.0](https://github.com/usnistgov/oscal-content/tree/v1.4.0/src/nist.gov/SP800-53/rev5/xml)
  (offline; every `sp_800_53` reference is validated against it).

`gen_governance.py` renders two generated docs from these:
`controls_catalog.md` (consolidated, cross-correlated catalog) and `applicability_matrix.md`
(what is **Covered / a GAP / N-A**, per framework, with remediation for gaps).

**Workflow to keep docs current:** edit `controls_manifest.yaml` (and, for a new framework
item, `frameworks_reference.yaml`) → run `./gen_governance.py` → run `./build_pdfs.sh`. CI
enforces this: `tests/lab_analytics_hunter/test_governance_manifest.py` (15 tests) fails if
a generated doc is stale, if a control references a missing implementation/test path, or if
an SP 800-53 reference is not a real OSCAL rev5 control.

```bash
./gen_governance.py          # regenerate controls_catalog.md from the manifest
./gen_governance.py --check  # CI: exit 1 if the catalog is out of sync
./build_pdfs.sh              # regenerate the catalog + rebuild every PDF
```

## Documents

| Document | PDF | Addresses |
|---|---|---|
| **Control Catalog** (generated) | `controls_catalog.pdf` | Consolidated cross-correlation: OWASP · ATLAS · AI 600-1 · 800-53 · CSF |
| **Applicability & Gap Matrix** (generated) | `applicability_matrix.pdf` | Covered / GAP / N-A per framework; outstanding addressable gaps + remediation |
| System Security Plan | `system_security_plan.pdf` | SP 800-53 families · CSF 2.0 functions · AI RMF; IaC hardening; secure ingestion/transmission path |
| AI System Inventory | `ai_system_inventory.pdf` | GV-1.6 (Models A–D + swarm + frontier) |
| GAI Risk-Tier Statement | `gai_risk_tier_statement.pdf` | GV-1.3 (Tier 1 — autonomous/consequential) |
| AI Incident Response Plan + After-Action template | `ai_incident_response_plan.pdf` | GV-1.5-002, MG-4.3, GV-4.3-002 |
| Applicability Determinations | `applicability_determinations.pdf` | GV-1.3-003 (CBRN/CSAM/violent/IP = N-A) |
| Data Retention & Decommissioning Policy | `data_retention_decommission_policy.pdf` | GV-1.7-002, MS-2.10-001 (NC-4) |
| Environmental Impact Estimate | `environmental_impact_estimate.pdf` | MS-2.12 (NC-6) |

**Authoritative, test-linked control status:** `../nist_ai_600_1_control_tracker.md` and
`../security_controls.md`. These governance docs are the human-readable policy layer; the
manifest + catalog are the consolidated control register; the tracker is the AI-control
implementation-status layer (with proving tests).
