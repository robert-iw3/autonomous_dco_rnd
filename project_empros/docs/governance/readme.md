# GRC-as-Code Documentation — Sentinel Nexus

> [!NOTE]
>
> This initial assessment will be followed by a thorough analysis once codebase changes,
> testing, and validation are complete. Just as testing is mandatory before production,
> so is the GRC assessment. This process saves time and effort in maintaining risk management
> documentation while ensuring continuous control monitoring throughout the development cycle.
> Please note that the assessment tooling is also in active development and will improve in parallel.

Governance artifacts for the platform's NIST AI 600-1 (GenAI Profile),
NIST CSF 2.0, and SP 800-53 posture. Each document is authored in Markdown and built to
**PDF** with `./build_pdfs.sh` (pandoc + xelatex).

## Single source of truth — the controls manifest

Machine-readable inputs drive the generated docs:

- **`controls_manifest.yaml`** — every control once, with its implementing module, proving
  tests, and its mappings across **all** the disparate taxonomies (OWASP Top 10 for LLM,
  MITRE ATLAS, NIST AI 600-1, NIST SP 800-53 Rev. 5, NIST CSF 2.0).
- **`frameworks_reference.yaml`** — the OWASP / ATLAS enumerations with applicability +
  remediation, used to compute coverage vs. gaps.
- **`_oscal_sp800-53_rev5.json`** — authoritative SP 800-53 control titles cached from
  [NIST OSCAL v1.4.0](https://github.com/usnistgov/oscal-content/tree/v1.4.0/src/nist.gov/SP800-53/rev5/xml)
  (offline; every `sp_800_53` reference is validated against it).
- **`_oscal_csf_v2.0.json`** — authoritative NIST CSF 2.0 functions/categories/subcategories
  cached from [NIST OSCAL v1.4.0](https://github.com/usnistgov/oscal-content/blob/v1.4.0/src/nist.gov/CSF/v2.0/xml/NIST_CSF_v2.0_catalog.xml)
  (6 functions · 22 categories · 103 active subcategories; withdrawn v1.1 items filtered).
- **`csf_category_map.yaml`** — control → CSF 2.0 *category* mapping (validated against the
  catalog), used for the function/category coverage self-assessment.
- **`evidence_map.yaml`** — control → *actual source* (`file` + unique `anchor`), from which
  `gen_evidence.py` extracts the proving code (cited `file:line`).

`gen_governance.py` renders `controls_catalog.md` (consolidated, cross-correlated catalog)
and `applicability_matrix.md` (what is **Covered / a GAP / N-A** per framework, plus the
**CSF 2.0 function & category coverage** view). `gen_evidence.py` renders the **Control
Evidence Dossier** (`control_evidence.md` → PDF) and per-control `artifacts/<ID>.md`
snippets, and refreshes **Annex B** of the System Security Plan.

**Workflow to keep docs current:** edit `controls_manifest.yaml` (and, as needed,
`frameworks_reference.yaml` / `csf_category_map.yaml` / `evidence_map.yaml`) →
run `./gen_governance.py && ./gen_evidence.py` → run `./build_pdfs.sh`. CI enforces this:
`tests/lab_analytics_hunter/test_governance_manifest.py` (26 tests) fails if a generated doc
is stale, if a control references a missing implementation/test path, if an SP 800-53 /
CSF 2.0 reference is not a real OSCAL control, or if a cited code-evidence anchor no longer
resolves.

```bash
./gen_governance.py          # regenerate catalog + applicability matrix from the manifest
./gen_evidence.py            # extract code-evidence dossier + artifacts/ + SSP Annex B
./gen_governance.py --check  # CI: exit 1 if a generated doc is out of sync
./gen_evidence.py --check    # CI: exit 1 if an evidence artifact is stale / anchor moved
./build_pdfs.sh              # regenerate everything + rebuild every PDF
```

## Documents

| Document | PDF | Addresses |
|---|---|---|
| **Control Catalog** (generated) | `controls_catalog.pdf` | Consolidated cross-correlation: OWASP · ATLAS · AI 600-1 · 800-53 · CSF (incl. CSF 2.0 category cross-ref) |
| **Applicability & Gap Matrix** (generated) | `applicability_matrix.pdf` | Covered / GAP / N-A per framework; CSF 2.0 function & category coverage; outstanding addressable gaps + remediation |
| **Control Evidence Dossier** (generated) | `control_evidence.pdf` | The *actual source code* answering each control, extracted + cited `file:line` (per-control under `artifacts/`) |
| System Security Plan | `system_security_plan.pdf` | SP 800-53 families · CSF 2.0 functions · AI RMF; IaC hardening; secure ingestion/transmission path; **Annex B** code-evidence index |
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
