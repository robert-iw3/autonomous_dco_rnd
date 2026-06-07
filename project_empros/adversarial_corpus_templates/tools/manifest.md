# tools/ -- Supplemental Corpus Manifest

**Source tools:** `arcanaeum/offsec/ttps/tools/`
**Script:** `stage_tools_supplemental.py`
**Status:** RETIRED STUB (2026-06-05) -- all classes migrated to category scripts

All 24 tool function pairs and their TOOL_CLASSES / S3_QUERIES entries have been
migrated from `stage_tools_supplemental.py` into their respective category scripts.
`stage_tools_supplemental.py` is now an empty stub (`TOOL_CLASSES = {}`) that exits
gracefully if called directly.

## Migration Map

| Class | Destination Script |
|---|---|
| `PoolPartyInjection` | `stage_bypass_behavioral.py` |
| `EDRLogWipe` | `stage_bypass_behavioral.py` |
| `ProcessImpersonationEDR` | `stage_bypass_behavioral.py` |
| `EDRStartupHinder` | `stage_bypass_behavioral.py` |
| `SignatureStealer` | `stage_bypass_behavioral.py` |
| `HVNCHiddenDesktop` | `stage_c2_behavioral.py` |
| `HoaxShellWebC2` | `stage_c2_behavioral.py` |
| `FilelessMemLoader` | `stage_c2_behavioral.py` |
| `DeserializationRCE` | `stage_c2_behavioral.py` |
| `DarkWidowC2` | `stage_c2_behavioral.py` |
| `MSSQLLateral` | `stage_lateral_movement_behavioral.py` |
| `EntraTokenHijack` | `stage_lateral_movement_behavioral.py` |
| `PAExecLateral` | `stage_lateral_movement_behavioral.py` |
| `SCCMHunterLateral` | `stage_lateral_movement_behavioral.py` |
| `GraphAPIEnumeration` | `stage_recon_behavioral.py` |
| `MFABypassEnum` | `stage_recon_behavioral.py` |
| `ExchangeEmailRecon` | `stage_recon_behavioral.py` |
| `SharePointCredSearch` | `stage_recon_behavioral.py` |
| `AzureDevOpsPersistence` | `stage_persistence_behavioral.py` |
| `VMkatzHypervisorDump` | `stage_persistence_behavioral.py` |
| `NanodumpLSASS` | `stage_persistence_behavioral.py` |
| `DPAPISecretExtract` | `stage_persistence_behavioral.py` |
| `MetadataStripExfil` | `stage_exfiltration_behavioral.py` |
| `ASPNETViewStateRCE` | `stage_windows_exploitation_behavioral.py` |
| `DNSAPIDLLProxyHijack` (new) | `stage_windows_exploitation_behavioral.py` |
