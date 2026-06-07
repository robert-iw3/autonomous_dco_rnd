"""
stage_tools_supplemental.py -- RETIRED STUB (2026-06-05)

All tool function pairs and TOOL_CLASSES entries have been migrated to their
respective category scripts:

  BypassDetection  → stage_bypass_behavioral.py
                     (PoolPartyInjection, EDRLogWipe, ProcessImpersonationEDR,
                      EDRStartupHinder, SignatureStealer)

  C2               → stage_c2_behavioral.py
                     (HVNCHiddenDesktop, HoaxShellWebC2, FilelessMemLoader,
                      DeserializationRCE, DarkWidowC2)

  LateralMovement  → stage_lateral_movement_behavioral.py
                     (MSSQLLateral, EntraTokenHijack, PAExecLateral,
                      SCCMHunterLateral)

  Recon            → stage_recon_behavioral.py
                     (GraphAPIEnumeration, MFABypassEnum, ExchangeEmailRecon,
                      SharePointCredSearch)

  Persistence      → stage_persistence_behavioral.py
                     (AzureDevOpsPersistence, VMkatzHypervisorDump,
                      NanodumpLSASS, DPAPISecretExtract)

  Exfiltration     → stage_exfiltration_behavioral.py
                     (MetadataStripExfil)

  WindowsExploit   → stage_windows_exploitation_behavioral.py
                     (ASPNETViewStateRCE, DNSAPIDLLProxyHijack)

This file is retained as a stub so existing imports do not crash.
"""

import sys
import logging

logger = logging.getLogger(__name__)

TOOL_CLASSES: dict = {}
S3_QUERIES: dict   = {}


def main() -> None:
    if not TOOL_CLASSES:
        logger.info(
            "stage_tools_supplemental: no classes registered -- "
            "all content migrated to category scripts. Nothing to do."
        )
        sys.exit(0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
