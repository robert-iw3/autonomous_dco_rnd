# Active-Directory -- Adversarial Corpus Manifest

**MITRE Tactics:** TA0001 (Initial Access), TA0007 (Discovery), TA0004 (Privilege Escalation)
**Source tools:** `arcanaeum/offsec/ttps/Active-Directory/`
**Script:** `stage_active_directory_behavioral.py`
**Pipeline target:** `make stage-ad` / `make data-ad`

---

## Tool Classes (20 total)

### 1_Initial-Access (6 classes)

| Class | Source Tools | Key Signal |
|---|---|---|
| `ADPasswordSprayLDAP` | AD_Sprayer, DomainPasswordSpray | LDAP policy query first + fan-out across UPNs below lockout threshold |
| `ADCSCertAbuse` | certipy (ESC1-ESC16) | LDAP pKICertificateTemplate enum → cert enrollment → PKINIT AS-REQ for privileged account |
| `NTLMPoisoningRelay` | responder | Multi-service rogue listener (HTTP+SMB+LDAP+MSSQL) + NTLMv2 hash capture + relay |
| `TimeroastNTPHash` | timeroast, Invoke-AuthenticatedTimeRoast | NTP to DC: RID sweep, SNTP mode 3/4, MD5 hash extraction from computer/trust accounts |
| `GPORelayInjection` | GPOddity, OUned | NTLM relay → LDAP gPCFileSysPath+gPCMachineExtensionNames write → malicious task XML in SYSVOL |
| `ADWSSOAPEnum` | SoaPy, Invoke-PassTheCert | SOAP/NNS/NMF to port 9389 with custom framing, LDAP write via ADWS |

### 2_Enumeration (7 classes)

| Class | Source Tools | Key Signal |
|---|---|---|
| `LDAPDomainDump` | ldapdomaindump, Invoke-ADEnum | SUBTREE from DC= root, filter=(&(objectClass=*)), attributes=*, off-hours, python UA |
| `DACLACEEnumeration` | dacl_search, Cable | nTSecurityDescriptor attribute on 500-20k objects, dangerous ACE type discovery |
| `BloodHoundCollection` | ShadowHound, bloodhound-automation | 5-9 simultaneous collection methods (ACL+Session+LocalAdmin+Trusts+GPO) |
| `RemoteRegistrySessionEnum` | Invoke-SessionHunter | OpenRemoteRegistry + HKEY_USERS + EnumKeyEx + LookupAccountSid on 10-100 hosts |
| `DCSyncHashExtract` | secretsdump, DCSync-To-Hashcat | IDL_DRSGetNCChanges (MS-DRSR opnum 3) from non-DC source, Event 4662 |
| `UnderlayCopyNTDS` | underlay_copy | Raw device \\.\PhysicalDrive0 access, MFT parsing, SAM+SYSTEM+NTDS.dit extraction without VSS |
| `NRPCUnauthEnum` | nauth_nrpc | MS-NRPC calls at auth-level=1 (no authentication), NetrGetDCName/DsrEnumerateDomainTrusts |

### 3_PrivEsc (7 classes)

| Class | Source Tools | Key Signal |
|---|---|---|
| `KerberosTicketAbuse` | Rubeus | Raw Kerberos port 88 from non-lsass; AS-REP roast / Kerberoast / pass-ticket / golden ticket |
| `TargetedKerberoast` | targetedKerberoast | LDAP write SPN → TGS-REQ RC4 → LDAP delete SPN (anti-forensic 3-step) |
| `ShadowCredentialWrite` | pywhisker, KeyCredentialLink | LDAP write msDS-KeyCredentialLink → self-generated cert → PKINIT AS-REQ → UnPAC-the-Hash |
| `DCShadowReplication` | dcshadow | Non-DC registers rogue DC via Netlogon, AD attribute modification via DRS replication |
| `GPOBackdoor` | GroupPolicyBackdoor, pyGPOAbuse | GPO LDAP modification + malicious task XML written to SYSVOL |
| `DACLPrivEsc` | PowerDACL | nTSecurityDescriptor write granting DCSync/GenericAll/WriteDACL, Event 4662 |
| `BadSuccessorDMSA` | badSuccessor | CreateChild → dMSA computer object → msDS-ManagedAccountPrecededBy → S4U2self+S4U2proxy |
