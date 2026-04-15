# Phase 2 — Windows Server 2022 CIS Level 1 Hardening

**Benchmark:** CIS Microsoft Windows Server 2022 Benchmark v5.0.0 (February 18, 2026)  
**Scope:** Windows Server 2022 Domain Controller — `soc-lab.local` (`10.0.10.10`)  
**Implementation period:** April 8–12, 2026  
**Controls applied:** ~393 across CIS Sections 1, 2.2, 2.3, 9, 17, and 18  
**Deferred (risk-accepted):** 6 | **Not present / N/A:** ~41  
**Primary deliverable:** [Phase2-CIS-Hardening-Changelog.docx](https://github.com/user-attachments/files/26753058/Phase2-CIS-Hardening-Changelog-v2.docx)


---

## Contents

- [Architecture note — GPO routing](#architecture-note--gpo-routing)
- [Implementation tooling](#implementation-tooling)
- [Baseline documentation package](#baseline-documentation-package)
- [Section 1 — Account Policies](#section-1--account-policies)
- [Section 2.2 — User Rights Assignment](#section-22--user-rights-assignment)
- [Section 2.3 — Security Options](#section-23--security-options)
- [Section 9 — Windows Defender Firewall with Advanced Security](#section-9--windows-defender-firewall-with-advanced-security)
- [Section 17 — Advanced Audit Policy Configuration](#section-17--advanced-audit-policy-configuration)
- [Section 18 — Administrative Templates (Computer)](#section-18--administrative-templates-computer)
- [Post-hardening verification](#post-hardening-verification)
- [Post-hardening incident](#post-hardening-incident)
- [Deferred controls](#deferred-controls)
- [MITRE ATT&CK coverage](#mitre-attck-coverage)
- [Phase 2 control summary](#phase-2-control-summary)

---

## Architecture note — GPO routing

This DC requires split GPO routing. Applying controls to the wrong GPO causes silent failure — the correct domain GPO overwrites local policy on every `gpupdate` cycle. `secedit` is unreliable on a DC for exactly this reason.

| GPO | Scope | CIS sections |
|---|---|---|
| Default Domain Policy | Entire domain (`soc-lab.local`) | Section 1 — Account Policies |
| Default Domain Controllers Policy (DDCP) | Domain Controllers OU only | Sections 2.2, 2.3, 9, 17, 18 |

**Verification:**
- Account Policies: `Get-ADDefaultDomainPasswordPolicy`
- All other sections: `gpresult /H C:\CIS-Hardening\gpresult.html /F`

---

## Implementation tooling

| Tool | Disposition | Reason |
|---|---|---|
| GPMC (`gpmc.msc`) | **Used — primary** | Authoritative for DC; domain policy enforces on every gpupdate |
| Microsoft Security Compliance Toolkit (SCT) | **Used** | Source for `SecGuide.admx` and `MSS-legacy.admx` template deployment |
| Policy Analyzer | **Used** | `.PolicyRules` baseline snapshots (Day 1 and Day 2) |
| `Get-ADDefaultDomainPasswordPolicy` | **Used** | Section 1 account policy verification |
| `gpresult /H` | **Used** | All other section verification; winning GPO confirmed |
| `secedit` | **Rejected** | Local security database only; overwritten by domain policy on every gpupdate |
| `gpedit.msc` | **Rejected** | Local GPO editor; fields greyed out on DC |
| SCAP Workbench | **Rejected** | Archived September 2024; local scan target unavailable on Windows |

---

## Baseline documentation package

All files stored at `~/Documents/lab-baselines/windows-server/` on the Linux Mint admin workstation and committed to [`baselines/`](./baselines/).

| File | Type | Description |
|---|---|---|
| `baseline-firewall.csv` | Before | Pre-hardening Windows Firewall rule state |
| `baseline-security.cfg` | Before | Pre-hardening secedit security policy export |
| `baseline-services.csv` | Before | Pre-hardening services inventory |
| `WS2022-Baseline.PolicyRules` | Before | Microsoft SCT baseline for Policy Analyzer |
| `EffectiveState.PolicyRules (20260408)` | Snapshot | Day 1 Policy Analyzer snapshot |
| `EffectiveState.PolicyRules (20260409)` | Snapshot | Day 2 Policy Analyzer snapshot |
| `admin-lockout-check.cfg` | Verification | Built-in Administrator lockout verification export |
| `userrights-check.cfg` | Verification | User Rights Assignment verification export |
| `final-password-policy.txt` | After | `Get-ADDefaultDomainPasswordPolicy` final output |
| `final-services.csv` | After | Post-hardening services inventory |
| `final-security.cfg` | After | Post-hardening secedit export |
| `current-security.cfg` | After | Current secedit state snapshot |
| `dcdiag-results.txt` | Verification | Post-hardening DC health check output |
| `gpresult-final.html` | Verification | Final Group Policy Results report |

---

## Section 1 — Account Policies

**GPO:** Default Domain Policy  
**Verified via:** `Get-ADDefaultDomainPasswordPolicy`  
**Applied:** April 8, 2026

### 1.1 — Password Policy (7 controls applied, 0 deferred)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 1.1.1 Enforce Password History | 24 or more passwords | 24 | 24 — Compliant prior, enforced for documentation |
| 1.1.2 Maximum Password Age | 365 or fewer days, not 0 | 42 days | 365 days — Adjusted to CIS maximum |
| 1.1.3 Minimum Password Age | 1 or more day | 1 day | 1 day — Compliant prior |
| 1.1.4 Minimum Password Length | 14 or more characters | 7 characters | 14 — **Non-compliant remediated** |
| 1.1.5 Password Must Meet Complexity Requirements | Enabled | Enabled | Compliant prior |
| 1.1.6 Relax Minimum Password Length Limits | Enabled | Not configured | Applied — Enabled |
| 1.1.7 Store Passwords Using Reversible Encryption | Disabled | Disabled | Compliant prior |

### 1.2 — Account Lockout Policy (4 controls applied, 1 N/A)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 1.2.1 Account Lockout Duration | 15 or more minutes | 30 minutes | 30 minutes — Compliant prior |
| 1.2.2 Account Lockout Threshold | 5 or fewer, not 0 | 0 (disabled) | 5 — **Non-compliant remediated** |
| 1.2.3 Allow Administrator Account Lockout | Enabled (MS only) | N/A | **Not applicable — DC profile exemption.** CIS v5.0.0 specifies Member Server only; DC exclusion documented |
| 1.2.4 Reset Account Lockout Counter After | 15 or more minutes | 30 minutes | 30 minutes — Compliant prior |

---

## Section 2.2 — User Rights Assignment

**GPO:** Default Domain Controllers Policy  
**Verified via:** `gpresult /H` (Winning GPO: Default Domain Controllers Policy confirmed)  
**Applied:** April 8–9, 2026  
**Controls applied:** 37 | **Deferred:** 0 | **Not applicable:** 0

> **Orphaned SID note:** `S-1-5-0` was found in `SeInteractiveLogonRight` (Allow Log On Locally). The SID was unresolvable — translation returned "Some or all identity references could not be translated." Safely removed as part of remediation.

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.2.1 Access Credential Manager as Trusted Caller | Empty | Empty | Compliant — confirmed |
| 2.2.2 Access This Computer From the Network | Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS | Everyone, Authenticated Users, Administrators, Pre-Windows 2000 Compatible Access, ENTERPRISE DOMAIN CONTROLLERS | **Non-compliant remediated** — Removed: Everyone, Pre-Windows 2000 Compatible Access |
| 2.2.3 Act as Part of the Operating System | Empty | Empty | Compliant — confirmed |
| 2.2.4 Add Workstations to Domain | Administrators | Authenticated Users | **Non-compliant remediated** — Removed: Authenticated Users |
| 2.2.5 Adjust Memory Quotas for a Process | Administrators, LOCAL SERVICE, NETWORK SERVICE | Administrators, LOCAL SERVICE, NETWORK SERVICE | Compliant — confirmed |
| 2.2.6 Allow Log On Locally | Administrators | Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, ENTERPRISE DOMAIN CONTROLLERS, S-1-5-0 | **Non-compliant remediated** — Removed all non-Administrator entries including orphaned SID |
| 2.2.7 Allow Log On Through Remote Desktop Services | Administrators | Administrators | Compliant — confirmed |
| 2.2.8 Back Up Files and Directories | Administrators | Administrators | Compliant — confirmed |
| 2.2.9 Bypass Traverse Checking | Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS, LOCAL SERVICE, NETWORK SERVICE, Pre-Windows 2000 Compatible Access | Matches | Compliant — confirmed |
| 2.2.10 Change the System Time | Administrators, LOCAL SERVICE | Administrators, LOCAL SERVICE | Compliant — confirmed |
| 2.2.11 Change the Time Zone | Administrators, LOCAL SERVICE | Administrators, LOCAL SERVICE | Compliant — confirmed |
| 2.2.12 Create a Pagefile | Administrators | Administrators | Compliant — confirmed |
| 2.2.13 Create a Token Object | Empty | Empty | Compliant — confirmed |
| 2.2.14 Create Global Objects | Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE | Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE | Compliant — confirmed |
| 2.2.15 Create Permanent Shared Objects | Empty | Empty | Compliant — confirmed |
| 2.2.16 Create Symbolic Links | Administrators | Administrators | Compliant — confirmed |
| 2.2.17 Debug Programs | Administrators | Administrators | Compliant — confirmed |
| 2.2.18 Deny Access to This Computer From the Network | Guests, Local Account | Guests, Local Account | Compliant — confirmed |
| 2.2.19 Deny Log On as a Batch Job | Guests | Guests | Compliant — confirmed |
| 2.2.20 Deny Log On as a Service | Guests | Guests | Compliant — confirmed |
| 2.2.21 Deny Log On Locally | Guests | Guests | Compliant — confirmed |
| 2.2.22 Deny Log On Through Remote Desktop Services | Guests | Guests | Compliant — confirmed |
| 2.2.23 Enable Computer and User Accounts to Be Trusted for Delegation | Administrators | Administrators | Compliant — confirmed |
| 2.2.24 Force Shutdown From a Remote System | Administrators | Administrators | Compliant — confirmed |
| 2.2.25 Generate Security Audits | LOCAL SERVICE, NETWORK SERVICE | LOCAL SERVICE, NETWORK SERVICE | Compliant — confirmed |
| 2.2.26 Impersonate a Client After Authentication | Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE | Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE | Compliant — confirmed |
| 2.2.27 Increase a Process Working Set | Administrators, LOCAL SERVICE | Administrators, LOCAL SERVICE | Compliant — confirmed |
| 2.2.28 Increase Scheduling Priority | Administrators, Window Manager\Window Manager Group | Administrators, Window Manager\Window Manager Group | Compliant — confirmed |
| 2.2.29 Load and Unload Device Drivers | Administrators | Administrators | Compliant — confirmed |
| 2.2.30 Lock Pages in Memory | Empty | Empty | Compliant — confirmed |
| 2.2.31 Log On as a Batch Job | Administrators, Backup Operators, Performance Log Users | Administrators, Backup Operators, Performance Log Users | Compliant — confirmed |
| 2.2.32 Log On as a Service | NETWORK SERVICE | NETWORK SERVICE | Compliant — confirmed |
| 2.2.33 Manage Auditing and Security Log | Administrators | Administrators | Compliant — confirmed |
| 2.2.34 Modify Firmware Environment Values | Administrators | Administrators | Compliant — confirmed |
| 2.2.35 Obtain an Impersonation Token for Another User in the Same Session | Empty | Empty | Compliant — confirmed |
| 2.2.36 Perform Volume Maintenance Tasks | Administrators | Administrators | Compliant — confirmed |
| 2.2.37 Profile Single Process | Administrators | Administrators | Compliant — confirmed |
| 2.2.38 Profile System Performance | Administrators, NT SERVICE\WdiServiceHost | Administrators, NT SERVICE\WdiServiceHost | Compliant — confirmed |
| 2.2.39 Remove Computer From Docking Station | Administrators | Administrators | Compliant — physically irrelevant to VM; included for compliance scoring consistency |
| 2.2.40 Replace a Process Level Token | LOCAL SERVICE, NETWORK SERVICE | LOCAL SERVICE, NETWORK SERVICE | Compliant — confirmed |
| 2.2.41 Restore Files and Directories | Administrators | Administrators | Compliant — confirmed |
| 2.2.42 Shut Down the System | Administrators | Administrators | Compliant — confirmed |
| 2.2.43 Synchronize Directory Service Data | Empty | Empty | Compliant — confirmed. **Critical DCSync attack prevention. MITRE T1003.006.** |
| 2.2.44 Take Ownership of Files or Other Objects | Administrators | Administrators | Compliant — confirmed |

---

## Section 2.3 — Security Options

**GPO:** Default Domain Controllers Policy  
**Applied:** April 8–9, 2026  
**Controls applied:** ~89 | **Deferred:** 3 | **Not present/N/A:** 4

### 2.3.1 — Accounts (5 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.1 Administrator Account Status | Disabled | Enabled | **Non-compliant remediated** — `Disable-ADAccount` used (GPO alone insufficient for AD-managed accounts) |
| 2.3.2 Block Microsoft Accounts | Users can't add or log on | Not configured | Applied |
| 2.3.3 Guest Account Status | Disabled | Enabled | Applied — Disabled |
| 2.3.4 Rename Administrator Account | Non-default name | Administrator | Applied — Renamed to `NOTANADMIN` |
| 2.3.5 Rename Guest Account | Non-default name | Guest | Applied — Renamed to `Tseug` |

### 2.3.7–2.3.8 — Audit (5 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.7 Audit: Audit the Access of Global System Objects | Disabled | Not configured | Applied |
| 2.3.8 Audit: Audit the Use of Backup and Restore Privilege | Disabled | Not configured | Applied |
| 2.3.9 Audit: Force Audit Policy Subcategory Settings | Enabled | Not configured | Applied |
| 2.3.10 Audit: Shut Down System if Unable to Log Security Audits | Disabled | Not configured | Applied |

### 2.3.11–2.3.12 — DCOM (2 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.11 DCOM: Machine Access Restrictions | Remove ANONYMOUS LOGON from Access Permission | ANONYMOUS LOGON present | **Non-compliant remediated** — ANONYMOUS LOGON removed. Post-hardening EventID 10016 generated; confirmed expected and benign. |
| 2.3.12 DCOM: Machine Launch Restrictions | Administrators all, LOCAL SERVICE all, SYSTEM all | Everyone had Local Launch/Activation only | Applied — Administrators, LOCAL SERVICE, SYSTEM with full permissions |

### 2.3.13–2.3.17 — Devices (6 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.13 Devices: Allow Undock Without Having to Log On | Disabled | Not configured | Applied |
| 2.3.14 Devices: Allowed to Format and Eject Removable Media | Administrators | Not configured | Applied |
| 2.3.15 Devices: Prevent Users From Installing Printer Drivers | Enabled | Not configured | Applied |
| 2.3.16 Devices: Restrict CD-ROM Access to Locally Logged-On User Only | Disabled | Not configured | Applied |
| 2.3.17 Devices: Restrict Floppy Access to Locally Logged-On User Only | Disabled | Not configured | Applied |

### 2.3.18–2.3.22 — Domain Controller (6 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.18 DC: Allow Server Operators to Schedule Tasks | Disabled | Not configured | Applied |
| 2.3.19 DC: Allow Vulnerable Netlogon Secure Channel Connections | Not Configured | Not configured | Compliant — Zerologon mitigation (CVE-2020-1472). Not Configured = strict enforcement |
| 2.3.20 DC: LDAP Server Channel Binding Token Requirements | Always | Not configured | Applied — **Always**. LDAP relay attack prevention |
| 2.3.21 DC: LDAP Server Signing Requirements | Require signing | Not configured | Applied — Required |
| 2.3.22 DC: Refuse Machine Account Password Changes | Disabled | Not configured | Applied |

### 2.3.23–2.3.28 — Domain Member (6 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.23 Domain Member: Digitally Encrypt or Sign Secure Channel Data (Always) | Enabled | Not configured | Applied |
| 2.3.24 Domain Member: Digitally Encrypt Secure Channel Data (When Possible) | Enabled | Not configured | Applied |
| 2.3.25 Domain Member: Digitally Sign Secure Channel Data (When Possible) | Enabled | Not configured | Applied |
| 2.3.26 Domain Member: Disable Machine Account Password Changes | Disabled | Not configured | Applied |
| 2.3.27 Domain Member: Maximum Machine Account Password Age | 30 or fewer days | Not configured | Applied — 30 days |
| 2.3.28 Domain Member: Require Strong Session Key | Enabled | Not configured | Applied |

### 2.3.29–2.3.42 — Interactive Logon (14 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.29 Display User Information When Session Locked | Do not display user information | Not configured | Applied |
| 2.3.30 Do Not Require CTRL+ALT+DEL | Disabled | Not configured | Applied — Disabled (CTRL+ALT+DEL IS required) |
| 2.3.31 Don't Display Last Signed-In | Enabled | Not configured | Applied |
| 2.3.32 Don't Display Username at Sign-In | Enabled | Not configured | Applied |
| 2.3.33 Machine Inactivity Limit | 900 or fewer seconds, not 0 | Not configured | Applied — 900 seconds |
| 2.3.34 Message Text for Users Attempting to Log On | Configured | Not configured | Applied — "AUTHORIZED ACCESS ONLY" banner |
| 2.3.35 Message Title for Users Attempting to Log On | Configured | Not configured | Applied |
| 2.3.36 Number of Previous Logons to Cache | 4 or fewer | Not configured | Applied — 4 |
| 2.3.37 Prompt User to Change Password Before Expiration | 5–14 days | Not configured | Applied — 14 days |
| 2.3.38 Require Domain Controller Authentication to Unlock | Enabled | Not configured | Applied |
| 2.3.39 Require Smart Card | Disabled | Not configured | Applied |
| 2.3.40 Smart Card Removal Behavior | Lock Workstation | Not configured | Applied |
| 2.3.41 Username Not Displayed at Sign-In | Enabled | Not configured | Applied |

### 2.3.42–2.3.50 — Microsoft Network Client/Server (10 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.42 MS Network Client: Digitally Sign Communications (Always) | Enabled | Not configured | Applied — **SMB relay mitigation. MITRE T1021.002** |
| 2.3.43 MS Network Client: Digitally Sign Communications (If Server Agrees) | Enabled | Not configured | Applied |
| 2.3.44 MS Network Client: Send Unencrypted Password to Third-Party SMB Servers | Disabled | Not configured | Applied |
| 2.3.45 MS Network Server: Amount of Idle Time Before Suspending Session | 15 or fewer minutes | Not configured | Applied — 15 minutes |
| 2.3.46 MS Network Server: Digitally Sign Communications (Always) | Enabled | Not configured | Applied |
| 2.3.47 MS Network Server: Digitally Sign Communications (If Client Agrees) | Enabled | Not configured | Applied |
| 2.3.48 MS Network Server: Disconnect Clients When Logon Hours Expire | Enabled | Not configured | Applied |
| 2.3.49 MS Network Server: Server SPN Target Name Validation Level | Accept if provided by client | Not configured | Applied |

### 2.3.51–2.3.62 — Network Access (13 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.51 Network Access: Allow Anonymous SID/Name Translation | Disabled | Not configured | Applied |
| 2.3.52 Network Access: Do Not Allow Anonymous Enumeration of SAM Accounts | Enabled | Not configured | Applied |
| 2.3.53 Network Access: Do Not Allow Anonymous Enumeration of SAM Accounts and Shares | Enabled | Not configured | Applied |
| 2.3.54 Network Access: Do Not Allow Storage of Passwords and Credentials for Network Authentication | Enabled | Not configured | Applied — **MITRE T1555.004** |
| 2.3.55 Network Access: Let Everyone Permissions Apply to Anonymous Users | Disabled | Not configured | Applied |
| 2.3.56 Network Access: Named Pipes Accessible Anonymously (DC) | NETLOGON, SAMR (only) | Not configured | Applied |
| 2.3.57 Network Access: Remotely Accessible Registry Paths | Configured per CIS | Not configured | Applied |
| 2.3.58 Network Access: Remotely Accessible Registry Paths and Sub-Paths | Configured per CIS | Not configured | Applied |
| 2.3.59 Network Access: Restrict Anonymous Access to Named Pipes and Shares | Enabled | Not configured | Applied |
| 2.3.60 Network Access: Restrict Clients Allowed to Make Remote Calls to SAM | Administrators only | Not configured | Applied — **Local account discovery prevention. MITRE T1087.001** |
| 2.3.61 Network Access: Shares Accessible Anonymously | None | Not configured | Applied |
| 2.3.62 Network Access: Sharing and Security Model for Local Accounts | Classic | Not configured | Applied |

### 2.3.63–2.3.76 — Network Security (11 controls applied, 3 deferred)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.63 Network Security: Allow Local System to Use Computer Identity for NTLM | Enabled | Not configured | Applied |
| 2.3.64 Network Security: Allow LocalSystem NULL Session Fallback | Disabled | Not configured | Applied |
| 2.3.65 Network Security: Allow PKU2U Authentication Requests to Use Online Identities | Disabled | Not configured | Applied |
| 2.3.66 Network Security: Configure Encryption Types Allowed for Kerberos | AES128, AES256 only | Not configured | Applied — **RC4, DES_CBC_CRC, DES_CBC_MD5 eliminated. MITRE T1558.003** |
| 2.3.67 Network Security: Do Not Store LAN Manager Hash Value on Next Password Change | Enabled | Not configured | Applied |
| 2.3.68 Network Security: Force Logoff When Logon Hours Expire | Disabled | Not configured | Applied |
| 2.3.69 Network Security: LAN Manager Authentication Level | NTLMv2 only; refuse LM and NTLM | Not configured | Applied — **MITRE T1550.002** |
| 2.3.70 Network Security: LDAP Client Signing Requirements | Negotiate signing | Not configured | Applied |
| 2.3.71 Network Security: Minimum Session Security for NTLM SSP Based Clients | NTLMv2 + 128-bit encryption | Not configured | Applied |
| 2.3.72 Network Security: Minimum Session Security for NTLM SSP Based Servers | NTLMv2 + 128-bit encryption | Not configured | Applied |
| 2.3.73–2.3.74 Restrict NTLM: Remote Server / Domain Exceptions | Not Configured | Not configured | Compliant — Not Configured confirmed |
| 2.3.75 Restrict NTLM: Audit Incoming NTLM Traffic | Enable auditing for all accounts | Not configured | Applied — Audit applied as interim visibility measure |
| 2.3.76 Restrict NTLM: Audit NTLM Authentication in This Domain | Enable all | Not configured | Applied — Audit applied as interim visibility measure |
| 2.3.77 Restrict NTLM: Incoming NTLM Traffic | Deny all domain accounts | Not configured | **DEFERRED** — Breakage risk; no accessible VM recovery path |
| 2.3.78 Restrict NTLM: NTLM Authentication in This Domain | Deny all | Not configured | **DEFERRED** — Domain-wide impact; dependency audit required |
| 2.3.79 Restrict NTLM: Outgoing NTLM Traffic to Remote Servers | Deny all | Not configured | **DEFERRED** — Would break Velociraptor, Ansible, and Splunk connectivity |

### 2.3.80–2.3.83 — Recovery Console and Shutdown (4 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.80 Recovery Console: Allow Automatic Administrative Logon | Disabled | Not configured | Applied |
| 2.3.81 Recovery Console: Allow Floppy Copy and Access to All Drives and Folders | Disabled | Not configured | Applied |
| 2.3.82 Shutdown: Allow System to Be Shut Down Without Having to Log On | Disabled | Not configured | Applied |
| 2.3.83 Shutdown: Clear Virtual Memory Pagefile | Disabled | Not configured | Applied |

### 2.3.84–2.3.89 — System Cryptography and Objects (5 controls, 1 deferred)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.84 System Cryptography: Force Strong Key Protection | User must enter password each time | Not configured | Applied — **MITRE T1552.004** |
| 2.3.85 System Cryptography: Use FIPS Compliant Algorithms | Enabled | Not configured | **DEFERRED** — Splunk and Velociraptor compatibility risk |
| 2.3.86 System Objects: Require Case Insensitivity for Non-Windows Subsystems | Enabled | Not configured | Applied |
| 2.3.87 System Objects: Strengthen Default Permissions of Internal System Objects | Enabled | Not configured | Applied |
| 2.3.88 System Settings: Optional Subsystems | Blank | Not configured | Applied |
| 2.3.89 System Settings: Use Certificate Rules on Windows Executables for SRP | Disabled | Not configured | Applied |

### 2.3.90–2.3.99 — User Account Control / UAC (10 controls)

| Control | CIS Requirement | Before | After / Status |
|---|---|---|---|
| 2.3.90 UAC: Admin Approval Mode for Built-In Administrator | Enabled | Not configured | Applied |
| 2.3.91 UAC: Allow UIAccess Applications to Prompt for Elevation Without Using Secure Desktop | Disabled | Not configured | Applied |
| 2.3.92 UAC: Behavior of Elevation Prompt for Administrators in Admin Approval Mode | Prompt for consent on the secure desktop | Not configured | Applied |
| 2.3.93 UAC: Behavior of Elevation Prompt for Standard Users | Automatically deny elevation requests | Not configured | Applied |
| 2.3.94 UAC: Detect Application Installations and Prompt for Elevation | Enabled | Not configured | Applied |
| 2.3.95 UAC: Only Elevate Executables That Are Signed and Validated | Disabled | Not configured | Applied |
| 2.3.96 UAC: Only Elevate UIAccess Applications Installed in Secure Locations | Enabled | Not configured | Applied |
| 2.3.97 UAC: Run All Administrators in Admin Approval Mode | Enabled | Not configured | Applied — **Full UAC enforcement** |
| 2.3.98 UAC: Switch to the Secure Desktop When Prompting for Elevation | Enabled | Not configured | Applied |
| 2.3.99 UAC: Virtualize File and Registry Write Failures to Per-User Locations | Enabled | Not configured | Applied |

---

## Section 9 — Windows Defender Firewall with Advanced Security

**GPO:** Default Domain Controllers Policy  
**Applied:** April 9, 2026  
**Controls applied:** 26 (9.1: 8, 9.2: 8, 9.3: 10)

### 9.1 — Domain Profile (8 controls)

| Control | CIS Requirement | After / Status |
|---|---|---|
| 9.1.1 Firewall State | On | Applied |
| 9.1.2 Inbound Connections | Block (default-deny) | Applied |
| 9.1.3 Outbound Connections | Allow | Applied |
| 9.1.4 Display Notifications | No | Applied |
| 9.1.5 Apply Local Firewall Rules | Yes | Applied |
| 9.1.6 Apply Local Connection Security Rules | Yes | Applied |
| 9.1.7 Log Dropped Packets | Yes | Applied |
| 9.1.8 Log Successful Connections | Yes, 16384 KB — `domainfw.log` | Applied |

### 9.2 — Private Profile (8 controls)

| Control | CIS Requirement | After / Status |
|---|---|---|
| 9.2.1 Firewall State | On | Applied |
| 9.2.2 Inbound Connections | Block (default-deny) | Applied |
| 9.2.3 Outbound Connections | Allow | Applied |
| 9.2.4 Display Notifications | No | Applied |
| 9.2.5 Apply Local Firewall Rules | Yes | Applied |
| 9.2.6 Apply Local Connection Security Rules | Yes | Applied |
| 9.2.7 Log Dropped Packets | Yes | Applied |
| 9.2.8 Log Successful Connections | Yes, 16384 KB — `privatefw.log` | Applied |

### 9.3 — Public Profile (10 controls)

| Control | CIS Requirement | After / Status |
|---|---|---|
| 9.3.1 Firewall State | On | Applied |
| 9.3.2 Inbound Connections | Block (default-deny) | Applied |
| 9.3.3 Outbound Connections | Allow | Applied |
| 9.3.4 Display Notifications | No | Applied |
| 9.3.5 Apply Local Firewall Rules | **No** | Applied — **This is the setting that triggered the post-hardening incident** |
| 9.3.6 Apply Local Connection Security Rules | No | Applied |
| 9.3.7 Log Dropped Packets | Yes | Applied |
| 9.3.8 Log Successful Connections | Yes, 16384 KB — `publicfw.log` | Applied |
| 9.3.9 Unicast Response | Yes | Applied |
| 9.3.10 Inbound Notifications | No | Applied |

### Post-hardening administrative allow rules

These rules were added after hardening to maintain lab administrative access. They are locally-scoped allow rules — suppressed by the Public profile policy in 9.3.5 when the network profile regression occurred (see [Post-hardening incident](#post-hardening-incident) below).

| Rule | Protocol/Port | Direction | Justification |
|---|---|---|---|
| Allow ICMPv4 Inbound | ICMPv4 Type 8 | Inbound | Administrative ping testing between lab VMs |
| Allow OpenSSH | TCP 22 | Inbound | SCP file transfer for baseline document offloading |
| Allow WinRM HTTPS | TCP 5986 | Inbound | Ansible control node connectivity |
| Allow RDP | TCP 3389 | Inbound | Administrative GUI access |
| Allow WinRM HTTP | TCP 5985 | Inbound | Velociraptor agent communication |

---

## Section 17 — Advanced Audit Policy Configuration

**GPO:** Default Domain Controllers Policy  
**Applied:** April 9, 2026  
**Controls applied:** 35 | **CIS requires Not Configured:** 2 | **No CIS v5.0.0 requirement (tracked for completeness):** 24

> CIS v5.0.0 Section 17 contains exactly 34 benchmark controls. All 34 apply to the Domain Controller profile — there are no Section 17 controls scoped to Member Server only. The 24 additional subcategories listed in this section are real Windows Advanced Audit Policy subcategories visible in GPMC and `auditpol`, but carry no CIS v5.0.0 control number. They are documented for completeness with the label "No CIS v5.0.0 requirement." The 2 Global Object Access entries are left at Not Configured because CIS v5.0.0 explicitly requires that state.

### 17.1 — Account Logon (4 CIS controls, all applied)

| Control | CIS Requirement | Key Event IDs | Notes |
|---|---|---|---|
| 17.1.1 Audit Credential Validation | Success and Failure | 4776, 4768/4769 | Primary brute force/credential attack detection |
| 17.1.2 Audit Kerberos Authentication Service | Success and Failure | 4768 | AS-REP Roasting detection. **MITRE T1558.004** |
| 17.1.3 Audit Kerberos Service Ticket Operations | Success and Failure | 4769 | Kerberoasting detection. **MITRE T1558.003** |
| 17.1.4 Audit Other Account Logon Events | Success and Failure | — | Applied |

### 17.2 — Account Management (6 CIS controls, all applied)

| Control | CIS Requirement | Key Event IDs | Notes |
|---|---|---|---|
| 17.2.1 Audit Application Group Management | Success and Failure | — | Applied — Success and Failure. Remediated April 15, 2026. Confirmed via `auditpol /get /subcategory:"Application Group Management"`. Previously not configured due to documentation error in prior implementation session. |
| 17.2.2 Audit Computer Account Management | include Success | 4741, 4742, 4743 | Applied |
| 17.2.3 Audit Distribution Group Management | include Success | — | Applied |
| 17.2.4 Audit Other Account Management Events | include Success | 4782 | Applied — Event ID 4782 password hash access; DCSync detection complement |
| 17.2.5 Audit Security Group Management | include Success | 4728, 4732 | **MITRE T1098** |
| 17.2.6 Audit User Account Management | include Success | 4720, 4740 | Account creation and lockout. **MITRE T1136** |

### 17.3 — Detailed Tracking (2 CIS controls, all applied)

| Control | CIS Requirement | Key Event IDs | Notes |
|---|---|---|---|
| 17.3.1 Audit PNP Activity | include Success | 6416 | Applied — Physical device connection visibility |
| 17.3.2 Audit Process Creation | include Success | 4688 | Applied — **Critical.** Initially showed "No Auditing" despite GPMC configuration. Discovered and corrected during Phase 3 T1082 investigation. Verified via `auditpol /get /subcategory:"Process Creation"` |

*Non-CIS subcategories tracked for completeness (no v5.0.0 requirement): Audit DPAPI Activity, Audit Process Termination, Audit RPC Events, Audit Token Right Adjusted — all left at Not Configured.*

### 17.4 — DS Access (2 CIS controls, all applied)

| Control | CIS Requirement | Key Event IDs | Notes |
|---|---|---|---|
| 17.4.1 Audit Directory Service Access | include Failure | 4662 | Applied — Success and Failure configured (exceeds CIS minimum). Foundation for AD object-level auditing |
| 17.4.2 Audit Directory Service Changes | include Success | 5136–5141 | Applied — AD object modifications captured with before/after values. Required for DCSync audit chain |

*Non-CIS subcategories tracked for completeness (no v5.0.0 requirement): Audit Detailed Directory Service Replication, Audit Directory Service Replication — both left at Not Configured.*

### 17.5 — Logon/Logoff (6 CIS controls, all applied)

| Control | CIS Requirement | Key Event IDs | Notes |
|---|---|---|---|
| 17.5.1 Audit Account Lockout | include Failure | 4625 | Applied — Brute force detection. **MITRE T1110, T1110.003** |
| 17.5.2 Audit Group Membership | include Success | 4627 | Applied — Token elevation group membership |
| 17.5.3 Audit Logoff | include Success | 4634 | Applied — Session duration analysis |
| 17.5.4 Audit Logon | Success and Failure | 4624, 4625 | Applied — Full logon visibility |
| 17.5.5 Audit Other Logon/Logoff Events | Success and Failure | 4649 | Applied — Pass-the-Ticket replay detection. **MITRE T1550.003** |
| 17.5.6 Audit Special Logon | include Success | 4964 | Applied — Privileged account logon |

*Non-CIS subcategories tracked for completeness (no v5.0.0 requirement): Audit User/Device Claims, Audit IPsec Extended Mode, Audit IPsec Main Mode, Audit IPsec Quick Mode, Audit Network Policy Server — all left at Not Configured.*

### 17.6 — Object Access (4 CIS controls, all applied)

| Control | CIS Requirement | Key Event IDs | Notes |
|---|---|---|---|
| 17.6.1 Audit Detailed File Share | include Failure | 5145 | Applied — SYSVOL/NETLOGON unauthorized access detection |
| 17.6.2 Audit File Share | Success and Failure | 5140 | Applied — SMB share access visibility. **MITRE T1021.002** |
| 17.6.3 Audit Other Object Access Events | Success and Failure | 4698–4702 | Applied — Scheduled task creation/modification detection. **MITRE T1053.005** |
| 17.6.4 Audit Removable Storage | Success and Failure | 4663 | Applied — USB data exfiltration detection. **MITRE T1052.001** |

*Non-CIS subcategories tracked for completeness (no v5.0.0 requirement): Audit Application Generated, Audit Certification Services, Audit File System, Audit Filtering Platform Connection, Audit Filtering Platform Packet Drop, Audit Handle Manipulation, Audit Kernel Object, Audit Registry, Audit SAM, Audit Central Access Policy Staging — all left at Not Configured.*

*CIS v5.0.0 requires Not Configured: Audit File System (Global Object Access), Audit Registry (Global Object Access) — compliant.*

### 17.7 — Policy Change (5 CIS controls, all applied)

| Control | CIS Requirement | Key Event IDs | Notes |
|---|---|---|---|
| 17.7.1 Audit Audit Policy Change | include Success | 4719 | Applied — Detects audit policy disabling attempts. Self-protecting audit category |
| 17.7.2 Audit Authentication Policy Change | include Success | 4706 | Applied — Domain trust changes. **MITRE T1484.002** |
| 17.7.3 Audit Authorization Policy Change | include Success | 4703–4705 | Applied — User Rights Assignment modification detection |
| 17.7.4 Audit MPSSVC Rule-Level Policy Change | Success and Failure | 4944–4950 | Applied — Windows Firewall rule modification detection |
| 17.7.5 Audit Other Policy Change Events | include Failure | — | Applied — Detects unauthorized policy change attempts that were blocked |

*Non-CIS subcategory tracked for completeness (no v5.0.0 requirement): Audit Filtering Platform Policy Change — left at Not Configured.*

### 17.8 — Privilege Use (1 CIS control, applied)

| Control | CIS Requirement | Key Event IDs | Notes |
|---|---|---|---|
| 17.8.1 Audit Sensitive Privilege Use | Success and Failure | 4673, 4674 | Applied — SeDebugPrivilege, SeTakeOwnershipPrivilege use. **MITRE T1134** |

*Non-CIS subcategories tracked for completeness (no v5.0.0 requirement): Audit Non Sensitive Privilege Use, Audit Other Privilege Use Events — both left at Not Configured.*

### 17.9 — System (5 CIS controls, all applied)

| Control | CIS Requirement | Key Event IDs | Notes |
|---|---|---|---|
| 17.9.1 Audit IPsec Driver | Success and Failure | — | IPsec integrity violation detection |
| 17.9.2 Audit Other System Events | Success and Failure | 5025 | Windows Firewall service stop detection |
| 17.9.3 Audit Security State Change | Success | 4616 | System time change and state changes |
| 17.9.4 Audit Security System Extension | Success | 4610 | Auth package persistence detection. **MITRE T1547.002** |
| 17.9.5 Audit System Integrity | Success and Failure | 5038 | Rootkit/driver integrity violation. **MITRE T1014** |

---

## Section 18 — Administrative Templates (Computer)

**GPO:** Default Domain Controllers Policy  
**Applied:** April 9–12, 2026  
**Controls applied:** ~197 | **Deferred:** 2 | **Not present/N/A:** ~12

> `SecGuide.admx` and `MSS-legacy.admx` were manually copied from the Microsoft SCT Windows Server 2022 baseline to `C:\Windows\PolicyDefinitions\` before implementation.

### 18.1 — Control Panel: Personalization (2 controls)

| Control | CIS Requirement | After / Status |
|---|---|---|
| 18.1.1.1 Prevent Enabling Lock Screen Camera | Enabled | Applied |
| 18.1.1.2 Prevent Enabling Lock Screen Slide Show | Enabled | Applied |

### 18.3 — MS Security Guide / SecGuide.admx (6 controls applied, 2 not applicable)

| Control | CIS Requirement | After / Status |
|---|---|---|
| 18.3.1 Apply UAC Restrictions to Local Accounts on Network Logon | Enabled | Applied — **Pass-the-Hash local account mitigation. MITRE T1550.002** |
| 18.3.2 Configure RPC Packet Level Privacy Setting for Incoming Connections | Enabled | NOT APPLICABLE — Not present in SecGuide.admx template |
| 18.3.3 Configure SMB v1 Client Driver | Disabled | Applied — SMBv1 client driver disabled |
| 18.3.4 Configure SMB v1 Server | Disabled | Applied — SMBv1 server disabled |
| 18.3.5 Enable Structured Exception Handling Overwrite Protection (SEHOP) | Enabled | Applied |
| 18.3.6 NetBT NodeType Configuration | P-node | Applied — **LLMNR/NBT-NS poisoning prevention. MITRE T1557.001** |
| 18.3.7 WDigest Authentication | Disabled | Applied — **MITRE T1003.001** |
| 18.3.8 Turn Off Printing over HTTP | Enabled | NOT APPLICABLE — Not present in template |

### 18.4 — MSS (Legacy) / MSS-legacy.admx (8 controls)

| Control | CIS Requirement | After / Status |
|---|---|---|
| 18.4.1 MSS: AutoAdminLogon | Disabled | Applied — Prevents plaintext credential storage in registry |
| 18.4.2 MSS: DisableIPSourceRouting IPv6 | Highest protection | Applied |
| 18.4.3 MSS: DisableIPSourceRouting | Highest protection | Applied |
| 18.4.4 MSS: EnableICMPRedirect | Disabled | Applied |
| 18.4.5 MSS: NoNameReleaseOnDemand | Enabled | Applied |
| 18.4.6 MSS: SafeDllSearchMode | Enabled | Applied — **DLL hijacking mitigation. MITRE T1574.001** |
| 18.4.7 MSS: ScreenSaverGracePeriod | 5 or fewer seconds | Applied — 5 seconds |
| 18.4.8 MSS: WarningLevel | 90% or less | Applied — 90% |

### 18.5 — Network (13 controls)

| Control | After / Status |
|---|---|
| 18.5.1 LLMNR: Turn Off Multicast Name Resolution | Applied — **LLMNR disabled. Primary Responder attack prevention. MITRE T1557.001** |
| 18.5.2 Network Fonts: Enable Font Providers | Applied — Disabled. Eliminates external font download connections |
| 18.5.3 Lanman Workstation: Enable Insecure Guest Logons | Applied — Disabled |
| 18.5.4 Link-Layer Topology Discovery: Mapper I/O Driver | Applied — Disabled |
| 18.5.5 Link-Layer Topology Discovery: Responder Driver | Applied — Disabled |
| 18.5.6 Microsoft Peer-to-Peer Networking Services | Applied — Disabled |
| 18.5.7 Network Bridges: Prohibit Installation | Applied — Enabled |
| 18.5.8 Minimize Number of Simultaneous Connections | Applied — Enabled |
| 18.5.9 Prohibit Connection to Non-Domain Networks | Applied — Enabled |
| 18.5.10 NETLOGON UNC Hardening (RequireMutualAuthentication, RequireIntegrity) | Applied — Enabled |
| 18.5.11 SYSVOL UNC Hardening (RequireMutualAuthentication, RequireIntegrity) | Applied — Enabled |
| 18.5.12 Windows Connect Now: Configuration of Wireless Settings | Applied — Disabled |
| 18.5.13 Prohibit Access of the Windows Connect Now Wizard | Applied — Enabled |

### 18.8 — System (38 controls applied, 1 deferred, 1 not present)

Key controls from this subsection:

| Control | After / Status |
|---|---|
| 18.8.1.1 Audit Process Creation: Include Command Line | Applied — **CRITICAL: Full CommandLine captured in Event ID 4688. MITRE T1059.001** |
| 18.8.2.1 Credentials Delegation: Encryption Oracle Remediation | Applied — Force Updated Clients. CVE-2018-0886 CredSSP mitigation |
| 18.8.2.2 Credentials Delegation: Remote Host Allows Delegation of Non-Exportable Credentials | Applied — Prevents credential extraction from remote sessions |
| 18.8.3.1 Device Guard: Virtualization Based Security | **DEFERRED** — Proxmox nested virtualization support unverified |
| 18.8.4.1 Device Installation: Prevent Device Metadata Retrieval From the Internet | Applied |
| 18.8.5.1 Early Launch Antimalware: Boot-Start Driver Initialization Policy | Applied — Good, unknown, and bad but critical. MITRE T1014 |
| 18.8.6.1 Group Policy: Always Process Group Policy | Applied |
| 18.8.6.2 Group Policy: Configure Registry Policy Processing | Applied |
| 18.8.6.3 Group Policy: Continue Experiences on This Device | Applied — Disabled |
| 18.8.7.1 Internet Communication: Turn Off Access to All Windows Update Features | Applied |
| 18.8.x Internet Communication: (multiple controls) | Applied — All external telemetry and online service connections disabled |
| 18.8.x Kernel DMA Protection | Applied |
| 18.8.x Remote Procedure Call: (multiple controls) | Applied — RPC authentication required. MITRE T1047 |
| 18.8.x Shutdown: Require Secure Boot | Applied |
| 18.8.x System Restore: Turn Off System Restore | Applied |
| 18.8.x Troubleshooting and Diagnostics: (multiple controls) | Applied — All diagnostic data channels disabled |
| 18.8.x Windows Error Reporting | Applied — Disabled |
| 18.8.x User Profiles: (multiple controls) | Applied |

### 18.9 — Windows Components (~130 controls applied, 1 deferred, ~8 not present)

#### 18.9.x App Runtime
| Control | After / Status |
|---|---|
| Allow Microsoft Accounts to Be Optional | Applied |

#### 18.9.x AutoPlay Policies (4 controls)
| Control | After / Status |
|---|---|
| Disallow AutoPlay for Non-Volume Devices | Applied |
| Set the Default Behavior for AutoRun | Applied — Do not execute any autorun commands |
| Turn Off AutoPlay for all drives | Applied |
| Turn Off AutoPlay — additional | Applied |

#### 18.9.x BitLocker Drive Encryption (18 controls)
| Control | After / Status |
|---|---|
| Fixed Drives: Allow access from earlier versions | Disabled — Prevents legacy compatibility encryption bypass |
| Fixed Drives: Choose how BitLocker-protected drives can be recovered | Enabled |
| Fixed Drives: Deny write access to drives not protected by BitLocker | Enabled |
| Operating System Drive: (multiple controls) | Configured per CIS |
| Removable Drives: Deny write access to removable drives not protected by BitLocker | Applied — **CRITICAL: USB exfiltration prevention. MITRE T1052.001** |
| *(remaining BitLocker controls)* | Applied per CIS requirements |

#### 18.9.x Camera
| Control | After / Status |
|---|---|
| Allow Use of Camera | Applied — Disabled |

#### 18.9.x Cloud Content
| Control | After / Status |
|---|---|
| Turn Off Cloud Consumer Account State Content | NOT APPLICABLE — Not present in template |
| Turn Off Microsoft Consumer Experiences | Applied |

#### 18.9.x Connect
| Control | After / Status |
|---|---|
| Require Pin for Pairing | Applied — First Time |

#### 18.9.x Credential User Interface (4 controls)
| Control | After / Status |
|---|---|
| Do Not Display the Password Reveal Button | Applied |
| Enumerate Administrator Accounts on Elevation | Applied — Disabled |
| Prevent the Use of Security Questions for Local Accounts | Applied |

#### 18.9.x Data Collection and Preview Builds (9 controls)
| Control | After / Status |
|---|---|
| Allow Diagnostic Data | Applied — Diagnostic data off |
| Configure Authenticated Proxy Usage | Applied — Disable Authenticated Proxy usage |
| Disable OneSettings Downloads | Applied |
| Do Not Show Feedback Notifications | Applied |
| Enable OneSettings Auditing | Applied |
| Limit Diagnostic Log Collection | Applied |
| Limit Dump Collection | Applied |
| Toggle user control over Insider builds | Applied — Disabled |

#### 18.9.x Event Log Service (8 controls)
| Control | After / Status |
|---|---|
| Application: Control Event Log Behavior When Log File Reaches Maximum Size | Applied — Disabled (do not overwrite — preserve evidence) |
| Application: Specify the Maximum Log File Size | Applied — 32,768 KB |
| Security: Control Event Log Behavior | Applied — Disabled (do not overwrite) |
| Security: Specify the Maximum Log File Size | Applied — **196,608 KB (192 MB)** |
| Setup: Control Event Log Behavior | Applied — Disabled |
| Setup: Specify the Maximum Log File Size | Applied — 32,768 KB |
| System: Control Event Log Behavior | Applied — Disabled |
| System: Specify the Maximum Log File Size | Applied — 32,768 KB |

#### 18.9.x Internet Explorer (21 controls)
| Control | After / Status |
|---|---|
| Disable Internet Explorer 11 as a Standalone Browser | Applied — Always. IE is EoL but MSHTML engine remains in Windows Server 2022 |
| Prevent Bypassing SmartScreen Filter Warnings | Applied |
| Internet Zone: (multiple zone hardening controls) | Applied — All zones (Internet, Intranet, Restricted, Trusted, Locked-Down) hardened per CIS |
| *(remaining IE controls)* | Applied |

#### 18.9.x Location and Sensors (4 controls)
| Control | After / Status |
|---|---|
| Turn Off Location Scripting | Applied |
| Turn Off Location | Applied — Master location platform disabled |
| Turn Off Sensors | Applied |

#### 18.9.x Microsoft Defender Antivirus (15 controls)
| Control | After / Status |
|---|---|
| Configure Detection for Potentially Unwanted Applications | Applied — Block. MITRE T1204.002 |
| Turn Off Microsoft Defender Antivirus | Applied — Disabled (Defender IS active; setting disables override) |
| MAPS: Configure Local Setting Override for Reporting to Microsoft MAPS | Applied — Disabled |
| MAPS: Join Microsoft MAPS | Applied — Disabled |
| Network Inspection System: Turn On Definition Retirement | Applied |
| Network Inspection System: Turn On Protocol Recognition | Applied |
| Real-Time Protection: Turn Off Real-Time Protection | Applied — Disabled (real-time protection IS active) |
| Real-Time Protection: Turn On Behavior Monitoring | Applied — Enabled |
| Reporting: Turn Off Enhanced Notifications | Applied |
| Scan: Scan Removable Drives | Applied — Enabled |
| Scan: Turn On E-Mail Scanning | Applied |
| Threats: Specify Threat Alert Levels | Applied |

#### 18.9.x OneDrive
| Control | After / Status |
|---|---|
| Prevent the Usage of OneDrive for File Storage | Applied — **Cloud sync/exfiltration prevention** |

#### 18.9.x PowerShell (2 controls)
| Control | After / Status |
|---|---|
| Turn On PowerShell Script Block Logging | Applied — **CRITICAL: Event ID 4104. Captures deobfuscated PowerShell. MITRE T1059.001** |
| Turn On PowerShell Transcription | Applied — Full PowerShell session recording |

#### 18.9.x Remote Desktop Services (16 controls)
| Control | After / Status |
|---|---|
| Do Not Allow Passwords to Be Saved | Applied — **MITRE T1552.001** |
| Do Not Allow Drive Redirection | Applied |
| Always Prompt for Password Upon Connection | Applied |
| Require Use of Specific Security Layer for RDP | Applied — SSL/TLS |
| Require NLA for Authentication | Applied |
| Set Encryption Level | Applied — High Level |
| Disconnect Session if Time Limit is Reached | Applied |
| Set Time Limit for Active but Idle RDS Sessions | Applied — 15 minutes |
| Set Time Limit for Disconnected Sessions | Applied — 1 minute |
| Do Not Allow COM Port Redirection | Applied |
| Do Not Allow LPT Port Redirection | Applied |
| Do Not Allow Supported Plug and Play Device Redirection | Applied |
| *(remaining RDS controls)* | Applied |

#### 18.9.x RSS Feeds
| Control | After / Status |
|---|---|
| Prevent Downloading of Enclosures | Applied |

#### 18.9.x Search (5 controls)
| Control | After / Status |
|---|---|
| Allow Cortana | Applied — Disabled. AI assistant cloud data stream eliminated |
| Allow Cortana Above Lock Screen | Applied — Disabled |
| Allow Indexing of Encrypted Files | Applied — Disabled |
| Allow Search Highlights | Applied — Disabled |
| Allow Cloud Search | Applied — Disable Cloud Search |

#### 18.9.x Windows Ink Workspace
| Control | After / Status |
|---|---|
| Allow Suggested Apps in Windows Ink Workspace | Applied — Disabled |
| Allow Windows Ink Workspace | Applied — Disabled |

#### 18.9.x Windows Installer (3 controls)
| Control | After / Status |
|---|---|
| Allow User Control Over Installs | Applied — Disabled. MITRE T1218.007 |
| Always Install with Elevated Privileges | Applied — **CRITICAL: Privilege escalation via installer prevented. MITRE T1548** |
| Prevent Internet Explorer Security Prompt for Windows Installer Scripts | Applied — Disabled (prompts ARE shown) |

#### 18.9.x Windows Logon Options (2 controls)
| Control | After / Status |
|---|---|
| Enable MPR Notifications for the System | NOT APPLICABLE — Not present in template |
| Sign-in and Lock Last Interactive User Automatically After a Restart | Applied — **Disabled. CRITICAL: Prevents automatic admin logon after reboot** |

#### 18.9.x Windows Media Player (2 controls)
| Control | After / Status |
|---|---|
| Prevent Automatic Updates | Applied |
| Do Not Show First Use Dialog Boxes | Applied |

#### 18.9.x Windows Update (10 controls)
| Control | After / Status |
|---|---|
| Configure Automatic Updates | Applied — Enabled |
| Configure Automatic Updates: Scheduled Install Day | Applied — Every day |
| Do Not Adjust Default Option to Install Updates and Shut Down | Applied |
| No Auto-Restart With Logged On Users | Applied |
| Remove Access to "Pause Updates" Feature | Applied |
| Manage Preview Builds | Applied — Release Preview Channel (Disable option absent from template) |
| *(remaining Windows Update controls)* | Applied |

---

## Post-hardening verification

**All verification performed April 12, 2026.**

| Check | Result | Notes |
|---|---|---|
| `dcdiag /a` | All tests passed | Requires full administrative elevation as MERLIN. Initial failures (NetLogons, Replications, WinRM) were due to insufficient elevation, not policy issues |
| SYSVOL state | 4 — Normal | |
| WinRM SPN | Fixed | `setspn` required after unexpected shutdown |
| AD password policy | All values compliant | Verified via `Get-ADDefaultDomainPasswordPolicy` |
| ADWS | Running, Automatic | |
| DNS | Running, Automatic | |
| Netlogon | Running, Automatic | |
| Velociraptor | Running, Automatic | |
| W32Time | Running, Automatic | |
| WinRM | Running, Automatic | |
| WinRM HTTP (5985) | Listening | All interfaces (10.0.10.10, 127.0.0.1) |
| WinRM HTTPS (5986) | Listening | Certificate thumbprint confirmed |
| Velociraptor agent | Online | Green dot confirmed in GUI at `https://10.0.10.20:8889` |
| Splunk | Running | GUI accessible at `http://10.0.10.20:8000` |

---

## Post-hardening incident

**Date:** April 2026  
**Discovered:** During Phase 3 investigation setup

**Symptom:** After a Proxmox force-stop, SSH, ICMP, and RDP access to the DC was lost.

**Root cause:** The abrupt force-stop prevented domain network authentication during boot. Windows defaulted to the Public network profile. Section 9.3.5 — "Apply Local Firewall Rules: No" — correctly suppressed all locally-created allow rules in the Public profile, blocking the administrative access rules.

**Resolution:** `Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory Private`

**Analysis:** This incident confirmed that Section 9.3 hardening worked exactly as designed. The allow rules for SSH, ICMP, and RDP were never deleted — they were suppressed by policy. A single PowerShell command restored access. No policy rollback was required.

---

## Deferred controls

See [exceptions/deferred-controls.md](./exceptions/deferred-controls.md) for full risk acceptance documentation.

| Control | CIS Reference | Reason | Compensating measure | Resolution path |
|---|---|---|---|---|
| Restrict NTLM: Incoming NTLM Traffic | 2.3.77 | Breakage risk; no accessible VM recovery path at time of hardening | NTLMv2-only enforcement applied (2.3.69); NTLM audit controls (2.3.75–2.3.76) applied for visibility | Apply after VM clone confirmed accessible; full NTLM dependency audit required |
| Restrict NTLM: NTLM Authentication in This Domain | 2.3.78 | Domain-wide denial of all NTLM authentication; dependency audit required | Same as above | Same as above; verify Velociraptor and Ansible NTLM usage |
| Restrict NTLM: Outgoing NTLM Traffic to Remote Servers | 2.3.79 | Would break Velociraptor agent, Ansible WinRM, and Splunk connectivity | Same as above | Apply as final NTLM restriction after all lab tools verified NTLM-free |
| System Cryptography: FIPS Compliant Algorithms | 2.3.85 | Splunk and Velociraptor compatibility risk | AES-only Kerberos applied (2.3.66) as partial mitigation | Test Splunk and Velociraptor behavior under FIPS before applying |
| Device Guard: Virtualization Based Security | 18.8.3.1 | Proxmox nested virtualization support unverified | Defense-in-depth through all other applied controls | Verify Proxmox nested virt support; apply in Phase 5 Ansible automation |
| Manage Preview Builds — Disable | 18.9.94.4.1 | "Disabled" option absent from Administrative Templates | Release Preview Channel applied as closest available option | Monitor for template update |

---

## MITRE ATT&CK coverage

ATT&CK Navigator layer: [`mitre-attack-coverage.json`](./mitre-attack-coverage.json)

| ATT&CK ID | Technique | Mitigating control(s) | CIS section |
|---|---|---|---|
| T1003.001 | LSASS Memory Credential Dumping | WDigest disabled; SeDebugPrivilege auditing | 18.3, 17.8 |
| T1003.005 | Cached Domain Credentials | Previous logon cache limited to 4 | 2.3.36 |
| T1003.006 | DCSync | Synchronize Directory Service Data — empty; DS Changes auditing | 2.2.43, 17.4 |
| T1014 | Rootkit | System Integrity auditing; Boot driver policy | 17.9, 18.8 |
| T1021.002 | SMB/Windows Admin Shares | SMB signing enforced; File Share auditing | 2.3.42–47, 17.6 |
| T1047 | Windows Management Instrumentation | RPC authentication required | 18.8 |
| T1052.001 | Exfiltration Over Physical Medium | BitLocker write protection for removable drives; Removable storage auditing | 18.9, 17.6 |
| T1053.005 | Scheduled Task Persistence | Other Object Access auditing (4698–4702) | 17.6 |
| T1059.001 | PowerShell | Script Block Logging; Transcription; CommandLine in 4688 | 18.9, 18.8 |
| T1078 | Valid Accounts | Account lockout; Special logon auditing | 1.2, 17.5 |
| T1087.001 | Local Account Discovery | SAM remote call restrictions | 2.3.60 |
| T1087.002 | Domain Account Discovery | Anonymous SID/Name translation disabled; SAM enumeration blocked | 2.3.51, 2.3.52 |
| T1098 | Account Manipulation | Security Group Management auditing (4728) | 17.2 |
| T1110 | Brute Force | Lockout threshold 5; Credential validation auditing | 1.2, 17.1 |
| T1110.003 | Password Spraying | Account lockout auditing (4625) | 17.5 |
| T1134 | Access Token Manipulation | Create Token Object right empty; Sensitive privilege auditing | 2.2.13, 17.8 |
| T1136 | Create Account | User Account Management auditing (4720) | 17.2 |
| T1204.002 | Malicious File Execution | Always install with elevated privileges disabled | 18.9 |
| T1218.007 | Msiexec | User control over installs disabled | 18.9 |
| T1484.002 | Domain Trust Modification | Authentication Policy Change auditing (4706) | 17.7 |
| T1547.002 | Authentication Package Persistence | Security System Extension auditing (4610) | 17.9 |
| T1548 | Abuse Elevation Control Mechanism | Always install with elevated privileges disabled; UAC fully configured | 18.9, 2.3.90–99 |
| T1550.002 | Pass-the-Hash | NTLMv2 only; UAC restrictions on local accounts; LM hash disabled | 2.3.69, 18.3, 2.3.67 |
| T1550.003 | Pass-the-Ticket | Other Logon/Logoff auditing (4649) | 17.5 |
| T1552.001 | Credentials in Files | Passwords not saved in RDP | 18.9 |
| T1552.004 | Private Keys | Strong key protection required | 2.3.84 |
| T1555.004 | Windows Credential Manager | Credential storage disabled for network authentication | 2.3.54 |
| T1557.001 | LLMNR/NBT-NS Poisoning and SMB Relay | LLMNR disabled; NetBT P-node; SMB signing | 18.5, 18.3, 2.3.42 |
| T1558.001 | Golden Ticket | Kerberos auditing; DS Changes auditing | 17.1, 17.4 |
| T1558.003 | Kerberoasting | Kerberos restricted to AES128/AES256; Service Ticket auditing | 2.3.66, 17.1 |
| T1558.004 | AS-REP Roasting | Kerberos Authentication Service auditing (4768) | 17.1 |
| T1574.001 | DLL Search Order Hijacking | SafeDllSearchMode enabled | 18.4 |

---

## Phase 2 control summary

| CIS Section | Our Reference | Controls Applied | Deferred | Not Present / N/A |
|---|---|---|---|---|
| Section 1 — Account Policies | Section 1 | 9 | 1 (DC profile N/A) | 0 |
| Section 2.2 — User Rights Assignment | Section 2.2 | 37 | 0 | 0 |
| Section 2.3 — Security Options | Section 2.3 | ~89 | 3 | 4 |
| Section 9 — Windows Firewall | Section 3 | 26 | 0 | 0 |
| Section 17 — Advanced Audit Policy | Section 4 | 35 | 0 | 2 |
| Section 18.1 — Control Panel | Section 5.1 | 2 | 0 | 0 |
| Section 18.3 — MS Security Guide | Section 5.2 | 6 | 0 | 2 |
| Section 18.4 — MSS Legacy | Section 5.3 | 8 | 0 | 0 |
| Section 18.5 — Network | Section 5.4 | 13 | 0 | 0 |
| Section 18.6 — Start Menu and Taskbar | Section 5.5 | 0 | 0 | 1 |
| Section 18.8 — System | Section 5.6 | 38 | 1 | 1 |
| Section 18.9 — Windows Components | Section 5.7 | ~130 | 1 | ~8 |
| **TOTAL** | | **~393** | **6** | **~18** |
