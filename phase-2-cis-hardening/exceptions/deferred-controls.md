# Deferred Controls and Exceptions
## Phase 2 — CIS Microsoft Windows Server 2022 Benchmark v5.0.0
**Target:** Windows Server 2022 Domain Controller — soc-lab.local (10.0.10.10)
**Benchmark Date:** February 18, 2026
**Document Date:** April 15, 2026

---

## Purpose

This document is a formal risk acceptance record for all CIS benchmark controls identified during Phase 2 hardening that were not applied to the target system. It distinguishes between two categories of non-compliance:

**Deferred** controls are technically applicable to this target but were not implemented due to operational risk, compatibility constraints, or infrastructure prerequisites that were not met at the time of hardening. Each deferred control carries an explicit risk acceptance rationale, a documented compensating control, and a defined trigger condition that will prompt revisitation. Deferred status does not indicate permanent non-compliance — it indicates a planned remediation path with documented justification.

**Not Applicable** controls are explicitly excluded from this target by the CIS benchmark itself, either due to system role (Domain Controller versus Member Server), platform, or feature scope. These controls are not risk-accepted — they are outside the benchmark's stated applicability for this configuration. No compensating control or revisit trigger is required.

This document should be reviewed and updated whenever a deferred control is implemented, a revisit trigger condition is met, or a change in the lab environment materially affects the documented risk or compensating control.

---

## Deferred Controls

Controls in this table were identified as applicable to the target system but were not implemented. Each entry reflects a documented risk acceptance decision made during the Phase 2 hardening period.

| Control | CIS Section | Reason Deferred | Residual Risk | Compensating Control | Revisit Trigger |
|---|---|---|---|---|---|
| Restrict NTLM: Incoming NTLM Traffic | 2.3.77 | Applying this control without a full NTLM dependency audit would block all incoming NTLM authentication to the DC — potentially causing domain-wide authentication outages. No accessible VM recovery path was available at time of implementation to safely test and roll back the change. | **HIGH** — NTLM remains accepted for incoming authentication to the DC. An attacker who captures NTLM credentials from the network can attempt relay or pass-the-hash attacks targeting the DC. | NTLM audit mode enabled via 2.3.75 (Audit Incoming NTLM Traffic — All Accounts). All NTLM authentication to the DC is logged. NTLMv2 minimum enforced via 2.3.69. Deny anonymous enumeration active via 2.3.52. LM hash storage disabled via 2.3.67. | (1) NTLM dependency audit completed using 2.3.75 audit log data confirming no legitimate services require NTLM to the DC. (2) VM clone confirmed accessible and bootable as recovery baseline. (3) Both conditions met simultaneously before implementation. |
| Restrict NTLM: NTLM Authentication in This Domain | 2.3.78 | This is the most aggressive NTLM restriction available — it denies all NTLM authentication domain-wide. Applying without prior confirmation that all domain members support Kerberos exclusively would cause complete authentication failure across soc-lab.local. Dependency on 2.3.77 remediation first. | **HIGH** — Domain-wide NTLM authentication remains permitted. Lateral movement via NTLM relay and pass-the-hash is not blocked at the domain policy level. | Same compensating controls as 2.3.77. Additionally: SMB signing enforced on both client and server (2.3.42, 2.3.43, 2.3.47, 2.3.48) blocks the most common NTLM relay path. Kerberos AES-only enforcement (2.3.66) ensures Kerberos is the preferred authentication path where supported. | (1) 2.3.77 successfully implemented and stable. (2) Full domain Kerberos compatibility confirmed — all domain members verified Kerberos-capable. (3) NTLM audit domain log (2.3.76) reviewed and shows no legitimate Kerberos-incapable domain members. |
| Restrict NTLM: Outgoing NTLM Traffic to Remote Servers | 2.3.79 | Applying outgoing NTLM restriction on the DC would break Velociraptor agent communication, Ansible WinRM sessions from the Rocky Linux control node, and Splunk Universal Forwarder connectivity — all of which were unverified for Kerberos-only operation at implementation time. | **MEDIUM** — The DC can initiate outbound NTLM authentication to remote servers. An attacker controlling a remote server could capture DC machine account NTLM credentials. | Outbound NTLM traffic is logged via 2.3.75. Network segmentation via pfSense limits outbound DC connections to known lab infrastructure. DC has no internet-facing outbound connections. Velociraptor, Ansible, and Splunk UF connections are internal to the lab network. | (1) Velociraptor, Ansible WinRM, and Splunk UF verified as Kerberos-capable or confirmed to not use NTLM for authentication. (2) 2.3.77 and 2.3.78 both implemented and stable. (3) All three conditions met before implementing 2.3.79 as the final NTLM restriction layer. |
| System Cryptography: Use FIPS Compliant Algorithms | 2.3.85 | Enabling FIPS mode enforces FIPS 140-2 validated cryptographic algorithms system-wide. Splunk Enterprise and Velociraptor were not verified as FIPS-compatible at implementation time. Both tools use TLS connections that may rely on non-FIPS cryptographic implementations — enabling FIPS without verification risks breaking both tools entirely. | **LOW** — The DC uses non-FIPS cryptographic algorithms for some operations. In a lab environment without classified data handling requirements this represents minimal operational risk. AES-128 and AES-256 are enforced for Kerberos (2.3.66) and NTLMv2 with 128-bit encryption is required (2.3.71, 2.3.72), providing strong encryption without full FIPS mode. | Kerberos restricted to AES128 and AES256 (CIS 2.3.66) — RC4 and DES eliminated. NTLMv2 with 128-bit encryption required (CIS 2.3.71, 2.3.72). Strong key protection required for user keys (CIS 2.3.84). TLS 1.2 minimum enforced across IE security zones (CIS 18.10.x). | (1) Splunk Enterprise version confirmed FIPS-compatible via Splunk documentation. (2) Velociraptor version confirmed FIPS-compatible or replaced with FIPS-capable version. (3) Test FIPS enablement on DC clone — verify both tools maintain full functionality before applying to production DC. |
| Device Guard: Turn On Virtualization Based Security | 18.9.5.1 | VBS requires nested virtualization support in the Proxmox hypervisor. Enabling VBS without confirmed nested virtualization risks VM boot failure or severe performance degradation on the DC. Nested virtualization availability on the Proxmox host was not verified at implementation time. | **MEDIUM** — Credential Guard (a VBS-dependent feature) is not active. LSASS memory is not protected by VBS isolation, making it more susceptible to credential dumping attacks (T1003.001). WDigest is disabled (CIS 18.3.7) and LSA protection provides partial mitigation, but hardware-backed credential isolation is not in effect. | WDigest authentication disabled (CIS 18.3.7) — no plaintext credentials in LSASS memory. SeDebugPrivilege auditing active (CIS 17.8.1) — Event ID 4673 generated on LSASS access attempts. Sysmon Event ID 10 monitoring active — process access to lsass.exe generates alert telemetry. Sensitive privilege use audit captures credential dumping tool behavior. | (1) Verify Proxmox host nested virtualization: `cat /sys/module/kvm_amd/parameters/nested` returns `Y` or `1`. (2) Enable nested virtualization in Proxmox VM hardware settings for the DC VM. (3) Test VBS enablement on DC clone before applying to production DC. All three conditions must be met. |
| Windows Update for Business: Manage Preview Builds (Disable Preview Builds option) | 18.10.94.4.1 | The CIS-required setting value — Disable Preview Builds — was not present in the Windows Update Administrative Template on this Windows Server 2022 build. The dropdown options available were Dev Channel, Beta Channel, and Release Preview Channel only. The Disable Preview Builds option may be present in a different template version or OS build. | **LOW** — The DC could theoretically be enrolled in a preview build channel if a user selected Dev or Beta Channel. Release Preview Channel is applied as a partial control, restricting to near-final builds only. The DC is not currently enrolled in any preview program and no user has sufficient access to change this without Domain Admin credentials. | Release Preview Channel applied as the most restrictive available option — restricts to near-final builds rather than early development builds, minimizing instability risk. Windows Update for Business quality update deferral set to 0 days (18.10.94.4.3) and feature update deferral set to 180 days (18.10.94.4.2) provide additional update control. | (1) Windows Server 2022 Administrative Template updated to a version that includes the Disable Preview Builds dropdown option. (2) Verify option availability after any major Windows Update or template update. Apply Disable Preview Builds immediately upon availability. |

---

## Not Applicable Controls

Controls in this table are explicitly outside the scope of the CIS benchmark for this target system role or configuration. These are not risk-accepted decisions — they reflect the benchmark's own applicability statements and require no compensating control or remediation path.

| Control | CIS Section | Benchmark Exclusion Basis | Notes |
|---|---|---|---|
| Allow Administrator Account Lockout | 1.2.3 | CIS v5.0.0 explicitly specifies this control for Member Server profile only. The DC profile does not include this control. The built-in Administrator account on a Domain Controller is subject to different lockout handling than on Member Servers — the benchmark acknowledges this distinction and excludes the control from the DC profile accordingly. | The built-in Administrator account (renamed NOTANADMIN) is disabled via Disable-ADAccount per control 2.3.1. Disabling the account provides stronger protection than lockout policy for this account on the DC. |

---

## Document Revision History

| Date | Change | Author |
|---|---|---|
| April 12, 2026 | Initial document created — 6 deferred controls, 1 not applicable | SOC Lab |
| April 15, 2026 | CIS 17.2.1 Application Group Management confirmed remediated — removed from deferred scope | SOC Lab |

---

*This document is part of the Phase 2 CIS hardening evidence package for soc-lab.local.*
*Primary hardening reference: Phase2-CIS-Hardening-Changelog.docx*
*Benchmark: CIS Microsoft Windows Server 2022 Benchmark v5.0.0 (February 18, 2026)*
