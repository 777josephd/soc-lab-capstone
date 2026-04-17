# Investigation 003 — T1069.002 Permission Groups Discovery: Domain Groups

**Status:** CLOSED  
**Date:** April 14, 2026  
**Analyst:** MERLIN (Domain Admin) — soc-lab.local  
**Target:** WIN-9J5N24TODJ0 — 10.0.10.10  
**Simulation framework:** Invoke-AtomicRedTeam (Atomic Red Team)  
**Tests executed:** T1069.002 Tests 1, 3, 9  
**Baseline timestamp:** 2026-04-14 11:09:38

---

## Technique Overview

**MITRE ATT&CK:** [T1069.002 — Permission Groups Discovery: Domain Groups](https://attack.mitre.org/techniques/T1069/002/)  
**Tactic:** Discovery  
**Platforms:** Windows, Linux, macOS

Adversaries enumerate domain-level groups and permission settings to determine which groups exist and which users belong to each group. This information is used to identify accounts with elevated privileges — such as Domain Admins, Enterprise Admins, and Backup Operators — enabling targeted follow-on attacks including credential theft, lateral movement, and privilege escalation. T1069.002 is consistently observed in the post-compromise reconnaissance phase across both nation-state and financially motivated threat actor groups.

**Observed threat actors using this technique:** FIN8 (BADHATCH — `net.exe group "domain admins" /domain`), APT29 (SolarWinds — AdFind domain group enumeration), Medusa Group (`net group`), Turla (`net group "Domain Admins" /domain`).

---

## Pre-Test Research

### Commands expected

| Command | Purpose | Detection method |
|---|---|---|
| `net localgroup` | Enumerate local groups | 4688, Sysmon 1 |
| `net group /domain` | Enumerate all domain groups | 4688, Sysmon 1 |
| `net group "domain admins" /domain` | Target privileged group | 4688, Sysmon 1 |
| `net group "enterprise admins" /domain` | Target privileged group | 4688, Sysmon 1 |
| `Get-AdGroup -filter *` | Enumerate all AD groups via PowerShell | 4688, Sysmon 1, Sysmon 3 (port 9389) |

### Event IDs predicted

| Source | Event ID | Expected? |
|---|---|---|
| Windows Security Log | 4688 — Process Creation | Yes — primary native source |
| Windows Security Log | 4799 — Security-enabled local group enumerated | Yes — net localgroup |
| Windows Security Log | 4798 — User local group membership enumerated | Yes — net localgroup |
| PowerShell Log | 4103 — Module Logging | Yes — if Get-AdGroup uses module pipeline |
| PowerShell Log | 4104 — Script Block Logging | Yes — if PowerShell script block executes |
| Sysmon | Event ID 1 — Process Create | Yes — full CommandLine capture |
| Sysmon | Event ID 3 — Network Connection | Yes — LDAP port 389/636 or ADWS port 9389 |
| Sysmon | Event ID 10 — Process Access | Possible — ART framework overhead |

---

## Test Execution

Tests executed beginning at **11:09:38** via elevated PowerShell session as MERLIN.  
Velociraptor pre-execution Pslist Flow ID: `F.D7F217H2L4MQS`

Initial triage SPL:

```splunk
(index=soc-lab-ad OR index=sysmon-ad) earliest="04/14/2026:11:09:38"
| stats count by sourcetype, EventCode
| sort -count
```

---

## Layer 1 — Event Triage

| Bucket | Event | Count | Classification |
|---|---|---|---|
| A — Background noise | Sysmon 13 (Registry value set) | 100 | Expected OS background |
| A — Background noise | Sysmon 12 (Registry object created/deleted) | 29 | Expected OS background |
| A — Background noise | WinEventLog 4702 (Scheduled task updated) | 2 | Outside test window |
| A — Background noise | WinEventLog 5140 (Network share accessed) | 5 | SYSVOL Group Policy background |
| A — Background noise | WinEventLog 4670 (Permissions on object changed) | TBD | Regular interval — background |
| A — Background noise | WinEventLog 4673 (Sensitive Privilege Use) | 3 | LsaRegisterLogonProcess — standing FP |
| B — Expected telemetry | WinEventLog 4688 (Process Creation) | 77 | Filtered for test commands — see Layer 2 |
| B — Expected telemetry | WinEventLog 4799 (Security-enabled local group enumerated) | TBD | Investigate — VSSVC.exe pattern |
| B — Expected telemetry | WinEventLog 4627 (Group membership information) | TBD | Logon subcategory |
| B — Expected telemetry | Sysmon 1 (Process Create) | — | Filtered for test commands |
| B — Expected telemetry | Sysmon 3 (Network Connection) | 1 | Port 9389 — Get-AdGroup fingerprint |
| B — Expected telemetry | Sysmon 10 (Process Access) | — | ART framework overhead |
| C — Unexpected | Sysmon 17 (Pipe Created) | 1 | PSHost named pipe — investigate |
| C — Unexpected | Sysmon 22 (DNS Query) | 1 | PowerShell DNS resolution — investigate |
| C — Unexpected | WinEventLog 4670 (Permissions changed) | TBD | SDDL change — investigate |
| D — Predicted absent | WinEventLog 4798 (User local group membership enumerated) | 0 | Correct absence — see Layer 2 |
| D — Predicted absent | PowerShell 4103 (Module Logging) | 0 | ADWS execution path — see Layer 2 |
| D — Predicted absent | PowerShell 4104 (Script Block Logging) | 0 | Inline cmdlet — see Layer 2 |

---

## Layer 2 — Investigation by Priority

### Priority 1 — WinEventLog 4688 + Sysmon Event ID 1 (Process Creation) — Bucket B

**Finding: All three tests confirmed across dual telemetry sources.**

Filtered SPL:

```splunk
(index=soc-lab-ad OR index=sysmon-ad)
earliest="04/14/2026:11:09:38"
(EventCode=4688 OR EventCode=1)
(Process_Command_Line="*net group*" OR
 Process_Command_Line="*net localgroup*" OR
 Process_Command_Line="*Get-AdGroup*" OR
 CommandLine="*net group*" OR
 CommandLine="*net localgroup*" OR
 CommandLine="*Get-AdGroup*")
| table _time, EventCode, Account_Name, New_Process_Name,
  Process_Command_Line, CommandLine, Creator_Process_Name, ParentImage
| sort _time
```

**Tests 1 and 3 — net command execution:**

| Field | Value |
|---|---|
| Account_Name | MERLIN |
| New_Process_Name | cmd.exe |
| Process_Command_Line | `"cmd.exe" /c net localgroup & net group /domain & net group "enterprise admins" /domain & net group "domain admins" /domain` |
| Creator_Process_Name | powershell.exe |
| Sysmon CommandLine | `net group "domain admins" /domain` |
| Sysmon User | SOC-LAB\MERLIN |

**Test 9 — Get-AdGroup execution:**

| Field | Value |
|---|---|
| Account_Name | MERLIN |
| New_Process_Name | powershell.exe |
| Process_Command_Line | `"powershell.exe" & {Get-AdGroup -filter *}` |
| Creator_Process_Name | powershell.exe |
| Notable | PowerShell spawning PowerShell — ART script block execution pattern |

Execution chain confirmed: **PowerShell → cmd.exe → net.exe** for Tests 1 and 3. **PowerShell → child PowerShell** for Test 9. Account MERLIN confirmed as executing principal across all test-correlated events.

**Assessment: CONFIRMED — All three tests detected. Dual-source coverage achieved via 4688 and Sysmon Event ID 1.**

> **Detection note:** PowerShell spawning a child PowerShell process with AD cmdlet CommandLine is a high-fidelity indicator of PowerShell-based AD enumeration. This execution pattern is distinct from the cmd.exe-based tests and warrants inclusion in detection rules.

---

### Priority 2 — Sysmon Event ID 3 + Event ID 22 — Bucket B/C
**Get-AdGroup Network Execution Fingerprint**

**Finding: Port 9389 ADWS connection identified as Test 9 network signature.**

SPL:

```splunk
index=sysmon-ad earliest="04/14/2026:11:09:38"
(EventCode=22 OR EventCode=3)
| where User="SOC-LAB\\MERLIN" OR DestinationPort=9389
| table _time, EventCode, Image, QueryName,
  DestinationIp, DestinationPort, User
| sort _time
```

**Event ID 22 — DNS Query:**

| Field | Value |
|---|---|
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| QueryName | `win-9j5n24todj0.soc-lab.local` |
| User | SOC-LAB\MERLIN |
| Deviation | Typical Image is `<unknown process>` / NT AUTHORITY\SYSTEM |

**Event ID 3 — Network Connection:**

| Field | Value |
|---|---|
| Image | powershell.exe |
| DestinationPort | 9389 |
| DestinationIp | `fe80::50d2:a933:e07:2b0a` (local IPv6 loopback) |
| SourceIp | `fe80::50d2:a933:e07:2b0a` (same — loopback confirmed) |
| User | SOC-LAB\MERLIN |
| Sequence | DNS query immediately preceding ADWS connection |

**Assessment: CONFIRMED — Get-AdGroup execution network fingerprint. Port 9389 connection is the definitive network indicator of PowerShell AD module cmdlet execution.**

> **Critical detection engineering note:** PowerShell AD module cmdlets — including `Get-AdGroup`, `Get-ADUser`, and `Get-ADObject` — communicate with the domain controller via Active Directory Web Services (ADWS) on port 9389, not traditional LDAP on ports 389 or 636. Detection rules relying exclusively on ports 389/636 will miss all PowerShell-based AD enumeration. Port 9389 monitoring from PowerShell processes is required for complete coverage.

---

### Priority 3 — WinEventLog 4799 (Security-Enabled Local Group Enumerated) — Bucket B

**Finding: Group enumeration confirmed — attributed to Windows Defender, not test execution.**

SPL:

```splunk
index=soc-lab-ad earliest="04/14/2026:11:09:38" EventCode=4799
| table _time, Account_Name, Group_Name,
  Calling_Process_Name, Calling_Process_ID
| sort _time
```

| Field | Value |
|---|---|
| Account_Name | WIN-9J5N24TODJ0$ (machine account) |
| Group_Name | Administrators / Backup Operators |
| Calling_Process_Name | VSSVC.exe |

This is the second consecutive investigation in which VSSVC.exe has generated 4799 events targeting privileged groups. Pattern first observed in T1087.002 (Administrators group only). In T1069.002, VSSVC.exe enumerated both Administrators and Backup Operators — confirming the Windows Defender on-access scanning behavior as a consistent environmental pattern rather than an isolated occurrence.

**Assessment: CONFIRMED BENIGN — Known environmental false positive. VSSVC.exe + 4799 documented as standing pattern. Exclude VSSVC.exe from 4799 detection rules.**

> **Production note:** In any environment, VSSVC.exe enumerating privileged groups outside expected maintenance windows warrants investigation. The benign conclusion here is specific to this lab's observed Defender scanning behavior. Always verify calling process and timing before closing in production.

---

### Priority 4 — Sysmon Event ID 17 (Pipe Created) — Bucket C

**Finding: PSHost named pipe — PowerShell runtime artifact.**

SPL:

```splunk
index=sysmon-ad earliest="04/14/2026:11:09:38" EventCode=17
| table _time, PipeName, Image, User
```

| Field | Value |
|---|---|
| PipeName | `\PSHost.134206387714280984.4360.DefaultAppDomain.powershell` |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| User | SOC-LAB\MERLIN |

The `PSHost.[timestamp].[PID].DefaultAppDomain.powershell` naming convention is exclusive to the PowerShell .NET runtime — it cannot be spoofed by common C2 frameworks. Timing correlates with Test 9 Get-AdGroup execution.

**Assessment: CONFIRMED BENIGN — PowerShell runtime artifact. Distinguished from malicious named pipes by naming convention.**

> **Named pipe reference for production environments:**
> - Cobalt Strike: `\postex_*`, `\msagent_*`, `\status_*`
> - Meterpreter: `\meterpreter_*`
> - PSHost pipes are exclusive to the PowerShell runtime and not reused by known C2 frameworks.

---

### Priority 5 — WinEventLog 4670 (Permissions on Object Changed) — Bucket C

**Finding: SDDL permission maintenance — background OS activity.**

| Field | Value |
|---|---|
| SDDL | `D:(A;;GA;;;SY)(A;;GA;;;NS)` |
| Translation | SYSTEM and NETWORK SERVICE granted Generic All access |
| Timing | Regular interval — not correlated with test execution |

**Assessment: CONFIRMED BENIGN — Standard Windows service account permission maintenance. Regular interval confirms scheduled process, not attacker activity.**

> **SDDL reference:** Security Descriptor Definition Language — standard Windows format for expressing security descriptors. `D` = DACL, `A` = Allow, `GA` = Generic All, `SY` = SYSTEM, `NS` = NETWORK SERVICE.

---

### Priority 6 — WinEventLog 4673 (Sensitive Privilege Use) — Bucket A

**Disposition: CONFIRMED BENIGN — Third consecutive occurrence.**  
LsaRegisterLogonProcess via lsass.exe confirmed as standing environmental pattern across T1082, T1087.002, and T1069.002. Background LSA authentication service activity. No further investigation required. Forward reference: LSASS investigated specifically in T1003.001.

---

### Priority 7 — Bucket D Resolution

**4798 — User Local Group Membership Enumerated — ABSENT**

`net localgroup` lists group names only — it does not query which users belong to each group. Event ID 4798 fires specifically for membership queries, not group listing operations. Event ID 4799 covers security-enabled group enumeration, which fired as expected. Absence is semantically correct given the commands executed.  
**Status: CORRECT ABSENCE — not a logging gap.**

**PowerShell 4103 — Module Logging — ABSENT**

`Get-AdGroup` communicates with the domain controller via ADWS on port 9389 — a SOAP/XML protocol that bypasses the PowerShell module pipeline entirely. Module logging captures pipeline activity; ADWS calls do not traverse this path. Confirmed by Sysmon Event ID 3 showing port 9389 connection rather than module execution artifacts.  
**Status: CORRECT ABSENCE — confirmed by Sysmon network telemetry.**

**PowerShell 4104 — Script Block Logging — ABSENT**

Get-AdGroup was executed as an inline cmdlet by the ART framework. Script Block Logging confirmed active via registry (`EnableScriptBlockLogging = 1`). Inline cmdlet execution does not generate 4104 at the same threshold as script file execution.  
**Status: CORRECT ABSENCE — control verified active.**

---

## Layer 3 — Analyst Narrative

At 11:09:38 on April 14, 2026, Invoke-AtomicRedTeam executed three T1069.002 Permission Groups Discovery tests under account SOC-LAB\MERLIN on WIN-9J5N24TODJ0 (10.0.10.10). The tests covered three distinct enumeration methods: native net command chaining via cmd.exe for Tests 1 and 3, and PowerShell AD module enumeration via Get-AdGroup for Test 9. Each test produced distinct telemetry signatures enabling independent identification.

All three tests were confirmed across dual telemetry sources. Windows Security Event ID 4688 and Sysmon Event ID 1 captured the complete execution chain for Tests 1 and 3 — powershell.exe spawning cmd.exe, which executed chained net commands targeting net localgroup, net group /domain, net group "enterprise admins" /domain, and net group "domain admins" /domain. Test 9 was confirmed by a distinct 4688 event showing powershell.exe spawning a child powershell.exe process with CommandLine `"powershell.exe" & {Get-AdGroup -filter *}` — the ART script block execution pattern for PowerShell-native tests. Account MERLIN was attributed as the executing principal across all test-correlated events with no unexpected accounts observed.

Test 9 produced a unique network execution fingerprint not present in the net command-based tests. Sysmon Event ID 22 captured PowerShell resolving the DC FQDN `win-9j5n24todj0.soc-lab.local` via DNS, immediately followed by Sysmon Event ID 3 recording a loopback connection to port 9389 — the Active Directory Web Services port used exclusively by PowerShell AD module cmdlets. Source and destination IP were identical (`fe80::50d2:a933:e07:2b0a`), confirming local on-DC enumeration with no remote infrastructure involved. This two-event sequence — DNS resolution followed by ADWS connection — is a high-fidelity detection indicator for PowerShell-based AD enumeration. Traditional LDAP monitoring on ports 389 and 636 would have missed this activity entirely; port 9389 monitoring is required for complete PowerShell AD cmdlet detection coverage.

Sysmon Event ID 17 captured a PSHost named pipe created by powershell.exe under MERLIN, corroborating Test 9 execution. The pipe naming convention `PSHost.[timestamp].[PID].DefaultAppDomain.powershell` is exclusive to the PowerShell .NET runtime and is distinguishable from malicious named pipe patterns used by frameworks such as Cobalt Strike (`\postex_*`, `\msagent_*`) and Meterpreter (`\meterpreter_*`). Combined with confirmed legitimate process path, known execution account, and correlated test timing, the finding was closed as benign. In production environments, named pipe creation by PowerShell always warrants investigation — the benign conclusion here is context-dependent.

Windows Security Event ID 4799 fired during the test window, confirming security-enabled local group enumeration of both the Administrators and Backup Operators groups. Investigation revealed the calling process was VSSVC.exe under machine account WIN-9J5N24TODJ0$ — the second consecutive investigation in which VSSVC.exe has generated 4799 events targeting privileged groups. The pattern is attributed to Windows Defender on-access scanning behavior and is now documented as a confirmed standing environmental false positive. Detection rules for 4799 should exclude VSSVC.exe as a calling process to reduce false positive volume while preserving detection coverage for unauthorized enumeration from unexpected processes.

Background events across Sysmon 12, 13, WinEventLog 4673, 4702, 4670, and 5140 were confirmed benign through timing analysis and field verification. WinEventLog 4670 SDDL notation `D:(A;;GA;;;SY)(A;;GA;;;NS)` reflects standard SYSTEM and NETWORK SERVICE permission maintenance at regular intervals — not test-correlated. WinEventLog 4673 LsaRegisterLogonProcess is confirmed as a standing environmental pattern across all three prior investigations.

Predicted Event IDs 4798, 4103, and 4104 were absent and confirmed as correct absences. 4798 is semantically inapplicable to group listing commands — only membership queries generate this event. 4103 and 4104 were not generated because Get-AdGroup communicates via ADWS rather than the PowerShell module pipeline; Script Block Logging was verified active via registry inspection (`EnableScriptBlockLogging = 1`). No logging gaps were identified in this investigation.

CIS hardening controls were validated throughout. Section 2.3.52 — Do Not Allow Anonymous Enumeration of SAM Accounts — remained active, requiring authenticated MERLIN credentials for all enumeration. Section 5.7.7.2 — Enumerate Administrator Accounts on Elevation: Disabled — confirmed consistent with T1087.002 findings. No hardening controls were bypassed. Detection is the primary defensive layer for this technique given that ATT&CK notes T1069.002 cannot be effectively mitigated with preventive controls, as it abuses legitimate OS functionality.

---

## Diamond Model

| Axis | Value |
|---|---|
| **Adversary** | ART simulation — Invoke-AtomicRedTeam (T1069.002 Tests 1, 3, 9) |
| **Capability** | `net.exe` (chained group enumeration commands), `powershell.exe` (`Get-AdGroup -filter *`), ADWS port 9389 AD module communication |
| **Infrastructure** | Local execution on WIN-9J5N24TODJ0 (10.0.10.10) via elevated PowerShell. Loopback ADWS connection — no external infrastructure involved. |
| **Victim** | soc-lab.local AD domain — domain group structure exposed including Domain Admins, Enterprise Admins, Account Operators, Backup Operators membership |

---

## ATT&CK Coverage

| Field | Value |
|---|---|
| Technique | T1069 — Permission Groups Discovery |
| Sub-technique | T1069.002 — Domain Groups |
| Tactic | Discovery |
| Detection status | **DETECTED** via WinEventLog 4688, Sysmon Event ID 1, Sysmon Event ID 3 (port 9389) |
| Coverage | Dual-source: 4688 + Sysmon Event ID 1. Get-AdGroup additionally detected via Sysmon Event IDs 3 and 22. |

---

## Detection Artifacts

| Artifact | File | Status |
|---|---|---|
| Splunk detection rule | [`detection-rule.spl`](./detection-rule.spl) | Active |
| Sigma rule | [`sigma-rule.yml`](./sigma-rule.yml) | Experimental |
| Diamond Model | [`diamond-model.md`](./diamond-model.md) | Complete |

---

## OSINT Enrichment

No external IOCs generated. All activity was local domain enumeration via authenticated session. No external connections, file hashes, or network indicators requiring OSINT investigation. Threat actor context drawn from ATT&CK documented procedure examples and published incident reports.

---

## Threat Actor Context

| Threat actor | T1069.002 usage |
|---|---|
| FIN8 | BADHATCH backdoor — `net.exe group "domain admins" /domain` targeting insurance, retail, technology, and chemical sectors |
| APT29 | AdFind domain group enumeration during SolarWinds compromise post-exploitation phase |
| Medusa Group | `net group` command to query domain groups within victim environments |
| Turla | `net group "Domain Admins" /domain` for domain administrator identification, attributed to Russia's FSB |

---

## Standing Notes Established

The following environmental patterns and detection insights were established during this investigation and apply to all subsequent Phase 3 investigations:

1. **Port 9389 = ADWS:** PowerShell AD module cmdlets (`Get-AdGroup`, `Get-ADUser`, `Get-ADObject`) communicate via Active Directory Web Services on port 9389, not traditional LDAP ports 389/636. Detection rules must include port 9389 monitoring for complete PowerShell AD cmdlet coverage.
2. **DNS + ADWS sequence:** Sysmon Event ID 22 (DNS resolution of DC FQDN) immediately preceding Sysmon Event ID 3 (port 9389 connection) is the complete network fingerprint of PowerShell AD module cmdlet execution.
3. **PSHost named pipes:** `\PSHost.[timestamp].[PID].DefaultAppDomain.powershell` is the PowerShell runtime pipe naming convention. Distinguished from C2 pipes by the `DefaultAppDomain.powershell` suffix. Always verify naming convention before closing named pipe findings in production.
4. **VSSVC.exe + 4799 confirmed standing FP:** Second occurrence across investigations. Windows Defender on-access scanning causes VSSVC.exe to enumerate Administrators and Backup Operators groups. Exclude from 4799 detection rules.
5. **PowerShell spawning PowerShell:** Child `powershell.exe` from parent `powershell.exe` with AD cmdlet CommandLine is the ART script block execution pattern and a detection indicator for PowerShell-based AD enumeration.
6. **ATT&CK T1069.002 mitigation note:** ATT&CK explicitly notes this technique cannot be easily mitigated with preventive controls as it abuses legitimate OS features. Detection is the primary defensive layer.

---

## Investigation Outcome

| Item | Result |
|---|---|
| Tests confirmed in telemetry | 3/3 |
| Unexpected events requiring investigation | 3 (Sysmon 17, Sysmon 22, WinEventLog 4670) |
| Unexpected events confirmed malicious | 0 |
| Logging gaps identified | 0 |
| Environmental false positives documented | 1 (VSSVC.exe + 4799 — second occurrence) |
| Standing notes established | 6 |
| Key detection insight | Port 9389 ADWS monitoring required for PowerShell AD cmdlet detection |
| Detection rules created | 2 (SPL + Sigma) |
