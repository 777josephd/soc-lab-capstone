# Investigation 002 — T1087.002 Account Discovery: Domain Account

**Status:** CLOSED  
**Date:** April 13, 2026  
**Analyst:** MERLIN (Domain Admin) — soc-lab.local  
**Target:** WIN-9J5N24TODJ0 — 10.0.10.10  
**Simulation framework:** Invoke-AtomicRedTeam (Atomic Red Team)  
**Tests executed:** T1087.002 Tests 1, 2, 3  
**Baseline timestamp:** 2026-04-13 13:38:37

---

## Technique Overview

**MITRE ATT&CK:** [T1087.002 — Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)  
**Tactic:** Discovery  
**Platforms:** Windows, Linux, macOS

Adversaries enumerate domain accounts to identify privileged targets for follow-on attacks including credential access and lateral movement. By mapping domain user and group memberships — particularly privileged accounts such as Domain Admins — adversaries can prioritize targets, tailor payloads, and reduce operational noise during later intrusion stages. T1087.002 is consistently observed in the early post-compromise phase across both nation-state and financially motivated threat actor groups.

**Observed threat actors using this technique:** APT29 (SolarWinds — `Get-ADUser`, `Get-ADGroupMember`), APT41 (`net` commands for domain admin enumeration), FIN7, Medusa Group (`net user /domain`), Empire framework operators.

---

## Pre-Test Research

### Commands expected

| Command | Purpose | Detection method |
|---|---|---|
| `net user /domain` | Enumerate all domain users | 4688, Sysmon 1 |
| `net group /domain` | Enumerate all domain groups | 4688, Sysmon 1 |
| `Get-ADUser -filter *` | Enumerate all AD user objects | 4688, Sysmon 1, 4104 |
| `Get-LocalGroupMember -group Users` | Enumerate local group membership | 4688, Sysmon 1, 4798 |
| `query user /SERVER:%COMPUTERNAME%` | Enumerate active sessions | 4688, Sysmon 1 |

### Event IDs predicted

| Source | Event ID | Expected? |
|---|---|---|
| Windows Security Log | 4688 — Process Creation | Yes — primary native source |
| Windows Security Log | 4799 — Security-enabled local group enumerated | Yes — net group / Get-LocalGroupMember |
| Windows Security Log | 4798 — User local group membership enumerated | Yes — Get-LocalGroupMember |
| Windows Security Log | 4661 — SAM handle requested | Yes — SAM database access |
| Windows Security Log | 4662 — AD object operation | Yes — AD object enumeration |
| PowerShell Log | 4104 — Script Block Logging | Yes — if PowerShell-based |
| PowerShell Log | 4103 — Module Logging | Yes — if PowerShell-based |
| Sysmon | Event ID 1 — Process Create | Yes — full CommandLine capture |
| Sysmon | Event ID 3 — Network Connection | Possible — LDAP port 389/636 if AD queries route externally |
| Sysmon | Event ID 10 — Process Access | Possible — enumeration tool accessing SAM or LSASS |

---

## Test Execution

Tests executed beginning at **14:44:23** via elevated PowerShell session as MERLIN.  
Velociraptor post-execution Pslist Flow ID: `F.D7EG7F7Q6V5D0`

> **Note:** Pre-execution Velociraptor baseline was not captured before test execution for this investigation. Post-execution Pslist collected for comparison against the pre-T1082 baseline. Baseline capture procedure corrected going forward — Velociraptor Pslist is collected immediately after Timestamp #2 before any test execution.

**Test 2 cancellation:** `Get-ADUser -filter *` exceeded expected execution time. Ctrl+C cancellation at 14:51:09. Partial execution confirmed — full command block captured in Sysmon Event ID 1 telemetry regardless of completion status.

Initial triage SPL:

```splunk
index=* earliest="04/13/2026:14:44:23"
| stats count by sourcetype, EventCode
| sort -count
```

---

## Layer 1 — Event Triage

| Bucket | Event | Count | Classification |
|---|---|---|---|
| A — Background noise | Sysmon 13 (Registry value set) | 381 | Expected OS background |
| A — Background noise | Sysmon 12 (Registry object created/deleted) | 116 | Expected OS background |
| A — Background noise | WinEventLog 4672 (Special privileges assigned to new logon) | 58 | Domain Admin session — background |
| A — Background noise | WinEventLog 4634 (Account logged off) | 54 | Background logoff activity |
| A — Background noise | WinEventLog 4702 (Scheduled task updated) | 2 | Pre-existing background |
| B — Expected telemetry | WinEventLog 4688 (Process Creation) | 160 | Filtered for test commands — see Layer 2 |
| B — Expected telemetry | WinEventLog 4799 (Security-enabled local group enumerated) | 8 | **Primary investigation target** |
| B — Expected telemetry | WinEventLog 4627 (Group membership information) | 58 | Logon subcategory — test-correlated |
| B — Expected telemetry | Sysmon 1 (Process Create) | — | Filtered for test commands |
| B — Expected telemetry | Sysmon 3 (Network Connection) | — | Investigate for LDAP activity |
| B — Expected telemetry | Sysmon 10 (Process Access) | — | ART framework behavior |
| C — Unexpected | WinEventLog 4673 (Sensitive Privilege Use) | 7 | Investigate |
| C — Unexpected | WinEventLog 4624 (Successful Logon) | 58 | Investigate for test-time clustering |
| D — Predicted absent | WinEventLog 4661 (SAM handle requested) | 0 | No direct SAM access in selected tests |
| D — Predicted absent | WinEventLog 4662 (AD object operation) | — | Present but background — see Layer 2 |
| D — Predicted absent | WinEventLog 4798 (User local group membership enumerated) | 0 | Test 2 cancellation — see Layer 2 |
| D — Predicted absent | WinEventLog 4104 (Script Block Logging) | 0 | cmd.exe execution path — see Layer 2 |

---

## Layer 2 — Investigation by Priority

### Priority 1 — WinEventLog 4688 + Sysmon Event ID 1 (Process Creation) — Bucket B

**Finding: All three tests confirmed across dual telemetry sources.**

Filtered SPL:

```splunk
index=soc-lab-ad earliest="04/13/2026:14:44:23" EventCode=4688
| where match(Process_Command_Line, "(?i)net user|net group|get-aduser|query user|localgroupmember")
| table _time, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort _time
```

| Timestamp | CommandLine | Test | Account |
|---|---|---|---|
| 14:45:xx | `cmd.exe /c net user /domain & net group /domain` | Test 1 | MERLIN |
| 14:4x:xx | `powershell.exe & {net user /domain; get-localgroupmember -group Users; get-aduser -filter *}` | Test 2 (partial) | MERLIN |
| 14:51:xx | `cmd.exe /c query user /SERVER:%COMPUTERNAME%` | Test 3 | MERLIN |

Sysmon Event ID 1 independently corroborated all three entries. Execution chain confirmed: **PowerShell → cmd.exe → native enumeration utilities**. Account MERLIN confirmed as the executing principal across all test-correlated events. No unexpected accounts observed.

**Test 2 note:** The full command block — including `get-aduser -filter *` — was captured in Sysmon Event ID 1 telemetry despite Ctrl+C cancellation. Partial execution confirmed. Enumeration began before interruption; telemetry is present regardless of completion status.

**Assessment: CONFIRMED — All three tests detected. Dual-source coverage achieved via 4688 and Sysmon Event ID 1.**

---

### Priority 2 — WinEventLog 4799 (Security-Enabled Local Group Enumerated) — Bucket B

**Finding: Group enumeration confirmed — one anomalous entry attributed to Windows Defender.**

SPL:

```splunk
index=soc-lab-ad earliest="04/13/2026:14:44:23" EventCode=4799
| table _time, Account_Name, Group_Name, Calling_Process_Name, Calling_Process_ID
| sort _time
```

Eight events observed. The majority correlated with test execution timeframes. One event at **14:54:54** was generated by `VSSVC.exe` (Volume Shadow Copy Service) enumerating the Administrators group — outside the expected test window.

**VSSVC.exe investigation:**

Cross-referenced in Sysmon:

```splunk
index=sysmon-ad earliest="04/13/2026:14:44:23"
| search Image="*VSSVC*" OR ParentImage="*VSSVC*"
| table _time, EventCode, Image, CommandLine, ParentImage, User
| sort _time
```

Sysmon Event ID 7 (Image Load) revealed `MpOAV.dll` and `amsi.dll` loading — Windows Defender on-access scan components invoking AMSI during active PowerShell test execution. The VSS service was scanned by Defender mid-execution, triggering the group enumeration event as a side effect of the on-access scan routine.

**Assessment: CONFIRMED BENIGN — Windows Defender on-access scanning behavior. VSSVC.exe + 4799 established as a standing environmental false positive pattern. Exclude VSSVC.exe from 4799 detection rules.**

> **Analyst note:** In a production environment, VSSVC.exe enumerating privileged groups outside expected maintenance windows warrants escalation regardless of explanation. The VSS/Defender interaction is a recognized false positive pattern that experienced analysts learn to distinguish from genuine anomalies through contextual field verification.

---

### Priority 3 — WinEventLog 4673 (Sensitive Privilege Use) — Bucket C

**Finding: Background LSA activity — not correlated with test execution.**

SPL:

```splunk
index=soc-lab-ad earliest="04/13/2026:14:44:23" EventCode=4673
| table _time, Account_Name, Service_Name, Process_Name, Privileges
| sort _time
```

All 4673 events showed `LsaRegisterLogonProcess()` called by `lsass.exe`. This is periodic LSA authentication service activity present in every investigation. Not correlated with T1087.002 test execution.

**Assessment: CONFIRMED BENIGN — Background LSA activity. Cross-reference: T1082 Investigation 001, same finding documented. Standing false positive pattern — do not re-investigate.**

---

### Priority 4 — WinEventLog 4624 (Successful Logon) — Bucket C

**Finding: Authentication spikes correlated with test execution timeframes.**

WinEventLog 4624 timechart analysis showed event clusters corresponding to test execution windows for Tests 1, 2, and 3. Logon activity is consistent with domain authentication generated when enumeration commands query AD services. No unexpected source addresses or logon types observed outside test-correlated windows.

**Assessment: CONFIRMED BENIGN — Expected authentication activity generated by domain enumeration commands querying AD. No anomalous logon sources or types identified.**

---

### Priority 5 — Bucket D Resolution

**4662 — AD Object Operation:**

Present in the event log but attributed to a machine account (`WIN-9J5N24TODJ0$`) accessing an AD schema GUID (`%{b2413b90-f848-4380-ba6d-ee03e228fb9b}`) at an exact one-hour interval. One-hour precision confirms scheduled automated domain maintenance — not test-generated. Reclassified to Bucket A.

**4798 — User Local Group Membership Enumerated:**

Absent. Expected from `Get-LocalGroupMember -group Users` in Test 2. Test 2 cancellation via Ctrl+C prevented the `Get-LocalGroupMember` component from completing execution. Absence explained by test interruption — not a logging gap. Re-run recommended in a future session to confirm 4798 generation.

**4661 — SAM Handle Requested:**

Absent. No direct SAM database access occurred in the selected tests. Acceptable absence given test design.

**4104 — Script Block Logging:**

Absent. Tests 1 and 3 executed via `cmd.exe` and `net.exe` — not PowerShell script blocks. Test 2's cancellation prevented sufficient PowerShell script block activity from completing. `EnableScriptBlockLogging` registry key confirmed active (value: 1). Not a logging gap — correct behavior confirmed.

---

## Layer 3 — Analyst Narrative

At 14:44:23, Invoke-AtomicRedTeam executed three T1087.002 Domain Account Discovery tests via an elevated PowerShell session under the MERLIN Domain Admin account on the lab domain controller WIN-9J5N24TODJ0 (10.0.10.10). Tests 1 and 3 completed fully. Test 2 was cancelled at 14:51:09 after `Get-ADUser -filter *` exceeded expected execution time; however, the full command block was captured in Sysmon Event ID 1 telemetry prior to interruption, confirming partial execution regardless of completion status.

All three test commands were confirmed across dual telemetry sources — Windows Security Event 4688 and Sysmon Event ID 1 — providing independent corroboration of execution. The account MERLIN was attributed as the executing principal across every test-correlated event. No unexpected accounts appeared. The execution chain followed the expected pattern: PowerShell spawning cmd.exe, which invoked native enumeration utilities including `net.exe` and `query.exe`, with Test 2 invoking a child PowerShell process for the Get-ADUser and Get-LocalGroupMember cmdlets.

WinEventLog 4799 confirmed security-enabled local group enumeration across eight events, the majority correlated with test execution. One anomalous event at 14:54:54 was attributed to VSSVC.exe enumerating the Administrators group outside the expected test window. Cross-referencing Sysmon Event ID 7 image load activity identified `MpOAV.dll` and `amsi.dll` loading into the VSS process — confirming Windows Defender on-access scanning as the trigger. This is a documented environmental false positive: VSSVC.exe will appear in 4799 telemetry whenever Defender scans VSS operations during active PowerShell execution. WinEventLog 4627 and 4624 clustered within test execution windows, consistent with domain authentication activity generated when enumeration commands contact AD services.

Secondary events were investigated and resolved. WinEventLog 4673 showed `LsaRegisterLogonProcess()` via `lsass.exe` — the same background LSA pattern documented in Investigation 001, confirmed benign and not correlated with test activity. WinEventLog 4662 appeared at a precise one-hour interval attributed to a machine account performing scheduled AD schema maintenance — reclassified from Bucket D to Bucket A upon verification. Sysmon Event ID 10 confirmed ART framework process access behavior consistent with PowerShell monitoring its own child processes, with no unexpected source images or sensitive target processes observed.

Predicted Event IDs 4661, 4798, and 4104 were absent. 4661 absence is acceptable given no direct SAM database access occurred in the selected tests. 4798 absence is attributed to Test 2 cancellation preventing `Get-LocalGroupMember` from completing — a test design outcome, not a logging gap. 4104 absence is explained by the cmd.exe execution paths used in Tests 1 and 3; Script Block Logging confirmed active via registry verification. No logging gaps were identified in this investigation.

CIS Benchmark control M1028 (Section 2.3.52 — Do Not Allow Anonymous Enumeration of SAM Accounts) and CIS control 5.7.7.2 (Enumerate Administrator Accounts on Elevation: Disabled) were both confirmed active. All enumeration in this investigation required an authenticated MERLIN session — anonymous access was correctly blocked throughout. The detection surface for authenticated domain account enumeration is confirmed adequate via 4688, Sysmon Event ID 1, and 4799 telemetry.

---

## Diamond Model

| Axis | Value |
|---|---|
| **Adversary** | ART simulation — Invoke-AtomicRedTeam (T1087.002 Tests 1, 2, 3) |
| **Capability** | `net.exe` (`net user /domain`, `net group /domain`), `powershell.exe` (`Get-ADUser`, `Get-LocalGroupMember`), `query.exe` — native Windows domain enumeration utilities |
| **Infrastructure** | Local execution on WIN-9J5N24TODJ0 (10.0.10.10) via elevated PowerShell session |
| **Victim** | soc-lab.local AD domain — domain user accounts, group memberships, and active session data enumerated |

---

## ATT&CK Coverage

| Field | Value |
|---|---|
| Technique | T1087.002 — Account Discovery: Domain Account |
| Tactic | Discovery |
| Detection status | **DETECTED** via WinEventLog 4688, Sysmon Event ID 1, WinEventLog 4799 |
| Partial detection | 4798 absent due to Test 2 cancellation — re-run recommended |
| Coverage | Dual-source: 4688 + Sysmon Event ID 1 |

---

## Detection Artifacts

| Artifact | File | Status |
|---|---|---|
| Splunk detection rule | [`detection-rule.spl`](./detection-rule.spl) | Active |
| Sigma rule | [`sigma-rule.yml`](./sigma-rule.yml) | Experimental |
| Diamond Model | [`diamond-model.md`](./diamond-model.md) | Complete |

---

## OSINT Enrichment

No external IOCs generated by this technique. T1087.002 is domain-internal enumeration — no external network connections were attributed to test execution. Threat actor context drawn from ATT&CK documented procedure examples and published incident reports.

---

## Threat Actor Context

| Threat actor | T1087.002 usage |
|---|---|
| APT29 | `Get-ADUser` and `Get-ADGroupMember` during SolarWinds compromise post-compromise phase |
| APT41 | Built-in `net` commands to enumerate domain administrator accounts |
| Medusa Group | `net user /domain` for domain user enumeration |
| Empire | Native PowerShell cmdlets for local and domain account collection |
| FIN7 | Domain account enumeration chained with credential access techniques |

`net user /domain` and `net group /domain` are the most universally observed commands across documented threat actor groups using T1087.002, making detection of their execution from interactive user sessions — particularly outside business hours or from unexpected hosts — a high-value detection opportunity.

---

## Standing Notes Established

The following environmental patterns were identified during this investigation and apply to all subsequent Phase 3 investigations:

1. **VSSVC.exe + 4799** — Windows Defender on-access scanning causes VSSVC.exe to enumerate privileged groups during active PowerShell test execution. Confirmed environmental false positive. Exclude VSSVC.exe from 4799 detection rules.
2. **4673 LsaRegisterLogonProcess** — Background LSA authentication service activity. Appears in every investigation. Confirmed standing false positive — do not re-investigate.
3. **One-hour interval events** — Precise one-hour intervals confirm scheduled automated processes. Not human or attacker activity.
4. **Test cancellation and partial telemetry** — Ctrl+C cancellation does not prevent command block capture in Sysmon Event ID 1. Full CommandLine is logged at invocation, not at completion.
5. **Sysmon RuleName field** — Reflects detection rule labels from the loaded Olaf Hartong configuration ruleset, not confirmed technique attribution. Treat as investigative hypothesis requiring contextual validation. Never close a finding based on RuleName alone.

---

## Investigation Outcome

| Item | Result |
|---|---|
| Tests confirmed in telemetry | 3/3 (Test 2 partial — cancellation documented) |
| Unexpected events requiring investigation | 4 |
| Unexpected events confirmed malicious | 0 |
| Logging gaps identified | 0 |
| Environmental false positives documented | 1 (VSSVC.exe + 4799) |
| Standing notes established | 5 |
| Detection rules created | 2 (SPL + Sigma) |
