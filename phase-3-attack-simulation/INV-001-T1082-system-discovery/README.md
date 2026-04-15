# Investigation 001 — T1082 System Information Discovery

**Status:** CLOSED  
**Date:** April 13, 2026  
**Analyst:** MERLIN (Domain Admin) — soc-lab.local  
**Target:** WIN-[hostname] — 10.0.10.10  
**Simulation framework:** Invoke-AtomicRedTeam (Atomic Red Team)  
**Tests executed:** T1082 Tests 1, 7, 9  
**Baseline timestamp:** 2026-04-13 09:55:22

---

## Technique Overview

**MITRE ATT&CK:** [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)  
**Tactic:** Discovery  
**Platforms:** Windows, Linux, macOS, Cloud

Adversaries enumerate operating system details, hardware configuration, patch levels, and system architecture to inform follow-on decisions — including exploit selection, payload compatibility, and whether to proceed with full compromise. T1082 is one of the most universally observed techniques across documented threat actor groups precisely because it is low-risk, uses native OS utilities, and generates limited noise in default logging configurations.

**Observed threat actors using this technique:** APT41, Lazarus Group, FIN7, Medusa Group, Operation CuckooBees.

---

## Pre-Test Research

### Commands expected

| Command | Purpose | Detection method |
|---|---|---|
| `systeminfo` | Full OS/hardware enumeration | 4688, Sysmon 1 |
| `hostname` | Hostname enumeration | 4688, Sysmon 1 |
| `whoami` | Current user identity | 4688, Sysmon 1 |
| `reg query HKLM\...\Disk\Enum` | Disk enumeration via registry | 4688, Sysmon 1 |
| `REG QUERY HKLM\...\Cryptography /v MachineGuid` | Unique machine identifier | 4688, Sysmon 1 |

### Event IDs predicted

| Source | Event ID | Expected? |
|---|---|---|
| Windows Security Log | 4688 — Process Creation | Yes — primary native source |
| PowerShell Log | 4104 — Script Block Logging | Yes — if PowerShell-based |
| PowerShell Log | 4103 — Module Logging | Yes — if PowerShell-based |
| Sysmon | Event ID 1 — Process Create | Yes — full CommandLine capture |
| Sysmon | Event ID 3 — Network Connection | No — local enumeration only |

---

## Test Execution

Tests executed at **09:55:22** via elevated PowerShell session as MERLIN.  
Velociraptor Pslist Flow ID: `F.D7EBEDIESRC9E`

Initial triage SPL:

```
index=* host=WIN-* earliest="04/13/2026:09:55:22"
| stats count by EventCode, sourcetype
| sort -count
```

---

## Layer 1 — Event Triage

Initial results sorted into four buckets:

| Bucket | Event | Count | Classification |
|---|---|---|---|
| A — Background noise | Sysmon 12 (Registry object created/deleted) | High | Expected OS background |
| A — Background noise | Sysmon 13 (Registry value set) | High | Expected OS background |
| A — Background noise | Sysmon 26 (File delete logged) | High | Expected OS background |
| B — Expected telemetry | Sysmon 1 (Process Create) | 16 | **Primary investigation target** |
| B — Expected telemetry | WinEventLog 4673 (Sensitive Privilege Use) | 5 | Investigate — unexpected for T1082 |
| C — Unexpected | WinEventLog 5140 (Network Share Accessed) | 5 | Investigate |
| C — Unexpected | XmlWinEventLog 10 (Process Access) | 9 | Investigate |
| C — Unexpected | XmlWinEventLog 3 (Network Connection) | 1 | Investigate |
| C — Unexpected | XmlWinEventLog 22 (DNS Query) | 1 | Investigate |
| C — Unexpected | WinEventLog 4702 (Scheduled Task Updated) | 1 | Investigate |
| **D — Predicted absent** | **WinEventLog 4688 (Process Creation)** | **0** | **Logging gap — critical** |

---

## Layer 2 — Investigation by Priority

### Priority 1 — Sysmon Event ID 1 (Process Creation) — Bucket B

**Finding: All three planned tests confirmed.**

The following process creation events were identified in chronological order beginning at 09:55:22:

| Log ref | Timestamp | CommandLine | Assessment |
|---|---|---|---|
| Log-01 | 09:55:22 | `whoami.exe` | ART framework pre-execution identity check |
| Log-02 | 09:55:xx | `cmd.exe /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` | **Test 1** — system info and disk enumeration chained |
| Log-03 | 09:55:xx | `systeminfo` | Secondary systeminfo — ART validation |
| Log-04 | 09:55:xx | `reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` | Registry component of Test 1 |
| Log-05 | 09:55:xx | `cmd.exe /c REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid` | **Test 9** — MachineGUID discovery |
| — | 09:55:xx | `cmd.exe /c hostname` | **Test 7** — hostname enumeration |

<img width="1536" height="756" alt="SPL-query-eventcode1" src="https://github.com/user-attachments/assets/0f0fea27-caeb-4014-b6e6-8f15c2374ec5" />


Execution chain confirmed: **PowerShell → cmd.exe → discovery utilities**. All three planned tests (1, 7, 9) are present in the telemetry. Parent-child relationship is consistent with expected ART behavior.

**wmiprvse.exe — Investigated and closed:**

Two Sysmon Event ID 1 entries showed `wmiprvse.exe -secured -Embedding`. This is the Windows Management Instrumentation Provider Service Host, spawned when WMI queries are made. It appeared because `systeminfo` makes internal WMI calls on modern Windows systems.

Verification SPL:
```
index=sysmon-ad earliest="04/13/2026:09:55:22" EventCode=1
| where Image like "%wmiprvse%"
| table _time, Image, CommandLine, ParentImage, ParentCommandLine, User
```

Confirmed fields:
- ParentImage: `svchost.exe` — correct WMI service host parent
- User: `NT AUTHORITY\NETWORK SERVICE` / `NT AUTHORITY\LOCAL SERVICE` — correct WMI service accounts
- CommandLine: `-secured -Embedding` — normal COM object hosting flag

**Assessment: BENIGN — verified legitimate WMI Provider Service Host activity consistent with systeminfo internal WMI calls.**

---

### Priority 2 — WinEventLog 4673 (Sensitive Privilege Use) — Bucket B/C

**Finding: Background LSA activity — not correlated with test execution.**

Earliest relevant event within the test window:

- Service: `LsaRegisterLogonProcess()` called by `lsass.exe`
- Process ID: `0x2d0`
- Process Name: `C:\Windows\System32\lsass.exe`

This is periodic LSA authentication activity generated regardless of attack simulation. Remaining 4673 events occurred at 09:58:42 and later — outside the expected test execution window.

**Assessment: BENIGN — Background LSA activity. Not correlated with T1082 execution.**

> **Analyst note:** When investigating 4673, always verify the privilege name. `LsaRegisterLogonProcess` is benign background activity. `SeDebugPrivilege` from an unexpected process is a credential dumping indicator. Same Event ID — completely different threat context depending on the calling process and privilege name.

---

### Priority 3 — WinEventLog 5140 (Network Share Accessed) — Bucket C

**Finding: SYSVOL Group Policy background activity — not correlated with test execution.**

Share access events are consistent with Group Policy processing running on its background schedule. This confirms UNC path hardening controls from CIS Section 18.5 (NETLOGON and SYSVOL UNC hardening with `RequireMutualAuthentication=1` and `RequireIntegrity=1`) are active and enforcing authenticated share access.

**Assessment: BENIGN — SYSVOL share access consistent with Group Policy background processing. Not test-generated.**

---

### Priority 4 — XmlWinEventLog 3 + 22 (Network Connection + DNS Query) — Bucket C

**Finding: Windows Defender cloud lookup — not correlated with test execution.**

EventCode 3: `MpDefenderCoreService.exe` (Windows Defender) — timestamp 09:59:01, slightly outside the expected test execution window.

EventCode 22: `dsregcmd.exe` DNS query — Device Registration Command, a legitimate Microsoft diagnostic tool for Azure AD device registration. Background OS activity unrelated to tests.

**Assessment: BENIGN — Background Windows service activity. Not test-generated.**

---

### Priority 5 — WinEventLog 4702 (Scheduled Task Updated) — Bucket C

**Finding: Outside test window — not correlated with test execution.**

Timestamp: 09:59:31 — outside expected telemetry window. Standard Windows scheduled task maintenance activity.

**Assessment: BENIGN — Pre-existing background activity. Not test-generated.**

---

### Priority 6 — XmlWinEventLog 10 (Process Access) — Bucket C

**Finding: ART framework process access — expected behavior, GrantedAccess confirmed low-risk.**

Events within test window (09:57:37–09:57:xx):

| Log ref | Timestamp | Source (SourceImage) | Target (TargetImage) |
|---|---|---|---|
| Log-09 | 09:57:37 | `powershell.exe` | `HOSTNAME.EXE` |
| Log-10 | 09:57:xx | `powershell.exe` | `whoami.exe` |
| Log-11 | 09:57:xx | `powershell.exe` | `cmd.exe` |

<img width="1536" height="762" alt="GrantedAccess" src="https://github.com/user-attachments/assets/a5545467-9f85-4f03-9a4c-b3a0aed8c54e" />


These represent the ART framework monitoring child processes it spawned — expected behavior.

Events slightly outside window (09:59:47): `powershell.exe` accessing `HOSTNAME.EXE` and `whoami.exe` — consistent with ART cleanup routines running post-test.

**Standing note for all Phase 3 investigations:** ART tests are executed as MERLIN (Domain Admin). `PROCESS_ALL_ACCESS (0x1fffff)` on ART-spawned child processes is expected throughout Phase 3. Escalate only when SourceImage is not a known ART process, TargetImage is `lsass.exe` or other sensitive system processes, or timing does not correlate with known test execution windows.

**Assessment: BENIGN — ART framework process monitoring of its own child processes. GrantedAccess values consistent with framework behavior, not credential access.**

---

### Priority 7 — WinEventLog 4688 (Process Creation) — **Bucket D — CRITICAL**

**Finding: 4688 ABSENT — logging gap identified.**

Windows Security Event ID 4688 generated zero events for the test window despite Sysmon Event ID 1 capturing 16 process creation events for the same activity. Category-level audit policy was overriding the subcategory setting configured in GPMC during Phase 2 CIS hardening (Section 17.3.2 — Audit Process Creation: Success).

This represents a genuine detection gap: in the absence of Sysmon, process creation activity would have been entirely invisible to the SIEM.

**Resolution:** Advanced Audit Policy subcategory "Process Creation" directly configured to Success in Default Domain Controllers Policy. Verified via:
```
auditpol /get /subcategory:"Process Creation"
```
Result: `Process Creation: Success` confirmed post-`gpupdate`.

**Impact:** All subsequent investigations generate dual-source process creation visibility — Windows Security Event ID 4688 alongside Sysmon Event ID 1.

<img width="1536" height="960" alt="auditpol-config-1-4688" src="https://github.com/user-attachments/assets/353e12d4-ed03-4f8a-8fd5-37e0b135d68c" />


---

## Layer 3 — Analyst Narrative

At 09:55:22, Invoke-AtomicRedTeam executed three T1082 System Information Discovery tests (Tests 1, 7, and 9) via an elevated PowerShell session under the MERLIN Domain Admin account on the lab Domain Controller (10.0.10.10). The execution chain followed the expected pattern: PowerShell spawning cmd.exe, which spawned native discovery utilities including `systeminfo.exe`, `hostname.exe`, `whoami.exe`, and `reg.exe`.

All three planned tests were confirmed in Sysmon Event ID 1 telemetry. `wmiprvse.exe`, which appeared unexpectedly in the process creation log, was investigated and confirmed as legitimate WMI Provider Service Host activity triggered by `systeminfo`'s internal WMI calls — not adversarial behavior.

Secondary events (4673, 5140, Sysmon 3, Sysmon 22, 4702) were investigated and confirmed as pre-existing background activity coincidentally falling within the test window. None were correlated with T1082 execution. Sysmon Event ID 10 process access events confirmed ART framework behavior — PowerShell accessing its own child processes with access rights consistent with framework operation rather than credential theft.

The most significant finding was the absence of Windows Security Event ID 4688, revealing that process creation auditing was not generating native Windows events despite Sysmon capturing the same activity. This logging gap was identified, root-caused, remediated, and verified before the investigation was closed.

No external network connections were attributed to T1082 test execution. No lateral movement indicators were observed. Activity was confined to local system enumeration consistent with the technique definition.

---

## Diamond Model

| Axis | Value |
|---|---|
| **Adversary** | ART simulation — Red Canary Invoke-AtomicRedTeam (T1082 Tests 1, 7, 9) |
| **Capability** | `systeminfo.exe`, `hostname.exe`, `whoami.exe`, `reg.exe` — native Windows discovery utilities |
| **Infrastructure** | Local execution on WIN-[hostname] (10.0.10.10) via elevated PowerShell session |
| **Victim** | WIN-[hostname] 10.0.10.10 — OS version, hardware config, disk enumeration, MachineGUID exposed |

---

## ATT&CK Coverage

| Field | Value |
|---|---|
| Technique | T1082 — System Information Discovery |
| Tactic | Discovery |
| Detection status | **DETECTED** via Sysmon Event ID 1 |
| Detection gap | Windows native 4688 absent during test — remediated post-investigation |
| Coverage post-remediation | Dual-source: 4688 + Sysmon Event ID 1 |

---

## Detection Artifacts

| Artifact | File | Status |
|---|---|---|
| Splunk detection rule | [`detection-rule.spl`](./detection-rule.spl) | Active |
| Sigma rule | [`sigma-rule.yml`](./sigma-rule.yml) | Experimental |
| Diamond Model | [`diamond-model.md`](./diamond-model.md) | Complete |

---

## OSINT Enrichment

No external IOCs generated by this technique. T1082 is local system enumeration — no network connections were attributed to test execution. `wmiprvse.exe` verified via internal field analysis — no external OSINT lookups required.

---

## Threat Actor Context

| Threat actor | T1082 usage |
|---|---|
| APT41 | `systeminfo` during initial reconnaissance |
| Lazarus Group | WMI-based enumeration to avoid command-line detection |
| FIN7 | Chains system discovery with network discovery before lateral movement |
| Medusa Group | `cmd.exe /c systeminfo` |
| Operation CuckooBees | `systeminfo` to gather compromised system details |

`systeminfo.exe` is the most universally observed command across all documented threat actor groups using T1082 — making detection of its execution from unexpected parent processes a high-value, low-noise detection opportunity.

---

## Investigation Outcome

| Item | Result |
|---|---|
| Tests confirmed in telemetry | 3/3 |
| Unexpected events requiring investigation | 6 |
| Unexpected events confirmed malicious | 0 |
| Logging gaps identified | 1 (4688 — Process Creation) |
| Logging gaps remediated | 1 |
| Detection rules created | 2 (SPL + Sigma) |
