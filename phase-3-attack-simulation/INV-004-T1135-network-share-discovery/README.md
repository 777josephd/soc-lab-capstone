# Investigation 004 — T1135 Network Share Discovery

**Status:** CLOSED  
**Date:** April 16, 2026  
**Analyst:** MERLIN (Domain Admin) — soc-lab.local  
**Target:** WIN-9J5N24TODJ0 — 10.0.10.10  
**Simulation framework:** Invoke-AtomicRedTeam (Atomic Red Team)  
**Tests executed:** T1135 Tests 4, 5, 6, 10  
**Investigation opened:** 2026-04-16 15:50:32  
**Test execution:** 2026-04-16 17:21:03  
**Investigation closed:** 2026-04-16 (post Layer 4)

---

## Investigative Note

This investigation represents the fourth consecutive discovery technique documented in this phase. By this point, a structured pre-test research workflow, layered triage methodology, and consistent standing note framework had been established and refined across T1082, T1087.002, and T1069.002. The depth of pre-test prediction, the accuracy of bucket classification, and the quality of Bucket D resolution in this investigation reflect cumulative growth in investigative discipline rather than individual effort on a single technique.

Key improvements visible in this report compared to earlier investigations:

- **Pre-test SPL written before execution** — four distinct searches predicted and documented prior to any test activity, including a dedicated search for the PowerShell Script Block event anticipated from Test 5
- **Bucket D resolved with technical specificity** — 5145 and 5168 absence explained through understanding of OS-level trigger conditions rather than assumption
- **Source port correlation used as investigative evidence** — shared port 51552 across Logs 9/10/11 used to confirm SMB session reuse, not just noted as coincidence
- **Loopback reasoning applied proactively** — Sysmon Event ID 3 predicted as likely absent due to loopback execution and written as a documented expected-absent query before testing, not discovered absent and then rationalized after the fact

---

## Technique Overview

**MITRE ATT&CK:** [T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/)  
**Tactic:** Discovery  
**Platforms:** Windows, Linux, macOS

Adversaries enumerate network shares to identify sources of information for collection and to locate systems of interest for lateral movement. File sharing over Windows networks occurs over the SMB protocol. Native utilities including `net view`, `net share`, and PowerShell's `Get-SmbShare` cmdlet, as well as UNC path directory enumeration targeting administrative shares (`C$`, `ADMIN$`, `IPC$`), are the primary methods. T1135 is consistently observed in the post-compromise discovery phase — after initial access and system enumeration — as the adversary begins mapping the internal network for high-value targets.

ATT&CK notes that T1135 has **no effective preventive mitigations** beyond blocking anonymous enumeration. An adversary with authenticated credentials — the realistic post-compromise scenario — cannot be prevented from enumerating shares through OS configuration alone. Detection is the primary defensive layer.

**Observed threat actors using this technique:** APT32 (Operation Cobalt Kitty — `net view` targeting C$ and ADMIN$), APT39 (CrackMapExec share enumeration and permissions mapping), Conti ransomware (`NetShareEnum()` API call for pre-encryption share discovery), Emotet (`WNetEnumResourceW`), Latrodectus (`cmd.exe /c net view /all`).

---

## Pre-Test Research

### Commands expected

| Command | Purpose | Test | Detection method |
|---|---|---|---|
| `net view \\localhost` | Enumerate shares on local host | Test 4 | 4688, Sysmon 1 |
| `Get-SmbShare` | PowerShell SMB share enumeration | Test 5 | Sysmon 1, 4104 (possible) |
| `net share` | List local shares | Test 6 | 4688, Sysmon 1 |
| `dir \\127.0.0.1\c$` | UNC path access to C$ | Test 10 | 4688, Sysmon 1, 5140 |
| `dir \\127.0.0.1\admin$` | UNC path access to ADMIN$ | Test 10 | 4688, Sysmon 1, 5140 |
| `dir \\127.0.0.1\IPC$` | UNC path access to IPC$ | Test 10 | 4688, Sysmon 1, 5140 |

### Event IDs predicted

| Source | Event ID | Expected? | Rationale |
|---|---|---|---|
| Windows Security Log | 4688 — Process Creation | Yes | All tests spawn cmd.exe or powershell.exe |
| Windows Security Log | 5140 — Network share object accessed | Yes | Test 10 UNC path access to administrative shares |
| Windows Security Log | 5145 — Share object access check | Possible | Only fires on object-level access within share — not guaranteed |
| Windows Security Log | 5168 — SPN check failure | Possible | Only fires on Kerberos SMB negotiation — loopback uses NTLM |
| PowerShell Log | 4104 — Script Block Logging | Possible | Test 5 uses Get-SmbShare — may bypass script block pipeline |
| Sysmon | Event ID 1 — Process Create | Yes | Full CommandLine capture for all tests |
| Sysmon | Event ID 3 — Network Connection | Expected absent | Loopback SMB typically does not generate Sysmon 3 — documented as expected-absent |
| Sysmon | Event ID 17 — Pipe Created | Possible | SMB IPC$ communication may generate named pipe artifacts |

### Pre-test SPL searches written before execution

Four searches were written and documented before any test was executed — a discipline developed across prior investigations.

**Search 1 — Process creation sweep:**
```splunk
(index=soc-lab-ad OR index=sysmon-ad) earliest="2026-04-16T17:21:03"
(EventCode=4688 OR EventCode=1)
(Process_Command_Line="*net view*" OR Process_Command_Line="*net share*"
 OR CommandLine="*net view*" OR CommandLine="*net share*"
 OR CommandLine="*Get-SmbShare*" OR Process_Command_Line="*Get-SmbShare*"
 OR CommandLine="*dir \\\\*" OR Process_Command_Line="*dir \\\\*")
| table _time, EventCode, Account_Name, Process_Command_Line, CommandLine,
  ParentImage, ParentCommandLine, Image, host
| sort _time
```

**Search 2 — SMB share access events:**
```splunk
(index=soc-lab-ad) earliest="2026-04-16T17:21:03"
(EventCode=5140 OR EventCode=5145 OR EventCode=5168)
| table _time, EventCode, Account_Name, Account_Domain, Logon_ID,
  src_ip, src_port, Share_Name, Share_Path, Relative_Target_Name,
  Access_Mask, Accesses, host
| sort _time
```

**Search 3 — Sysmon network connections (expected absent — documented):**
```splunk
(index=sysmon-ad) earliest="2026-04-16T17:21:03"
EventCode=3
(DestinationPort=445 OR DestinationPort=139)
| table _time, Image, User, SourceIp, SourcePort,
  DestinationIp, DestinationPort, host
| sort _time
```
*Predicted absent due to loopback execution. Query written and run to confirm absence — not assumed.*

**Search 4 — PowerShell Script Block Logging for Test 5:**
```splunk
(index=sysmon-ad) earliest="2026-04-16T17:21:03"
EventCode=4104
ScriptBlockText="*Get-SmbShare*"
| table _time, ScriptBlockText, Path, Computer, host
| sort _time
```
*Predicted as possible, not certain. Get-SmbShare may bypass script block pipeline — outcome to be confirmed during investigation.*

---

## Test Execution

Tests executed sequentially beginning at **17:21:03** via elevated PowerShell session as MERLIN, with 15-second delays between each test.  
Velociraptor pre-execution Pslist Flow ID: `F.D7GH8HSMQKMCS`

```powershell
Invoke-AtomicTest T1135 -TestNumbers 4
Start-Sleep -Seconds 15
Invoke-AtomicTest T1135 -TestNumbers 5
Start-Sleep -Seconds 15
Invoke-AtomicTest T1135 -TestNumbers 6
Start-Sleep -Seconds 15
Invoke-AtomicTest T1135 -TestNumbers 10
```

Initial triage SPL:

```splunk
(index=soc-lab-ad OR index=sysmon-ad) earliest="2026-04-16T17:21:03"
| stats count by sourcetype, EventCode
| sort -count
```

---

## Layer 1 — Event Triage

| Bucket | Event | Count | Classification |
|---|---|---|---|
| A — Background noise | Sysmon 13 (Registry value set) | 376 | Expected OS background |
| A — Background noise | Sysmon 12 (Registry object created/deleted) | 116 | Expected OS background |
| A — Background noise | WinEventLog 4627 (Group membership information) | — | Logon subcategory — background |
| A — Background noise | WinEventLog 4634 (Account logged off) | — | Background logoff activity |
| A — Background noise | WinEventLog 4672 (Special privileges assigned) | — | Domain Admin session — background |
| A — Background noise | WinEventLog 4702 (Scheduled task updated) | 1 | Outside test window |
| A — Background noise | WinEventLog 4800 (Workstation locked) | 1 | Environmental — not test correlated |
| B — Expected telemetry | WinEventLog 4688 (Process Creation) | 132 | Filtered for test commands — see Layer 2 |
| B — Expected telemetry | WinEventLog 5140 (Network share accessed) | 10 | **Primary investigation target** |
| B — Expected telemetry | WinEventLog 4673 (Sensitive Privilege Use) | 4 | Count matches test count — verify |
| B — Expected telemetry | WinEventLog 4624 (Successful Logon) | — | Test-correlated authentication |
| B — Expected telemetry | WinEventLog 4674 (Operation on privileged object) | — | Investigate against test timing |
| B — Expected telemetry | Sysmon 1 (Process Create) | — | Filtered for test commands |
| B — Expected telemetry | Sysmon 3 (Network Connection) | 1 | Expected absent on 445/139 — investigate |
| B — Expected telemetry | Sysmon 10 (Process Access) | — | ART framework overhead |
| B — Expected telemetry | Sysmon 17 (Pipe Created) | 1 | Possible SMB IPC$ artifact |
| C — Unexpected | Sysmon 7 (Image Loaded) | — | DLL load activity — investigate |
| C — Unexpected | Sysmon 11 (File Created) | — | File creation — investigate |
| C — Unexpected | Sysmon 26 (File Delete Logged) | 1 | File deletion — investigate |
| C — Unexpected | WinEventLog 4670 (Permissions on object changed) | 8 | SDDL permission change — investigate |
| D — Predicted absent | WinEventLog 5145 (Share object access check) | 0 | Object-level access not triggered — see Layer 2 |
| D — Predicted absent | WinEventLog 5168 (SPN check failure) | 0 | Loopback NTLM — Kerberos not invoked — see Layer 2 |

---

## Layer 2 — Investigation by Priority

### Priority 1 — WinEventLog 4688 + Sysmon Event ID 1 (Process Creation) — Bucket B

**Finding: All four tests confirmed across dual telemetry sources.**

| Timestamp | CommandLine | Test | Source | Account |
|---|---|---|---|---|
| 17:21:27.166 | `"cmd.exe" /c net view \\localhost` | Test 4 | 4688 + Sysmon 1 | MERLIN |
| 17:22:42.416 | `"powershell.exe" & {get-smbshare}` | Test 5 | Sysmon 1 only | MERLIN |
| 17:23:38.675 | `"cmd.exe" /c net share` | Test 6 | 4688 + Sysmon 1 | MERLIN |
| 17:24:20.200 | `"cmd.exe" /c dir \\127.0.0.1\c$ & dir \\127.0.0.1\admin$ & dir \\127.0.0.1\IPC$` | Test 10 | 4688 + Sysmon 1 | MERLIN |

Execution chain confirmed for all cmd.exe tests: **powershell.exe → cmd.exe → net.exe or dir**. Test 5 (`Get-SmbShare`) captured by Sysmon Event ID 1 only — no corresponding 4688 was generated. This is a confirmed Security Log visibility gap for intra-process PowerShell cmdlet execution: when PowerShell invokes a child PowerShell process inline via script block, the execution may occur within the same process context without creating a new process entry visible to 4688. Sysmon operates at a lower kernel level and captured it regardless.

**Assessment: CONFIRMED — All four tests detected. Dual-source coverage for cmd.exe tests. Sysmon-only coverage for Get-SmbShare — 4688 gap documented.**

---

### Priority 2 — WinEventLog 5140 (Network Share Object Accessed) — Bucket B

**Finding: Administrative share access captured — MERLIN session token identified as anomalous indicator.**

```splunk
(index=soc-lab-ad) earliest="2026-04-16T17:21:03"
(EventCode=5140 OR EventCode=5145 OR EventCode=5168)
| table _time, EventCode, Account_Name, Account_Domain, Logon_ID,
  src_ip, src_port, Share_Name, Share_Path, Relative_Target_Name,
  Access_Mask, Accesses, host
| sort _time
```

| Log | Timestamp | Share_Name | Source_Address | src_port | Logon_ID | Test |
|---|---|---|---|---|---|---|
| Log 8 | 17:21:27.839 | `\\*\IPC$` | `::1` | 51541 | 0xADB63 | Test 4 |
| Log 9 | 17:24:20.619 | `\\*\IPC$` | 127.0.0.1 | 51552 | 0xADB63 | Test 10 |
| Log 10 | 17:24:20.782 | `\\*\C$` | 127.0.0.1 | 51552 | 0xADB63 | Test 10 |
| Log 11 | 17:24:20.858 | `\\*\ADMIN$` | 127.0.0.1 | 51552 | 0xADB63 | Test 10 |

**Key analytical observations:**

**Account_Name — MERLIN vs WIN-9J5N24TODJ0$:** Standard background SMB activity on this host is attributed to the machine account `WIN-9J5N24TODJ0$` (Logon ID 0x3E4). The appearance of user account MERLIN with Logon ID 0xADB63 across all four share access events is the primary anomaly indicator — it establishes that these connections originated from an interactive user session rather than a background OS process. In a real investigation, this distinction between user account and machine account in 5140 events is a high-fidelity signal of human-initiated share enumeration.

**Logon ID 0xADB63 — session consistency:** The same Logon ID appears across all four 5140 events, confirming they belong to a single authenticated SMB session — MERLIN's interactive logon. This allows an analyst to correlate backwards to the original 4624 logon event that established the session, building a complete authentication chain.

**Source port analysis — SMB session reuse:** Test 4 (Log 8) used source port 51541. Test 10 (Logs 9, 10, 11) used source port 51552 for all three sequential share accesses. The shared port across IPC$, C$, and ADMIN$ in Test 10 confirms SMB connection reuse — a single session was established and reused to enumerate all three administrative shares in sequence rather than opening three independent connections.

**Source address discrepancy — Log 8:** Log 8 shows Source_Address `::1` (IPv6 loopback) while Logs 9-11 show `127.0.0.1` (IPv4 loopback). This difference reflects the loopback address negotiation behavior between the two tests rather than a connectivity anomaly — both confirm entirely local execution with no remote infrastructure.

**Assessment: CONFIRMED — Share-level access to IPC$, C$, and ADMIN$ captured. MERLIN account and session Logon ID 0xADB63 identify interactive user-initiated enumeration. Source addresses confirm loopback — local simulation only.**

---

### Priority 3 — Sysmon Event ID 7 (Image Loaded) — Bucket C

**Finding: .NET CLR initialization sequence — PowerShell managed cmdlet execution artifact.**

All Sysmon 7 events were attributed to `powershell.exe` under user MERLIN, beginning at 17:22:42 — correlated with Test 5's Get-SmbShare execution window.

| DLL loaded | Classification |
|---|---|
| `mscoree.dll` | .NET CLR host initialization |
| `mscoreei.dll` | CLR engine interface |
| `clr.dll` | Common Language Runtime |
| `mscorlib.dll` | Core .NET base class library |
| `System.Management.Automation.dll` | PowerShell automation engine |
| `clrjit.dll` | CLR JIT compiler |
| `MpOAV.dll` | Windows Defender on-access scan component |
| `MpClient.dll` | Windows Defender client component |
| `UrlMon.dll` | URL moniker — PowerShell module resolution path |

The mscoree → mscoreei → clr → mscorlib chain is the standard .NET CLR initialization sequence that fires when PowerShell first loads the .NET runtime to execute a managed cmdlet. This sequence is specific to Test 5 — `Get-SmbShare` is a managed PowerShell cmdlet that requires the .NET CLR to initialize before execution. The same DLL sequence will not appear for the native cmd.exe-based tests.

MpOAV.dll and MpClient.dll are Windows Defender on-access scanning components loading into the PowerShell process — Defender inspecting the process at execution time. This is the same standing behavior documented in prior investigations. UrlMon.dll's presence is attributable to PowerShell module resolution paths during cmdlet loading.

**Assessment: CONFIRMED BENIGN — .NET CLR initialization for Get-SmbShare managed cmdlet execution, with Defender on-access inspection artifacts. The DLL load sequence is a composite behavioral signal: CLR initialization followed by SMB-related process creation is a detection indicator for PowerShell-based share enumeration, though benign in this context.**

---

### Priority 4 — Sysmon Event ID 10 (Process Access) — Bucket B

**Finding: ART pre-execution scaffolding — no unexpected source images or sensitive targets.**

PowerShell accessed HOSTNAME.EXE, whoami.exe, and cmd.exe via `PROCESS_ALL_ACCESS`. All three are consistent with ART framework pre-execution context gathering — the same pattern documented across T1082, T1087.002, and T1069.002. No unexpected SourceImages beyond powershell.exe were observed. TargetImage did not include lsass.exe or other sensitive system processes.

**Assessment: CONFIRMED BENIGN — ART pre-execution host enumeration scaffolding. Recurring pattern documented across all Phase 3 investigations.**

---

### Priority 5 — Sysmon Event ID 26 (File Delete Logged) — Bucket C

**Finding: PowerShell execution policy test artifact.**

| Field | Value |
|---|---|
| User | SOC-LAB\MERLIN |
| File path | `C:\Users\MERLIN\AppData\Local\Temp\__PSScriptPolicyTest_pjpdbcoo.hr5.ps1` |
| Timestamp | 17:22:45 |

The `__PSScriptPolicyTest_[random].ps1` naming pattern is the definitive signature of PowerShell's execution policy validation mechanism. When PowerShell prepares to execute a cmdlet under certain execution policy configurations, it writes a temporary `.ps1` file to `%TEMP%` to verify the policy permits script execution, then immediately deletes it. The timing — 17:22:45, within the Test 5 window — directly correlates with Get-SmbShare cmdlet preparation.

**Assessment: CONFIRMED BENIGN — PowerShell execution policy validation artifact. Standing note: this pattern will appear in every investigation involving PowerShell cmdlet execution.**

---

### Priority 6 — Sysmon Event ID 11 (File Created) — Bucket C

**Finding: Routine svchost.exe file creation — no test correlation.**

File creation events attributed to `svchost.exe` under NT AUTHORITY\SYSTEM. No involvement from MERLIN. Timing does not correlate with test execution windows.

**Assessment: CONFIRMED BENIGN — Environmental background file system activity.**

---

### Priority 7 — Sysmon Event ID 3 (Network Connection) — Bucket B

**Finding: Expected-absent on SMB ports — single Defender connection confirmed unrelated.**

The pre-test predicted SPL for Sysmon 3 on ports 445/139 returned no results, confirming the predicted absence of attack-relevant SMB network connections. The port filter was removed to surface all Event ID 3 activity, returning one event:

| Field | Value |
|---|---|
| Image | `MpDefenderCoreService.exe` |
| DestinationIp | 20.189.173.4 |
| DestinationPort | 443 |
| User | NT AUTHORITY\SYSTEM |

Windows Defender cloud telemetry — confirmed standing pattern. Unrelated to test activity.

**Assessment: Attack-relevant Sysmon 3 on ports 445/139 CONFIRMED ABSENT — consistent with loopback SMB execution model. Single observed Event ID 3 confirmed as Defender telemetry.**

---

### Priority 8 — Sysmon Event ID 17 (Pipe Created) — Bucket B

**Finding: PSHost named pipe — PowerShell runtime artifact corroborating Test 5 execution.**

Per standing note established in T1069.002: the `PSHost.[timestamp].[PID].DefaultAppDomain.powershell` naming convention is exclusive to the PowerShell .NET runtime. Timing correlated with Test 5.

**Assessment: CONFIRMED BENIGN — PowerShell runtime pipe. Distinguished from C2 pipes (Cobalt Strike: `\postex_*`, `\msagent_*`) by naming convention and process context.**

---

### Priority 9 — WinEventLog 4670 (Permissions on Object Changed) — Bucket C

**Finding: SDDL permission maintenance — scheduled background activity.**

SDDL `D:(A;;GA;;;SY)(A;;GA;;;NS)` — SYSTEM and NETWORK SERVICE granted Generic All access. Regular interval timing confirms scheduled OS maintenance. Identical to the 4670 pattern documented in T1069.002.

**Assessment: CONFIRMED BENIGN — Standard Windows permission maintenance. Standing environmental pattern.**

---

### Priority 10 — WinEventLog 4673 (Sensitive Privilege Use) — Bucket B

**Finding: LsaRegisterLogonProcess — confirmed standing pattern. Count of 4 correlates with test count.**

The count of 4 matching the number of tests executed initially suggested possible test correlation. Field investigation confirmed all events showed LsaRegisterLogonProcess() via lsass.exe — the same standing background LSA pattern documented across T1082, T1087.002, and T1069.002. The matching count is coincidental.

**Assessment: CONFIRMED BENIGN — Fourth consecutive investigation confirming this as standing environmental background. No further investigation required.**

---

### Bucket D — Resolution

**WinEventLog 5145 — Share Object Access Check — ABSENT**

Event ID 5145 fires when a client requests access to a specific object *within* a share — a named pipe, file, or directory within the share path. The tests executed in this investigation accessed shares at the directory level only using the `dir` command and `net view`. No specific files or named pipes within the shares were targeted. The OS trigger condition for 5145 was never met.

**Status: CORRECT ABSENCE — test design, not logging gap. No auditpol verification required.**

**WinEventLog 5168 — SPN Check Failure — ABSENT**

Event ID 5168 fires when an SPN check fails during Kerberos-based SMB negotiation. Loopback SMB connections to `127.0.0.1` and `::1` use NTLM authentication rather than Kerberos — the loopback address bypasses the Kerberos SPN resolution process entirely. No Kerberos negotiation occurred during these tests; therefore, no SPN check failure could have been generated.

**Status: CORRECT ABSENCE — loopback NTLM, not Kerberos. No logging gap.**

---

## Layer 3 — Analyst Narrative

On April 16, 2026, four Atomic Red Team tests simulating MITRE ATT&CK technique T1135 — Network Share Discovery — were executed against the Windows Server 2022 domain controller WIN-9J5N24TODJ0 between 17:21 and 17:25. Tests 4, 5, 6, and 10 were run sequentially under the domain administrator account MERLIN via an elevated PowerShell session, simulating an authenticated adversary conducting internal reconnaissance to identify accessible network shares as a precursor to lateral movement or collection. The simulation targeted both native enumeration commands and administrative shares, reflecting documented tradecraft used by threat groups including APT32, APT39, and Conti.

All four tests generated confirmed process creation telemetry captured across dual sources. Windows Security Event 4688 and Sysmon Event ID 1 produced corroborating records for each cmd.exe execution — `net view \\localhost` at 17:21:27 (Test 4), `net share` at 17:23:38 (Test 6), and the compound `dir \\127.0.0.1\c$ & dir \\127.0.0.1\admin$ & dir \\127.0.0.1\IPC$` at 17:24:20 (Test 10) — each spawned by powershell.exe under MERLIN's session context. Test 5's `Get-SmbShare` execution at 17:22:42 was captured exclusively by Sysmon Event ID 1, as PowerShell's inline child process execution did not generate a discrete 4688 entry, demonstrating a known Security Log visibility gap for intra-process PowerShell cmdlet execution. Sysmon operates at a lower kernel level and captured the execution regardless.

Windows Security Event 5140 confirmed share-level access for Tests 4 and 10, recording MERLIN's authenticated access to IPC$, C$, and ADMIN$ with Access Mask 0x1 (ReadData/ListDirectory). Critically, all four 5140 events carried Logon ID 0xADB63 — MERLIN's interactive session token — rather than the machine account WIN-9J5N24TODJ0$ (Logon ID 0x3E4), which is the expected actor for background SMB activity on this host. This distinction between a user account and a machine account in 5140 telemetry is a high-fidelity behavioral indicator of human-initiated share enumeration. Source addresses confirmed loopback execution throughout — `::1` for Test 4 and `127.0.0.1` for Test 10 — with no remote infrastructure involved. Source port analysis revealed that Test 4 established an independent SMB session on port 51541, while Test 10's three sequential administrative share accesses all shared port 51552, confirming SMB connection reuse across the C$, ADMIN$, and IPC$ enumeration chain.

Several ancillary and background events were investigated and resolved. Sysmon Event ID 7 captured the .NET CLR initialization sequence — mscoree, mscoreei, clr, mscorlib, and System.Management.Automation — loading into powershell.exe at 17:22:42, directly correlated with Test 5's Get-SmbShare execution. This DLL chain is the standard managed cmdlet runtime signature and is confirmed benign, though its sequential appearance alongside SMB-related process creation constitutes a composite behavioral signal worth retaining for future detection tuning. MpOAV.dll and MpClient.dll loading into the same process reflect Defender on-access inspection — the standing environmental pattern documented across all prior investigations. Sysmon Event ID 26 recorded deletion of `__PSScriptPolicyTest_pjpdbcoo.hr5.ps1` from MERLIN's temp directory at 17:22:45 — the PowerShell execution policy validation artifact consistent with cmdlet preparation for Test 5. Sysmon Event ID 10 confirmed ART pre-execution scaffolding with no unexpected SourceImages or sensitive TargetImages. Sysmon Events ID 11 and 17, WinEventLog 4670, and 4673 were all resolved as standing environmental patterns documented in prior investigations.

Predicted Event IDs 5145 and 5168 were absent and both absences are explained by test design rather than logging gaps. Event ID 5145 requires object-level access within a share — the tests accessed shares at the directory level only, never targeting specific files or named pipes within the share path. Event ID 5168 requires Kerberos-based SMB negotiation — loopback connections to 127.0.0.1 negotiate via NTLM, bypassing Kerberos SPN resolution entirely. The predicted absence of Sysmon Event ID 3 on ports 445 and 139 was confirmed — loopback SMB does not generate Sysmon network connection events in this configuration. The single Sysmon 3 event that did appear was attributed to MpDefenderCoreService.exe contacting Microsoft infrastructure on port 443 — unrelated to test activity.

CIS Benchmark control M1028, implemented under Section 2.3.53 — Do Not Allow Anonymous Enumeration of SAM Accounts and Shares — was not bypassed during this simulation. All share enumeration succeeded because the executing account MERLIN is an authenticated domain administrator with explicit access rights to administrative shares. This control is designed to block unauthenticated enumeration and functioned as intended. ATT&CK explicitly notes that T1135 cannot be effectively mitigated with preventive controls when an adversary has obtained authenticated credentials — making detection the sole defensive layer. The telemetry generated across Events 4688, Sysmon 1, and 5140 confirms that the detection surface is adequate for authenticated share enumeration activity originating from a user-context session.

No open items remain. All Bucket B, C, and D findings have been formally closed with specific field evidence.

---

## Diamond Model

| Axis | Value |
|---|---|
| **Adversary** | ART simulation — Invoke-AtomicRedTeam (T1135 Tests 4, 5, 6, 10) |
| **Capability** | `net view`, `net share`, `Get-SmbShare`, `dir` UNC paths targeting C$, ADMIN$, IPC$ — native Windows SMB enumeration |
| **Infrastructure** | Local execution on WIN-9J5N24TODJ0 (10.0.10.10) via elevated PowerShell. Loopback SMB (127.0.0.1 / ::1) — no external infrastructure involved. |
| **Victim** | WIN-9J5N24TODJ0 — administrative share structure exposed including C$, ADMIN$, and IPC$. Share enumeration enables follow-on lateral movement and targeted data collection. |

---

## ATT&CK Coverage

| Field | Value |
|---|---|
| Technique | T1135 — Network Share Discovery |
| Tactic | Discovery |
| Detection status | **DETECTED** via WinEventLog 4688, Sysmon Event ID 1, WinEventLog 5140 |
| Coverage gap | 4688 absent for Get-SmbShare (Test 5) — Sysmon-only coverage for inline PowerShell cmdlet execution |
| Detection notes | 5140 with user account (non-machine account) accessing administrative shares is a high-fidelity standalone detection signal independent of process creation telemetry |

---

## Detection Artifacts

| Artifact | File | Status |
|---|---|---|
| Splunk detection rule | [`detection-rule.spl`](./detection-rule.spl) | Active |
| Sigma rule | [`sigma-rule.yml`](./sigma-rule.yml) | Experimental |
| Diamond Model | [`diamond-model.md`](./diamond-model.md) | Complete |

---

## OSINT Enrichment

No external IOCs generated. All activity was local SMB enumeration via loopback addressing. No external network connections were attributed to test execution. Threat actor context drawn from ATT&CK documented procedure examples and published incident reports.

---

## Threat Actor Context

| Threat actor | T1135 usage |
|---|---|
| APT32 | `net view` to show all shares including administrative shares C$ and ADMIN$ — Operation Cobalt Kitty |
| APT39 | CrackMapExec to enumerate shared folders and associated permissions across targeted networks |
| Conti | `NetShareEnum()` API call for pre-encryption remote SMB share enumeration |
| Emotet | `WNetEnumResourceW` API for non-hidden network share enumeration |
| Latrodectus | `cmd.exe /c net view /all` for network share discovery |

T1135 is heavily represented in ransomware pre-encryption workflows — Conti, Babuk, BlackCat, LockBit, and others all enumerate network shares before beginning encryption to maximize impact. Detection of share enumeration activity from user-context accounts in environments where administrative tasks are normally performed by service accounts or machine accounts is a pre-ransomware indicator worth prioritizing.

---

## Standing Notes Updated

The following patterns were confirmed or refined during this investigation:

1. **PowerShell cmdlet execution — 4688 gap:** Inline PowerShell cmdlet execution via script block does not generate a discrete 4688 entry. Sysmon Event ID 1 captures it regardless. Detection rules relying solely on 4688 will miss PowerShell-native cmdlet execution.
2. **5140 user vs machine account:** 5140 events attributed to user accounts (no `$` suffix) accessing administrative shares are anomalous relative to background machine account activity. This field distinction is a reliable behavioral indicator for human-initiated share enumeration.
3. **Loopback SMB — NTLM, not Kerberos:** SMB connections to 127.0.0.1 or ::1 use NTLM authentication. Kerberos SPN checks (5168) will not fire for loopback connections. Detection rules that rely solely on 5168 for SMB enumeration detection will miss locally-executed techniques.
4. **5145 trigger condition:** 5145 fires on object-level access within a share. Directory-level enumeration (`net view`, `net share`, `dir \\host\share`) does not trigger 5145. Only file or named pipe access within the share path generates this event.
5. **PSScriptPolicyTest artifact:** `__PSScriptPolicyTest_*.ps1` file creation and deletion in `%TEMP%` is the definitive PowerShell execution policy validation artifact. Confirmed as standing pattern for all investigations involving PowerShell cmdlets.

---

## Cleanup

```powershell
Invoke-AtomicTest T1135 -TestNumbers 4,5,6,10 -Cleanup
```

**Status:** Completed

---

## Investigation Outcome

| Item | Result |
|---|---|
| Tests confirmed in telemetry | 4/4 |
| Pre-test SPL searches written before execution | 4 |
| Unexpected events requiring investigation | 4 (Sysmon 7, 11, 26, WinEventLog 4670) |
| Unexpected events confirmed malicious | 0 |
| Logging gaps identified | 0 |
| Bucket D findings resolved with technical specificity | 2 (5145, 5168 — trigger conditions documented) |
| Key detection insight | 5140 user account vs machine account distinction is a high-fidelity standalone detection signal |
| Standing notes updated | 5 |
| Detection rules created | 2 (SPL + Sigma) |
