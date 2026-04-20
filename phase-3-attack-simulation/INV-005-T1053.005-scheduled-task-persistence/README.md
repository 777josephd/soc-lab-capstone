# INV-005 — T1053.005 Scheduled Task/Job: Scheduled Task

**Status:** CLOSED  
**Date:** 2026-04-17  
**Analyst:** SOC-LAB\MERLIN (Domain Admin) — soc-lab.local  
**Target:** WIN-9J5N24TODJ0 — 10.0.10.10  
**Simulation framework:** Invoke-AtomicRedTeam (Atomic Red Team)  
**Tests executed:** T1053.005 Tests 1, 4, 6, 7  
**Investigation opened:** 2026-04-17 21:13:06  
**Test execution:** 2026-04-17 23:00:23  
**Investigation closed:** 2026-04-19  
**Type:** Full Vertical Slice

---

## Investigative Note

This investigation marks the transition from lightweight discovery technique coverage into the full vertical slice workflow. INV-005 is the first investigation in this capstone to deliver the complete detection-to-remediation chain: ART simulation, layered SIEM triage, detection engineering, Sigma rule authorship, n8n SOAR workflow, and Ansible remediation — all validated end-to-end in a live lab environment.

Four ART tests were selected across three distinct execution paths, each producing materially different telemetry signatures. This intentional diversity required a detection rule covering multiple method branches rather than a single binary or command pattern, reflecting production-grade detection engineering practice.

Key accomplishments visible in this investigation relative to prior work:

- **First full vertical slice delivered** — detection, SOAR, and IaC remediation all functional and validated
- **Velociraptor technique-specific hunt executed before cleanup** — Windows.System.TaskScheduler artifact captured all five ART tasks pre-cleanup, closing the persistent gap from prior investigations
- **n8n severity branching implemented and tested** — CRITICAL path triggers Ansible remediation, HIGH/MEDIUM path logs response timeline only
- **End-to-end automation validated** — Splunk alert → n8n webhook → SSH to Rocky Linux → Ansible WinRM → Windows DC remediation → artifact verification confirmed
- **Detection gap formally documented** — HKCU registry write invisible to both Windows audit and Sysmon pipelines; compensating visibility through 4698 TaskContent and Sysmon 1 CommandLine documented with Ansible remediation accounting for both artifacts
- **Layer 4 narrative written with inline log evidence** — every analytical assertion traced to a specific log, field, and value

Infrastructure challenges encountered and resolved during this investigation:

- ansible.windows.win_scheduled_task confirmed as non-existent in ansible.windows collection — correct module is community.windows.win_scheduled_task
- ansible-core 2.16+ required for community.windows 3.x — Python 3.11 virtual environment provisioned on Rocky Linux control node running ansible-core 2.19.8
- pywinrm not inherited from system Python — explicitly installed into venv
- n8n Code node payload path resolution — $('Webhook').first().json required for nodes preceded by action nodes on TRUE branch

---

## Technique Overview

**MITRE ATT&CK:** [T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)  
**Tactics:** Persistence, Execution, Privilege Escalation  
**Platforms:** Windows

Adversaries abuse the Windows Task Scheduler to establish persistence through initial or recurring execution of malicious code. Scheduled task persistence survives reboots without requiring re-exploitation, giving an adversary guaranteed code execution across system restarts. SYSTEM-context tasks eliminate the need for further privilege escalation. Tasks masquerading under trusted process names reduce likelihood of detection by name-based filtering. Hidden tasks created via registry SD deletion survive standard schtasks /query enumeration entirely.

Three primary execution paths are observed in the wild: the schtasks.exe CLI binary, PowerShell native task cmdlets (Register-ScheduledTask, New-ScheduledTaskAction), and WMI Invoke-CimMethod via the PS_ScheduledTask namespace. A fourth variant — registry-stored Base64 payload executed via IEX chain — is documented in Qakbot campaigns and represents the highest-severity persistence mechanism covered in this investigation.

ATT&CK notes no effective preventive mitigations beyond privileged account restrictions when an adversary has obtained administrative credentials. Detection is the primary defensive layer.

**Observed threat actors using this technique:**

| Actor | Method | Campaign / Context |
|---|---|---|
| APT29 | schtasks create + task modification + restoration to original config | SolarWinds Compromise — SUNSPOT/SUNBURST persistence |
| Qakbot | Base64 registry payload + scheduled task IEX chain | Ransomware delivery campaigns |
| TrickBot | Scheduled task persistence via schtasks | Big game hunting ransomware campaigns |
| Chimera | `schtasks /create /ru "SYSTEM" /tn "update"` invoking Cobalt Strike | Taiwan semiconductor sector targeting |
| Sandworm | GPO-deployed scheduled task executing CaddyWiper | 2022 Ukraine Electric Power Attack |
| Lazarus Group | Periodic scheduled task executing remote XSL script | Operation Dream Job |

---

## Pre-Test Research

### Execution paths expected

| Method | Command / Cmdlet | Test | Detection method |
|---|---|---|---|
| schtasks CLI — onlogon | `schtasks /create /tn T1053_005_OnLogon /sc onlogon /tr "cmd.exe /c calc.exe"` | Test 1 | 4688, 4698, Sysmon 1, 11, 13 |
| schtasks CLI — onstart SYSTEM | `schtasks /create /tn T1053_005_OnStartup /sc onstart /ru system /tr "cmd.exe /c calc.exe"` | Test 1 | 4688, 4698, Sysmon 1, 11, 13 |
| PowerShell native cmdlets | `Register-ScheduledTask AtomicTask` via New-ScheduledTaskAction / New-ScheduledTaskPrincipal | Test 4 | 4698, Sysmon 1, 11, 13 |
| WMI Invoke-CimMethod | `Invoke-CimMethod -ClassName PS_ScheduledTask -MethodName RegisterByXml` | Test 6 | 4698, Sysmon 1, 11, 13 |
| Registry Base64 + IEX | `reg add HKCU\SOFTWARE\ATOMIC-T1053.005` + schtasks IEX chain | Test 7 | 4698, Sysmon 1, 13 |

### Event IDs predicted

| Source | Event ID | Expected? | Rationale |
|---|---|---|---|
| Windows Security Log | 4698 — Scheduled task created | Yes | Primary signal — one per task |
| Windows Security Log | 4688 — Process creation | Yes | schtasks.exe CLI path |
| Windows Security Log | 4657 — Registry value modified | Yes | Test 7 reg add command |
| Windows Security Log | 4702 — Scheduled task updated | Possible | WMI registration path may trigger |
| PowerShell Log | 4104 — Script Block Logging | Yes | Tests 4, 6, 7 involve PowerShell |
| Sysmon | 1 — Process creation | Yes | All tests — full CommandLine capture |
| Sysmon | 11 — FileCreate | Yes | Task XML written to C:\Windows\System32\Tasks\ |
| Sysmon | 12 — RegistryEvent key created | Yes | TaskCache\Tree key creation |
| Sysmon | 13 — RegistryEvent value set | Yes | TaskCache\Tree value writes |

### Pre-test SPL searches written before execution

Five searches were written and documented before any test was executed.

**Search 1 — Scheduled task creation event sweep:**
```splunk
index=* earliest="TIMESTAMP_2"
EventCode=4698
| table _time, Account_Name, Task_Name, TaskContent
| sort _time
```

**Search 2 — Process creation for schtasks.exe and task-related binaries:**
```splunk
index=* earliest="TIMESTAMP_2"
EventCode=4688
(process_name="*schtasks.exe*" OR process_name="*taskeng.exe*" OR process_name="*taskhost.exe*")
| table _time, Account_Name, process_name, Process_Command_Line, Creator_Process_Name
| sort _time
```

**Search 3 — Sysmon correlation across process creation, registry, and file events:**
```splunk
index=sysmon-ad earliest="TIMESTAMP_2"
(EventCode=1 OR EventCode=11 OR EventCode=12 OR EventCode=13)
(Image="*schtasks.exe*" OR Image="*powershell.exe*" OR TargetObject="*Schedule*" OR TargetObject="*ATOMIC*" OR TargetFilename="*Tasks*")
| table _time, EventCode, Image, CommandLine, TargetObject, Details, TargetFilename
| sort _time
```

**Search 4 — PowerShell Script Block Logging for encoded and task-related execution:**
```splunk
index=* earliest="TIMESTAMP_2"
EventCode=4104
(ScriptBlockText="*ScheduledTask*" OR ScriptBlockText="*Register-ScheduledTask*" OR ScriptBlockText="*Invoke-CimMethod*" OR ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*schtasks*")
| table _time, ScriptBlockText, Path
| sort _time
```

**Search 5 — Full timeline correlation across both indexes:**
```splunk
(index=soc-lab-ad OR index=sysmon-ad) earliest="TIMESTAMP_2"
(EventCode=4698 OR EventCode=4688 OR EventCode=4657 OR EventCode=1 OR EventCode=11 OR EventCode=12 OR EventCode=13 OR EventCode=4104)
| eval source_index=index
| table _time, source_index, EventCode, Account_Name, process_name, Process_Command_Line, Image, CommandLine, Task_Name, TargetObject, Details
| sort _time
```

---

## Test Execution

Tests executed sequentially beginning at **23:00:23** via elevated PowerShell session as MERLIN, with 15-second delays between each test.

**Velociraptor pre-execution Pslist:** Flow ID `F.D7HBMLIJIUCO0` — captured before Timestamp #2

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
Start-Sleep -Seconds 15
Invoke-AtomicTest T1053.005 -TestNumbers 4
Start-Sleep -Seconds 15
Invoke-AtomicTest T1053.005 -TestNumbers 6
Start-Sleep -Seconds 15
Invoke-AtomicTest T1053.005 -TestNumbers 7
```

**Velociraptor technique-specific hunt:**

| Artifact | Flow ID | Timing | Result |
|---|---|---|---|
| Windows.System.Pslist (post) | Recorded | After test execution | Compared against baseline |
| Windows.System.TaskScheduler | F.D7HBQF1GB758E | Pre-cleanup | All 5 ART tasks confirmed |

Tasks confirmed in Velociraptor pre-cleanup:

| Task Name | Command | Arguments | RunLevel |
|---|---|---|---|
| \T1053_005_OnLogon | cmd | /c calc.exe | LeastPrivilege |
| \T1053_005_OnStartup | cmd | /c calc.exe | LeastPrivilege |
| \AtomicTask | calc.exe | — | HighestAvailable |
| \T1053_005_WMI | notepad.exe | — | LeastPrivilege |
| \ATOMIC-T1053.005 | cmd | /c start /min "" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\SOFTWARE\ATOMIC-T1053.005).test))) | LeastPrivilege |

Initial triage SPL:

```splunk
index=* earliest="04/17/2026:23:00:23"
| stats count by EventCode, sourcetype
| sort -count
```

---

## Layer 1 — Event Triage

| Bucket | EventCode | Source | Count | Classification |
|---|---|---|---|---|
| A | Sysmon 13 | XmlWinEventLog | 400 | Registry background — compensates for 4657 gap |
| A | Sysmon 12 | XmlWinEventLog | 116 | Registry key creation background |
| A | Sysmon 7 | XmlWinEventLog | — | DLL loads — CLR chain |
| A | 4624 | WinEventLog | — | Logon session background |
| A | 4673 | WinEventLog | — | LSA background — Standing Note #10 |
| A | 4634 | WinEventLog | — | Logoff background |
| A | 4799 | WinEventLog | — | VSSVC.exe FP — Standing Note #5 |
| B | 4688 | WinEventLog | 172 | Process creation — schtasks chain |
| B | 4698 | WinEventLog | 5 | Scheduled task created — primary signal |
| B | 4702 | WinEventLog | 3 | Scheduled task updated — machine account |
| B | 4627 | WinEventLog | — | Group membership — logon session |
| B | 4670 | WinEventLog | — | Object permissions — task registration |
| B | 4674 | WinEventLog | — | Privileged object — WilStaging |
| B | 5140 | WinEventLog | — | Network share — SYSVOL background |
| B | Sysmon 1 | XmlWinEventLog | — | Process creation corroboration |
| B | Sysmon 3 | XmlWinEventLog | 5 | Network connections |
| B | Sysmon 11 | XmlWinEventLog | — | FileCreate — task XML artifacts |
| B | Sysmon 17 | XmlWinEventLog | — | Pipe created — PSHost |
| C | Sysmon 10 | XmlWinEventLog | — | ProcessAccess — parent-child handles |
| D | 4657 | WinEventLog | 0 | Registry modification — audit not enabled |
| D | 4104 | WinEventLog | 0 | Script Block Logging — execution path gap |

---

## Layer 2 — Bucket Classification

### Bucket D — Formal Resolution

**WinEventLog 4657 — Registry Value Modified — ABSENT**

`auditpol /get /subcategory:"Registry"` confirmed No Auditing. CIS Level 1 benchmark excludes Object Access — Registry auditing by design due to prohibitive event volume in production environments. Compensating control: Sysmon 13 provides registry monitoring independently of Windows audit policy at kernel level.

**Status: EXPLAINED — CIS Level 1 design decision. Not a misconfiguration. Compensating control confirmed.**

**WinEventLog 4104 — Script Block Logging — ABSENT**

`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = REG_DWORD 0x1` confirmed active. Absence explained by execution path — Tests 4 and 6 invoke PowerShell via inline script blocks in child processes that do not route through the standard Script Block Logging pipeline in the parent session context. Consistent with Standing Note #12. Compensating visibility: Sysmon 1 captured complete PowerShell blocks for Tests 4, 6, and 7 in CommandLine field.

**Status: EXPLAINED — execution path, not logging failure. Compensating control confirmed.**

---

## Layer 3 — Investigation by Priority

### Priority 1 — WinEventLog 4698 (Scheduled Task Created) — Bucket B

**Finding: Five tasks created across three distinct execution paths — CRITICAL severity finding confirmed.**

| Log | Timestamp | Task_Name | Key Content |
|---|---|---|---|
| Log 1 | 23:03:32 | \ATOMIC-T1053.005 | IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\SOFTWARE\ATOMIC-T1053.005).test))) |
| Log 2 | 23:02:56 | \T1053_005_WMI | notepad.exe — WMI registration path |
| Log 3 | 23:01:06 | \T1053_005_OnStartup | cmd.exe /c calc.exe — LogonTrigger — SYSTEM |
| Log 4 | 23:02:04 | \AtomicTask | calc.exe — BUILTIN\Administrators — RunLevel Highest |
| Log 5 | 23:01:05 | \T1053_005_OnLogon | cmd.exe /c calc.exe — onlogon trigger |

**WHO:** MERLIN across all five task creation events — Domain Admin account, interactive elevated PowerShell session  
**WHAT:** Five scheduled tasks created in 147-second window across three distinct execution paths. Task \ATOMIC-T1053.005 contains Base64-encoded IEX chain reading payload from HKCU registry key — highest severity finding  
**HOW:** schtasks.exe CLI (Tests 1, 7), PowerShell Register-ScheduledTask cmdlets (Test 4), WMI Invoke-CimMethod PS_ScheduledTask namespace (Test 6)  
**FROM WHERE:** All tasks originated from MERLIN's interactive PowerShell session on 10.0.10.10 — no remote origin  
**WHEN:** First task at 23:01:05 (\T1053_005_OnLogon), final task at 23:03:32 (\ATOMIC-T1053.005) — 147 seconds total creation window

**Disposition: CONFIRMED MALICIOUS**  
TaskContent XML is the definitive evidence source — exposes complete task definition including action, trigger, principal, and encoded payload. Five tasks in 147 seconds across three execution paths is not consistent with any legitimate administrative activity pattern.

---

### Priority 2 — WinEventLog 4688 + Sysmon Event ID 1 (Process Creation) — Bucket B

**Finding: Three distinct process execution chains confirmed across dual telemetry sources.**

| Log | Timestamp | process_name | Process_Command_Line | Creator_Process_Name |
|---|---|---|---|---|
| Log 8 | 23:01:05 | cmd.exe | cmd.exe /c schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe" & schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe" | powershell.exe |
| Log 10 | 23:01:05 | schtasks.exe | schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe" | cmd.exe |
| Log 11 | 23:01:05 | schtasks.exe | schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe" | cmd.exe |
| Log 14 | 23:01:48 | powershell.exe | "powershell.exe" & {$Action = New-ScheduledTaskAction -Execute "calc.exe"... Register-ScheduledTask AtomicTask} | powershell.exe |
| Log 20 | 23:02:49 | powershell.exe | "powershell.exe" & {$xml = [System.IO.File]::ReadAllText("C:\AtomicRedTeam\atomics\T1053.005\src\T1053_005_WMI.xml") Invoke-CimMethod -ClassName PS_ScheduledTask...} | powershell.exe |
| Log 55 (Sysmon 1) | 23:03:32 | schtasks.exe | schtasks.exe /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min "" powershell.exe -Command IEX(...)..." | svchost.exe |

**Key finding — Log 55:** svchost.exe as parent of schtasks.exe for Test 7 task creation is visible only in Sysmon 1 — not captured in 4688. This parent process relationship difference between Test 7 and Tests 1/4/6 is a detection engineering finding: the 4688 audit pipeline did not capture the svchost.exe → schtasks.exe chain, while Sysmon 1 captured it regardless. Sysmon 1 is the authoritative source for complete parent-child process chain visibility.

**Disposition: CONFIRMED MALICIOUS**

---

### Priority 3 — Sysmon Event ID 11 (FileCreate — Task XML Artifacts) — Bucket B

**Finding: Five task XML files written to C:\Windows\System32\Tasks\ — on-disk persistence artifacts confirmed.**

| Log | Timestamp | Image | TargetFilename |
|---|---|---|---|
| Log 29 | 23:01:05 | svchost.exe | C:\Windows\System32\Tasks\T1053_005_OnLogon |
| Log 34 | 23:01:05 | svchost.exe | C:\Windows\System32\Tasks\T1053_005_OnStartup |
| Log 43 | 23:02:04 | svchost.exe | C:\Windows\System32\Tasks\AtomicTask |
| Log 52 | 23:02:56 | svchost.exe | C:\Windows\System32\Tasks\T1053_005_WMI |
| Log 59 | 23:03:32 | svchost.exe | C:\Windows\System32\Tasks\ATOMIC-T1053.005 |

Task XML files in C:\Windows\System32\Tasks\ are the on-disk persistence mechanism — read by Task Scheduler at startup to restore registered tasks across reboots. File creation timestamps align within milliseconds of corresponding 4698 events, providing authoritative cross-source timestamp validation.

Additional Sysmon 11 events confirmed benign: PSScriptPolicyTest files (Standing Note #13) and StartupProfileData-NonInteractive files (PowerShell non-interactive session initialization for Tests 4 and 6).

**Disposition: Task XML files — CONFIRMED MALICIOUS. PSScriptPolicyTest and StartupProfileData — CONFIRMED BENIGN.**

---

### Priority 4 — Sysmon Event ID 13 (Registry Value Set) — Bucket B/A

**Finding: TaskCache\Tree registry writes confirm standard visible task registration — Tarrask technique not employed.**

Three registry values written per task under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\[TaskName]\`:

| Value | Content | Significance |
|---|---|---|
| \Id | GUID assigned to task | Task identity reference |
| \SD | Binary Data — Security Descriptor | **Presence confirms task is visible to standard enumeration** |
| \Index | DWORD integer | Task ordering value |

Security Descriptor present for all five tasks confirms none employed the Tarrask hidden task technique (SD deletion requires SYSTEM privileges and renders task invisible to schtasks /query). Absence of SD write following task creation is the detection indicator for hidden task variant.

Additional Sysmon 13 events confirmed benign:
- Background scheduler Index updates for legitimate Microsoft tasks (Flighting\OneSettings\RefreshCache, SoftwareProtectionPlatform\SvcRestartTask) — machine account, unrelated to ART
- BAM (Background Activity Moderator) writes — powershell.exe execution timestamps recorded for power management — forensically useful as execution timeline artifact, not attacker-controlled

**Disposition: TaskCache writes — CONFIRMED MALICIOUS (system response to attacker task registration). BAM writes and background scheduler updates — CONFIRMED BENIGN.**

---

### Priority 5 — WinEventLog 4702 (Scheduled Task Updated) — Bucket B

**Finding: Machine account task housekeeping — no attacker involvement.**

| Timestamp | Account_Name | Task_Name |
|---|---|---|
| 23:01:13 | WIN-\<hostname\>$ | \Microsoft\Windows\Flighting\OneSettings\RefreshCache |
| 23:02:01 | WIN-\<hostname\>$ | \Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask |
| 23:04:15 | WIN-\<hostname\>$ | \Microsoft\Windows\WindowsUpdate\Scheduled Start |

Machine account ($ suffix) updating legitimate Microsoft system tasks — Task Scheduler internal housekeeping. Timing coincidental with test window.

**Disposition: CONFIRMED BENIGN**

---

### Priority 6 — Sysmon Event ID 10 (ProcessAccess) — Bucket C

**Finding: Parent-child handle retention — expected ART execution pattern.**

PowerShell opened PROCESS_ALL_ACCESS (0x1fffff) handles to HOSTNAME.exe, whoami.exe, cmd.exe, and child powershell.exe. CallTrace confirmed handles originated from .NET runtime and PowerShell automation engine (System.Management.Automation.ni.dll present for HOSTNAME.exe and whoami.exe). No lsass.exe or unexpected TargetImage values.

**Disposition: CONFIRMED BENIGN — Standing Note #1 applies.**

---

### Priority 7 — Sysmon Event ID 17 (Pipe Created) — Bucket B

**Finding: PSHost named pipes — PowerShell runtime artifact.**

Four events: User SOC-LAB\MERLIN, Image powershell.exe, PipeName `\PSHost.[timestamp].[PID].DefaultAppDomain.powershell`. Format matches Standing Note #7 exactly. Four pipes correspond to four PowerShell process instances spawned during testing. No Cobalt Strike pipe patterns observed.

**Disposition: CONFIRMED BENIGN — Standing Note #7 applies.**

---

### Priority 8 — Sysmon Event ID 3 (Network Connection) — Bucket B

**Finding: Windows Defender cloud telemetry — confirmed Microsoft infrastructure.**

Two events: Image MsMpEng.exe, DestinationIp 48.211.71.198, DestinationPort 443. OSINT confirmed Microsoft-owned infrastructure via AbuseIPDB and GreyNoise. Defender scanning ART process and file creation activity.

**Disposition: CONFIRMED BENIGN**

---

### Priority 9 — WinEventLog 4674 (Privileged Object Access) — Bucket B

**Finding: WilStaging objects — Windows Error Reporting telemetry buffer.**

Object_Name values `\Sessions\1\BaseNamedObjects\SM0:2376:304:WilStaging_02_p0h` and variants. Process_Name: powershell.exe. WilStaging is the Windows Instrumentation Logging staging buffer — standard telemetry infrastructure behavior during PowerShell execution.

**Disposition: CONFIRMED BENIGN**

---

### Priority 10 — WinEventLog 5140 (Network Share Access) — Bucket B

**Finding: SYSVOL Group Policy background processing — machine account.**

Account_Name: WIN-\<hostname\>$, Share_Name: SYSVOL and IPC$. Machine account ($ suffix). Standing Note #11 applies.

**Disposition: CONFIRMED BENIGN**

---

### Priority 11 — WinEventLog 4627, 4670 (Group Membership, Object Permissions) — Bucket B

4627: Logon session group membership metadata for MERLIN's interactive session. 4670: Computer account applying permissions to task objects after creation — Task Scheduler service behavior.

**Disposition: CONFIRMED BENIGN**

---

### Detection Gap — HKCU Registry Write (Test 7 Payload Storage)

**Finding: reg add HKCU\SOFTWARE\ATOMIC-T1053.005 not captured in any telemetry source.**

- 4657: Absent — Object Access Registry auditing = No Auditing per CIS Level 1
- Sysmon 13: Absent — HKCU\SOFTWARE\ATOMIC-T1053.005 path outside Olaf Hartong ruleset monitored scope
- Targeted query `TargetObject="*ATOMIC-T1053.005*"` returned only TaskCache\Tree entries

**Compensating visibility:**
- 4698 TaskContent XML references `HKCU:\SOFTWARE\ATOMIC-T1053.005` — key name exposed through task definition
- Sysmon 1 Log 55 CommandLine contains full Base64 IEX chain including registry key reference
- Velociraptor Flow ID F.D7HBQF1GB758E confirmed task arguments pre-cleanup

**Ansible remediation implication:** Two-artifact remediation required — scheduled task deletion + HKCU\SOFTWARE\ATOMIC-T1053.005 registry key removal — despite absence of direct registry write telemetry.

---

## Layer 4 — Analyst Narrative

On April 17, 2026, at 23:00:23, MERLIN initiated an ART-simulated persistence operation against WIN-9J5N24TODJ0 (10.0.10.10) using four distinct scheduled task creation techniques mapped to MITRE ATT&CK T1053.005. The operation spanned 147 seconds and produced five scheduled tasks across three execution paths — the schtasks.exe CLI binary, PowerShell native task cmdlets, and WMI Invoke-CimMethod via the PS_ScheduledTask namespace.

> **Log 8 (4688):** `cmd.exe /c schtasks /create /tn "T1053_005_OnLogon" /sc onlogon... & schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system...` — confirms schtasks.exe CLI path, Test 1, compound command creating two tasks simultaneously.
>
> **Log 14 (4688):** `"powershell.exe" & {$Action = New-ScheduledTaskAction -Execute "calc.exe"... Register-ScheduledTask AtomicTask}` — confirms PowerShell native cmdlet path, Test 4.
>
> **Log 20 (4688):** `"powershell.exe" & {$xml = [System.IO.File]::ReadAllText("C:\AtomicRedTeam\atomics\T1053.005\src\T1053_005_WMI.xml") Invoke-CimMethod -ClassName PS_ScheduledTask...}` — confirms WMI Invoke-CimMethod path, Test 6.
>
> **Log 55 (Sysmon 1):** svchost.exe executing schtasks.exe with full IEX Base64 chain — Test 7. Parent process svchost.exe not captured in 4688, visible only in Sysmon 1.

The most significant artifact produced was task \ATOMIC-T1053.005, whose TaskContent XML contained a Base64-encoded IEX chain reading a payload from a user-controlled registry key at HKCU:\SOFTWARE\ATOMIC-T1053.005 — a documented Qakbot persistence mechanism representing the highest-severity finding of this investigation.

> **Log 1 (4698):** Task_Name: `\ATOMIC-T1053.005`, TaskContent: `IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\SOFTWARE\ATOMIC-T1053.005).test)))` — TaskContent is the definitive evidence source exposing the encoded payload chain and registry key reference.

Telemetry was confirmed across multiple sources. Event ID 4698 produced five task creation events between 23:01:05 and 23:03:32, one per registered task, with TaskContent XML providing complete visibility into each task's action, trigger, and principal configuration. Event ID 4688 and Sysmon Event ID 1 jointly confirmed the three execution chains. Sysmon Event ID 11 captured the five on-disk persistence artifacts — task XML files written to C:\Windows\System32\Tasks\ by svchost.exe immediately following each 4698 event.

> **Log 29 (Sysmon 11):** TargetFilename `C:\Windows\System32\Tasks\T1053_005_OnLogon` — Image svchost.exe, 23:01:05, milliseconds after corresponding 4698.
>
> **Log 59 (Sysmon 11):** TargetFilename `C:\Windows\System32\Tasks\ATOMIC-T1053.005` — Image svchost.exe, 23:03:32, milliseconds after Log 1 (4698).

Sysmon Event ID 13 documented TaskCache\Tree registry writes for all five tasks, with Security Descriptor values present for all — confirming none employed the Tarrask hidden task technique of SD deletion.

> **Logs 26-28 (Sysmon 13):** svchost.exe writing `HKLM\...\Schedule\TaskCache\Tree\T1053_005_OnLogon\Id`, `\SD`, `\Index` — SD present confirms task visible to standard enumeration. Absence of SD write following task creation is the Tarrask detection indicator — its presence here is a definitive negative finding for that variant.

Background noise was resolved cleanly. Event ID 4702 produced three scheduled task update events attributed entirely to the machine account WIN-\<hostname\>$ updating legitimate Microsoft system tasks — unrelated to ART activity.

> **4702 Logs 1-3:** Account_Name WIN-\<hostname\>$ across all three events — machine account ($ suffix) and legitimate Microsoft Task_Name values are the definitive benign indicators.

Sysmon Event ID 17 produced four PSHost named pipe events from MERLIN's PowerShell instances.

> **Sysmon 17 Logs 1-4:** PipeName `\PSHost.[timestamp].[PID].DefaultAppDomain.powershell` — format matches Standing Note #7. No Cobalt Strike patterns observed.

Sysmon Event ID 10 showed powershell.exe opening PROCESS_ALL_ACCESS handles to its own child processes.

> **Sysmon 10 Logs 1-4:** TargetImages — HOSTNAME.exe, whoami.exe, cmd.exe, powershell.exe. No lsass.exe. Standing Note #1 applies. CallTrace includes System.Management.Automation.ni.dll for HOSTNAME.exe and whoami.exe, confirming handles originated from PowerShell automation engine.

Windows Defender generated two outbound port 443 connections to confirmed Microsoft infrastructure.

> **Sysmon 3 Logs 1-2:** MsMpEng.exe, DestinationIp 48.211.71.198 — confirmed Microsoft-owned via AbuseIPDB and GreyNoise.

Two Bucket D findings were formally investigated. Event ID 4657 was absent because Object Access — Registry auditing is not enabled per CIS Level 1 design.

> **auditpol verification:** `auditpol /get /subcategory:"Registry"` returned No Auditing — confirmed 2026-04-17. Compensating control: Sysmon 13.

Event ID 4104 was absent despite EnableScriptBlockLogging being confirmed active.

> **Registry verification:** `EnableScriptBlockLogging = REG_DWORD 0x1` confirmed. Compensating visibility: Sysmon 1 Log 37 captures complete Test 4 PowerShell block; Log 47 captures complete Test 6 WMI block.

A material detection gap was identified for the Test 7 registry payload storage component. The reg add command writing to HKCU:\SOFTWARE\ATOMIC-T1053.005 is invisible to both the Windows audit pipeline and the Sysmon 13 pipeline.

> **4657:** Absent — Object Access Registry auditing not enabled.
>
> **Sysmon 13 targeted query** `TargetObject="*ATOMIC-T1053.005*"`: returned only TaskCache\Tree entries — HKCU\SOFTWARE\ATOMIC-T1053.005 write not captured.
>
> **Compensating visibility — Log 1 (4698):** TaskContent XML references `HKCU:\SOFTWARE\ATOMIC-T1053.005` in IEX chain.
>
> **Compensating visibility — Log 55 (Sysmon 1):** schtasks.exe CommandLine contains full Base64 IEX chain including registry key reference.
>
> **Velociraptor — Flow ID F.D7HBQF1GB758E:** Windows.System.TaskScheduler captured \ATOMIC-T1053.005 task arguments pre-cleanup — independent ground truth.

CIS hardening controls performed as expected. M1028 (Section 2.3.18) confined task creation to MERLIN's Domain Admin session. M1026 (Section 2.2.28) is consistent with the elevated privilege context required for SYSTEM-context task registration in Test 1.

> **Test 1 (Log 11, 4688):** `schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system` — `/ru system` flag requires Domain Admin privileges. M1028 validated.
>
> **Test 4 (Log 37, Sysmon 1):** `New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest` — explicitly requests highest privilege. M1026 validated.

No hardening controls were bypassed. All findings carry formal dispositions. All Bucket D absences are explained. All detection gaps are documented with compensating controls. Investigation complete.

---

## Diamond Model

| Axis | Value |
|---|---|
| **Adversary** | ART simulation — Invoke-AtomicRedTeam (T1053.005 Tests 1, 4, 6, 7). Techniques mapped to APT29, Qakbot, TrickBot, Chimera, Sandworm |
| **Capability** | schtasks.exe CLI (/sc onlogon, /sc onstart /ru system), PowerShell Register-ScheduledTask cmdlets (RunLevel Highest, BUILTIN\Administrators principal), WMI Invoke-CimMethod PS_ScheduledTask RegisterByXml, Base64 registry payload IEX chain (Qakbot TTP) |
| **Infrastructure** | WIN-9J5N24TODJ0 (10.0.10.10) — MERLIN elevated PowerShell session. Task XML files: C:\Windows\System32\Tasks\. Registry payload: HKCU\SOFTWARE\ATOMIC-T1053.005. TaskCache: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\ |
| **Victim** | WIN-9J5N24TODJ0 — Windows Server 2022 Domain Controller, SOC-LAB.local. Five persistence mechanisms established across reboot and logon triggers. SYSTEM-context task provides guaranteed elevated execution. Base64 registry chain provides fileless payload storage with obfuscated execution. Domain Admin credentials, AD database, and all domain-joined systems at risk. |

---

## ATT&CK Coverage

| Field | Value |
|---|---|
| Technique | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Tactics | Persistence, Execution, Privilege Escalation |
| Detection status | **DETECTED** across all three execution paths |
| Primary sources | WinEventLog 4698 (TaskContent), Sysmon 1, Sysmon 11, Sysmon 13 |
| Coverage gap | HKCU registry write (Test 7 payload storage) not captured in any pipeline — compensating visibility via 4698 TaskContent and Sysmon 1 CommandLine |
| Detection notes | TaskContent XML in 4698 is the highest-value field for scheduled task investigations — exposes complete task definition including encoded payloads invisible elsewhere in the telemetry stack |

---

## Detection Artifacts

| Artifact | File | Status |
|---|---|---|
| Splunk detection rule | `detection-rule.spl` | Active — 5 minute schedule |
| Sigma rule | `sigma-rule-T1053.005.yml` | Experimental |
| Diamond model | `diamond-model.md` | Complete |
| n8n SOAR workflow | `n8n-workflow.json` | Published — active |
| Ansible remediation play | `ansible-play.yml` | Validated — ok=7 changed=4 |

---

## SOAR Integration — n8n

**Platform:** n8n — http://10.0.20.100:5678  
**Workflow:** T1053.005 - Scheduled Task Persistence Response  
**Trigger:** Splunk webhook POST on alert fire  
**Webhook URL:** http://10.0.20.100:5678/webhook/splunk-t1053

**Workflow logic:**

```
Splunk alert fires → n8n webhook receives JSON payload
→ IF node evaluates severity field
  → CRITICAL: SSH to Rocky Linux (10.0.10.105)
              → ansible-playbook t1053005-remediation.yml
              → Code node logs remediation timeline
  → HIGH/MEDIUM: Code node logs response timeline only
```

**Severity branching:**

| Severity | Trigger condition | n8n action |
|---|---|---|
| CRITICAL | TaskContent contains IEX, FromBase64String, EncodedCommand, GetItemProperty | SSH → Ansible remediation + log |
| HIGH | TaskContent contains powershell, cmd.exe, wscript, cscript, mshta, rundll32; or 4688/Sysmon 1 process creation events | Log response timeline |
| MEDIUM | 4698 without HIGH/CRITICAL pattern match | Log response timeline |

**End-to-end validation:** PASSED — 2026-04-19  
ART tests → Splunk alert fired within 5 minutes → n8n webhook received → IF branching correct → SSH executed → Ansible remediated DC → artifacts confirmed absent post-remediation

---

## Ansible Remediation

**Control node:** Rocky Linux (10.0.10.105)  
**Venv path:** /home/merlin/ansible-venv (ansible-core 2.19.8, Python 3.11)  
**Playbook:** /home/merlin/ansible-lab/capstone1/t1053005-remediation.yml  
**Inventory:** /home/merlin/ansible-lab/inventory.ini  
**Connection:** WinRM HTTPS port 5986 — TLS 1.3  
**Authentication:** MERLIN credentials  
**Collection:** community.windows 3.1.0

**Remediation scope:**

| Artifact | Method | Result |
|---|---|---|
| \T1053_005_OnLogon | community.windows.win_scheduled_task state=absent | Removed |
| \T1053_005_OnStartup | community.windows.win_scheduled_task state=absent | Removed |
| \AtomicTask | community.windows.win_scheduled_task state=absent | Removed |
| \T1053_005_WMI | community.windows.win_scheduled_task state=absent | Removed |
| \ATOMIC-T1053.005 | community.windows.win_scheduled_task state=absent | Removed |
| HKCU\SOFTWARE\ATOMIC-T1053.005 | community.windows.win_regedit state=absent | Removed |

**Execution result:** ok=7 changed=4  
**Post-remediation verification:** All scheduled tasks absent. Registry key absent. Confirmed on Windows DC.

**Infrastructure notes resolved during this investigation:**

- ansible.windows.win_scheduled_task does not exist — correct module is community.windows.win_scheduled_task
- ansible-core 2.16+ required for community.windows 3.x — Python 3.11 venv required
- pywinrm must be installed explicitly into venv: `/home/merlin/ansible-venv/bin/pip install pywinrm`
- n8n SSH node must call venv binary directly: `/home/merlin/ansible-venv/bin/ansible-playbook`

---

## Hardening Control Validation

| Control | Section | Expected | Observed | Effective |
|---|---|---|---|---|
| M1028 — OS Configuration | 2.3.18 | Non-admin accounts cannot create tasks | Only MERLIN (Domain Admin) created tasks | Yes |
| M1026 — Privileged Account Management | 2.2.28 | Admins only for scheduling priority | Elevated context required for SYSTEM task registration | Yes |

---

## OSINT Enrichment

No external IOCs generated from ART test execution. Windows Defender outbound connection to 48.211.71.198:443 confirmed Microsoft infrastructure via AbuseIPDB and GreyNoise — not test-related. Threat actor context drawn from ATT&CK documented procedure examples and published incident reports.

---

## Standing Notes Updated / Confirmed

The following patterns were confirmed or added during this investigation:

1. **community.windows vs ansible.windows:** win_scheduled_task and win_regedit belong to community.windows collection — not ansible.windows. ansible.windows.win_scheduled_task does not exist.
2. **ansible-core version requirements:** community.windows 3.x requires ansible-core 2.16+. Python 3.11 venv required on Rocky Linux running system Python 3.9.
3. **pywinrm venv isolation:** pywinrm installed at system Python level is not inherited by venv. Must be explicitly installed into venv before WinRM connections function.
4. **n8n Code node input reference:** On TRUE branch nodes preceded by SSH or other action nodes, use `$('Webhook').first().json` to reference original webhook payload — `$input` will contain action node output rather than webhook data.
5. **Sysmon 11 — task XML persistence:** Task XML files written to C:\Windows\System32\Tasks\ are the on-disk persistence mechanism. Ansible remediation targeting only scheduled task deletion is insufficient — XML files must also be removed or will be re-read at startup.
6. **Tarrask detection signal:** Absence of Sysmon 13 SD value write following a 4698 task creation event indicates hidden task via SD deletion — immediate escalation indicator. Presence of SD write confirms standard visible task.
7. **BAM registry writes:** powershell.exe writing to HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\ is Background Activity Moderator recording execution timestamps for power management — benign but forensically useful as execution timeline artifact in DFIR contexts.

---

## Cleanup

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1,4,6,7 -Cleanup
```

**Status:** Completed — all ART artifacts removed. Verified via schtasks /query and reg query.

---

## Investigation Outcome

| Item | Result |
|---|---|
| Tests confirmed in telemetry | 4/4 |
| Scheduled tasks created | 5 |
| Execution paths covered | 3 (schtasks CLI, PowerShell cmdlets, WMI CimMethod) |
| Pre-test SPL searches written before execution | 5 |
| Unexpected events requiring investigation | 2 (Sysmon 10, Sysmon 17) |
| Unexpected events confirmed malicious | 0 |
| Logging gaps identified | 1 (HKCU registry write — detection gap documented with compensating controls) |
| Bucket D findings resolved | 2 (4657 — CIS Level 1 design; 4104 — execution path) |
| Key detection finding | TaskContent XML in 4698 is the highest-value field — exposes encoded payloads invisible elsewhere |
| Key evasion finding | HKCU registry write invisible to both Windows audit and Sysmon pipelines |
| Detection rule created | Splunk SPL — CRITICAL/HIGH/MEDIUM severity tiers — validated 21 events |
| Sigma rule created | community.windows.win_scheduled_task — experimental |
| n8n SOAR workflow | Published — severity branching validated end-to-end |
| Ansible remediation | ok=7 changed=4 — all artifacts confirmed absent |
| Standing notes updated | 7 |
| Open items | None |

---

## Files in This Directory

| File | Description |
|---|---|
| README.md | This file — full investigation documentation |
| detection-rule.spl | Splunk detection rule — CRITICAL/HIGH/MEDIUM severity tiers |
| sigma-rule-T1053.005.yml | Sigma rule — process creation and task creation coverage |
| diamond-model.md | Diamond model |
| n8n-workflow.json | n8n SOAR workflow export — severity branching with Ansible integration |
| ansible-play.yml | Ansible remediation playbook — scheduled task + registry key removal |
