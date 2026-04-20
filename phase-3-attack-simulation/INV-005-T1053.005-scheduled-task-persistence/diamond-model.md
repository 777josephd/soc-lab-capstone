# Diamond Model — INV-005 T1053.005 Scheduled Task Persistence

**Investigation:** INV-005  
**Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task  
**Date:** 2026-04-17  
**Analyst:** SOC-LAB\MERLIN  

---

## Adversary

ART simulation executed by SOC-LAB\MERLIN (Domain Admin) on WIN-9J5N24TODJ0
(10.0.10.10). Four tests simulating post-compromise persistence tradecraft
mapped to real-world threat actors including APT29, Qakbot, TrickBot, Chimera,
and Sandworm Team.

**Threat actor context:**

| Actor | Specific TTP simulated | Campaign / Context |
|---|---|---|
| APT29 | schtasks /create + task modification + restoration to original config | SolarWinds Compromise — SUNSPOT/SUNBURST persistence when host booted |
| Qakbot | Base64 registry payload stored in HKCU + scheduled task IEX chain | Ransomware delivery — registry-stored encoded payload execution |
| TrickBot | Scheduled task creation for persistent execution | Big game hunting ransomware campaigns worldwide |
| Chimera | `schtasks /create /ru "SYSTEM" /tn "update"` invoking Cobalt Strike loader | Taiwan semiconductor sector targeting |
| Sandworm | GPO-deployed scheduled task executing CaddyWiper at predetermined time | 2022 Ukraine Electric Power Attack |
| Lazarus Group | Periodic scheduled task executing remote XSL script | Operation Dream Job |

---

## Capability

Four distinct scheduled task creation techniques executed across three
execution paths, producing five persistence artifacts.

**Execution Path 1 — schtasks.exe CLI (Test 1):**
```
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```
Two trigger types in a single compound command — onlogon for user persistence,
onstart /ru system for SYSTEM-context persistence surviving reboots.
Parent chain: powershell.exe → cmd.exe → schtasks.exe

**Execution Path 2 — PowerShell Native Cmdlets (Test 4):**
```powershell
$Action = New-ScheduledTaskAction -Execute "calc.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTask -InputObject $object
```
PowerShell API registration bypasses schtasks.exe binary — different telemetry
signature. Administrators group principal with RunLevel Highest.
Parent chain: powershell.exe → child powershell.exe (inline block)

**Execution Path 3 — WMI Invoke-CimMethod (Test 6):**
```powershell
$xml = [System.IO.File]::ReadAllText("C:\AtomicRedTeam\atomics\T1053.005\src\T1053_005_WMI.xml")
Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace "Root\Microsoft\Windows\TaskScheduler" -MethodName "RegisterByXml" -Arguments @{ Force = $true; Xml =$xml; }
```
COM-based task registration via WMI PS_ScheduledTask namespace. Task definition
read from attacker-controlled XML file on disk. Bypasses schtasks.exe entirely.
TrickBot and Industroyer2 attribution. Different parent process chain from CLI path.

**Execution Path 3b — Base64 Registry Payload + IEX Chain (Test 7):**
```
reg add HKCU\SOFTWARE\ATOMIC-T1053.005 /v test /t REG_SZ /d cGluZyAxMjcuMC4wLjE= /f
schtasks /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min "" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\SOFTWARE\\ATOMIC-T1053.005).test)))" /sc daily /st 07:45
```
Two-stage attack: Base64-encoded payload stored in registry, retrieved and
executed via IEX chain at scheduled time. Qakbot documented TTP. Registry write
invisible to Windows audit and Sysmon pipelines — compensating visibility via
4698 TaskContent only. Parent process svchost.exe (Schedule service) visible
only in Sysmon 1 — not captured in 4688.

**Tasks created:**

| Task Name | Trigger | Action | Execution Context | Severity |
|---|---|---|---|---|
| \T1053_005_OnLogon | OnLogon | cmd.exe /c calc.exe | User context | HIGH |
| \T1053_005_OnStartup | OnStart | cmd.exe /c calc.exe | SYSTEM | HIGH |
| \AtomicTask | AtLogon | calc.exe | BUILTIN\Administrators — RunLevel Highest | MEDIUM |
| \T1053_005_WMI | AtLogon | notepad.exe | LeastPrivilege | MEDIUM |
| \ATOMIC-T1053.005 | Daily 07:45 | IEX Base64 chain from HKCU registry | LeastPrivilege | CRITICAL |

---

## Infrastructure

**Source host:** WIN-9J5N24TODJ0 (10.0.10.10) — Windows Server 2022 Domain Controller  
**Execution context:** SOC-LAB\MERLIN elevated PowerShell session  
**Execution window:** 2026-04-17 23:00:23 — 23:03:32 (147 seconds)

**On-disk persistence artifacts:**
```
C:\Windows\System32\Tasks\T1053_005_OnLogon
C:\Windows\System32\Tasks\T1053_005_OnStartup
C:\Windows\System32\Tasks\AtomicTask
C:\Windows\System32\Tasks\T1053_005_WMI
C:\Windows\System32\Tasks\ATOMIC-T1053.005
```

**Registry artifacts:**
```
HKCU\SOFTWARE\ATOMIC-T1053.005\test = cGluZyAxMjcuMC4wLjE= (Base64 payload)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\[TaskName]\Id
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\[TaskName]\SD
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\[TaskName]\Index
```

**Detection gap identified:**  
HKCU\SOFTWARE\ATOMIC-T1053.005 registry write is invisible to both the Windows
audit pipeline (4657 — Object Access Registry auditing not enabled per CIS Level 1)
and the Sysmon 13 pipeline (path outside Olaf Hartong ruleset monitored scope).
Compensating visibility: 4698 TaskContent XML and Sysmon 1 CommandLine both
reference the registry key through the task action definition.

**No external infrastructure involved.**  
All activity local to 10.0.10.10. No C2 communications, no remote origins,
no lateral movement within this investigation scope.

---

## Victim

**Asset:** WIN-9J5N24TODJ0  
**Role:** Windows Server 2022 Domain Controller  
**Domain:** SOC-LAB.local  
**IP:** 10.0.10.10

**Impact analysis:**

Five persistence mechanisms established across reboot and logon event triggers.
\T1053_005_OnStartup running as SYSTEM provides guaranteed elevated code execution
on every system start without further exploitation. \T1053_005_OnLogon fires on
every user logon. \AtomicTask fires for any member of BUILTIN\Administrators
at logon with RunLevel Highest. \ATOMIC-T1053.005 executes daily at 07:45
via Base64 IEX chain — fileless payload execution with obfuscated content
invisible to string-based detection.

Persistence on a Domain Controller is uniquely severe — successful adversary
foothold on the DC provides access to the AD database (NTDS.dit), all domain
user credentials, Group Policy Objects, and trust relationships. Lateral movement
to any domain-joined system is trivially achievable from this position.

**Data at risk:**
- Active Directory database (NTDS.dit)
- All domain user credential hashes
- Kerberos ticket-granting infrastructure
- Group Policy configuration
- All domain-joined systems via lateral movement potential

**Remediation confirmed:**  
All five scheduled tasks removed. HKCU\SOFTWARE\ATOMIC-T1053.005 registry key
removed. Confirmed via schtasks /query and reg query post-remediation.
Ansible play result: ok=7 changed=4.

---

## Relationship Summary

```
ADVERSARY ──────────────────────────────────────────────────────────►
ART simulation (APT29/Qakbot/TrickBot TTPs)
        │
        │ uses
        ▼
CAPABILITY ─────────────────────────────────────────────────────────►
schtasks CLI, PowerShell cmdlets, WMI CimMethod, Base64 IEX registry chain
        │
        │ operates on
        ▼
INFRASTRUCTURE ──────────────────────────────────────────────────────►
WIN-9J5N24TODJ0 (10.0.10.10) — MERLIN session
C:\Windows\System32\Tasks\ — HKCU\SOFTWARE\ATOMIC-T1053.005
        │
        │ targets
        ▼
VICTIM ──────────────────────────────────────────────────────────────►
Windows Server 2022 Domain Controller — SOC-LAB.local
AD database, domain credentials, all domain-joined systems
```
