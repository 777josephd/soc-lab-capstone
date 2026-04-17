# Diamond Model — Investigation 004
## T1135 Network Share Discovery

**Investigation date:** April 16, 2026  
**Status:** CLOSED

---

```
                    ┌─────────────────────────┐
                    │        ADVERSARY         │
                    │                         │
                    │  ART simulation          │
                    │  Invoke-AtomicRedTeam    │
                    │  Tests 4, 5, 6, 10       │
                    │  Account: MERLIN         │
                    │  (Domain Admin)          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
         ┌──────────┤      CAPABILITY         ├──────────┐
         │          │                         │          │
         │          │  net view \\localhost    │          │
         │          │  Get-SmbShare            │          │
         │          │  net share               │          │
         │          │  dir \\127.0.0.1\c$      │          │
         │          │  dir \\127.0.0.1\admin$  │          │
         │          │  dir \\127.0.0.1\IPC$    │          │
         │          │  (native OS + PS cmdlet) │          │
         │          └─────────────────────────┘          │
         │                                               │
┌────────┴────────────┐               ┌──────────────────┴──────┐
│    INFRASTRUCTURE   │               │         VICTIM           │
│                     │               │                          │
│  Local execution    │               │  WIN-9J5N24TODJ0         │
│  WIN-9J5N24TODJ0    │               │  10.0.10.10              │
│  10.0.10.10         │               │                          │
│  via PowerShell     │               │  Data exposed:           │
│  (elevated session) │               │  - Local share structure │
│                     │               │  - C$ (full disk access) │
│  Loopback SMB —     │               │  - ADMIN$ (Windows dir)  │
│  127.0.0.1 / ::1    │               │  - IPC$ (named pipe IPC) │
│  NTLM auth —        │               │  - Share permissions     │
│  no Kerberos.       │               │    and access paths      │
│  No external C2.    │               │                          │
└─────────────────────┘               └──────────────────────────┘
```

---

## Axis Detail

### Adversary
Atomic Red Team simulation framework executing T1135 network share discovery tests via Invoke-AtomicRedTeam. Executed under the MERLIN Domain Admin account to replicate a post-compromise adversary with authenticated credentials mapping the internal network's share structure as a precursor to lateral movement or targeted data collection.

In real-world context, T1135 is executed after initial system discovery and domain enumeration are complete. The adversary goal is to identify accessible shares — particularly administrative shares (`C$`, `ADMIN$`) and IPC shares — that can be leveraged for remote code execution, file staging, or data exfiltration without requiring additional tooling. Conti's pre-encryption share enumeration via `NetShareEnum()` and APT32's `net view` targeting of administrative shares during Operation Cobalt Kitty are documented examples of this technique applied at different stages of the intrusion lifecycle.

### Capability
Two distinct capability tiers were exercised. Tests 4 and 6 used `net view` and `net share` — native Windows binaries requiring no additional tooling and generating no network connections beyond standard SMB. Test 5 used PowerShell's `Get-SmbShare` cmdlet — a managed .NET cmdlet that triggers CLR initialization and generates the `__PSScriptPolicyTest` execution policy artifact. Test 10 used UNC path directory enumeration via `dir \\127.0.0.1\[share]` — the most operationally relevant capability, directly accessing the administrative shares that adversaries target for lateral movement and data collection.

All four capabilities are native OS functionality. No external tooling, no custom malware, no network C2. This is the defining characteristic of this technique — it is entirely indistinguishable from legitimate administrative activity without behavioral context provided by the account identity and timing.

### Infrastructure
Entirely local. All test execution occurred on the target host (10.0.10.10) via an elevated PowerShell session. SMB connections used loopback addressing (`127.0.0.1` and `::1`) and NTLM authentication — no Kerberos, no external network connections, no remote infrastructure. Source port analysis confirmed two distinct SMB sessions: Test 4 on port 51541 and Test 10 reusing port 51552 across all three administrative share accesses. The loopback execution model means this technique generates no externally observable network traffic in the scenario simulated here — real lateral movement scenarios would generate SMB traffic to remote hosts on port 445, providing an additional detection surface not present in this test.

### Victim
Windows Server 2022 Domain Controller WIN-9J5N24TODJ0 hosting the `soc-lab.local` domain. Data exposed includes the complete local share structure, direct access paths to administrative shares (`C$` exposing the full disk, `ADMIN$` exposing the Windows directory), and the IPC$ named pipe interface used for remote procedure calls and inter-process communication. In a real intrusion, this information enables the adversary to stage payloads on `C$` or `ADMIN$`, execute remote services via the IPC$ named pipe, and identify data repositories for collection without requiring additional discovery tools.

---

## Meta-Features

| Meta-feature | Value |
|---|---|
| Timestamp | 2026-04-16 17:21:03 |
| Phase | Discovery (share reconnaissance — post domain enumeration) |
| Direction | Local loopback — SMB connections to 127.0.0.1 and ::1 |
| Result | Local share structure and administrative share access paths successfully enumerated |
| Detection | DETECTED — WinEventLog 4688, Sysmon Event ID 1, WinEventLog 5140 |
| Coverage gap | 4688 absent for Get-SmbShare — Sysmon-only for inline PowerShell cmdlet |
| Key detection signal | 5140 with user account (non-machine account $) accessing administrative shares |
| Bucket D findings | 5145 and 5168 — correct absences, trigger conditions documented |
| Logging gaps identified | None |
| Standing notes updated | 5 |
| Detection rules created | 2 (SPL + Sigma) |
