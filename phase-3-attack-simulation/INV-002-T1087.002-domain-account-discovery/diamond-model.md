# Diamond Model — Investigation 002
## T1087.002 Account Discovery: Domain Account

**Investigation date:** April 13, 2026  
**Status:** CLOSED

---

```
                    ┌─────────────────────────┐
                    │        ADVERSARY         │
                    │                         │
                    │  ART simulation          │
                    │  Invoke-AtomicRedTeam    │
                    │  Tests 1, 2, 3           │
                    │  Account: MERLIN         │
                    │  (Domain Admin)          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
         ┌──────────┤      CAPABILITY         ├──────────┐
         │          │                         │          │
         │          │  net.exe                 │          │
         │          │  net user /domain        │          │
         │          │  net group /domain       │          │
         │          │  powershell.exe          │          │
         │          │  Get-ADUser              │          │
         │          │  Get-LocalGroupMember    │          │
         │          │  query.exe               │          │
         │          │  (native OS utilities)   │          │
         │          └─────────────────────────┘          │
         │                                               │
┌────────┴────────────┐               ┌──────────────────┴──────┐
│    INFRASTRUCTURE   │               │         VICTIM           │
│                     │               │                          │
│  Local execution    │               │  WIN-9J5N24TODJ0         │
│  WIN-9J5N24TODJ0    │               │  10.0.10.10              │
│  10.0.10.10         │               │                          │
│  via PowerShell     │               │  Data exposed:           │
│  (elevated session) │               │  - Domain user accounts  │
│                     │               │  - Domain group memberships│
│  No C2 observed.    │               │  - Privileged account    │
│  No external        │               │    identification        │
│  infrastructure     │               │  - Active session data   │
│  involved.          │               │  - Local group membership│
└─────────────────────┘               └──────────────────────────┘
```

---

## Axis Detail

### Adversary
Atomic Red Team simulation framework executing T1087.002 domain account discovery tests via Invoke-AtomicRedTeam. Executed under the MERLIN Domain Admin account to replicate a post-compromise adversary with elevated privileges mapping the domain's user and group landscape following initial access.

In real-world context, T1087.002 is executed after initial access and basic system discovery are complete. The adversary goal is to identify which domain accounts exist, which hold elevated privileges, and which are worth targeting for credential theft or impersonation during lateral movement. APT29's use of `Get-ADUser` and `Get-ADGroupMember` during the SolarWinds compromise is a documented example of this technique applied at scale in a high-value target environment.

### Capability
Native Windows domain enumeration utilities — `net.exe` (`net user /domain`, `net group /domain`), `powershell.exe` (`Get-ADUser`, `Get-LocalGroupMember`), and `query.exe`. These are built-in OS binaries and PowerShell cmdlets requiring no external tooling and generating no network traffic beyond standard AD authentication. This is the defining characteristic of Living Off the Land (LotL) techniques — the capability is indistinguishable from legitimate administrative activity without behavioral context.

Test 2 (`Get-ADUser -filter *`) was cancelled before full completion. The command block was captured in Sysmon Event ID 1 telemetry at invocation, confirming partial execution regardless of completion status.

### Infrastructure
Entirely local. No command and control infrastructure, no external network connections, no lateral movement. All test execution occurred on the target host (10.0.10.10) via an elevated PowerShell session. Domain authentication activity generated during enumeration was confined to the local domain controller. This is consistent with how T1087.002 operates in real intrusions — standard LDAP and AD queries blend with legitimate domain traffic and require behavioral detection rather than network-based signatures.

### Victim
Windows Server 2022 Domain Controller hosting the `soc-lab.local` domain. Data exposed by the technique includes the full domain user account list (informing credential targeting), domain group memberships (identifying privileged accounts such as Domain Admins and Backup Operators), active session data (identifying who is currently logged in and from where), and local group membership (identifying accounts with local administrative access on the compromised host). This information directly enables follow-on techniques including credential access (T1003), lateral movement (T1021), and targeted phishing or impersonation.

---

## Meta-Features

| Meta-feature | Value |
|---|---|
| Timestamp | 2026-04-13 14:44:23 |
| Phase | Discovery (domain reconnaissance — post initial access) |
| Direction | Local — host querying domain controller AD services |
| Result | Domain user accounts, group memberships, and session data successfully enumerated |
| Detection | DETECTED — WinEventLog 4688, Sysmon Event ID 1, WinEventLog 4799 |
| Partial detection | 4798 absent — Test 2 cancellation, not a logging gap |
| Logging gaps identified | None |
| Environmental FP documented | VSSVC.exe + 4799 — Windows Defender on-access scan behavior |
