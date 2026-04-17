# Diamond Model — Investigation 003
## T1069.002 Permission Groups Discovery: Domain Groups

**Investigation date:** April 14, 2026  
**Status:** CLOSED

---

```
                    ┌─────────────────────────┐
                    │        ADVERSARY         │
                    │                         │
                    │  ART simulation          │
                    │  Invoke-AtomicRedTeam    │
                    │  Tests 1, 3, 9           │
                    │  Account: MERLIN         │
                    │  (Domain Admin)          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
         ┌──────────┤      CAPABILITY         ├──────────┐
         │          │                         │          │
         │          │  net.exe                 │          │
         │          │  net localgroup          │          │
         │          │  net group /domain       │          │
         │          │  net group "domain       │          │
         │          │    admins" /domain       │          │
         │          │  net group "enterprise   │          │
         │          │    admins" /domain       │          │
         │          │  powershell.exe          │          │
         │          │  Get-AdGroup -filter *   │          │
         │          │  ADWS port 9389          │          │
         │          └─────────────────────────┘          │
         │                                               │
┌────────┴────────────┐               ┌──────────────────┴──────┐
│    INFRASTRUCTURE   │               │         VICTIM           │
│                     │               │                          │
│  Local execution    │               │  WIN-9J5N24TODJ0         │
│  WIN-9J5N24TODJ0    │               │  10.0.10.10              │
│  10.0.10.10         │               │                          │
│  via PowerShell     │               │  Data exposed:           │
│  (elevated session) │               │  - Domain group structure│
│                     │               │  - Domain Admins members │
│  ADWS loopback      │               │  - Enterprise Admins     │
│  port 9389 —        │               │  - Account Operators     │
│  no external C2.    │               │  - Backup Operators      │
│  No remote          │               │  - All AD group objects  │
│  infrastructure     │               │    via Get-AdGroup       │
│  involved.          │               │                          │
└─────────────────────┘               └──────────────────────────┘
```

---

## Axis Detail

### Adversary
Atomic Red Team simulation framework executing T1069.002 domain group discovery tests via Invoke-AtomicRedTeam. Executed under the MERLIN Domain Admin account to replicate a post-compromise adversary mapping the domain's privilege group structure following initial access and basic system discovery.

In real-world context, T1069.002 is executed after initial system reconnaissance to identify which groups exist and who holds elevated privileges. FIN8's use of BADHATCH to execute `net.exe group "domain admins" /domain`, and APT29's use of AdFind for domain group enumeration during the SolarWinds compromise, are documented examples of this technique applied during high-value intrusions.

### Capability
Two distinct capability tiers were exercised. Tests 1 and 3 used native `net.exe` commands — built-in OS binaries requiring no additional tooling, generating no network connections beyond standard Windows operation, and producing output indistinguishable from legitimate administrative activity. Test 9 used PowerShell's `Get-AdGroup` cmdlet, which communicates with the domain controller via Active Directory Web Services (ADWS) on port 9389 — a SOAP/XML protocol distinct from traditional LDAP. This creates a unique network fingerprint: DNS resolution of the DC FQDN followed immediately by a loopback connection to port 9389, captured in Sysmon Event IDs 22 and 3 respectively.

### Infrastructure
Entirely local. No command and control infrastructure, no external network connections, no lateral movement. All test execution occurred on the target host (10.0.10.10) via an elevated PowerShell session. The ADWS connection from Get-AdGroup used local IPv6 loopback addressing — source and destination IP were identical, confirming on-DC enumeration with no remote infrastructure involved. This is consistent with how T1069.002 operates in real intrusions — both net commands and PowerShell AD cmdlets generate no externally observable network traffic.

### Victim
Windows Server 2022 Domain Controller hosting the `soc-lab.local` domain. Data exposed by the technique includes the complete domain group structure, membership of privileged groups including Domain Admins, Enterprise Admins, Account Operators, and Backup Operators, and the full AD group object inventory via Get-AdGroup. This information directly enables targeted follow-on attacks: Backup Operators membership enables shadow copy abuse for credential theft; Domain Admins membership identifies the highest-value impersonation targets for lateral movement.

---

## Meta-Features

| Meta-feature | Value |
|---|---|
| Timestamp | 2026-04-14 11:09:38 |
| Phase | Discovery (domain privilege mapping — post initial access) |
| Direction | Local — host querying domain controller via net commands and ADWS |
| Result | Domain group structure and privileged group membership successfully enumerated |
| Detection | DETECTED — WinEventLog 4688, Sysmon Event ID 1, Sysmon Event ID 3 (port 9389), Sysmon Event ID 22 |
| Key detection insight | Port 9389 ADWS monitoring required — LDAP port 389/636 monitoring misses PowerShell AD cmdlet activity entirely |
| Logging gaps identified | None |
| Environmental FP documented | VSSVC.exe + 4799 — second occurrence, confirmed standing pattern |
| Standing notes established | 6 including port 9389 ADWS fingerprint and PSHost named pipe convention |
