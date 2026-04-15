# Diamond Model — Investigation 001
## T1082 System Information Discovery

**Investigation date:** April 13, 2026  
**Status:** CLOSED

---

```
                    ┌─────────────────────────┐
                    │        ADVERSARY         │
                    │                         │
                    │  ART simulation          │
                    │  Invoke-AtomicRedTeam    │
                    │  Tests 1, 7, 9           │
                    │  Account: MERLIN         │
                    │  (Domain Admin)          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
         ┌──────────┤      CAPABILITY         ├──────────┐
         │          │                         │          │
         │          │  systeminfo.exe          │          │
         │          │  hostname.exe            │          │
         │          │  whoami.exe              │          │
         │          │  reg.exe                 │          │
         │          │  (native OS utilities)   │          │
         │          └─────────────────────────┘          │
         │                                               │
┌────────┴────────────┐               ┌──────────────────┴──────┐
│    INFRASTRUCTURE   │               │         VICTIM           │
│                     │               │                          │
│  Local execution    │               │  WIN-[hostname]          │
│  WIN-[hostname]     │               │  10.0.10.10              │
│  10.0.10.10         │               │                          │
│  via PowerShell     │               │  Data exposed:           │
│  (elevated session) │               │  - OS version/build      │
│                     │               │  - Hardware config       │
│  No C2 observed.    │               │  - Disk enumeration      │
│  No external        │               │  - MachineGUID           │
│  infrastructure     │               │  - Hostname              │
│  involved.          │               │  - Current user identity │
└─────────────────────┘               └──────────────────────────┘
```

---

## Axis Detail

### Adversary
Atomic Red Team simulation framework executing T1082 discovery tests via Invoke-AtomicRedTeam. Executed under the MERLIN Domain Admin account to replicate a post-compromise adversary with elevated privileges performing initial reconnaissance on a newly compromised system.

In real-world context, T1082 is typically executed early in the post-exploitation phase after initial access is established. The adversary goal is to determine whether the target is worth fully compromising and what exploits or payloads are compatible with the target environment.

### Capability
Native Windows discovery utilities — `systeminfo.exe`, `hostname.exe`, `whoami.exe`, and `reg.exe`. These are built-in OS binaries, making them difficult to block without impacting legitimate administrative activity. No malware or custom tooling required. This is the defining characteristic of Living Off the Land (LotL) techniques.

`wmiprvse.exe` was observed during testing as a secondary process spawned by `systeminfo`'s internal WMI calls — not an adversarial capability, confirmed benign WMI service activity.

### Infrastructure
Entirely local. No command and control infrastructure, no external network connections, no lateral movement. All test execution occurred on the target host (10.0.10.10) via an elevated PowerShell session. This is consistent with how T1082 operates in real intrusions — it generates no network traffic and requires no external tools.

### Victim
Windows Server 2022 Domain Controller hosting the `soc-lab.local` domain. Data exposed by the technique includes OS version and build number (informing exploit compatibility), hardware configuration, disk enumeration (informing storage-based persistence options), MachineGUID (unique identifier usable for target tracking), hostname, and current user identity and privilege level.

---

## Meta-Features

| Meta-feature | Value |
|---|---|
| Timestamp | 2026-04-13 09:55:22 |
| Phase | Discovery (initial post-compromise enumeration) |
| Direction | Local — host to self |
| Result | System configuration data successfully enumerated |
| Detection | DETECTED — Sysmon Event ID 1 |
| Detection gap identified | Windows native 4688 absent — remediated |
