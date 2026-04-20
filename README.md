# Capstone SOC Lab

A security operations lab built on Proxmox, covering the full security operations lifecycle — from infrastructure provisioning and CIS hardening through adversary emulation, detection engineering, SOAR automation, and IaC remediation. Designed, built, and operated solo.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│  Proxmox Host — Ryzen 9 9900X · 64GB RAM · 2TB SSD                 │
│                                                                    │
│  ┌──────────┐                                                      │
│  │ pfSense  │ VLAN 10 · VLAN 20 · VLAN 30 · VLAN 99                │
│  └──────────┘                                                      │
│                                                                    │
│  VLAN 10 — 10.0.10.0/24                                            │
│  ┌─────────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │  Windows Server     │  │  Ubuntu Server   │  │  Rocky Linux  │  │
│  │  2022 DC            │  │  10.0.10.20      │  │  10.0.10.105  │  │
│  │  10.0.10.10         │  │  Splunk +        │  │  Ansible      │  │
│  │  soc-lab.local      │  │  Velociraptor    │  │  Control Node │  │
│  └─────────────────────┘  └──────────────────┘  └───────────────┘  │
│                                                                    │
│  VLAN 20 — 10.0.20.0/24                                            │
│  ┌─────────────────────┐                                           │
│  │  Ubuntu Server      │                                           │
│  │  10.0.20.100        │                                           │
│  │  Docker + Portainer │                                           │
│  │  n8n SOAR           │                                           │
│  └─────────────────────┘                                           │
│                                                                    │
│  VLAN 30 — 10.0.30.0/24                                            │
│  ┌─────────────────────┐  ┌──────────────────┐                     │
│  │  Kali Linux         │  │  Caldera         │                     │
│  │  10.0.30.101        │  │  (pending)       │                     │
│  └─────────────────────┘  └──────────────────┘                     │
│                                                                    │
│  VLAN 99 — 10.0.99.0/24                                            │
│  ┌─────────────────────┐                                           │
│  │  Linux Mint         │                                           │
│  │  10.0.99.10         │                                           │
│  │  Admin workstation  │                                           │
│  └─────────────────────┘                                           │
└────────────────────────────────────────────────────────────────────┘
```

---

## Phases

| Phase | Description |
|---|---|
| 1 | Lab Provisioning — Proxmox, pfSense, VLANs, VM fleet, AD DS |
| 2 | CIS Hardening — Windows Server 2022 DC, CIS Benchmark v5.0.0 |
| 3 | Attack Simulation — Atomic Red Team, Kali, Caldera |
| 4 | Detection and Response — Splunk, Velociraptor |
| 4.5 | SOAR Integration — n8n |
| 5 | Ansible Automation |
| 6 | Documentation and Portfolio |

---

## Highlights

- **~393 CIS controls applied** to a Windows Server 2022 Domain Controller against the CIS Benchmark v5.0.0 (February 2026), with correct split-GPO routing between Default Domain Policy and Default Domain Controllers Policy and full traceability to technique-level ATT&CK mitigations

- **Post-hardening network regression caught and resolved** — Public network profile regression after a Proxmox force-stop suppressed administrative allow rules; root-caused, documented, and resolved without policy rollback

- **Audit gap discovered and corrected during live investigation** — Process Creation subcategory found not auditing despite GPMC configuration; identified during T1082 investigation, corrected via auditpol, and documented as a detection feedback loop finding

- **Five MITRE ATT&CK techniques investigated** across four discovery techniques and one persistence technique, each producing a validated Splunk SPL detection rule, Sigma rule, Diamond Model, and analyst narrative with inline log evidence

- **First full vertical slice completed — T1053.005** — Four ART tests across three distinct execution paths (schtasks CLI, PowerShell Register-ScheduledTask, WMI Invoke-CimMethod) plus a Qakbot-documented Base64 registry payload chain, producing 21 confirmed detection events with CRITICAL/HIGH/MEDIUM severity tiering

- **End-to-end SOAR pipeline validated** — Splunk alert fires webhook to n8n, which branches on severity, SSHes into the Ansible control node, and executes a remediation playbook against the Windows DC over WinRM HTTPS — removing scheduled task artifacts and a registry payload key within minutes of detection

- **Detection engineering from live telemetry** — Every detection rule is built from confirmed field evidence against a CIS-hardened target. No rule is theoretical. All false positive patterns are documented with specific field evidence and excluded with precision filters

- **23 standing environmental patterns documented** across five investigations — a structured knowledge base of recurring telemetry artifacts, known false positives, and audit gaps that applies to every future investigation in this environment

---

## Tech Stack

| Category | Tools |
|---|---|
| Hypervisor | Proxmox VE |
| Firewall | pfSense |
| Windows infrastructure | Windows Server 2022, Active Directory DS, DNS, Group Policy |
| SIEM | Splunk Enterprise |
| Endpoint telemetry | Velociraptor, Sysmon (Olaf Hartong ruleset) |
| Adversary simulation | Atomic Red Team, Kali Linux, Caldera (pending) |
| SOAR | n8n (Docker — 10.0.20.100) |
| Automation | Ansible (ansible-core 2.19.8, Python 3.11, Rocky Linux) |
| Windows automation | community.windows collection, WinRM HTTPS, TLS 1.3 |
| Detection formats | Splunk SPL, Sigma, MITRE ATT&CK Navigator |

---

## Repository Structure

```
soc-lab-capstone/
├── README.md
├── phase-1-provisioning/
│   └── README.md
├── phase-2-cis-hardening/
│   ├── README.md
│   ├── Phase2-CIS-Hardening-Changelog.docx
│   ├── mitre-attack-coverage.json
│   ├── baselines/
│   └── exceptions/
│       └── deferred-controls.md
├── phase-3-attack-simulation/
│   ├── README.md
│   └── investigations/
│       ├── INV-001-T1082-system-discovery/
│       ├── INV-002-T1087.002-domain-account-discovery/
│       ├── INV-003-T1069.002-permission-groups-discovery/
│       ├── INV-004-T1135-network-share-discovery/
│       └── INV-005-T1053.005-scheduled-task-persistence/
│           ├── README.md
│           ├── detection-rule.spl
│           ├── sigma-rule-T1053.005.yml
│           ├── diamond-model.md
│           ├── n8n-workflow.json
│           └── ansible-play.yml
├── phase-4-detection-response/
│   └── README.md
├── phase-4.5-soar-n8n/
│   ├── README.md
│   └── workflows/
│       └── T1053.005-scheduled-task/
│           └── n8n-workflow.json
├── phase-5-ansible/
│   ├── README.md
│   └── plays/
│       └── t1053005-remediation.yml
└── phase-6-documentation/
    └── README.md
```

---

## Phase Documentation

- [Phase 1 — Lab Provisioning](./phase-1-provisioning)
- [Phase 2 — CIS Hardening](./phase-2-cis-hardening)
- [Phase 3 — Attack Simulation](./phase-3-attack-simulation)
- [Phase 4 — Detection and Response](./phase-4-detection-response)
- [Phase 4.5 — SOAR Integration](./phase-4.5-soar-n8n)
- [Phase 5 — Ansible Automation](./phase-5-ansible)
- [Phase 6 — Documentation and Portfolio](./phase-6-documentation)
