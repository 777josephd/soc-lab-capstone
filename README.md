# Capstone Lab

A home security operations lab built on Proxmox, covering the full security operations lifecycle — from infrastructure provisioning and CIS hardening through adversary simulation, detection engineering, and SOAR automation. Designed, built, and operated solo.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Proxmox Host — Ryzen 9 9900X · 64GB RAM · 2TB SSD             │
│                                                                │
│  ┌──────────┐                                                  │
│  │ pfSense  │ VLAN 10 · VLAN 30 · VLAN 99                      │
│  └──────────┘                                                  │
│                                                                │
│  VLAN 10 — 10.0.10.0/24                                        │
│  ┌─────────────────────┐  ┌──────────────────┐  ┌───────────┐  │
│  │  Windows Server     │  │  Ubuntu Server   │  │   Rocky   │  │
│  │  2022 DC            │  │  24.04 LTS       │  │   Linux   │  │
│  │  10.0.10.10         │  │  10.0.10.20      │  │  10.0.10  │  │
│  │  soc-lab.local      │  │  Splunk +        │  │  .105     │  │
│  └─────────────────────┘  │  Velociraptor    │  │  Ansible  │  │
│                           └──────────────────┘  └───────────┘  │
│  VLAN 30 — 10.0.30.0/24                                        │
│  ┌─────────────────────┐  ┌──────────────────┐                 │
│  │  Kali Linux         │  │  Caldera         │                 │
│  │  10.0.30.101        │  │  (pending)       │                 │
│  └─────────────────────┘  └──────────────────┘                 │
│                                                                │
│  VLAN 99 — 10.0.99.0/24                                        │
│  ┌─────────────────────┐                                       │
│  │  Linux Mint         │                                       │
│  │  10.0.99.10         │                                       │
│  │  Admin workstation  │                                       │
│  └─────────────────────┘                                       │
└────────────────────────────────────────────────────────────────┘
```

---

## Phase Status

| Phase | Description | Status |
|---|---|---|
| 1 | Lab Provisioning — Proxmox, pfSense, VLANs, VM fleet, AD DS | ✅ Complete |
| 2 | CIS Hardening — Windows Server 2022 DC, CIS Benchmark v5.0.0 | ✅ Complete |
| 3 | Attack Simulation — Atomic Red Team, Kali, Caldera | 🔄 In Progress |
| 4 | Detection and Response — Splunk, Velociraptor | ⏳ Pending |
| 4.5 | SOAR Integration — n8n | ⏳ Pending |
| 5 | Ansible Automation | ⏳ Pending |
| 6 | Documentation and Portfolio | ⏳ Pending |

---

## Highlights

- **~393 CIS controls applied** to a Windows Server 2022 Domain Controller against the CIS Benchmark v5.0.0 (February 2026), including correct split-GPO routing between Default Domain Policy and Default Domain Controllers Policy
- **32 MITRE ATT&CK techniques mitigated** by hardening controls, with full technique-to-control traceability and an ATT&CK Navigator coverage layer
- **Post-hardening incident caught and resolved** — Public network profile regression after Proxmox force-stop suppressed administrative allow rules; root-caused, documented, and resolved without policy rollback
- **Audit gap discovered during attack simulation** — Process Creation subcategory found not auditing despite GPMC configuration; corrected during Phase 3 T1082 investigation, demonstrating the detection feedback loop
- **Structured detection pipeline** — each Phase 3 investigation produces a Splunk SPL rule, a Sigma rule, a Diamond Model write-up, and an analyst narrative before the investigation is closed

---

## Tech Stack

| Category | Tools |
|---|---|
| Hypervisor | Proxmox VE |
| Firewall | pfSense |
| Windows infrastructure | Windows Server 2022, Active Directory DS, DNS, Group Policy |
| SIEM | Splunk Enterprise |
| Incident response | Velociraptor |
| Adversary simulation | Atomic Red Team, Kali Linux, Caldera |
| SOAR | n8n *(pending)* |
| Automation | Ansible *(pending)* |
| Detection formats | Splunk SPL, Sigma, MITRE ATT&CK Navigator |

---

## Repository Structure

```
capstone-soc-lab/
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
│       └── INV-003-T1069.002-permission-groups-discovery/
├── phase-4-detection-response/
├── phase-4.5-soar-n8n/
├── phase-5-ansible/
└── phase-6-documentation/
```

---

## Phase Documentation

- [Phase 1 — Lab Provisioning](./phase-1-provisioning/README.md)
- [Phase 2 — CIS Hardening](./phase-2-cis-hardening/README.md)
- [Phase 3 — Attack Simulation](./phase-3-attack-simulation/README.md)
