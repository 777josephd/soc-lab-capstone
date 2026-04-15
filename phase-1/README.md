# Phase 1 — Lab Provisioning and Configuration

**Status:** Complete  
**Hypervisor:** Proxmox VE — Ryzen 9 9900X, 64GB RAM, 2TB SSD

---

## VM Inventory

| VM | OS | Role | vCPUs | RAM | Disk | IP |
|---|---|---|---|---|---|---|
| pfSense | pfSense | Firewall / Router | 1 | 2 GB | 32 GB | Gateway |
| Windows Server 2022 | Windows Server 2022 | Active Directory DC | 4 | 12 GB | 150 GB | 10.0.10.10 |
| Ubuntu Server | Ubuntu Server 24.04 LTS | Splunk Enterprise + Velociraptor Server | 4 | 16 GB | 80 GB | 10.0.10.20 |
| Linux Mint | Linux Mint | Admin Workstation | 2 | 4 GB | 32 GB | 10.0.99.10 |
| Kali Linux | Kali Linux | Attack Simulation | 4 | 16 GB | 150 GB | 10.0.30.101 |
| Rocky Linux | Rocky Linux | Ansible Control Node | 2 | 2 GB | 25 GB | 10.0.10.105 |

---

## Network Design

pfSense provides routing and VLAN segmentation across three network segments.

| VLAN | Subnet | Purpose |
|---|---|---|
| VLAN 10 | 10.0.10.0/24 | Production — DC, Splunk/Velociraptor server, Ansible node |
| VLAN 30 | 10.0.30.0/24 | Attack simulation — Kali Linux |
| VLAN 99 | 10.0.99.0/24 | Management — admin workstation |

---

## Windows Server 2022 — Domain Controller

**Domain:** `soc-lab.local`  
**IP:** `10.0.10.10`

Configured during Phase 1:

- AD DS role installed and domain promoted (`soc-lab.local`)
- DNS server configured and verified
- Primary administrative account: `MERLIN` (Domain Admin)
- Microsoft Security Compliance Toolkit (SCT) installed — baseline capture and Policy Analyzer
- Sysmon installed and configured — process creation, network connections, and file activity telemetry
- Splunk Universal Forwarder installed and configured — forwarding Windows event logs and Sysmon telemetry to Splunk at `10.0.10.20`
- Velociraptor agent installed and enrolled — confirmed online in Velociraptor GUI

---

## Ubuntu Server 24.04 LTS — Splunk + Velociraptor

**IP:** `10.0.10.20`

- Splunk Enterprise installed and verified — GUI accessible at `http://10.0.10.20:8000`
- Splunk receiving configuration applied — accepting forwarder connections from Windows DC
- Velociraptor server installed and configured — GUI accessible at `https://10.0.10.20:8889`
- Velociraptor client enrollment verified — DC agent confirmed online

---

## Linux Mint — Admin Workstation

**IP:** `10.0.99.10`

Primary configuration and administration workstation for the lab. Accesses the DC via:

- **OpenSSH** — remote shell for PowerShell and SCP file transfer
- **Remmina** — RDP client for GUI access to the DC when required

Baseline documentation files stored locally at `~/Documents/lab-baselines/windows-server/` and committed to the Phase 2 repository directory.

---

## Phase 1 Outcome

All core infrastructure operational at Phase 1 close. Telemetry pipeline confirmed end-to-end: Sysmon and Windows event logs forwarding from DC → Splunk Universal Forwarder → Splunk Enterprise. Velociraptor agent enrolled and responsive. Lab ready for CIS hardening in Phase 2.
