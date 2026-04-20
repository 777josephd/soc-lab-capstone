# Phase 5 — Ansible Automation

This phase documents the Infrastructure as Code remediation layer implemented using Ansible. Per-technique remediation plays are developed alongside each full vertical slice investigation and accumulate into a master playbook covering all simulated techniques by Phase 6. Each play is triggered automatically by n8n on CRITICAL-severity detections and targets only the specific artifacts created by the simulated technique.

## Contents

- Control node architecture — Rocky Linux configuration, ansible-core version, Python virtual environment, WinRM HTTPS connectivity, and collection dependencies
- Infrastructure troubleshooting log — version compatibility issues encountered and resolved during initial setup, documented for reproducibility
- Remediation play index — all plays with artifact scope, validation results, and execution outcomes
- Per-technique playbooks — complete YAML with inline documentation

## Platform Summary

The Ansible control node runs ansible-core 2.19.8 under a Python 3.11 virtual environment on Rocky Linux (10.0.10.105). Playbooks target the Windows DC (10.0.10.10) over WinRM HTTPS port 5986 using TLS 1.3 authentication. The community.windows collection provides Windows-native modules for scheduled task and registry management. Each play includes post-remediation verification tasks that produce explicit PASS/FAIL output per artifact, independent of Ansible's changed/ok status reporting.
