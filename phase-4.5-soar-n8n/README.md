# Phase 4.5 — SOAR Integration (n8n)

This phase documents the Security Orchestration, Automation, and Response layer implemented using n8n. SOAR integration enters the capstone workflow at T1053.005 — the first full vertical slice — and produces an automated response workflow for each subsequent full slice technique. n8n bridges Splunk detection alerts and Ansible remediation, implementing severity-based branching that determines whether a detection warrants automated remediation or analyst notification only.

## Contents

- Platform architecture — n8n deployment details, Docker configuration, and Splunk webhook integration
- Workflow index — all published workflows with technique mapping, webhook paths, and Ansible integration status
- Per-technique workflow documentation — node configuration, branching logic, JavaScript code, and end-to-end validation results

## Platform Summary

n8n is deployed as a Docker container on a dedicated Ubuntu Server VM (10.0.20.100). Splunk alerts fire HTTP POST requests to n8n webhook endpoints. n8n evaluates severity and branches: CRITICAL-tier alerts trigger SSH to the Ansible control node and execute a remediation playbook against the Windows DC over WinRM HTTPS. HIGH and MEDIUM alerts log a response timeline only. All workflows are validated end-to-end against live ART execution before being marked complete.
