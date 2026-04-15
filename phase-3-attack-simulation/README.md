# Phase 3 — Attack Simulation

Phase 3 simulates adversary techniques against the CIS-hardened Domain Controller established in Phase 2, using Atomic Red Team to execute controlled, repeatable tests mapped directly to the MITRE ATT&CK framework. Each investigation follows a structured workflow: pre-test research, baseline capture, test execution, telemetry analysis, and detection rule development.

The goal is threefold — validate that Phase 2 hardening controls produce the expected detection telemetry, identify any logging gaps that would leave the environment blind to real adversary behavior, and produce a library of detection rules grounded in observed lab evidence rather than theoretical signatures.
Investigation logs are intentionally detailed in early Phase 3 to establish methodology. 
