# Windows SOC Lab

A hands-on Windows Security Operations Center (SOC) lab designed to demonstrate security event analysis, detection engineering, incident investigation, and MITRE ATT&CK mapping using Python and YAML-based detection rules.

## Project Overview

This project simulates a small Windows SOC environment using sample Windows security events.

The lab analyzes authentication, process creation, account management, and privilege-related events to identify potentially suspicious activity.

The project demonstrates a basic detection-to-investigation workflow:

Security Events -> Detection Rules -> Alerts -> Evidence -> MITRE ATT&CK -> Investigation

## Features

- Windows security event analysis
- Failed login detection
- Brute-force detection
- PowerShell execution detection
- New account creation detection
- Administrator privilege detection
- YAML-based detection rules
- MITRE ATT&CK technique mapping
- Automated SOC alert reporting
- Incident investigation documentation
- Evidence-based analyst assessment

## Technologies

- Python 3
- PyYAML
- Windows Security Event concepts
- YAML
- MITRE ATT&CK
- Git / GitHub
- PowerShell

## Project Structure

```text
Windows-SOC-Lab/
|
+-- detections/
|   +-- brute_force_detection.yml
|   +-- powershell_detection.yml
|
+-- investigations/
|   +-- INC-001-brute-force.md
|   +-- INC-002-powershell.md
|
+-- logs/
|   +-- security_events.log
|
+-- reports/
|   +-- soc_alert_report.txt
|
+-- docs/
|   +-- mitre_attack_mapping.md
|
+-- screenshots/
|
+-- src/
|   +-- event_analyzer.py
|
+-- .gitignore
+-- README.md
+-- requirements.txt
```
