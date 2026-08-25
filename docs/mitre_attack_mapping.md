# MITRE ATT&CK Detection Mapping

This document maps the Windows SOC Lab detections to MITRE ATT&CK techniques.

## Detection 1 - Brute Force

**Windows Event ID:** 4625

**Detection:** Multiple failed authentication attempts

**MITRE ATT&CK Technique:** T1110 - Brute Force

**Severity:** HIGH

**Evidence:**

Three failed authentication attempts were observed against the `admin` account from source IP `10.10.10.50`.

**Investigation:**

See `investigations/INC-001-brute-force.md`

---

## Detection 2 - PowerShell

**Windows Event ID:** 4688

**Detection:** PowerShell process execution

**MITRE ATT&CK Technique:** T1059.001 - PowerShell

**Severity:** MEDIUM

**Evidence:**

PowerShell was executed by account `alice`.

The parent process was `explorer.exe`.

**Investigation:**

See `investigations/INC-002-powershell.md`

---

## Detection 3 - Create Account

**Windows Event ID:** 4720

**Detection:** New Windows user account created

**MITRE ATT&CK Technique:** T1136.001 - Create Account: Local Account

**Severity:** MEDIUM

**Evidence:**

The account `temp_admin` was created.

**Investigation:**

See `investigations/INC-003-account-creation.md`

---

## Detection 4 - Administrator Privileges

**Windows Event ID:** 4672

**Detection:** Special administrative privileges assigned

**Severity:** HIGH

**Evidence:**

The account `temp_admin` received administrator-level privileges.

**Investigation:**

Determine whether the privilege assignment was authorized and review subsequent activity performed by the account.

---

## Summary

| Detection                 | Event ID | MITRE ATT&CK                  | Severity |
| ------------------------- | -------: | ----------------------------- | -------- |
| Brute Force               |     4625 | T1110                         | HIGH     |
| PowerShell                |     4688 | T1059.001                     | MEDIUM   |
| Create Account            |     4720 | T1136.001                     | MEDIUM   |
| Administrative Privileges |     4672 | Special Privilege Assignment  | HIGH     |

## Analyst Perspective

The purpose of this mapping is to associate observable Windows security events with adversary behaviors described by the MITRE ATT&CK framework.

Detection of a technique does not automatically indicate malicious activity. Analysts should evaluate the context, affected account, source system, process relationships, and surrounding events before determining whether activity is malicious.# MITRE ATT&CK Detection Mapping

This document maps the Windows SOC Lab detections to MITRE ATT&CK techniques.

## Detection 1 - Brute Force

**Windows Event ID:** 4625

**Detection:** Multiple failed authentication attempts

**MITRE ATT&CK Technique:** T1110 - Brute Force

**Severity:** HIGH

**Evidence:**

Three failed authentication attempts were observed against the `admin` account from source IP `10.10.10.50`.

**Investigation:**

See `investigations/INC-001-brute-force.md`

---

## Detection 2 - PowerShell

**Windows Event ID:** 4688

**Detection:** PowerShell process execution

**MITRE ATT&CK Technique:** T1059.001 - PowerShell

**Severity:** MEDIUM

**Evidence:**

PowerShell was executed by account `alice`.

The parent process was `explorer.exe`.

**Investigation:**

See `investigations/INC-002-powershell.md`

---

## Detection 3 - Create Account

**Windows Event ID:** 4720

**Detection:** New Windows user account created

**MITRE ATT&CK Technique:** T1136.001 - Create Account: Local Account

**Severity:** MEDIUM

**Evidence:**

The account `temp_admin` was created.

**Investigation:**

See `investigations/INC-003-account-creation.md`

---

## Detection 4 - Administrator Privileges

**Windows Event ID:** 4672

**Detection:** Special administrative privileges assigned

**Severity:** HIGH

**Evidence:**

The account `temp_admin` received administrator-level privileges.

**Investigation:**

Determine whether the privilege assignment was authorized and review subsequent activity performed by the account.

---

## Summary

| Detection                 | Event ID | MITRE ATT&CK                  | Severity |
| ------------------------- | -------: | ----------------------------- | -------- |
| Brute Force               |     4625 | T1110                         | HIGH     |
| PowerShell                |     4688 | T1059.001                     | MEDIUM   |
| Create Account            |     4720 | T1136.001                     | MEDIUM   |
| Administrative Privileges |     4672 | Special Privilege Assignment  | HIGH     |

## Analyst Perspective

The purpose of this mapping is to associate observable Windows security events with adversary behaviors described by the MITRE ATT&CK framework.

Detection of a technique does not automatically indicate malicious activity. Analysts should evaluate the context, affected account, source system, process relationships, and surrounding events before determining whether activity is malicious.