# Incident INC-003 - Suspicious Account Creation

## Severity

MEDIUM

## Status

Open

## Detection

A new Windows user account was created and detected through Windows Security Event ID 4720.

## Account Created

temp_admin

## Event Time

2026-08-23 09:17:33

## Evidence

The following Windows account creation event was observed:

- Event ID: 4720
- Account Name: temp_admin
- Action: UserCreated
- Event Time: 2026-08-23 09:17:33

## MITRE ATT&CK

T1136.001 - Create Account: Local Account

## Analyst Assessment

The creation of a new local account may be legitimate administrative activity, but unauthorized account creation can provide an attacker with persistent access to a Windows system.

The account `temp_admin` should be validated to determine whether it was created by an authorized administrator for a legitimate purpose.

Additional investigation should determine whether the account received elevated privileges or performed suspicious activity after creation.

## Recommended Actions

1. Identify the administrator or process that created `temp_admin`.
2. Determine whether the account creation was authorized.
3. Review Event ID 4672 for privileged activity associated with the account.
4. Review subsequent authentication events involving `temp_admin`.
5. Check whether the account was added to a privileged group.
6. Review processes and network activity associated with the account.
7. Disable or remove the account if unauthorized activity is confirmed.

## Evidence Source

`logs/security_events.log`
