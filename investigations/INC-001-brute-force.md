# Incident INC-001 - Suspected Brute Force Activity

## Severity

HIGH

## Status

Open

## Detection

Multiple failed authentication attempts followed by a successful login.

## Affected Account

admin

## Source IP

10.10.10.50

## Evidence

Three failed authentication attempts were observed:

- 09:12:41 - Event ID 4625
- 09:12:45 - Event ID 4625
- 09:12:49 - Event ID 4625

A successful authentication occurred shortly afterward:

- 09:13:02 - Event ID 4624

## MITRE ATT&CK

T1110 - Brute Force

## Analyst Assessment

The sequence of multiple failed authentication attempts followed by a successful authentication may indicate password-guessing activity.

Further investigation is required to determine whether the successful authentication was legitimate.

## Recommended Actions

1. Validate whether the `admin` account owner initiated the login.
2. Review additional authentication events from source IP `10.10.10.50`.
3. Check whether the source IP belongs to an authorized workstation.
4. Review activity performed by the account after successful authentication.
5. Consider temporarily disabling or resetting the account if malicious activity is confirmed.

## Evidence Source

`logs/security_events.log`
