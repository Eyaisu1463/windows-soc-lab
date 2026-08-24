from pathlib import Path
import yaml

LOG_FILE = Path("logs/security_events.log")
BRUTE_FORCE_RULE = Path("detections/brute_force_detection.yml")
POWERSHELL_RULE = Path("detections/powershell_detection.yml")
REPORT_FILE = Path("reports/soc_alert_report.txt")


def load_rule(rule_file):
    with rule_file.open("r") as file:
        return yaml.safe_load(file)


def analyze_events():
    brute_force_rule = load_rule(BRUTE_FORCE_RULE)
    powershell_rule = load_rule(POWERSHELL_RULE)

    failed_logins = []
    successful_logins = []
    suspicious_events = []
    powershell_events = []

    with LOG_FILE.open("r") as file:
        for line in file:
            line = line.strip()

            if "EventID=4625" in line:
                failed_logins.append(line)

            elif "EventID=4624" in line:
                successful_logins.append(line)

            if "EventID=4720" in line:
                suspicious_events.append(
                    "New user account created: " + line
                )

            if "EventID=4672" in line:
                suspicious_events.append(
                    "Administrator privileges assigned: " + line
                )

            if (
                "EventID=4688" in line
                and "Process=powershell.exe" in line
            ):
                powershell_events.append(line)

    alerts = []

    # Brute-force detection
    threshold = brute_force_rule["threshold"]["count"]

    if len(failed_logins) >= threshold:
        alerts.append(
            f"ALERT: {brute_force_rule['name']}\n"
            f"MITRE ATT&CK: "
            f"{brute_force_rule['mitre_attack']['technique_id']} - "
            f"{brute_force_rule['mitre_attack']['technique_name']}\n"
            f"Severity: {brute_force_rule['severity']}"
        )

    # PowerShell detection
    if powershell_events:
        powershell_alert = (
            f"ALERT: {powershell_rule['name']}\n"
            f"MITRE ATT&CK: "
            f"{powershell_rule['mitre_attack']['technique_id']} - "
            f"{powershell_rule['mitre_attack']['technique_name']}\n"
            f"Severity: {powershell_rule['severity']}\n"
            f"Events Detected: {len(powershell_events)}\n"
            "Evidence:"
        )

        for event in powershell_events:
            powershell_alert += f"\n  {event}"

        alerts.append(powershell_alert)

    # Account creation and privilege detection
    for event in suspicious_events:

        if "New user account created" in event:
            alerts.append(
                "ALERT: New user account created.\n"
                "MITRE ATT&CK: T1136 - Create Account\n"
                "Severity: MEDIUM"
            )

        if "Administrator privileges assigned" in event:
            alerts.append(
                "ALERT: Administrator privileges assigned.\n"
                "Severity: HIGH"
            )

    # Build report
    report = []

    report.append("================================")
    report.append("       WINDOWS SOC ALERT REPORT")
    report.append("================================")
    report.append("")
    report.append(f"Failed Logins: {len(failed_logins)}")
    report.append(f"Successful Logins: {len(successful_logins)}")
    report.append(f"Suspicious Events: {len(suspicious_events)}")
    report.append(f"PowerShell Events: {len(powershell_events)}")
    report.append("")
    report.append("ALERTS")
    report.append("--------------------------------")

    for alert in alerts:
        report.append(alert)
        report.append("--------------------------------")

    REPORT_FILE.parent.mkdir(exist_ok=True)
    REPORT_FILE.write_text("\n".join(report))

    print("=== Windows SOC Lab ===")
    print()
    print(f"Failed Logins: {len(failed_logins)}")
    print(f"Successful Logins: {len(successful_logins)}")
    print(f"Suspicious Events: {len(suspicious_events)}")
    print(f"PowerShell Events: {len(powershell_events)}")
    print()
    print(f"Alerts Generated: {len(alerts)}")
    print(f"Report Created: {REPORT_FILE}")


if __name__ == "__main__":
    analyze_events()