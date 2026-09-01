from parser import parser
from detector import (
    failed_login,
    successful_login,
    bruteforce,
    root_login,
    sudo,
)
from report import export_json , print_report
from ssh_auth import enrich_ssh_events
from correlation import failed_then_success

logs = parser()
enrich_ssh_events(logs)

detectors = [
    failed_login,
    successful_login,
    bruteforce,
    root_login,
    sudo,
]

alerts = []

for detector in detectors:
    alerts.extend(detector(logs))

correlation_incidents = failed_then_success(logs)
alerts.extend(correlation_incidents)

print_report(logs, alerts)
export_json(alerts, "alerts.json")
