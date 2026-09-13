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
from correlation import run_correlations

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

correlation_incidents = run_correlations(logs)

alerts.extend(correlation_incidents)

print_report(logs, alerts)
export_json(alerts, "alerts.json")
# Export correlation incidents separately
export_json(correlation_incidents, "correlation_incidents.json")


