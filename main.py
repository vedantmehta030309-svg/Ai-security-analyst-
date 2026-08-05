from parser import parser
from detector import (
    failed_login,
    successful_login,
    bruteforce,
    root_login,
    sudo,
)
from report import export_json , print_report

logs = parser()

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


print_report(logs, alerts)
export_json(alerts, "alerts.json")