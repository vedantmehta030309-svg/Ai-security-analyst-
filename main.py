from parser import parser
from detector import (
    failed_login,
    successful_login,
    bruteforce,
    root_login,
    sudo,
)

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


print(f"\nTotal parsed logs : {len(logs)}")
print(f"Total alerts      : {len(alerts)}")


for alert in alerts:
    print(alert)