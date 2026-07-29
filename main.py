from parser import parser
from detector import failed_login,successful_login,bruteforce

logs = parser()
alerts = []
alerts.extend(failed_login(logs))
alerts.extend(successful_login(logs))
alerts.extend(bruteforce(logs))

print(f"total parsed logs :  {len(logs)}")
print(f"Alerts :  {len(alerts)}")

for alert in alerts:
    print(alert)