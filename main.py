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
from risk_score import score_alerts
from config import CONFIG
from ml_anomaly import score_anomalies
from ai_analyst import analyze_alerts

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
score_alerts(alerts)

if CONFIG.get("ml_anomaly", {}).get("enabled", True):
    score_anomalies(alerts)

ai_report = None
if CONFIG.get("ai_analyst", {}).get("enabled", True):
    ai_mode = CONFIG.get("ai_analyst", {}).get("mode", "offline")
    ai_report = analyze_alerts(alerts, mode=ai_mode)
    export_json(ai_report, "ai_analysis.json")

print_report(logs, alerts, ai_report)
export_json(alerts, "alerts.json")
# Export correlation incidents separately
export_json(correlation_incidents, "correlation_incidents.json")


