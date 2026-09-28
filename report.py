import json
import datetime

from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.rule import Rule

console = Console()

#called by json.dump() when not serializable
def json_default(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type '{type(obj).__name__}' is not JSON serializable")

def export_json(alerts , filepath = "alerts.json"):
    with open(filepath, "w" , encoding = "utf-8") as f:
        json.dump(alerts , f, default=json_default , indent=4)
    print(f"Exported {len(alerts)} alerts to {filepath}")


def print_summary(logs, alerts):

    severity_counter = Counter()

    for alert in alerts:
        severity_counter[alert["severity"]] += 1

    table = Table(title="Security Analysis Report")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Logs Parsed", str(len(logs)))
    table.add_row("Total Alerts", str(len(alerts)))
    table.add_row("HIGH", str(severity_counter["HIGH"]))
    table.add_row("MEDIUM", str(severity_counter["MEDIUM"]))
    table.add_row("LOW", str(severity_counter["LOW"]))
    table.add_row("INFO", str(severity_counter["INFO"]))

    console.print(table)

def print_alerts(alerts):

    console.print()
    console.print(Rule("[bold cyan]Detected Events"))

    for number, alert in enumerate(alerts, start=1):

        table = Table(
            title=f"Alert #{number}",
            show_header=False,
            expand=False
        )

        table.add_column(style="cyan", width=18)
        table.add_column()

        for key, value in alert.items():
            if key in ("ai_analysis", "ml_features"):
                continue
            table.add_row(key, str(value))

        console.print(table)

def print_ai_report(ai_report):
    if not ai_report:
        return

    console.print()
    console.print(Rule("[bold cyan]AI Security Analyst"))
    console.print(ai_report.get("executive_summary", ""))
    console.print(f"Mode: {ai_report.get('analyst_mode', 'offline')}")
    if ai_report.get("note"):
        console.print(ai_report["note"])

    for number, item in enumerate(ai_report.get("incident_analyses") or [], start=1):
        analysis = item.get("ai_analysis") or {}
        table = Table(
            title=f"AI Analysis #{number}",
            show_header=False,
            expand=False
        )
        table.add_column(style="cyan", width=22)
        table.add_column()
        table.add_row("incident", str(item.get("incident_type") or item.get("attack_type")))
        table.add_row("risk_score", str(item.get("risk_score")))
        table.add_row("risk_level", str(item.get("risk_level")))
        table.add_row("ml_is_anomaly", str(item.get("ml_is_anomaly")))
        table.add_row("summary", str(analysis.get("summary", "")))
        table.add_row("why_suspicious", str(analysis.get("why_suspicious", "")))
        table.add_row("attack_pattern", str(analysis.get("attack_pattern", "")))
        table.add_row("risk_explanation", str(analysis.get("risk_explanation", "")))
        steps = analysis.get("investigation_steps") or []
        table.add_row("investigation", " | ".join(str(step) for step in steps))
        console.print(table)


def print_report(logs, alerts, ai_report=None):

    print_summary(logs, alerts)

    print_alerts(alerts)
    print_ai_report(ai_report)



