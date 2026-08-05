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
            table.add_row(key, str(value))

        console.print(table)

def print_report(logs, alerts):

    print_summary(logs, alerts)

    print_alerts(alerts)



