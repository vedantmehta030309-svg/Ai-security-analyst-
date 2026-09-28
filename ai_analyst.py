"""
AI Security Analyst — explains already-detected, already-scored activity.

This module does not detect threats, correlate events, or calculate risk.
Numerical risk always comes from risk_score.py.

Default mode is offline (template-based) so the demo works without an API key.
Optional LLM mode uses an OpenAI-compatible HTTP API when:
  AI_ANALYST_API_KEY  (or OPENAI_API_KEY)
  AI_ANALYST_BASE_URL (optional, default https://api.openai.com/v1)
  AI_ANALYST_MODEL    (optional, default gpt-4o-mini)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime


PRIORITY_SEVERITIES = {"HIGH", "CRITICAL"}


def _text(value):
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _is_priority(alert):
    if alert.get("incident_type"):
        return True
    if str(alert.get("severity", "")).upper() in PRIORITY_SEVERITIES:
        return True
    if alert.get("risk_score", 0) >= 60:
        return True
    return False


def collect_evidence(alert):
    evidence = []

    description = alert.get("description")
    if description:
        evidence.append(_text(description))

    for label, key in (
        ("Source IP", "source_ip"),
        ("IP", "ip"),
        ("Username", "username"),
        ("Failed attempts", "failed_attempts"),
        ("Invalid-user attempts", "invalid_user_attempts"),
        ("Command", "command"),
        ("Success time", "success_time"),
        ("Root login time", "root_login_time"),
        ("Window start", "window_start"),
        ("Message", "message"),
        ("Attack type", "attack_type"),
        ("Incident type", "incident_type"),
    ):
        value = alert.get(key)
        if value not in (None, "", [], {}):
            evidence.append(f"{label}: {_text(value)}")

    factors = alert.get("risk_factors") or []
    for factor in factors:
        evidence.append(f"Risk factor: {factor}")

    # Keep the list short and readable for the dashboard/report.
    seen = []
    for item in evidence:
        if item not in seen:
            seen.append(item)
    return seen[:12]


def _pattern_text(alert):
    incident = alert.get("incident_type") or alert.get("attack_type") or "Suspicious activity"
    incident = _text(incident)

    mapping = {
        "Possible Account Compromise": (
            "Credential-guessing followed by a successful login from the same source. "
            "This pattern often indicates a brute-force attempt that eventually succeeded."
        ),
        "Multiple Failed Logins Then Root Login": (
            "Repeated authentication failures were followed by a successful root login. "
            "This is consistent with targeting of a privileged account."
        ),
        "Root Login Followed By Privileged Activity": (
            "A successful root SSH login was followed by sudo/privileged command activity "
            "inside the correlation window."
        ),
        "Authentication Then Suspicious Sudo": (
            "A successful authentication was followed by sudo activity, which may indicate "
            "privilege escalation or post-compromise administration."
        ),
        "Invalid User Attack Followed By Success": (
            "Invalid-user probes were followed by a successful authentication from the same IP, "
            "suggesting account discovery then a valid credential."
        ),
        "Multiple Accounts From Same IP": (
            "One source IP tried several usernames in a short window, which is typical of "
            "account enumeration or password spraying."
        ),
        "Same Account From Multiple IPs": (
            "One account was targeted from several source IPs, which can indicate a distributed "
            "guessing campaign."
        ),
        "Bruteforce Attack": (
            "Many failed passwords from one IP occurred inside a short time window."
        ),
        "Root Login": (
            "A successful authentication as root was recorded. Root logins are high-value events."
        ),
        "Sudo Command": (
            "A privileged command was executed via sudo."
        ),
        "SSH Login Then Session Activity": (
            "A successful SSH login was followed by a session open/close event."
        ),
    }
    return mapping.get(incident, f"Detected activity classified as '{incident}'.")


def _why_suspicious(alert):
    factors = alert.get("risk_factors") or []
    if factors:
        return (
            "The activity is treated as suspicious because: "
            + "; ".join(factors)
            + "."
        )
    return _pattern_text(alert)


def _investigation_steps(alert):
    ip = alert.get("source_ip") or alert.get("ip") or "<source IP>"
    user = alert.get("username") or "<account>"
    steps = [
        f"Confirm whether login activity for '{user}' from {ip} was expected.",
        "Review auth.log / journalctl around the incident timestamps for additional hosts and commands.",
        "Check for other successful logins, sudo commands, and file changes after the success time.",
        "If unauthorized: disable the account or SSH key, rotate credentials, and isolate the host.",
    ]
    if alert.get("username") == "root" or "root" in _text(alert.get("incident_type", "")).lower():
        steps.insert(1, "Treat this as privileged-account investigation: inspect root history and sudoers usage.")
    if alert.get("command"):
        steps.insert(2, f"Validate the sudo command `{alert.get('command')}` against change-control.")
    return steps[:6]


def _risk_explanation(alert):
    score = alert.get("risk_score")
    level = alert.get("risk_level")
    factors = alert.get("risk_factors") or []
    if score is None:
        return (
            "No numerical risk score is attached yet. "
            "risk_score.py is the authoritative scorer for this project."
        )
    factor_text = ", ".join(factors) if factors else "base severity only"
    return (
        f"risk_score.py assigned {score}/100 ({level}). "
        f"That score is rule-based and was increased by: {factor_text}. "
        "The AI analyst does not recalculate or override this number."
    )


def _summary(alert):
    incident = alert.get("incident_type") or alert.get("attack_type") or "Alert"
    user = alert.get("username") or "unknown user"
    ip = alert.get("source_ip") or alert.get("ip") or "unknown IP"
    score = alert.get("risk_score")
    level = alert.get("risk_level") or alert.get("severity")
    score_part = f" Risk {score}/100 ({level})." if score is not None else f" Severity {level}."
    return (
        f"{incident} involving '{user}' from {ip}.{score_part} "
        "This explanation is generated after detection, correlation, and scoring."
    )


def offline_analysis(alert):
    return {
        "summary": _summary(alert),
        "why_suspicious": _why_suspicious(alert),
        "evidence": collect_evidence(alert),
        "attack_pattern": _pattern_text(alert),
        "investigation_steps": _investigation_steps(alert),
        "risk_explanation": _risk_explanation(alert),
        "analyst_mode": "offline",
    }


def _llm_prompt(alert):
    payload = {
        key: _text(value) if not isinstance(value, (list, dict, int, float, bool)) else value
        for key, value in alert.items()
        if key != "ai_analysis"
    }
    return (
        "You are a SOC analyst explaining a Linux SSH/auth incident.\n"
        "Use ONLY the structured fields provided. Do not invent IOCs.\n"
        "Do NOT change or replace risk_score, risk_level, or risk_factors; explain them.\n"
        "Return JSON with keys: summary, why_suspicious, evidence (array), "
        "attack_pattern, investigation_steps (array), risk_explanation.\n\n"
        f"INCIDENT:\n{json.dumps(payload, default=str, indent=2)}"
    )


def _call_llm(prompt):
    api_key = os.environ.get("AI_ANALYST_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None

    base = os.environ.get("AI_ANALYST_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("AI_ANALYST_MODEL", "gpt-4o-mini")
    body = json.dumps(
        {
            "model": model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": "Return only valid JSON."},
                {"role": "user", "content": prompt},
            ],
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        f"{base}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        return json.loads(content)
    except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError, IndexError):
        return None


def llm_analysis(alert):
    parsed = _call_llm(_llm_prompt(alert))
    if not isinstance(parsed, dict):
        result = offline_analysis(alert)
        result["analyst_mode"] = "offline_fallback"
        return result

    base = offline_analysis(alert)
    for key in (
        "summary",
        "why_suspicious",
        "evidence",
        "attack_pattern",
        "investigation_steps",
        "risk_explanation",
    ):
        if parsed.get(key):
            base[key] = parsed[key]
    base["analyst_mode"] = "llm"
    # Always keep the authoritative score explanation if the model omitted it.
    if "risk_score.py" not in _text(base.get("risk_explanation")):
        base["risk_explanation"] = _risk_explanation(alert)
    return base


def analyze_alert(alert, mode="offline"):
    if mode == "llm":
        return llm_analysis(alert)
    return offline_analysis(alert)


def _executive_summary(alerts, analyses):
    total = len(alerts)
    incidents = [a for a in alerts if a.get("incident_type")]
    scored = [a for a in alerts if isinstance(a.get("risk_score"), (int, float))]
    top = max(scored, key=lambda a: a["risk_score"], default=None)
    anomaly_count = sum(1 for a in alerts if a.get("ml_is_anomaly") is True)

    top_line = "No scored alerts were present."
    if top:
        label = top.get("incident_type") or top.get("attack_type") or "alert"
        top_line = (
            f"Highest authoritative risk is {top.get('risk_score')}/100 "
            f"({top.get('risk_level')}) for {label}."
        )

    return (
        f"Parsed pipeline produced {total} alerts/incidents, "
        f"including {len(incidents)} correlated incidents and "
        f"{len(analyses)} AI analyst write-ups. {top_line} "
        f"ML prototype flagged {anomaly_count} item(s) as anomalous "
        f"(prototype only; not a production accuracy claim)."
    )


def analyze_alerts(alerts, mode="offline"):
    """
    Attach ai_analysis to priority alerts and return an exportable report object.
    """
    incident_analyses = []
    for alert in alerts:
        if not _is_priority(alert):
            continue
        analysis = analyze_alert(alert, mode=mode)
        alert["ai_analysis"] = analysis
        incident_analyses.append(
            {
                "incident_type": alert.get("incident_type"),
                "attack_type": alert.get("attack_type"),
                "severity": alert.get("severity"),
                "risk_score": alert.get("risk_score"),
                "risk_level": alert.get("risk_level"),
                "username": alert.get("username"),
                "source_ip": alert.get("source_ip") or alert.get("ip"),
                "ml_is_anomaly": alert.get("ml_is_anomaly"),
                "ml_anomaly_score": alert.get("ml_anomaly_score"),
                "ai_analysis": analysis,
            }
        )

    report = {
        "analyst_mode": mode,
        "note": (
            "AI explains detector/correlation/risk_score output. "
            "It does not replace those components."
        ),
        "executive_summary": _executive_summary(alerts, incident_analyses),
        "incident_count": len(incident_analyses),
        "incident_analyses": incident_analyses,
    }
    return report
