import streamlit as st
import pandas as pd
import plotly.express as px
import json
from pathlib import Path

# Page Config
st.set_page_config(
    page_title="AI Security Analyst",
    page_icon="🛡️",
    layout="wide"
)

# Load Data

ALERT_PATH = Path("alerts.json")
AI_PATH = Path("ai_analysis.json")

if not ALERT_PATH.exists():
    st.error("alerts.json not found. Run main.py first.")
    st.stop()

with open(ALERT_PATH, encoding="utf-8") as f:
    alerts = json.load(f)

df = pd.DataFrame(alerts)
if df.empty:
    st.warning("alerts.json is empty.")
    st.stop()

if "severity" not in df.columns:
    df["severity"] = "UNKNOWN"
if "attack_type" not in df.columns:
    df["attack_type"] = "Unknown"

df["severity"] = df["severity"].fillna("UNKNOWN")
df["attack_type"] = df["attack_type"].fillna("Unknown")

# Sidebar

st.sidebar.title("🛡️ AI Security Analyst")
st.sidebar.caption("Parser → Detect → Correlate → Risk → ML → AI")
st.sidebar.caption("Journalctl SIEM")

severity_filter = st.sidebar.multiselect(
    "Severity",
    options=sorted(df["severity"].astype(str).unique()),
    default=sorted(df["severity"].astype(str).unique())
)

attack_filter = st.sidebar.multiselect(
    "Attack Type",
    options=sorted(df["attack_type"].astype(str).unique()),
    default=sorted(df["attack_type"].astype(str).unique())
)

filtered = df[
    (df["severity"].isin(severity_filter))
    &
    (df["attack_type"].isin(attack_filter))
]

# Header

st.title("🛡️ AI Security Analyst")
st.caption("Linux log analysis: detectors, correlation, risk_score.py, ML prototype, AI explanation")

st.divider()


# KPI Cards
total_alerts = len(filtered)
high_count = len(filtered[filtered["severity"] == "HIGH"])
medium_count = len(filtered[filtered["severity"] == "MEDIUM"])
low_count = len(filtered[filtered["severity"] == "LOW"])
critical_count = len(filtered[filtered["severity"] == "CRITICAL"]) if "CRITICAL" in filtered["severity"].values else 0

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.metric("📋 Total Alerts", total_alerts)

with c2:
    st.markdown(f"""
    <div style="
        background:#2b1515;
        padding:18px;
        border-radius:12px;
        border-left:6px solid #ff4b4b;">
        <h4 style="margin:0;color:#ff4b4b;">🔴 HIGH / CRITICAL</h4>
        <h1 style="margin:0;">{high_count + critical_count}</h1>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div style="
        background:#33270f;
        padding:18px;
        border-radius:12px;
        border-left:6px solid orange;">
        <h4 style="margin:0;color:orange;">🟠 MEDIUM</h4>
        <h1 style="margin:0;">{medium_count}</h1>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div style="
        background:#18301f;
        padding:18px;
        border-radius:12px;
        border-left:6px solid #34c759;">
        <h4 style="margin:0;color:#34c759;">🟢 LOW</h4>
        <h1 style="margin:0;">{low_count}</h1>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# Executive Security Overview
overview_left, overview_right = st.columns([2, 1])

with overview_left:

    st.subheader("Security Overview")

    if len(filtered) > 0:

        # Highest severity
        if critical_count > 0 or high_count > 0:
            threat = "🔴 HIGH"
        elif medium_count > 0:
            threat = "🟠 MEDIUM"
        elif low_count > 0:
            threat = "🟢 LOW"
        else:
            threat = "⚪ NONE"

        # Most common attack
        top_attack = (
            filtered["attack_type"]
            .value_counts()
            .idxmax()
        )

        st.markdown(f"""
### Current Threat Level

**{threat}**

---

**Most Common Attack**

{top_attack}
""")

with overview_right:

    top_ip = "N/A"
    top_attempts = 0

    bruteforce_rows = filtered[
        filtered["attack_type"] == "Bruteforce Attack"
    ]

    if not bruteforce_rows.empty:

        row = bruteforce_rows.iloc[0]

        top_ip = row.get("ip", "N/A")
        top_attempts = row.get("attempts", 0)

    st.markdown(f"""
### 🎯 Top Attacker

**IP**

`{top_ip}`

**Attempts**

**{top_attempts}**
""")

st.divider()

# Charts
left, right = st.columns(2)

with left:

    severity_counts = (
        filtered["severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = ["Severity","Count"]

    fig = px.bar(
        severity_counts,
        x="Severity",
        y="Count",
        title="Alerts by Severity"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

with right:

    attack_counts = (
        filtered["attack_type"]
        .value_counts()
        .reset_index()
    )

    attack_counts.columns = ["Attack Type", "Count"]

    fig2 = px.bar(
        attack_counts,
        x="Attack Type",
        y="Count",
        title="Alerts by Attack Type"
    )

    st.plotly_chart(
        fig2,
        use_container_width=True
    )

st.divider()

if "risk_score" in filtered.columns:
    st.subheader("Authoritative risk scores (risk_score.py)")
    risk_cols = [c for c in ["attack_type", "incident_type", "severity", "risk_score", "risk_level", "username", "source_ip", "ip", "ml_status", "ml_anomaly_score"] if c in filtered.columns]
    st.dataframe(filtered[risk_cols].sort_values("risk_score", ascending=False), use_container_width=True)

st.subheader("Alert Details")
st.dataframe(filtered, use_container_width=True)

st.divider()
st.subheader("AI Security Analyst")

if AI_PATH.exists():
    with open(AI_PATH, encoding="utf-8") as f:
        ai_report = json.load(f)

    st.info(ai_report.get("executive_summary", ""))
    st.caption(ai_report.get("note", ""))
    st.caption(f"Analyst mode: {ai_report.get('analyst_mode', 'offline')}")

    for item in ai_report.get("incident_analyses") or []:
        analysis = item.get("ai_analysis") or {}
        title = item.get("incident_type") or item.get("attack_type") or "Incident"
        with st.expander(f"{title} — risk {item.get('risk_score')} ({item.get('risk_level')})"):
            st.markdown(f"**Summary:** {analysis.get('summary', '')}")
            st.markdown(f"**Why suspicious:** {analysis.get('why_suspicious', '')}")
            st.markdown(f"**Attack pattern:** {analysis.get('attack_pattern', '')}")
            st.markdown(f"**Risk explanation:** {analysis.get('risk_explanation', '')}")
            st.markdown(f"**ML anomaly:** {item.get('ml_is_anomaly')} (score {item.get('ml_anomaly_score')})")
            evidence = analysis.get("evidence") or []
            if evidence:
                st.markdown("**Evidence**")
                for row in evidence:
                    st.write(f"- {row}")
            steps = analysis.get("investigation_steps") or []
            if steps:
                st.markdown("**Investigation steps**")
                for step in steps:
                    st.write(f"- {step}")
else:
    st.warning("ai_analysis.json not found. Run main.py to generate AI explanations.")
