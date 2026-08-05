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

if not ALERT_PATH.exists():
    st.error("alerts.json not found. Run main.py first.")
    st.stop()

with open(ALERT_PATH, encoding="utf-8") as f:
    alerts = json.load(f)

df = pd.DataFrame(alerts)

# Sidebar

st.sidebar.title("🛡️ AI Security Analyst")
st.sidebar.caption("Parser v1.0")
st.sidebar.caption("Journalctl SIEM")

severity_filter = st.sidebar.multiselect(
    "Severity",
    options=sorted(df["severity"].unique()),
    default=sorted(df["severity"].unique())
)

attack_filter = st.sidebar.multiselect(
    "Attack Type",
    options=sorted(df["attack_type"].unique()),
    default=sorted(df["attack_type"].unique())
)

filtered = df[
    (df["severity"].isin(severity_filter))
    &
    (df["attack_type"].isin(attack_filter))
]

# Header

st.title("🛡️ AI Security Analyst")
st.caption("Real-Time Journalctl Threat Detection Dashboard")

st.divider()


# KPI Cards
total_alerts = len(filtered)
high_count = len(filtered[filtered["severity"] == "HIGH"])
medium_count = len(filtered[filtered["severity"] == "MEDIUM"])
low_count = len(filtered[filtered["severity"] == "LOW"])

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
        <h4 style="margin:0;color:#ff4b4b;">🔴 HIGH</h4>
        <h1 style="margin:0;">{high_count}</h1>
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
        if high_count > 0:
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

        top_ip = row["ip"]
        top_attempts = row["attempts"]

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

    attack_counts