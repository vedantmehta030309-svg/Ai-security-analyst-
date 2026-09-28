"""
Dashboard V2 — AI Security Analyst (SOC-style UI layer).

This dashboard is a READ-ONLY view over the JSON exports produced by main.py:
    alerts.json, correlation_incidents.json, ai_analysis.json

No detection, correlation, risk, AI, or ML logic lives in this file.
risk_score.py remains the single authoritative numerical risk engine:
risk values are displayed exactly as exported and are never recalculated.
"""

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# ------------------------------------------------------------------
# Page configuration
# ------------------------------------------------------------------
st.set_page_config(
    page_title="AI Security Analyst",
    page_icon="🛡️",
    layout="wide",
)

ALERT_PATH = Path("alerts.json")
AI_PATH = Path("ai_analysis.json")
INCIDENTS_PATH = Path("correlation_incidents.json")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",  # red
    "HIGH": "#f97316",       # orange
    "MEDIUM": "#eab308",    # amber
    "LOW": "#22c55e",        # green
    "INFO": "#60a5fa",       # blue
}
ML_STATUS_COLORS = {
    "anomaly": "#38bdf8",
    "typical": "#3b82f6",
    "unavailable": "#64748b",
}
ACCENT = "#38bdf8"
GRID_COLOR = "#1c2942"
TEXT_COLOR = "#e6edf3"
MUTED = "#8fa3c0"

# ------------------------------------------------------------------
# Theme: restrained SOC palette (dark charcoal/navy, blue/cyan accent)
# Inline CSS only — no JS, no external files, no new dependencies.
# ------------------------------------------------------------------
CSS = """
<style>
  .stApp { background-color: #0b1220; color: #e6edf3; }
  header[data-testid="stHeader"] { background: transparent; }
  .block-container, div[data-testid="block-container"] {
      padding-top: 1.1rem !important; padding-bottom: 2.5rem !important;
  }

  section[data-testid="stSidebar"] {
      background-color: #0e1526;
      border-right: 1px solid #22304f;
  }

  /* ---- Header ---- */
  .soc-header {
      display: flex; justify-content: space-between; align-items: center;
      flex-wrap: wrap; gap: 12px;
      padding: 16px 22px;
      background: linear-gradient(90deg, #101a30 0%, #0d1526 100%);
      border: 1px solid #22304f; border-radius: 14px;
      margin-bottom: 14px;
  }
  .soc-title { font-size: 1.45rem; font-weight: 700; color: #f1f5f9; }
  .soc-subtitle { color: #8fa3c0; font-size: .85rem; margin-top: 2px; }
  .soc-status { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .status-pill {
      display: inline-flex; align-items: center; gap: 6px;
      background: #10251a; border: 1px solid #1d4d33; color: #4ade80;
      border-radius: 999px; padding: 4px 12px; font-size: .75rem; font-weight: 600;
  }
  .chip {
      display: inline-block; background: #16213a; border: 1px solid #22304f;
      color: #cbd5e1; border-radius: 999px; padding: 3px 11px;
      font-size: .75rem; margin: 1px 4px 1px 0;
  }

  /* ---- KPI cards ---- */
  .kpi-grid { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; }
  .kpi-card {
      flex: 1 1 0; min-width: 150px;
      background: #111a2e; border: 1px solid #22304f; border-radius: 12px;
      padding: 12px 16px; border-left-width: 4px;
  }
  .kpi-label {
      color: #8fa3c0; font-size: .68rem; letter-spacing: .09em;
      text-transform: uppercase; font-weight: 600;
  }
  .kpi-value { color: #f1f5f9; font-size: 1.7rem; font-weight: 700; margin-top: 2px; }
  .kpi-sub  { color: #8fa3c0; font-size: .72rem; margin-top: 2px; }
  .kpi-total     { border-left-color: #38bdf8; }
  .kpi-critical  { border-left-color: #ef4444; }
  .kpi-high      { border-left-color: #f97316; }
  .kpi-medium    { border-left-color: #eab308; }
  .kpi-low       { border-left-color: #22c55e; }
  .kpi-incidents { border-left-color: #a78bfa; }
  .kpi-anomalies { border-left-color: #38bdf8; }
  .kpi-peak      { border-left-color: #f1f5f9; }

  /* ---- Panels & sections ---- */
  .panel {
      background: #111a2e; border: 1px solid #22304f; border-radius: 12px;
      padding: 16px 18px; height: 100%;
  }
  .section-title { font-size: 1.05rem; font-weight: 650; color: #f1f5f9; margin-top: 20px; }
  .section-sub { color: #8fa3c0; font-size: .8rem; margin: 2px 0 10px 0; }
  .kv { color: #e6edf3; font-weight: 600; }
  .kv-muted { color: #8fa3c0; font-size: .8rem; margin-top: 10px; }

  .banner {
      background: #0f1b33; border: 1px solid #1e3a5f; border-left: 4px solid #38bdf8;
      border-radius: 10px; padding: 10px 14px; color: #cbd5e1; font-size: .85rem;
      margin-bottom: 10px;
  }
  .banner strong { color: #f1f5f9; }

  /* ---- AI analyst console ---- */
  .ai-label {
      color: #38bdf8; font-size: .7rem; font-weight: 700;
      text-transform: uppercase; letter-spacing: .09em; margin-top: 12px;
  }
  .ai-text { color: #dbe4f0; font-size: .88rem; line-height: 1.55; margin-top: 2px; }

  /* ---- Risk bars ---- */
  .riskbar { background: #18233c; border-radius: 999px; height: 8px; width: 100%; margin-top: 8px; }
  .riskbar-fill { border-radius: 999px; height: 8px; }

  div[data-testid="stExpander"] {
      background: #101a2e; border: 1px solid #22304f; border-radius: 10px;
  }
</style>
"""


def kpi_card(label, value, css_class, sub=""):
    sub_html = f'<div class="kpi-sub">{sub}</div>' if sub else ""
    return (
        f'<div class="kpi-card {css_class}">'
        f'<div class="kpi-label">{label}</div>'
        f'<div class="kpi-value">{value}</div>{sub_html}</div>'
    )


def chips(items):
    return "".join(f'<span class="chip">{item}</span>' for item in items)


def section_header(title, subtitle=""):
    sub_html = f'<div class="section-sub">{subtitle}</div>' if subtitle else ""
    st.markdown(
        f'<div class="section-title">{title}</div>{sub_html}',
        unsafe_allow_html=True,
    )


def style_fig(fig, height=330):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": TEXT_COLOR, "size": 13},
        height=height,
        margin={"l": 10, "r": 10, "t": 46, "b": 10},
        showlegend=False,
        xaxis={"gridcolor": GRID_COLOR, "zeroline": False},
        yaxis={"gridcolor": GRID_COLOR, "zeroline": False},
        title={"font": {"size": 15, "color": TEXT_COLOR}, "x": 0.01, "xanchor": "left"},
    )
    return fig


def counts_frame(series, name):
    counts = series.astype(str).value_counts()
    return pd.DataFrame({name: counts.index, "Count": counts.values})


# ------------------------------------------------------------------
# Load data (read-only; produced by main.py)
# ------------------------------------------------------------------
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

severity_options = sorted(
    df["severity"].astype(str).unique(),
    key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER),
)
attack_options = sorted(df["attack_type"].astype(str).unique())

# ------------------------------------------------------------------
# Sidebar — filters (same semantics as before, cleaner presentation)
# ------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ AI Security Analyst")
    st.caption("Linux Security Intelligence & Threat Analysis")
    st.caption("Parser → Detect → Correlate → Risk → ML → AI")
    st.divider()
    st.caption("FILTERS")
    severity_filter = st.multiselect(
        "Severity",
        options=severity_options,
        default=severity_options,
    )
    attack_filter = st.multiselect(
        "Attack Type",
        options=attack_options,
        default=attack_options,
    )
    st.divider()
    st.caption("Journalctl SIEM")

filtered = df[
    (df["severity"].isin(severity_filter))
    & (df["attack_type"].isin(attack_filter))
]

# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------
total_alerts = len(df)
total_incidents = int(df["incident_type"].notna().sum()) if "incident_type" in df.columns else 0
total_anomalies = int((df["ml_is_anomaly"] == True).sum()) if "ml_is_anomaly" in df.columns else 0

st.markdown(CSS, unsafe_allow_html=True)
st.markdown(
    f"""
    <div class="soc-header">
      <div>
        <div class="soc-title">🛡️ AI Security Analyst</div>
        <div class="soc-subtitle">Linux Security Intelligence &amp; Threat Analysis</div>
      </div>
      <div class="soc-status">
        <span class="status-pill">● PIPELINE ACTIVE</span>
        <span class="chip">{total_alerts} alerts</span>
        <span class="chip">{total_incidents} correlated incidents</span>
        <span class="chip">{total_anomalies} ML anomalies</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ------------------------------------------------------------------
# KPI / security summary cards
# ------------------------------------------------------------------
sev_counts = filtered["severity"].value_counts()
n_critical = int(sev_counts.get("CRITICAL", 0))
n_high = int(sev_counts.get("HIGH", 0))
n_medium = int(sev_counts.get("MEDIUM", 0))
n_low = int(sev_counts.get("LOW", 0))
n_incidents = int(filtered["incident_type"].notna().sum()) if "incident_type" in filtered.columns else 0
n_anomalies = int((filtered["ml_is_anomaly"] == True).sum()) if "ml_is_anomaly" in filtered.columns else 0

peak_value, peak_level = 0, "—"
if "risk_score" in filtered.columns:
    scored = filtered["risk_score"].dropna()
    if not scored.empty:
        peak_value = int(scored.max())
        peak_row = filtered.loc[scored.idxmax()]
        peak_level = str(peak_row.get("risk_level") or peak_row.get("severity") or "—")

row_one = "".join(
    (
        kpi_card("Total Alerts", len(filtered), "kpi-total", f"of {total_alerts} in dataset"),
        kpi_card("Critical", n_critical, "kpi-critical", "severity"),
        kpi_card("High", n_high, "kpi-high", "severity"),
        kpi_card("Medium", n_medium, "kpi-medium", "severity"),
    )
)
row_two = "".join(
    (
        kpi_card("Low", n_low, "kpi-low", "severity"),
        kpi_card("Correlated Incidents", n_incidents, "kpi-incidents", "from correlation.py"),
        kpi_card("ML Anomalies", n_anomalies, "kpi-anomalies", "prototype model"),
        kpi_card("Peak Risk", f"{peak_value}/100", "kpi-peak", peak_level),
    )
)
st.markdown(f'<div class="kpi-grid">{row_one}</div>', unsafe_allow_html=True)
st.markdown(f'<div class="kpi-grid">{row_two}</div>', unsafe_allow_html=True)

# ------------------------------------------------------------------
# Threat overview — summary panel + charts
# ------------------------------------------------------------------
if n_critical > 0 or n_high > 0:
    threat = "🔴 HIGH"
elif n_medium > 0:
    threat = "🟠 MEDIUM"
elif n_low > 0:
    threat = "🟢 LOW"
else:
    threat = "⚪ NONE"

top_attack = (
    filtered["attack_type"].value_counts().idxmax() if not filtered.empty else "N/A"
)

top_ip, top_attempts = "N/A", 0
if "attack_type" in filtered.columns:
    bruteforce_rows = filtered[filtered["attack_type"] == "Bruteforce Attack"]
    if not bruteforce_rows.empty:
        if "attempts" in bruteforce_rows.columns:
            bruteforce_rows = bruteforce_rows.assign(
                _a=pd.to_numeric(bruteforce_rows["attempts"], errors="coerce")
            ).sort_values("_a", ascending=False)
        row = bruteforce_rows.iloc[0]
        top_ip = row.get("ip", "N/A") or "N/A"
        top_attempts = row.get("attempts", 0) or 0

overview_left, overview_right = st.columns([1, 2], gap="medium")

with overview_left:
    st.markdown(
        f"""
        <div class="panel">
          <div class="section-title" style="margin-top:0;">Security Overview</div>
          <div class="kv-muted">Current Threat Level</div>
          <div class="kv">{threat}</div>
          <div class="kv-muted">Most Common Attack</div>
          <div class="kv">{top_attack}</div>
          <div class="kv-muted">Top Attacker (bruteforce detector)</div>
          <div class="kv">{top_ip}</div>
          <div class="kv-muted">Attempts in detection window</div>
          <div class="kv">{top_attempts}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with overview_right:
    tab_sev, tab_atk, tab_risk, tab_ml = st.tabs(
        ["Alerts by Severity", "Alerts by Attack Type", "Risk Levels", "ML Status"]
    )

    with tab_sev:
        sev_df = counts_frame(filtered["severity"], "Severity")
        order = [s for s in SEVERITY_ORDER if s in sev_df["Severity"].tolist()]
        order += [s for s in sev_df["Severity"].tolist() if s not in order]
        sev_df["__order"] = sev_df["Severity"].apply(order.index)
        sev_df = sev_df.sort_values("__order").drop(columns="__order")
        fig_sev = px.bar(sev_df, x="Severity", y="Count", title="Alerts by Severity")
        fig_sev.update_traces(
            marker_color=[SEVERITY_COLORS.get(s, ACCENT) for s in sev_df["Severity"]]
        )
        st.plotly_chart(style_fig(fig_sev), use_container_width=True)

    with tab_atk:
        atk_df = counts_frame(filtered["attack_type"], "Attack Type").sort_values("Count")
        fig_atk = px.bar(
            atk_df,
            x="Count",
            y="Attack Type",
            orientation="h",
            title="Alerts by Attack Type",
        )
        fig_atk.update_traces(marker_color=ACCENT, marker_line_width=0)
        st.plotly_chart(style_fig(fig_atk), use_container_width=True)

    with tab_risk:
        if "risk_level" in filtered.columns:
            risk_df = counts_frame(filtered["risk_level"], "Risk Level")
            fig_risk = px.bar(risk_df, x="Risk Level", y="Count", title="Risk Level Distribution")
            fig_risk.update_traces(
                marker_color=[SEVERITY_COLORS.get(s, ACCENT) for s in risk_df["Risk Level"]]
            )
            st.plotly_chart(style_fig(fig_risk), use_container_width=True)
        else:
            st.caption("No risk_level column in alerts.json — run risk scoring via main.py.")

    with tab_ml:
        if "ml_status" in filtered.columns:
            ml_df = counts_frame(filtered["ml_status"], "ML Status")
            fig_ml = px.pie(
                ml_df,
                names="ML Status",
                values="Count",
                hole=0.55,
                title="ML Anomaly Status (prototype)",
            )
            fig_ml.update_traces(
                marker=dict(
                    colors=[ML_STATUS_COLORS.get(s, ACCENT) for s in ml_df["ML Status"]]
                ),
                textinfo="value",
            )
            fig_ml = style_fig(fig_ml)
            fig_ml.update_layout(showlegend=True)
            fig_ml.update_layout(legend=dict(font=dict(color=MUTED)))
            st.plotly_chart(fig_ml, use_container_width=True)
            st.caption("Prototype Isolation Forest — not a production accuracy claim.")
        else:
            st.caption("No ml_status column — ML anomaly detection is disabled or not yet run.")

# ------------------------------------------------------------------
# Risk overview — authoritative scores from risk_score.py
# ------------------------------------------------------------------
section_header(
    "Authoritative Risk Scores",
    "Every score below is computed by risk_score.py. The dashboard displays "
    "these values exactly as exported — it never recalculates them.",
)
if "risk_score" in filtered.columns:
    st.markdown(
        """
        <div class="banner">
          <strong>Risk scores are authoritative and come from risk_score.py.</strong>
          AI and ML components annotate alerts; they do not change these numbers.
        </div>
        """,
        unsafe_allow_html=True,
    )
    risk_cols = [
        c
        for c in [
            "attack_type",
            "incident_type",
            "severity",
            "risk_score",
            "risk_level",
            "username",
            "source_ip",
            "ip",
            "ml_status",
            "ml_anomaly_score",
        ]
        if c in filtered.columns
    ]
    st.dataframe(
        filtered[risk_cols].sort_values("risk_score", ascending=False),
        use_container_width=True,
        height=340,
    )
else:
    st.caption("No risk_score column found. Run main.py to score alerts.")

# ------------------------------------------------------------------
# Security incidents — correlation engine output
# ------------------------------------------------------------------
section_header(
    "Security Incidents",
    "Correlated incidents produced by correlation.py — compact incident cards.",
)

incident_records = []
if INCIDENTS_PATH.exists():
    try:
        with open(INCIDENTS_PATH, encoding="utf-8") as f:
            incident_records = json.load(f) or []
        if incident_records:
            inc_df = pd.DataFrame(incident_records)
            if "severity" in inc_df.columns:
                inc_df = inc_df[inc_df["severity"].isin(severity_filter)]
            if "attack_type" in inc_df.columns:
                # Incidents without an attack_type cannot match this filter;
                # keep them so no correlated incident is silently hidden.
                inc_df = inc_df[
                    inc_df["attack_type"].isna()
                    | inc_df["attack_type"].isin(attack_filter)
                ]
            incident_records = inc_df.to_dict("records")
    except (json.JSONDecodeError, ValueError):
        incident_records = []

if not incident_records and "incident_type" in filtered.columns:
    incident_records = filtered[filtered["incident_type"].notna()].to_dict("records")

incident_records = sorted(
    incident_records,
    key=lambda rec: -(rec.get("risk_score") or 0),
)

if incident_records:
    for inc in incident_records:
        sev = str(inc.get("severity") or "HIGH")
        level = str(inc.get("risk_level") or sev)
        score = inc.get("risk_score")
        title = inc.get("incident_type") or inc.get("attack_type") or "Incident"
        score_part = f" — risk {score}/100 ({level})" if score is not None else ""
        with st.expander(f"{sev} · {title}{score_part}"):
            color = SEVERITY_COLORS.get(level.upper(), ACCENT)
            description = inc.get("description")
            if description:
                st.markdown(
                    f'<div class="ai-text">{description}</div>',
                    unsafe_allow_html=True,
                )
            meta = []
            if inc.get("username"):
                meta.append(f"user: {inc.get('username')}")
            if inc.get("source_ip"):
                meta.append(f"source: {inc.get('source_ip')}")
            if inc.get("failed_attempts"):
                meta.append(f"failed attempts: {inc.get('failed_attempts')}")
            if inc.get("invalid_user_attempts"):
                meta.append(f"invalid-user attempts: {inc.get('invalid_user_attempts')}")
            if inc.get("window_seconds"):
                meta.append(f"window: {inc.get('window_seconds')}s")
            if meta:
                st.markdown(chips(meta), unsafe_allow_html=True)
            factors = inc.get("risk_factors") or []
            if factors:
                st.markdown(
                    f'<div class="ai-label">Risk Factors</div>',
                    unsafe_allow_html=True,
                )
                st.markdown(chips(factors), unsafe_allow_html=True)
            if score is not None:
                width = max(0, min(int(score), 100))
                st.markdown(
                    f'<div class="riskbar"><div class="riskbar-fill" '
                    f'style="width:{width}%;background:{color};"></div></div>',
                    unsafe_allow_html=True,
                )
            ml_flag = inc.get("ml_is_anomaly")
            if ml_flag is not None and not pd.isna(ml_flag):
                status = "anomaly" if bool(ml_flag) else "typical"
                st.caption(
                    f"ML prototype: {status} (score {inc.get('ml_anomaly_score')})"
                )
else:
    st.caption("No correlated incidents match the current filters.")

# ------------------------------------------------------------------
# AI Security Analyst — analyst console
# ------------------------------------------------------------------
section_header(
    "AI Security Analyst",
    "Analyst console — explanations generated after detection, correlation, "
    "and scoring. AI output is shown verbatim and never modifies risk values.",
)

if AI_PATH.exists():
    with open(AI_PATH, encoding="utf-8") as f:
        ai_report = json.load(f)

    st.markdown(
        f"""
        <div class="panel">
          <div class="ai-label">Executive Summary</div>
          <div class="ai-text">{ai_report.get("executive_summary", "")}</div>
          <div class="kv-muted">Analyst mode: {ai_report.get("analyst_mode", "offline")}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption(ai_report.get("note", ""))

    analyses = ai_report.get("incident_analyses") or []
    analyses = sorted(analyses, key=lambda a: -(a.get("risk_score") or 0))

    st.caption(f"{len(analyses)} analyst write-ups — expand an incident to read the full analysis.")

    for item in analyses:
        analysis = item.get("ai_analysis") or {}
        sev = str(item.get("severity") or "HIGH")
        level = str(item.get("risk_level") or sev)
        title = (
            item.get("incident_type")
            or item.get("attack_type")
            or "Incident"
        )
        subject = item.get("username") or item.get("source_ip") or ""
        subject_part = f" — {subject}" if subject else ""
        with st.expander(
            f"{sev} · {title}{subject_part} — risk {item.get('risk_score')}/100 ({level})"
        ):
            for label, key in (
                ("Summary", "summary"),
                ("Why Suspicious", "why_suspicious"),
                ("Attack Pattern", "attack_pattern"),
                ("Risk Explanation", "risk_explanation"),
            ):
                text = analysis.get(key)
                if text:
                    st.markdown(
                        f'<div class="ai-label">{label}</div>'
                        f'<div class="ai-text">{text}</div>',
                        unsafe_allow_html=True,
                    )
            if item.get("ml_is_anomaly") is True:
                ml_text = (
                    f"Flagged anomalous by the prototype ML model "
                    f"(anomaly score {item.get('ml_anomaly_score')}). "
                    "Prototype output only — not a production accuracy claim."
                )
            elif item.get("ml_is_anomaly") is False:
                ml_text = (
                    f"Within the learned baseline (anomaly score "
                    f"{item.get('ml_anomaly_score')}). "
                    "Prototype output only — not a production accuracy claim."
                )
            else:
                ml_text = ""
            if ml_text:
                st.markdown(
                    '<div class="ai-label">ML Anomaly</div>'
                    f'<div class="ai-text">{ml_text}</div>',
                    unsafe_allow_html=True,
                )
            evidence = analysis.get("evidence") or []
            if evidence:
                st.markdown('<div class="ai-label">Evidence</div>', unsafe_allow_html=True)
                st.markdown(
                    "".join(f'<div class="ai-text">• {e}</div>' for e in evidence),
                    unsafe_allow_html=True,
                )
            steps = analysis.get("investigation_steps") or []
            if steps:
                st.markdown(
                    '<div class="ai-label">Investigation</div>',
                    unsafe_allow_html=True,
                )
                st.markdown(
                    "".join(
                        f'<div class="ai-text">{i}. {step}</div>'
                        for i, step in enumerate(steps, start=1)
                    ),
                    unsafe_allow_html=True,
                )
else:
    st.warning("ai_analysis.json not found. Run main.py to generate AI explanations.")

# ------------------------------------------------------------------
# Alert details
# ------------------------------------------------------------------
section_header(
    "Alert Details",
    "Every detector alert, correlated incident, risk score, and ML field "
    "exactly as exported by main.py.",
)

key_cols = [
    c
    for c in [
        "timestamp",
        "attack_type",
        "incident_type",
        "severity",
        "risk_score",
        "risk_level",
        "username",
        "source_ip",
        "ip",
        "ml_status",
        "ml_anomaly_score",
    ]
    if c in filtered.columns
]
if key_cols:
    st.dataframe(filtered[key_cols], use_container_width=True, height=360)

with st.expander("Show all columns (full raw detail)"):
    st.dataframe(filtered, use_container_width=True)

st.caption(
    f"Showing {len(filtered)} of {len(df)} alerts · "
    "risk values are authoritative from risk_score.py · "
    "ML anomaly detection is a prototype"
)