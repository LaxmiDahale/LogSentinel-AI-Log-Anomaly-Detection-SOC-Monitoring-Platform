import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

SOC_DARK_TEMPLATE = "plotly_dark"
COLOR_PALETTE = {
    "CRITICAL": "#FF4B4B",
    "HIGH": "#FF8C00",
    "MEDIUM": "#FFC107",
    "LOW": "#00E676",
    "PRIMARY": "#00E5FF",
    "SECONDARY": "#7C4DFF"
}

def plot_threat_level_gauge(risk_score: float):
    """
    Renders high-tech circular Threat Level Gauge meter (0 - 100).
    """
    if risk_score >= 75.0:
        bar_color = COLOR_PALETTE["CRITICAL"]
        status_text = "CRITICAL THREAT LEVEL"
    elif risk_score >= 50.0:
        bar_color = COLOR_PALETTE["HIGH"]
        status_text = "HIGH RISK ELEVATED"
    elif risk_score >= 25.0:
        bar_color = COLOR_PALETTE["MEDIUM"]
        status_text = "MODERATE THREAT LEVEL"
    else:
        bar_color = COLOR_PALETTE["LOW"]
        status_text = "SYSTEM NORMAL"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"<b>{status_text}</b>", 'font': {'size': 14, 'color': bar_color}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#8A99AD"},
            'bar': {'color': bar_color, 'width': 0.3},
            'bgcolor': "rgba(18, 25, 41, 0.8)",
            'borderwidth': 1,
            'bordercolor': "#1F293D",
            'steps': [
                {'range': [0, 25], 'color': 'rgba(0, 230, 118, 0.15)'},
                {'range': [25, 50], 'color': 'rgba(255, 193, 7, 0.15)'},
                {'range': [50, 75], 'color': 'rgba(255, 140, 0, 0.15)'},
                {'range': [75, 100], 'color': 'rgba(255, 75, 75, 0.15)'}
            ],
            'threshold': {
                'line': {'color': "#FF4B4B", 'width': 3},
                'thickness': 0.75,
                'value': 75
            }
        }
    ))
    fig.update_layout(
        template=SOC_DARK_TEMPLATE,
        margin=dict(l=20, r=20, t=35, b=20),
        height=220,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)"
    )
    return fig

def plot_events_over_time(df: pd.DataFrame):
    if df.empty or "timestamp" not in df.columns:
        return px.line(title="Events Over Time (No Data)")
    
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    resampled = df.resample("15min", on="timestamp").size().reset_index(name="count")
    fig = px.area(
        resampled, x="timestamp", y="count",
        title="<b>Security Event Velocity Over Time</b>",
        labels={"timestamp": "Time", "count": "Event Volume"},
        template=SOC_DARK_TEMPLATE,
        color_discrete_sequence=[COLOR_PALETTE["PRIMARY"]]
    )
    fig.update_layout(
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(18, 25, 41, 0.5)"
    )
    return fig

def plot_alerts_by_severity(df: pd.DataFrame):
    if df.empty or "severity" not in df.columns:
        return px.pie(title="Alerts by Severity (No Data)")

    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]
    fig = px.pie(
        counts, names="severity", values="count",
        title="<b>Alert Severity Breakdown</b>",
        color="severity",
        color_discrete_map=COLOR_PALETTE,
        hole=0.55,
        template=SOC_DARK_TEMPLATE
    )
    fig.update_layout(
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)"
    )
    return fig

def plot_top_source_ips(df: pd.DataFrame, top_n: int = 10):
    if df.empty or "source_ip" not in df.columns:
        return px.bar(title="Top Source IPs")

    ip_counts = df[df["source_ip"].notnull()]["source_ip"].value_counts().head(top_n).reset_index()
    ip_counts.columns = ["source_ip", "count"]
    fig = px.bar(
        ip_counts, x="count", y="source_ip", orientation="h",
        title=f"<b>Top {top_n} Active Source IPs</b>",
        labels={"count": "Event Count", "source_ip": "Source IP"},
        template=SOC_DARK_TEMPLATE,
        color="count",
        color_continuous_scale="Cyan"
    )
    fig.update_layout(
        yaxis=dict(autorange="reversed"),
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(18, 25, 41, 0.5)"
    )
    return fig

def plot_top_targeted_users(df: pd.DataFrame, top_n: int = 10):
    if df.empty or "username" not in df.columns:
        return px.bar(title="Top Targeted Users")

    user_counts = df[df["username"].notnull()]["username"].value_counts().head(top_n).reset_index()
    user_counts.columns = ["username", "count"]
    fig = px.bar(
        user_counts, x="username", y="count",
        title=f"<b>Top {top_n} Targeted Usernames</b>",
        labels={"username": "User", "count": "Attempts"},
        template=SOC_DARK_TEMPLATE,
        color="count",
        color_continuous_scale="Purples"
    )
    fig.update_layout(
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(18, 25, 41, 0.5)"
    )
    return fig

def plot_auth_status_distribution(df: pd.DataFrame):
    if df.empty or "status" not in df.columns:
        return px.pie(title="Auth Status")

    counts = df["status"].value_counts().reset_index()
    counts.columns = ["status", "count"]
    fig = px.pie(
        counts, names="status", values="count",
        title="<b>Authentication Outcome (Success vs Failure)</b>",
        color_discrete_sequence=["#00E676", "#FF4B4B", "#FFC107"],
        template=SOC_DARK_TEMPLATE,
        hole=0.45
    )
    fig.update_layout(
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)"
    )
    return fig

def plot_anomaly_distribution(df: pd.DataFrame):
    if df.empty or "anomaly_score" not in df.columns:
        return px.histogram(title="Anomaly Score Distribution")

    fig = px.histogram(
        df, x="anomaly_score", nbins=20,
        title="<b>Isolation Forest Anomaly Score Distribution</b>",
        labels={"anomaly_score": "Anomaly Score (0 = Normal, 1 = Outlier)"},
        template=SOC_DARK_TEMPLATE,
        color_discrete_sequence=["#FF8C00"]
    )
    fig.update_layout(
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(18, 25, 41, 0.5)"
    )
    return fig

def plot_detection_rule_distribution(df: pd.DataFrame):
    if df.empty or "rule_name" not in df.columns:
        return px.bar(title="Detection Rules Triggered")

    rule_counts = df["rule_name"].value_counts().reset_index()
    rule_counts.columns = ["rule_name", "count"]
    fig = px.bar(
        rule_counts, x="rule_name", y="count",
        title="<b>Detections by Rule Type</b>",
        color="rule_name",
        template=SOC_DARK_TEMPLATE
    )
    fig.update_layout(
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(18, 25, 41, 0.5)"
    )
    return fig

def plot_ip_host_relationship(df: pd.DataFrame):
    if df.empty or "source_ip" not in df.columns or "hostname" not in df.columns:
        return px.scatter(title="Source IP to Host Relationship")

    grouped = df.groupby(["source_ip", "hostname"]).size().reset_index(name="count")
    fig = px.scatter(
        grouped.head(50), x="source_ip", y="hostname", size="count", color="count",
        title="<b>Source IP -> Destination Host Interaction Density</b>",
        template=SOC_DARK_TEMPLATE,
        color_continuous_scale="Reds"
    )
    fig.update_layout(
        margin=dict(l=20, r=20, t=40, b=20),
        height=340,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(18, 25, 41, 0.5)"
    )
    return fig
