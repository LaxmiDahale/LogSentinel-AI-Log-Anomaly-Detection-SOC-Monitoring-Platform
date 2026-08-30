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

def plot_events_over_time(df: pd.DataFrame):
    if df.empty or "timestamp" not in df.columns:
        return px.line(title="Events Over Time (No Data)")
    
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    resampled = df.resample("15min", on="timestamp").size().reset_index(name="count")
    fig = px.area(
        resampled, x="timestamp", y="count",
        title="Security Event Velocity Over Time",
        labels={"timestamp": "Time", "count": "Event Volume"},
        template=SOC_DARK_TEMPLATE,
        color_discrete_sequence=[COLOR_PALETTE["PRIMARY"]]
    )
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
    return fig

def plot_alerts_by_severity(df: pd.DataFrame):
    if df.empty or "severity" not in df.columns:
        return px.pie(title="Alerts by Severity (No Data)")

    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]
    fig = px.pie(
        counts, names="severity", values="count",
        title="Alert Severity Breakdown",
        color="severity",
        color_discrete_map=COLOR_PALETTE,
        hole=0.4,
        template=SOC_DARK_TEMPLATE
    )
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
    return fig

def plot_top_source_ips(df: pd.DataFrame, top_n: int = 10):
    if df.empty or "source_ip" not in df.columns:
        return px.bar(title="Top Source IPs")

    ip_counts = df[df["source_ip"].notnull()]["source_ip"].value_counts().head(top_n).reset_index()
    ip_counts.columns = ["source_ip", "count"]
    fig = px.bar(
        ip_counts, x="count", y="source_ip", orientation="h",
        title=f"Top {top_n} Active Source IPs",
        labels={"count": "Event Count", "source_ip": "Source IP"},
        template=SOC_DARK_TEMPLATE,
        color_discrete_sequence=[COLOR_PALETTE["SECONDARY"]]
    )
    fig.update_layout(yaxis=dict(autorange="reversed"), margin=dict(l=20, r=20, t=40, b=20), height=320)
    return fig

def plot_top_targeted_users(df: pd.DataFrame, top_n: int = 10):
    if df.empty or "username" not in df.columns:
        return px.bar(title="Top Targeted Users")

    user_counts = df[df["username"].notnull()]["username"].value_counts().head(top_n).reset_index()
    user_counts.columns = ["username", "count"]
    fig = px.bar(
        user_counts, x="username", y="count",
        title=f"Top {top_n} Targeted Usernames",
        labels={"username": "User", "count": "Attempts"},
        template=SOC_DARK_TEMPLATE,
        color_discrete_sequence=[COLOR_PALETTE["PRIMARY"]]
    )
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
    return fig

def plot_auth_status_distribution(df: pd.DataFrame):
    if df.empty or "status" not in df.columns:
        return px.pie(title="Auth Status")

    counts = df["status"].value_counts().reset_index()
    counts.columns = ["status", "count"]
    fig = px.pie(
        counts, names="status", values="count",
        title="Authentication Outcome (Success vs Failure)",
        color_discrete_sequence=["#00E676", "#FF4B4B", "#FFC107"],
        template=SOC_DARK_TEMPLATE
    )
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
    return fig

def plot_anomaly_distribution(df: pd.DataFrame):
    if df.empty or "anomaly_score" not in df.columns:
        return px.histogram(title="Anomaly Score Distribution")

    fig = px.histogram(
        df, x="anomaly_score", nbins=20,
        title="Isolation Forest Anomaly Score Distribution",
        labels={"anomaly_score": "Anomaly Score (0 = Normal, 1 = Outlier)"},
        template=SOC_DARK_TEMPLATE,
        color_discrete_sequence=["#FF8C00"]
    )
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
    return fig

def plot_detection_rule_distribution(df: pd.DataFrame):
    if df.empty or "rule_name" not in df.columns:
        return px.bar(title="Detection Rules Triggered")

    rule_counts = df["rule_name"].value_counts().reset_index()
    rule_counts.columns = ["rule_name", "count"]
    fig = px.bar(
        rule_counts, x="rule_name", y="count",
        title="Detections by Rule Type",
        color="rule_name",
        template=SOC_DARK_TEMPLATE
    )
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=320)
    return fig

def plot_ip_host_relationship(df: pd.DataFrame):
    if df.empty or "source_ip" not in df.columns or "hostname" not in df.columns:
        return px.scatter(title="Source IP to Host Relationship")

    grouped = df.groupby(["source_ip", "hostname"]).size().reset_index(name="count")
    fig = px.scatter(
        grouped.head(50), x="source_ip", y="hostname", size="count", color="count",
        title="Source IP -> Destination Host Interaction Density",
        template=SOC_DARK_TEMPLATE,
        color_continuous_scale="Reds"
    )
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=340)
    return fig
