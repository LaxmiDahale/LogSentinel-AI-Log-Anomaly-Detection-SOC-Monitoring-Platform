import streamlit as st
import pandas as pd

def render_events_table(df: pd.DataFrame):
    """
    Renders dynamic pandas dataframe for events with progress bar risk scores.
    """
    if df.empty:
        st.info("No security events found.")
        return

    display_cols = [
        col for col in [
            "timestamp", "severity", "status", "event_type",
            "source_ip", "username", "hostname", "risk_score", "is_anomaly", "message"
        ] if col in df.columns
    ]

    column_config = {}
    if "risk_score" in display_cols:
        column_config["risk_score"] = st.column_config.ProgressColumn(
            "Risk Score",
            help="Multi-factor Risk Score (0-100)",
            format="%.1f",
            min_value=0,
            max_value=100,
        )
    if "is_anomaly" in display_cols:
        column_config["is_anomaly"] = st.column_config.CheckboxColumn(
            "ML Anomaly",
            help="Flagged by Isolation Forest"
        )

    st.dataframe(
        df[display_cols],
        use_container_width=True,
        hide_index=True,
        column_config=column_config
    )

def render_alerts_table(df: pd.DataFrame):
    """
    Renders dynamic pandas dataframe for alerts.
    """
    if df.empty:
        st.info("No security alerts found.")
        return

    display_cols = [
        col for col in [
            "alert_id", "timestamp", "rule_name", "severity",
            "risk_score", "source_ip", "username", "status", "description"
        ] if col in df.columns
    ]

    column_config = {}
    if "risk_score" in display_cols:
        column_config["risk_score"] = st.column_config.ProgressColumn(
            "Risk Score",
            help="Multi-factor Risk Score (0-100)",
            format="%.1f",
            min_value=0,
            max_value=100,
        )

    st.dataframe(
        df[display_cols],
        use_container_width=True,
        hide_index=True,
        column_config=column_config
    )
