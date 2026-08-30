import streamlit as st
import pandas as pd

def render_events_table(df: pd.DataFrame):
    """
    Renders styled pandas dataframe for events.
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

    st.dataframe(
        df[display_cols],
        use_container_width=True,
        hide_index=True
    )

def render_alerts_table(df: pd.DataFrame):
    """
    Renders styled pandas dataframe for alerts.
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

    st.dataframe(
        df[display_cols],
        use_container_width=True,
        hide_index=True
    )
