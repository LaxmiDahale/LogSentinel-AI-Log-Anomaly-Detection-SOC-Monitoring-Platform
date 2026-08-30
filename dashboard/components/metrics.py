import streamlit as st

def render_kpi_cards(
    total_events: int,
    total_alerts: int,
    critical_alerts: int,
    high_alerts: int,
    anomalies: int,
    failed_logins: int,
    unique_ips: int,
    unique_users: int
):
    """
    Renders styled 8-card SOC metrics layout.
    """
    col1, col2, col3, col4, col5, col6, col7, col8 = st.columns(8)

    with col1:
        st.metric("Total Events", f"{total_events:,}")
    with col2:
        st.metric("Total Alerts", f"{total_alerts:,}")
    with col3:
        st.metric("Critical Alerts", f"{critical_alerts}", delta_color="inverse")
    with col4:
        st.metric("High Alerts", f"{high_alerts}")
    with col5:
        st.metric("Anomalies", f"{anomalies}")
    with col6:
        st.metric("Failed Logins", f"{failed_logins:,}")
    with col7:
        st.metric("Unique IPs", f"{unique_ips}")
    with col8:
        st.metric("Unique Users", f"{unique_users}")
