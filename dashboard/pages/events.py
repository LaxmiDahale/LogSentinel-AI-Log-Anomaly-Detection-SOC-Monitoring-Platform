import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session
from src.database.models import EventModel
from src.search.query_engine import execute_search_query
from dashboard.components.tables import render_events_table

def render_events_page(db: Session):
    st.title("🔍 Events Explorer & Splunk-Style Search")

    # Splunk Query Bar
    query_str = st.text_input(
        "Splunk-Style Query Language (SPL)",
        value="",
        placeholder="e.g. status=failed  |  source_ip=192.168.1.100  |  event_type=authentication | stats count by source_ip"
    )

    with st.expander("ℹ️ Supported Query Syntax Documentation"):
        st.markdown("""
        **Key-Value Filters:**
        - `status=failed`
        - `severity=HIGH`
        - `source_ip=192.168.1.100`
        - `username=admin`
        
        **Aggregations & Commands:**
        - `status=failed | stats count by source_ip`
        - `event_type=authentication | stats count by username`
        - `event_type=authentication | top source_ip`
        """)

    if query_str.strip():
        res = execute_search_query(db, query_str)
        st.markdown(f"**Query Results ({res['total_results']} matching events):**")
        
        if res.get("stats"):
            st.markdown("#### Aggregated Statistics")
            st.dataframe(pd.DataFrame(res["stats"]), use_container_width=True)

        if res.get("events"):
            df = pd.DataFrame(res["events"])
            render_events_table(df)
        else:
            st.info("No events matched the Splunk query.")
        return

    # Standard Field Filtering
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        status_filter = st.selectbox("Status", ["ALL", "success", "failed", "invalid", "unknown"])
    with c2:
        severity_filter = st.selectbox("Severity", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    with c3:
        ip_filter = st.text_input("Source IP", "")
    with c4:
        user_filter = st.text_input("Username", "")

    query = db.query(EventModel)
    if status_filter != "ALL":
        query = query.filter(EventModel.status.ilike(status_filter))
    if severity_filter != "ALL":
        query = query.filter(EventModel.severity == severity_filter)
    if ip_filter.strip():
        query = query.filter(EventModel.source_ip == ip_filter.strip())
    if user_filter.strip():
        query = query.filter(EventModel.username.ilike(f"%{user_filter.strip()}%"))

    events = query.order_by(EventModel.timestamp.desc()).limit(300).all()

    st.caption(f"Showing {len(events)} events")

    if not events:
        st.info("No security events match the selected filters.")
        return

    events_df = pd.DataFrame([
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp,
            "severity": e.severity,
            "status": e.status,
            "event_type": e.event_type,
            "source_ip": e.source_ip,
            "username": e.username,
            "hostname": e.hostname,
            "risk_score": e.risk_score,
            "is_anomaly": e.is_anomaly,
            "message": e.message
        }
        for e in events
    ])

    render_events_table(events_df)

    st.markdown("### 🔍 Raw Event Inspector")
    selected_idx = st.selectbox("Select Event ID to inspect raw JSON", options=events_df["event_id"].tolist())
    if selected_idx:
        selected_event = next((e for e in events if e.event_id == selected_idx), None)
        if selected_event:
            st.json({
                "event_id": selected_event.event_id,
                "timestamp": selected_event.timestamp.isoformat() if selected_event.timestamp else None,
                "hostname": selected_event.hostname,
                "username": selected_event.username,
                "source_ip": selected_event.source_ip,
                "destination_ip": selected_event.destination_ip,
                "source_port": selected_event.source_port,
                "event_type": selected_event.event_type,
                "action": selected_event.action,
                "status": selected_event.status,
                "process": selected_event.process,
                "service": selected_event.service,
                "message": selected_event.message,
                "severity": selected_event.severity,
                "risk_score": selected_event.risk_score,
                "is_anomaly": selected_event.is_anomaly,
                "anomaly_score": selected_event.anomaly_score,
                "detection_rule": selected_event.detection_rule
            })
