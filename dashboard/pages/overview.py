import streamlit as st
import pandas as pd
from pathlib import Path
from sqlalchemy.orm import Session

from src.database.database import get_db, clear_db
from src.database.models import EventModel, AlertModel
from src.ingestion.file_ingestion import process_and_ingest_file
from src.detection.rule_engine import run_detection_pipeline
from dashboard.components.metrics import render_kpi_cards
from dashboard.components.charts import (
    plot_threat_level_gauge, plot_events_over_time, plot_alerts_by_severity,
    plot_top_source_ips, plot_top_targeted_users,
    plot_auth_status_distribution, plot_ip_host_relationship
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
SAMPLE_AUTH_LOG = BASE_DIR / "data" / "sample_auth.log"

def render_overview_page(db: Session):
    st.title("🛡️ LogSentinel AI — Security Operations Dashboard")
    st.caption("Production-Style Security Log Analysis & SOC Threat Monitoring Platform")

    # Top Operations & Threat Meter Row
    c_ops, c_gauge = st.columns([2, 1])

    with c_ops:
        st.subheader("⚡ Data Operations & Ingestion")
        o1, o2 = st.columns(2)
        with o1:
            if st.button("🚀 Load Demo Dataset", type="primary", use_container_width=True):
                with st.spinner("Executing full security pipeline (Parsing → Normalizing → ML Detection → Scoring)..."):
                    clear_db()
                    if SAMPLE_AUTH_LOG.exists():
                        with open(SAMPLE_AUTH_LOG, "r", encoding="utf-8") as f:
                            content = f.read()
                        process_and_ingest_file(db, content, filename="sample_auth.log")
                        
                        db_events = db.query(EventModel).all()
                        events_list = [
                            {
                                "event_id": e.event_id,
                                "timestamp": e.timestamp,
                                "hostname": e.hostname,
                                "username": e.username,
                                "source_ip": e.source_ip,
                                "destination_ip": e.destination_ip,
                                "status": e.status,
                                "event_type": e.event_type
                            }
                            for e in db_events
                        ]
                        run_detection_pipeline(db, events_list)
                        st.success("✅ Demo dataset loaded & analyzed!")
                        st.rerun()
                    else:
                        st.error("Sample dataset file not found.")

        with o2:
            uploaded_file = st.file_uploader("Upload Log (.log, .txt, .json, .csv)", type=["log", "txt", "json", "csv"], label_visibility="collapsed")
            if uploaded_file is not None:
                if st.button("📥 Ingest File", use_container_width=True):
                    with st.spinner("Ingesting log file..."):
                        content = uploaded_file.read().decode("utf-8", errors="replace")
                        process_and_ingest_file(db, content, filename=uploaded_file.name)
                        
                        db_events = db.query(EventModel).all()
                        events_list = [
                            {
                                "event_id": e.event_id,
                                "timestamp": e.timestamp,
                                "hostname": e.hostname,
                                "username": e.username,
                                "source_ip": e.source_ip,
                                "destination_ip": e.destination_ip,
                                "status": e.status,
                                "event_type": e.event_type
                            }
                            for e in db_events
                        ]
                        run_detection_pipeline(db, events_list)
                        st.success(f"✅ Ingested '{uploaded_file.name}'!")
                        st.rerun()

    # Fetch data from DB
    events_query = db.query(EventModel).all()
    alerts_query = db.query(AlertModel).all()

    # Calculate Max Threat Score
    max_risk = max([e.risk_score for e in events_query]) if events_query else 0.0

    with c_gauge:
        st.plotly_chart(plot_threat_level_gauge(max_risk), use_container_width=True)

    st.markdown("---")

    if not events_query:
        st.warning("⚠️ No logs ingested yet. Click '🚀 Load Demo Dataset' above to populate the SOC dashboard with realistic synthetic data.")
        return

    # Convert to DataFrames
    events_df = pd.DataFrame([
        {
            "timestamp": e.timestamp,
            "source_ip": e.source_ip,
            "username": e.username,
            "hostname": e.hostname,
            "status": e.status,
            "event_type": e.event_type,
            "severity": e.severity,
            "risk_score": e.risk_score,
            "is_anomaly": e.is_anomaly,
            "anomaly_score": e.anomaly_score
        }
        for e in events_query
    ])

    alerts_df = pd.DataFrame([
        {
            "severity": a.severity,
            "rule_name": a.rule_name,
            "risk_score": a.risk_score
        }
        for a in alerts_query
    ])

    # Calculate KPIs
    total_events = len(events_df)
    total_alerts = len(alerts_df)
    critical_alerts = len(alerts_df[alerts_df["severity"] == "CRITICAL"]) if not alerts_df.empty else 0
    high_alerts = len(alerts_df[alerts_df["severity"] == "HIGH"]) if not alerts_df.empty else 0
    anomalies = int(events_df["is_anomaly"].sum())
    failed_logins = len(events_df[events_df["status"].str.lower().isin(["failed", "failure", "invalid"])])
    unique_ips = events_df["source_ip"].dropna().nunique()
    unique_users = events_df["username"].dropna().nunique()

    # Render High-Tech Dynamic KPI Cards
    render_kpi_cards(
        total_events, total_alerts, critical_alerts, high_alerts,
        anomalies, failed_logins, unique_ips, unique_users
    )

    st.markdown("### 📊 Security Threat Visualizations")

    # Row 1 Charts
    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(plot_events_over_time(events_df), use_container_width=True)
    with col2:
        st.plotly_chart(plot_alerts_by_severity(alerts_df), use_container_width=True)

    # Row 2 Charts
    col3, col4 = st.columns(2)
    with col3:
        st.plotly_chart(plot_top_source_ips(events_df), use_container_width=True)
    with col4:
        st.plotly_chart(plot_top_targeted_users(events_df), use_container_width=True)

    # Row 3 Charts
    col5, col6 = st.columns(2)
    with col5:
        st.plotly_chart(plot_auth_status_distribution(events_df), use_container_width=True)
    with col6:
        st.plotly_chart(plot_ip_host_relationship(events_df), use_container_width=True)
