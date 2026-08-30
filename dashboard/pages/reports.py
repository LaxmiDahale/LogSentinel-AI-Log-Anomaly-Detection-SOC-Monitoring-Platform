import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session
from src.reporting.report_generator import generate_security_summary_report
from src.reporting.exporters import export_to_csv, export_to_json, export_report_markdown
from src.database.models import EventModel, AlertModel

def render_reports_page(db: Session):
    st.title("📄 SOC Security Reporting & Data Export")

    report_data = generate_security_summary_report(db)

    st.markdown("### 📊 Security Executive Summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Ingested Events", f"{report_data['total_events']:,}")
    c2.metric("Total Generated Alerts", f"{report_data['total_alerts']:,}")
    c3.metric("Critical Alerts", f"{report_data['critical_alerts']}")
    c4.metric("ML Anomalies", f"{report_data['anomalies_count']}")

    st.markdown("---")

    col_left, col_right = st.columns(2)
    with col_left:
        st.markdown("#### 🌐 Top Targeted Source IPs")
        st.dataframe(pd.DataFrame(report_data["top_source_ips"]), use_container_width=True)

    with col_right:
        st.markdown("#### 👤 Top Targeted Usernames")
        st.dataframe(pd.DataFrame(report_data["top_targeted_users"]), use_container_width=True)

    st.markdown("---")

    st.markdown("#### 🚨 Detection Rule Breakdown")
    st.dataframe(pd.DataFrame(report_data["detection_rule_breakdown"]), use_container_width=True)

    st.markdown("### 📥 Export Reports & Raw Datasets")

    md_report = export_report_markdown(report_data)
    json_report = export_to_json(report_data)

    events_models = db.query(EventModel).limit(500).all()
    events_data = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "source_ip": e.source_ip,
            "username": e.username,
            "status": e.status,
            "severity": e.severity,
            "risk_score": e.risk_score
        }
        for e in events_models
    ]
    csv_events = export_to_csv(events_data)

    c_exp1, c_exp2, c_exp3 = st.columns(3)
    with c_exp1:
        st.download_button(
            "⬇️ Download Executive Report (Markdown)",
            data=md_report,
            file_name="security_summary_report.md",
            mime="text/markdown",
            use_container_width=True
        )
    with c_exp2:
        st.download_button(
            "⬇️ Download Security Summary (JSON)",
            data=json_report,
            file_name="security_summary_report.json",
            mime="application/json",
            use_container_width=True
        )
    with c_exp3:
        st.download_button(
            "⬇️ Download Raw Events (CSV)",
            data=csv_events,
            file_name="security_events.csv",
            mime="text/csv",
            use_container_width=True
        )
