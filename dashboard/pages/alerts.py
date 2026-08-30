import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session
from src.database.models import AlertModel
from dashboard.components.tables import render_alerts_table

def render_alerts_page(db: Session):
    st.title("🚨 SOC Security Alerts Management")

    c1, c2, c3 = st.columns(3)
    with c1:
        sev_filter = st.selectbox("Filter Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with c2:
        status_filter = st.selectbox("Filter Status", ["ALL", "NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"])
    with c3:
        search_term = st.text_input("Search Rule / IP / Username", "")

    query = db.query(AlertModel)
    if sev_filter != "ALL":
        query = query.filter(AlertModel.severity == sev_filter)
    if status_filter != "ALL":
        query = query.filter(AlertModel.status == status_filter)
    if search_term.strip():
        term = f"%{search_term.strip()}%"
        query = query.filter(
            (AlertModel.rule_name.ilike(term)) |
            (AlertModel.source_ip.ilike(term)) |
            (AlertModel.username.ilike(term))
        )

    alerts = query.order_by(AlertModel.timestamp.desc()).all()

    st.caption(f"Showing {len(alerts)} alerts")

    if not alerts:
        st.info("No security alerts generated yet.")
        return

    alerts_df = pd.DataFrame([
        {
            "alert_id": a.alert_id,
            "timestamp": a.timestamp,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "source_ip": a.source_ip,
            "username": a.username,
            "status": a.status,
            "description": a.description
        }
        for a in alerts
    ])

    render_alerts_table(alerts_df)

    st.markdown("---")
    st.markdown("### ✏️ Quick Alert Status Triage")
    selected_alert_id = st.selectbox("Select Alert ID to Update Status", options=alerts_df["alert_id"].tolist())
    if selected_alert_id:
        alert_obj = db.query(AlertModel).filter(AlertModel.alert_id == selected_alert_id).first()
        if alert_obj:
            c_st, c_btn = st.columns([2, 1])
            with c_st:
                new_st = st.selectbox("Set New Status", ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"], index=["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].index(alert_obj.status))
            with c_btn:
                st.write("")
                st.write("")
                if st.button("Update Status"):
                    alert_obj.status = new_st
                    db.commit()
                    st.success(f"Updated alert {selected_alert_id} status to {new_st}")
                    st.rerun()
