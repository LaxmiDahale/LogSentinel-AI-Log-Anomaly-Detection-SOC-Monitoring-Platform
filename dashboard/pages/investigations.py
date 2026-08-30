import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session
from src.database.models import AlertModel, EventModel, InvestigationModel
from src.utils.helpers import utc_now
from dashboard.components.tables import render_events_table

def render_investigations_page(db: Session):
    st.title("🔬 Analyst Alert Investigation Workbench")

    alerts = db.query(AlertModel).order_by(AlertModel.timestamp.desc()).all()
    if not alerts:
        st.info("No security alerts available for investigation.")
        return

    alert_options = {f"[{a.severity}] {a.rule_name} — {a.source_ip or 'No IP'} ({a.alert_id[:8]})": a.alert_id for a in alerts}
    selected_label = st.selectbox("Select Alert for Deep Investigation", list(alert_options.keys()))
    selected_id = alert_options[selected_label]

    alert = db.query(AlertModel).filter(AlertModel.alert_id == selected_id).first()
    if not alert:
        st.error("Selected alert not found.")
        return

    # Section 1: Alert Summary Cards
    st.markdown("### 📋 Alert Summary")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Alert ID", alert.alert_id[:8])
    c2.metric("Rule Name", alert.rule_name)
    c3.metric("Severity", alert.severity)
    c4.metric("Risk Score", f"{alert.risk_score:.1f}/100")
    c5.metric("Status", alert.status)

    st.info(f"**Description:** {alert.description}")

    # Section 2: Affected Entities
    st.markdown("### 🎯 Affected Entities")
    e1, e2, e3 = st.columns(3)
    e1.markdown(f"**Source IP:** `{alert.source_ip or 'N/A'}`")
    e2.markdown(f"**Target User:** `{alert.username or 'N/A'}`")
    e3.markdown(f"**Trigger Time:** `{alert.timestamp}`")

    st.markdown("---")

    # Section 3: Evidence Events Timeline
    st.markdown("### 🔍 Evidence & Related Events Timeline")
    ev_query = db.query(EventModel)
    if alert.source_ip:
        ev_query = ev_query.filter(EventModel.source_ip == alert.source_ip)
    if alert.username:
        ev_query = ev_query.filter(EventModel.username == alert.username)
    evidence_events = ev_query.order_by(EventModel.timestamp.desc()).limit(50).all()

    if evidence_events:
        ev_df = pd.DataFrame([
            {
                "timestamp": e.timestamp,
                "severity": e.severity,
                "status": e.status,
                "hostname": e.hostname,
                "source_ip": e.source_ip,
                "username": e.username,
                "message": e.message
            }
            for e in evidence_events
        ])
        render_events_table(ev_df)
    else:
        st.write("No directly correlated evidence events found.")

    st.markdown("---")

    # Section 4: Recommended Defensive Playbook
    st.markdown("### 🛡️ Recommended Analyst Investigation Guidance")
    playbook_box = st.container()
    with playbook_box:
        st.markdown("""
        1. **Verify Source IP**: Check if the IP `{ip}` belongs to a corporate VPN, internal subnet, or external threat actor feed.
        2. **Account Audit**: Inspect password change history and multi-factor authentication (MFA) status for targeted user `{user}`.
        3. **Host Inspection**: Determine whether successful logins resulted in unauthorized privilege escalation (`sudo`) or process execution.
        4. **Containment Consideration**: If malicious intent is verified, apply immediate firewall block on `{ip}` and force password reset.
        5. **Incident Escalation**: Document findings and escalate to Tier-2 SOC lead if lateral movement indicators are detected.
        """.format(ip=alert.source_ip or "N/A", user=alert.username or "N/A"))

    st.markdown("---")

    # Section 5: Analyst Investigation Notes & Case File
    st.markdown("### 📝 Incident Case File & Analyst Notes")

    investigation = db.query(InvestigationModel).filter(InvestigationModel.alert_id == alert.alert_id).first()
    existing_notes = investigation.analyst_notes if investigation else ""

    notes = st.text_area("Analyst Case Notes", value=existing_notes, height=150, placeholder="Document your forensic observations, triage steps, and containment actions...")
    
    col_st, col_save = st.columns([2, 1])
    with col_st:
        new_status = st.selectbox("Update Case Status", ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"], index=["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].index(alert.status))
    with col_save:
        st.write("")
        st.write("")
        if st.button("💾 Save Case Investigation", type="primary", use_container_width=True):
            alert.status = new_status
            if investigation:
                investigation.analyst_notes = notes
                investigation.status = new_status
                investigation.updated_at = utc_now()
            else:
                investigation = InvestigationModel(
                    alert_id=alert.alert_id,
                    analyst_notes=notes,
                    status=new_status
                )
                db.add(investigation)
            db.commit()
            st.success("✅ Case notes and alert status saved successfully!")
            st.rerun()
