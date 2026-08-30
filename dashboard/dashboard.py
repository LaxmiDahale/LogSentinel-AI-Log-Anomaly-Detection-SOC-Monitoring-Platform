import streamlit as st
from src.database.database import init_db, SessionLocal
from dashboard.pages.overview import render_overview_page
from dashboard.pages.events import render_events_page
from dashboard.pages.alerts import render_alerts_page
from dashboard.pages.investigations import render_investigations_page
from dashboard.pages.anomalies import render_anomalies_page
from dashboard.pages.reports import render_reports_page

def main():
    st.set_page_config(
        page_title="LogSentinel AI — SOC Monitoring Platform",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize database
    init_db()
    db = SessionLocal()

    # Sidebar Navigation
    st.sidebar.title("🛡️ LogSentinel AI")
    st.sidebar.caption("SOC Threat Detection & Analytics")

    page = st.sidebar.radio(
        "Navigation",
        [
            "📊 Executive Overview",
            "🔍 Events Explorer",
            "🚨 Security Alerts",
            "🔬 Incident Investigation",
            "🤖 ML Anomalies",
            "📄 Reports & Exports"
        ]
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("""
    **System Status:**
    - 🟢 Engine: Online
    - 🟢 DB: Connected
    - 🟢 Isolation Forest: Active
    """)

    try:
        if page == "📊 Executive Overview":
            render_overview_page(db)
        elif page == "🔍 Events Explorer":
            render_events_page(db)
        elif page == "🚨 Security Alerts":
            render_alerts_page(db)
        elif page == "🔬 Incident Investigation":
            render_investigations_page(db)
        elif page == "🤖 ML Anomalies":
            render_anomalies_page(db)
        elif page == "📄 Reports & Exports":
            render_reports_page(db)
    finally:
        db.close()

if __name__ == "__main__":
    main()
