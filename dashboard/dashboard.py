import streamlit as st
from src.database.database import init_db, SessionLocal
from dashboard.pages.overview import render_overview_page
from dashboard.pages.events import render_events_page
from dashboard.pages.alerts import render_alerts_page
from dashboard.pages.investigations import render_investigations_page
from dashboard.pages.anomalies import render_anomalies_page
from dashboard.pages.reports import render_reports_page

GLOBAL_SOC_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Background dark theme gradient */
.stApp {
    background: radial-gradient(circle at 10% 20%, #0d1322 0%, #080b14 90%);
}

/* Header Live Pulse Indicator */
.pulse-live {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #00E676;
    box-shadow: 0 0 0 rgba(0, 230, 118, 0.7);
    animation: pulse 1.6s infinite;
    margin-right: 6px;
    vertical-align: middle;
}

@keyframes pulse {
    0% {
        box-shadow: 0 0 0 0 rgba(0, 230, 118, 0.7);
    }
    70% {
        box-shadow: 0 0 0 10px rgba(0, 230, 118, 0);
    }
    100% {
        box-shadow: 0 0 0 0 rgba(0, 230, 118, 0);
    }
}

/* Sidebar styling */
[data-testid="stSidebar"] {
    background-color: #0b0f19 !important;
    border-right: 1px solid rgba(255, 255, 255, 0.08);
}

/* Custom buttons styling */
.stButton > button {
    border-radius: 8px;
    font-weight: 600;
    transition: all 0.2s ease-in-out;
    border: 1px solid rgba(0, 229, 255, 0.3);
}

.stButton > button:hover {
    box-shadow: 0 0 15px rgba(0, 229, 255, 0.4);
    border-color: #00E5FF;
}

/* Code & Data tables monospace font */
code, pre, .stDataFrame {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Hide default streamlit menu header */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
</style>
"""

def main():
    st.set_page_config(
        page_title="LogSentinel AI — SOC Threat Platform",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.markdown(GLOBAL_SOC_CSS, unsafe_allow_html=True)

    # Initialize database
    init_db()
    db = SessionLocal()

    # Sidebar Navigation Header
    st.sidebar.markdown('### 🛡️ **LogSentinel AI**')
    st.sidebar.markdown('<p><span class="pulse-live"></span> <strong style="color:#00E676;">LIVE Threat Monitoring</strong></p>', unsafe_allow_html=True)

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
    **Engine Telemetry:**
    - 🟢 Regex Engine: Active
    - 🟢 Isolation Forest: Active
    - 🟢 SQLite DB: Connected
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
