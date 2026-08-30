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
    Renders dynamic, high-tech glassmorphic SOC metric cards with neon glows and hover animations.
    """
    cards_html = f"""
    <style>
    .soc-metric-container {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
        gap: 12px;
        margin-bottom: 24px;
    }}
    .soc-metric-card {{
        background: rgba(18, 25, 41, 0.75);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 14px 12px;
        text-align: center;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    }}
    .soc-metric-card:hover {{
        transform: translateY(-4px);
        box-shadow: 0 8px 25px rgba(0, 229, 255, 0.15);
        border-color: rgba(0, 229, 255, 0.3);
    }}
    .soc-metric-title {{
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: #8A99AD;
        margin-bottom: 6px;
    }}
    .soc-metric-value {{
        font-size: 1.4rem;
        font-weight: 700;
        font-family: 'Inter', sans-serif;
        color: #FFFFFF;
    }}
    .soc-metric-value.cyan {{ color: #00E5FF; text-shadow: 0 0 10px rgba(0,225,255,0.3); }}
    .soc-metric-value.red {{ color: #FF4B4B; text-shadow: 0 0 10px rgba(255,75,75,0.4); }}
    .soc-metric-value.orange {{ color: #FF8C00; text-shadow: 0 0 10px rgba(255,140,0,0.3); }}
    .soc-metric-value.amber {{ color: #FFC107; text-shadow: 0 0 10px rgba(255,193,7,0.3); }}
    .soc-metric-value.green {{ color: #00E676; text-shadow: 0 0 10px rgba(0,230,118,0.3); }}
    .soc-metric-value.purple {{ color: #B388FF; text-shadow: 0 0 10px rgba(179,136,255,0.3); }}
    </style>

    <div class="soc-metric-container">
        <div class="soc-metric-card">
            <div class="soc-metric-title">Total Events</div>
            <div class="soc-metric-value cyan">{total_events:,}</div>
        </div>
        <div class="soc-metric-card">
            <div class="soc-metric-title">Total Alerts</div>
            <div class="soc-metric-value amber">{total_alerts:,}</div>
        </div>
        <div class="soc-metric-card">
            <div class="soc-metric-title">Critical Alerts</div>
            <div class="soc-metric-value red">{critical_alerts}</div>
        </div>
        <div class="soc-metric-card">
            <div class="soc-metric-title">High Alerts</div>
            <div class="soc-metric-value orange">{high_alerts}</div>
        </div>
        <div class="soc-metric-card">
            <div class="soc-metric-title">ML Anomalies</div>
            <div class="soc-metric-value purple">{anomalies}</div>
        </div>
        <div class="soc-metric-card">
            <div class="soc-metric-title">Failed Logins</div>
            <div class="soc-metric-value red">{failed_logins:,}</div>
        </div>
        <div class="soc-metric-card">
            <div class="soc-metric-title">Unique IPs</div>
            <div class="soc-metric-value green">{unique_ips}</div>
        </div>
        <div class="soc-metric-card">
            <div class="soc-metric-title">Unique Users</div>
            <div class="soc-metric-value cyan">{unique_users}</div>
        </div>
    </div>
    """
    st.markdown(cards_html, unsafe_allow_html=True)
