import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session
from src.database.models import EventModel
from dashboard.components.charts import plot_anomaly_distribution

def render_anomalies_page(db: Session):
    st.title("🤖 Unsupervised ML Anomaly Detection (Isolation Forest)")
    st.info("ℹ️ **Analyst Note:** Machine-learning anomalies indicate statistically unusual behavioral patterns (e.g. abnormal login frequencies, unexpected hour of activity, high failure ratio) and require analyst validation.")

    # Interactive Threshold Slider
    c_slider, c_btn = st.columns([3, 1])
    with c_slider:
        threshold = st.slider(
            "🎚️ Dynamic Isolation Forest Score Sensitivity Threshold",
            min_value=0.10,
            max_value=0.95,
            value=0.50,
            step=0.05,
            help="Filter anomalies by minimum Isolation Forest statistical outlier score."
        )

    all_events = db.query(EventModel).order_by(EventModel.anomaly_score.desc()).all()
    if not all_events:
        st.warning("No security events available for anomaly scoring.")
        return

    filtered_anomalies = [e for e in all_events if e.is_anomaly or e.anomaly_score >= threshold]
    all_cnt = len(all_events)
    anom_cnt = len(filtered_anomalies)
    anom_pct = (anom_cnt / all_cnt * 100.0) if all_cnt > 0 else 0.0
    highest_score = max([e.anomaly_score for e in all_events]) if all_events else 0.0

    c1, c2, c3 = st.columns(3)
    c1.metric("Filtered Outliers", f"{anom_cnt}")
    c2.metric("Anomaly Rate", f"{anom_pct:.2f}%")
    c3.metric("Highest Score", f"{highest_score:.4f}")

    anom_df = pd.DataFrame([
        {
            "timestamp": a.timestamp,
            "event_type": a.event_type,
            "source_ip": a.source_ip,
            "username": a.username,
            "anomaly_score": a.anomaly_score,
            "risk_score": a.risk_score,
            "severity": a.severity,
            "message": a.message
        }
        for a in filtered_anomalies
    ])

    st.markdown("### 📈 Anomaly Score Distribution & Interactive Filtering")
    st.plotly_chart(plot_anomaly_distribution(anom_df), use_container_width=True)

    st.markdown(f"### 📋 Detected Outliers (Score $\ge$ {threshold:.2f})")
    if not anom_df.empty:
        st.dataframe(
            anom_df[["timestamp", "anomaly_score", "risk_score", "severity", "source_ip", "username", "event_type", "message"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info(f"No statistical anomalies exceeded the {threshold:.2f} threshold.")
