import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session
from src.database.models import EventModel
from dashboard.components.charts import plot_anomaly_distribution

def render_anomalies_page(db: Session):
    st.title("🤖 Unsupervised ML Anomaly Detection (Isolation Forest)")
    st.info("ℹ️ **Analyst Note:** Machine-learning anomalies indicate statistically unusual behavioral patterns (e.g. abnormal login frequencies, unexpected hour of activity, high failure ratio) and require analyst validation.")

    anomalies = db.query(EventModel).filter(EventModel.is_anomaly == True).order_by(EventModel.anomaly_score.desc()).all()
    all_events_count = db.query(EventModel).count()

    anom_cnt = len(anomalies)
    anom_pct = (anom_cnt / all_events_count * 100.0) if all_events_count > 0 else 0.0
    highest_score = max([a.anomaly_score for a in anomalies]) if anomalies else 0.0

    c1, c2, c3 = st.columns(3)
    c1.metric("Total ML Anomalies", f"{anom_cnt}")
    c2.metric("Anomaly Rate", f"{anom_pct:.2f}%")
    c3.metric("Highest Anomaly Score", f"{highest_score:.4f}")

    if not anomalies:
        st.warning("No anomalies flagged by Isolation Forest model.")
        return

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
        for a in anomalies
    ])

    st.markdown("### 📈 Anomaly Score Distribution & Thresholding")
    st.plotly_chart(plot_anomaly_distribution(anom_df), use_container_width=True)

    st.markdown("### 📋 Detected Machine Learning Outliers Table")
    st.dataframe(
        anom_df[["timestamp", "anomaly_score", "risk_score", "severity", "source_ip", "username", "event_type", "message"]],
        use_container_width=True,
        hide_index=True
    )
