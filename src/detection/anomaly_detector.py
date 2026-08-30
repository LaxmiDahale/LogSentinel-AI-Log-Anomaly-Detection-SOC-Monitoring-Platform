from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from src.config import settings
from src.utils.logging import logger

class MLAnomalyDetector:
    """
    Unsupervised Anomaly Detector using sklearn.ensemble.IsolationForest.
    Extracts statistical features from events and scores anomalous behavior.
    """
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        cfg = settings.get_settings().get("isolation_forest", {})
        self.contamination = cfg.get("contamination", contamination)
        self.random_state = cfg.get("random_state", random_state)
        self.n_estimators = cfg.get("n_estimators", 100)
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state
        )
        self.is_trained = False

    def extract_features(self, events: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Extracts tabular numerical features per event based on its contextual group (per source IP / per user window).
        """
        if not events:
            return pd.DataFrame(), pd.DataFrame()

        df = pd.DataFrame(events)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hour_of_day"] = df["timestamp"].dt.hour

        # Ensure default values for missing columns
        for col in ["source_ip", "username", "hostname", "status"]:
            if col not in df.columns:
                df[col] = "unknown"

        df["is_failed"] = df["status"].astype(str).str.lower().isin(["failed", "failure", "invalid"]).astype(int)
        df["is_success"] = df["status"].astype(str).str.lower().isin(["success", "successful", "accepted"]).astype(int)

        # Feature matrix list
        features = []
        for idx, row in df.iterrows():
            ip = row["source_ip"]
            user = row["username"]
            ts = row["timestamp"]
            hour = row["hour_of_day"]

            # Filter IP-based window (past 1 hour)
            window_start = ts - pd.Timedelta(hours=1)
            window_ip = df[(df["source_ip"] == ip) & (df["timestamp"] >= window_start) & (df["timestamp"] <= ts)]
            window_user = df[(df["username"] == user) & (df["timestamp"] >= window_start) & (df["timestamp"] <= ts)]

            failed_cnt = int(window_ip["is_failed"].sum())
            success_cnt = int(window_ip["is_success"].sum())
            total_cnt = len(window_ip)
            unique_users = window_ip["username"].nunique()
            unique_ips = window_user["source_ip"].nunique()
            unique_hosts = window_ip["hostname"].nunique()
            events_per_min = total_cnt / 60.0
            login_freq = len(window_user) / 60.0
            fail_ratio = failed_cnt / total_cnt if total_cnt > 0 else 0.0

            features.append({
                "failed_attempt_count": failed_cnt,
                "successful_login_count": success_cnt,
                "unique_users": unique_users,
                "unique_source_ips": unique_ips,
                "unique_destination_hosts": unique_hosts,
                "events_per_minute": events_per_min,
                "login_frequency": login_freq,
                "hour_of_day": hour,
                "authentication_failure_ratio": fail_ratio
            })

        feat_df = pd.DataFrame(features)
        return df, feat_df

    def train_and_predict(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Trains IsolationForest on ingested events and assigns is_anomaly + anomaly_score.
        """
        if len(events) < 5:
            # Not enough data points to train meaningfully, return events as non-anomalous
            for ev in events:
                ev["is_anomaly"] = False
                ev["anomaly_score"] = 0.0
            return events

        df, feat_df = self.extract_features(events)
        if feat_df.empty:
            return events

        try:
            self.model.fit(feat_df)
            self.is_trained = True

            # IsolationForest returns -1 for anomaly, 1 for normal
            preds = self.model.predict(feat_df)
            # score_samples returns negative values (more negative = more anomalous)
            raw_scores = self.model.score_samples(feat_df)

            # Normalize raw scores to 0.0 (normal) to 1.0 (highly anomalous)
            min_score, max_score = raw_scores.min(), raw_scores.max()
            if max_score != min_score:
                norm_scores = (max_score - raw_scores) / (max_score - min_score)
            else:
                norm_scores = np.zeros(len(raw_scores))

            for i, ev in enumerate(events):
                is_anom = bool(preds[i] == -1)
                anom_score = float(norm_scores[i])
                ev["is_anomaly"] = is_anom
                ev["anomaly_score"] = round(anom_score, 4)

            logger.info(f"Isolation Forest trained on {len(events)} events. Anomaly count: {sum(preds == -1)}")
        except Exception as e:
            logger.error(f"Error training Isolation Forest model: {e}")
            for ev in events:
                ev["is_anomaly"] = False
                ev["anomaly_score"] = 0.0

        return events
