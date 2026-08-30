from datetime import timedelta
from typing import List, Dict, Any
import pandas as pd
from src.config import settings

def detect_password_spray(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects one source IP attempting authentication against multiple unique usernames.
    Rule: PASSWORD_SPRAYING
    """
    rules_cfg = settings.get_detection_rules().get("password_spraying", {})
    if not rules_cfg.get("enabled", True):
        return []

    unique_users_threshold = rules_cfg.get("unique_users_threshold", 5)
    window_minutes = rules_cfg.get("window_minutes", 10)

    if not events:
        return []

    df = pd.DataFrame(events)
    if df.empty or "source_ip" not in df.columns or "username" not in df.columns:
        return []

    failed_df = df[
        (df["status"].str.lower().isin(["failed", "failure", "invalid"])) &
        (df["source_ip"].notnull()) &
        (df["source_ip"] != "") &
        (df["username"].notnull())
    ].copy()

    if failed_df.empty:
        return []

    failed_df["timestamp"] = pd.to_datetime(failed_df["timestamp"])
    failed_df = failed_df.sort_values("timestamp")

    alerts = []
    for ip, group in failed_df.groupby("source_ip"):
        timestamps = group["timestamp"].tolist()
        
        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=window_minutes)
            window_events = group[
                (group["timestamp"] >= window_start) & 
                (group["timestamp"] <= window_end)
            ]
            
            unique_users = window_events["username"].unique()
            if len(unique_users) >= unique_users_threshold:
                max_ts = window_events["timestamp"].max()
                alerts.append({
                    "rule_id": "RULE_002",
                    "rule_name": "PASSWORD_SPRAYING",
                    "description": f"IP {ip} attempted authentication against {len(unique_users)} unique usernames within {window_minutes} minutes.",
                    "severity": rules_cfg.get("severity", "HIGH"),
                    "confidence": 0.85,
                    "risk_score": float(rules_cfg.get("risk_points", 30)),
                    "source_ip": str(ip),
                    "username": f"Multiple ({', '.join(map(str, unique_users[:3]))}...)",
                    "timestamp": max_ts.to_pydatetime() if hasattr(max_ts, "to_pydatetime") else max_ts,
                    "related_event_count": len(window_events),
                    "recommended_action": "1. Investigate IP reputation. 2. Enforce MFA across targeted accounts. 3. Check for successful logins from IP."
                })
                break

    return alerts
