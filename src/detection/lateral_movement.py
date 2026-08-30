from datetime import timedelta
from typing import List, Dict, Any
import pandas as pd
from src.config import settings

def detect_lateral_movement(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule #4: POSSIBLE_LATERAL_MOVEMENT
    Detects a single source IP authenticating across multiple destination hosts in a short window.
    """
    rules_cfg = settings.get_detection_rules().get("lateral_movement", {})
    if not rules_cfg.get("enabled", True):
        return []

    dst_threshold = rules_cfg.get("destination_threshold", 3)
    window_minutes = rules_cfg.get("window_minutes", 15)

    if not events:
        return []

    df = pd.DataFrame(events)
    if df.empty or "source_ip" not in df.columns or "hostname" not in df.columns:
        return []

    valid_df = df[
        (df["source_ip"].notnull()) & (df["source_ip"] != "") &
        (df["hostname"].notnull()) & (df["hostname"] != "")
    ].copy()

    if valid_df.empty:
        return []

    valid_df["timestamp"] = pd.to_datetime(valid_df["timestamp"])
    valid_df = valid_df.sort_values("timestamp")

    alerts = []
    for ip, group in valid_df.groupby("source_ip"):
        timestamps = group["timestamp"].tolist()
        
        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=window_minutes)
            window_events = group[
                (group["timestamp"] >= window_start) & 
                (group["timestamp"] <= window_end)
            ]
            
            unique_hosts = window_events["hostname"].unique()
            if len(unique_hosts) >= dst_threshold:
                max_ts = window_events["timestamp"].max()
                users = window_events["username"].dropna().unique()
                
                alerts.append({
                    "rule_id": "RULE_004",
                    "rule_name": "POSSIBLE_LATERAL_MOVEMENT",
                    "description": f"Indicator of potential lateral movement: IP {ip} authenticated across {len(unique_hosts)} destination hosts ({', '.join(map(str, unique_hosts[:4]))}) within {window_minutes} minutes.",
                    "severity": rules_cfg.get("severity", "HIGH"),
                    "confidence": 0.75,
                    "risk_score": float(rules_cfg.get("risk_points", 35)),
                    "source_ip": str(ip),
                    "username": str(users[0]) if len(users) > 0 else "unknown",
                    "timestamp": max_ts.to_pydatetime() if hasattr(max_ts, "to_pydatetime") else max_ts,
                    "related_event_count": len(window_events),
                    "recommended_action": "1. Audit accounts used by source IP. 2. Verify authorization for multi-host remote administration. 3. Inspect target hosts for secondary payloads."
                })
                break

    return alerts
