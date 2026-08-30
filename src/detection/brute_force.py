from datetime import timedelta
from typing import List, Dict, Any
import pandas as pd
from src.config import settings

def detect_brute_force(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects repeated failed authentication attempts from the same source IP.
    Rule: SSH_BRUTE_FORCE
    """
    rules_cfg = settings.get_detection_rules().get("brute_force", {})
    if not rules_cfg.get("enabled", True):
        return []

    threshold = rules_cfg.get("threshold", 5)
    window_minutes = rules_cfg.get("window_minutes", 5)

    if not events:
        return []

    df = pd.DataFrame(events)
    if df.empty or "source_ip" not in df.columns or "status" not in df.columns:
        return []

    # Filter failed authentication events
    failed_df = df[
        (df["status"].str.lower().isin(["failed", "failure", "invalid"])) &
        (df["source_ip"].notnull()) &
        (df["source_ip"] != "")
    ].copy()

    if failed_df.empty:
        return []

    failed_df["timestamp"] = pd.to_datetime(failed_df["timestamp"])
    failed_df = failed_df.sort_values("timestamp")

    alerts = []
    # Group by source_ip
    for ip, group in failed_df.groupby("source_ip"):
        timestamps = group["timestamp"].tolist()
        usernames = group["username"].dropna().unique().tolist()
        
        # Sliding window check
        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=window_minutes)
            window_events = group[
                (group["timestamp"] >= window_start) & 
                (group["timestamp"] <= window_end)
            ]
            
            if len(window_events) >= threshold:
                min_ts = window_events["timestamp"].min()
                max_ts = window_events["timestamp"].max()
                
                alerts.append({
                    "rule_id": "RULE_001",
                    "rule_name": "SSH_BRUTE_FORCE",
                    "description": f"Detected {len(window_events)} failed login attempts from IP {ip} within {window_minutes} minutes.",
                    "severity": rules_cfg.get("severity", "HIGH"),
                    "confidence": 0.9,
                    "risk_score": float(rules_cfg.get("risk_points", 25)),
                    "source_ip": str(ip),
                    "username": usernames[0] if len(usernames) > 0 else "multiple/unknown",
                    "timestamp": max_ts.to_pydatetime() if hasattr(max_ts, "to_pydatetime") else max_ts,
                    "related_event_count": len(window_events),
                    "recommended_action": "1. Block source IP at firewall. 2. Verify account security. 3. Check for compromised credentials."
                })
                break  # Alert generated for this IP window

    return alerts
