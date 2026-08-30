from datetime import timedelta
from typing import List, Dict, Any
import pandas as pd
from src.config import settings

def detect_suspicious_success(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule #3: SUCCESS_AFTER_BRUTE_FORCE
    Detects multiple failed authentication attempts followed by a successful login.
    """
    rules_cfg = settings.get_detection_rules().get("suspicious_success", {})
    if not rules_cfg.get("enabled", True):
        return []

    failed_threshold = rules_cfg.get("failed_attempt_threshold", 5)
    window_minutes = rules_cfg.get("window_minutes", 15)

    if not events:
        return []

    df = pd.DataFrame(events)
    if df.empty or "source_ip" not in df.columns or "status" not in df.columns:
        return []

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")

    alerts = []
    # Look for successful logins
    success_df = df[
        (df["status"].str.lower().isin(["success", "successful", "accepted"])) &
        (df["source_ip"].notnull()) &
        (df["source_ip"] != "")
    ]

    for idx, succ_row in success_df.iterrows():
        succ_ip = succ_row["source_ip"]
        succ_user = succ_row.get("username")
        succ_time = succ_row["timestamp"]
        window_start = succ_time - timedelta(minutes=window_minutes)

        # Check prior failed attempts from same source IP
        failed_window = df[
            (df["source_ip"] == succ_ip) &
            (df["status"].str.lower().isin(["failed", "failure", "invalid"])) &
            (df["timestamp"] >= window_start) &
            (df["timestamp"] < succ_time)
        ]

        if len(failed_window) >= failed_threshold:
            alerts.append({
                "rule_id": "RULE_003",
                "rule_name": "SUCCESS_AFTER_BRUTE_FORCE",
                "description": f"CRITICAL: Successful login for '{succ_user}' from IP {succ_ip} after {len(failed_window)} failed authentication attempts within {window_minutes} minutes.",
                "severity": rules_cfg.get("severity", "CRITICAL"),
                "confidence": 0.95,
                "risk_score": float(rules_cfg.get("risk_points", 40)),
                "source_ip": str(succ_ip),
                "username": str(succ_user or "unknown"),
                "timestamp": succ_time.to_pydatetime() if hasattr(succ_time, "to_pydatetime") else succ_time,
                "related_event_count": len(failed_window) + 1,
                "recommended_action": "1. IMMEDIATELY isolate host / terminate user session. 2. Force password reset & revoke tokens. 3. Check for privilege escalation or post-exploitation commands."
            })

    return alerts


def detect_unusual_login(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule #5: UNUSUAL_LOGIN
    Detects logins at unusual hours (e.g. 00:00 - 05:00 AM) or unusual login patterns.
    """
    rules_cfg = settings.get_detection_rules().get("unusual_login", {})
    if not rules_cfg.get("enabled", True):
        return []

    unusual_hours = rules_cfg.get("unusual_hours", [0, 1, 2, 3, 4, 5])

    if not events:
        return []

    df = pd.DataFrame(events)
    if df.empty or "status" not in df.columns:
        return []

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    success_df = df[
        (df["status"].str.lower().isin(["success", "successful", "accepted"])) &
        (df["timestamp"].dt.hour.isin(unusual_hours))
    ]

    alerts = []
    # Deduplicate alerts per user/IP per hour
    seen = set()
    for idx, row in success_df.iterrows():
        user = row.get("username", "unknown")
        ip = row.get("source_ip", "unknown")
        hour = row["timestamp"].hour
        key = (user, ip, hour)

        if key not in seen:
            seen.add(key)
            alerts.append({
                "rule_id": "RULE_005",
                "rule_name": "UNUSUAL_LOGIN_TIME",
                "description": f"Potentially suspicious authentication pattern: Successful login for user '{user}' from IP {ip} at off-hours ({hour:02d}:00).",
                "severity": rules_cfg.get("severity", "MEDIUM"),
                "confidence": 0.6,
                "risk_score": float(rules_cfg.get("risk_points", 15)),
                "source_ip": str(ip) if ip else None,
                "username": str(user) if user else None,
                "timestamp": row["timestamp"].to_pydatetime() if hasattr(row["timestamp"], "to_pydatetime") else row["timestamp"],
                "related_event_count": 1,
                "recommended_action": "1. Verify if employee was working during off-hours. 2. Check source IP location/VPN status."
            })

    return alerts
