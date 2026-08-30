from typing import Dict, Any, List
from src.config import settings

def calculate_event_risk_score(event: Dict[str, Any], triggered_rules: List[str] = None) -> Dict[str, Any]:
    """
    Calculates transparent 0-100 risk score and severity for an event based on multi-factor rules.
    """
    triggered_rules = triggered_rules or []
    cfg = settings.get_settings().get("risk_scoring", {})

    base_failed_auth = cfg.get("base_failed_auth", 5)
    base_multiple_users = cfg.get("base_multiple_users", 15)
    base_success_after_failure = cfg.get("base_success_after_failure", 30)
    base_multiple_destinations = cfg.get("base_multiple_destinations", 20)
    base_ml_anomaly = cfg.get("base_ml_anomaly", 15)

    rules_cfg = settings.get_detection_rules()
    bf_pts = rules_cfg.get("brute_force", {}).get("risk_points", 25)
    spray_pts = rules_cfg.get("password_spraying", {}).get("risk_points", 30)
    succ_pts = rules_cfg.get("suspicious_success", {}).get("risk_points", 40)
    lat_pts = rules_cfg.get("lateral_movement", {}).get("risk_points", 35)
    unusual_pts = rules_cfg.get("unusual_login", {}).get("risk_points", 15)

    score = 0.0
    reasons = []

    status = str(event.get("status", "")).lower()
    if status in ["failed", "failure", "invalid"]:
        score += base_failed_auth
        reasons.append(f"Failed authentication (+{base_failed_auth})")

    if "RULE_001" in triggered_rules or "SSH_BRUTE_FORCE" in triggered_rules:
        score += bf_pts
        reasons.append(f"SSH Brute Force pattern (+{bf_pts})")

    if "RULE_002" in triggered_rules or "PASSWORD_SPRAYING" in triggered_rules:
        score += spray_pts
        reasons.append(f"Password spraying pattern (+{spray_pts})")

    if "RULE_003" in triggered_rules or "SUCCESS_AFTER_BRUTE_FORCE" in triggered_rules:
        score += succ_pts
        reasons.append(f"Success login after repeated failures (+{succ_pts})")

    if "RULE_004" in triggered_rules or "POSSIBLE_LATERAL_MOVEMENT" in triggered_rules:
        score += lat_pts
        reasons.append(f"Multiple destination hosts authentication (+{lat_pts})")

    if "RULE_005" in triggered_rules or "UNUSUAL_LOGIN_TIME" in triggered_rules:
        score += unusual_pts
        reasons.append(f"Unusual login hour (+{unusual_pts})")

    if event.get("is_anomaly"):
        anom_points = base_ml_anomaly * float(event.get("anomaly_score", 0.5))
        score += anom_points
        reasons.append(f"ML Isolation Forest Anomaly (+{anom_points:.1f})")

    # Normalize final score between 0 and 100
    final_score = min(100.0, max(0.0, score))

    # Map to severity
    if final_score >= 75.0:
        severity = "CRITICAL"
    elif final_score >= 50.0:
        severity = "HIGH"
    elif final_score >= 25.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": round(final_score, 1),
        "severity": severity,
        "reasons": reasons
    }
