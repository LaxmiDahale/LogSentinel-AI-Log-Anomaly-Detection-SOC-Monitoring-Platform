from typing import List, Dict, Any
from sqlalchemy.orm import Session

from src.detection.brute_force import detect_brute_force
from src.detection.password_spray import detect_password_spray
from src.detection.suspicious_login import detect_suspicious_success, detect_unusual_login
from src.detection.lateral_movement import detect_lateral_movement
from src.detection.anomaly_detector import MLAnomalyDetector
from src.detection.risk_scoring import calculate_event_risk_score
from src.database.models import AlertModel, EventModel
from src.utils.logging import logger

def run_detection_pipeline(db: Session, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Executes full security detection pipeline:
    1. ML Anomaly Detection (Isolation Forest)
    2. Deterministic Detection Rules (Brute Force, Password Spray, Lateral Movement, etc.)
    3. Multi-Factor Risk Scoring
    4. DB Event Updates & Alert Generation
    """
    if not events:
        return {"alerts": [], "processed_count": 0, "anomaly_count": 0}

    # 1. Run ML Isolation Forest
    detector = MLAnomalyDetector()
    events = detector.train_and_predict(events)

    # 2. Run Deterministic Rules
    alerts_data = []
    alerts_data.extend(detect_brute_force(events))
    alerts_data.extend(detect_password_spray(events))
    alerts_data.extend(detect_suspicious_success(events))
    alerts_data.extend(detect_lateral_movement(events))
    alerts_data.extend(detect_unusual_login(events))

    # Map triggered rules to event IPs / usernames
    ip_rule_map = {}
    for alt in alerts_data:
        ip = alt.get("source_ip")
        if ip:
            if ip not in ip_rule_map:
                ip_rule_map[ip] = []
            ip_rule_map[ip].append(alt.get("rule_name"))

    # 3. Calculate Risk Scores & Update Events
    anomaly_count = 0
    for ev in events:
        if ev.get("is_anomaly"):
            anomaly_count += 1
        
        ip = ev.get("source_ip")
        triggered = ip_rule_map.get(ip, [])
        risk_res = calculate_event_risk_score(ev, triggered_rules=triggered)
        ev["risk_score"] = risk_res["risk_score"]
        ev["severity"] = risk_res["severity"]
        if triggered:
            ev["detection_rule"] = ", ".join(set(triggered))

    # Update DB event models if persisted
    db_events = db.query(EventModel).all()
    event_map = {e.event_id: e for e in db_events}
    for ev in events:
        eid = ev.get("event_id")
        if eid in event_map:
            db_ev = event_map[eid]
            db_ev.is_anomaly = ev.get("is_anomaly", False)
            db_ev.anomaly_score = ev.get("anomaly_score", 0.0)
            db_ev.risk_score = ev.get("risk_score", 0.0)
            db_ev.severity = ev.get("severity", "LOW")
            db_ev.detection_rule = ev.get("detection_rule")

    # 4. Save Generated Alerts to DB
    created_alerts = []
    for alt in alerts_data:
        # Check if alert already exists to prevent duplication
        existing = db.query(AlertModel).filter(
            AlertModel.rule_name == alt["rule_name"],
            AlertModel.source_ip == alt.get("source_ip"),
            AlertModel.timestamp == alt["timestamp"]
        ).first()

        if not existing:
            alert_obj = AlertModel(
                rule_id=alt["rule_id"],
                rule_name=alt["rule_name"],
                timestamp=alt["timestamp"],
                severity=alt["severity"],
                risk_score=alt["risk_score"],
                confidence=alt.get("confidence", 0.8),
                source_ip=alt.get("source_ip"),
                username=alt.get("username"),
                description=alt["description"],
                status="NEW"
            )
            db.add(alert_obj)
            created_alerts.append(alert_obj)

    db.commit()
    logger.info(f"Detection pipeline complete: Processed {len(events)} events, created {len(created_alerts)} new alerts.")

    return {
        "alerts": created_alerts,
        "processed_count": len(events),
        "anomaly_count": anomaly_count
    }
