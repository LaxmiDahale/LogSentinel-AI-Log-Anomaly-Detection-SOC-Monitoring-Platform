from typing import Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from src.database.models import EventModel, AlertModel
from src.utils.helpers import utc_now

def generate_security_summary_report(db: Session) -> Dict[str, Any]:
    """
    Generates comprehensive SOC Security Summary report.
    """
    total_events = db.query(EventModel).count()
    total_alerts = db.query(AlertModel).count()
    
    critical_alerts = db.query(AlertModel).filter(AlertModel.severity == "CRITICAL").count()
    high_alerts = db.query(AlertModel).filter(AlertModel.severity == "HIGH").count()
    medium_alerts = db.query(AlertModel).filter(AlertModel.severity == "MEDIUM").count()
    low_alerts = db.query(AlertModel).filter(AlertModel.severity == "LOW").count()

    anomalies_count = db.query(EventModel).filter(EventModel.is_anomaly == True).count()
    failed_logins = db.query(EventModel).filter(EventModel.status.ilike("failed")).count()

    # Top source IPs
    top_ips = (
        db.query(EventModel.source_ip, func.count(EventModel.id).label("count"))
        .filter(EventModel.source_ip.isnot(None))
        .group_by(EventModel.source_ip)
        .order_by(func.count(EventModel.id).desc())
        .limit(5)
        .all()
    )

    # Top targeted users
    top_users = (
        db.query(EventModel.username, func.count(EventModel.id).label("count"))
        .filter(EventModel.username.isnot(None))
        .group_by(EventModel.username)
        .order_by(func.count(EventModel.id).desc())
        .limit(5)
        .all()
    )

    # Alerts by rule name
    alerts_by_rule = (
        db.query(AlertModel.rule_name, func.count(AlertModel.id).label("count"))
        .group_by(AlertModel.rule_name)
        .order_by(func.count(AlertModel.id).desc())
        .all()
    )

    return {
        "generated_at": utc_now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_events": total_events,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "anomalies_count": anomalies_count,
        "failed_logins": failed_logins,
        "top_source_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
        "top_targeted_users": [{"username": usr, "count": cnt} for usr, cnt in top_users],
        "detection_rule_breakdown": [{"rule": r, "count": cnt} for r, cnt in alerts_by_rule]
    }
