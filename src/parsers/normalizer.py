from datetime import datetime
from typing import Dict, Any, Optional
from src.utils.helpers import generate_uuid, utc_now
from src.utils.validators import validate_ip, parse_iso_or_syslog_timestamp

def normalize_event(parsed_data: Dict[str, Any], log_source: str = "linux_auth") -> Dict[str, Any]:
    """
    Normalizes arbitrary parsed log dicts into standard Event schema.
    """
    # Timestamp handling
    raw_ts = parsed_data.get("timestamp")
    if isinstance(raw_ts, datetime):
        ts = raw_ts
    elif isinstance(raw_ts, str):
        ts = parse_iso_or_syslog_timestamp(raw_ts) or utc_now()
    else:
        ts = utc_now()

    # IP validation
    src_ip = parsed_data.get("source_ip")
    if src_ip and not validate_ip(str(src_ip)):
        src_ip = None

    dst_ip = parsed_data.get("destination_ip")
    if dst_ip and not validate_ip(str(dst_ip)):
        dst_ip = None

    # Source & destination ports
    def safe_int(val):
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    event_type = parsed_data.get("event_type", "authentication")
    action = parsed_data.get("action", "login")
    status = parsed_data.get("status", "unknown")
    if isinstance(status, str):
        status = status.lower()

    # Determine base initial severity based on status
    severity = parsed_data.get("severity")
    if not severity:
        if status in ["failed", "failure", "invalid"]:
            severity = "LOW"
        else:
            severity = "LOW"

    return {
        "event_id": parsed_data.get("event_id") or generate_uuid(),
        "timestamp": ts,
        "hostname": parsed_data.get("hostname") or "unknown-host",
        "username": parsed_data.get("username") or None,
        "source_ip": src_ip or None,
        "destination_ip": dst_ip or None,
        "source_port": safe_int(parsed_data.get("source_port")),
        "destination_port": safe_int(parsed_data.get("destination_port")),
        "protocol": parsed_data.get("protocol") or "SSH",
        "event_type": event_type,
        "action": action,
        "status": status,
        "authentication_method": parsed_data.get("authentication_method") or None,
        "process": parsed_data.get("process") or "sshd",
        "service": parsed_data.get("service") or "sshd",
        "message": parsed_data.get("message") or "",
        "log_source": parsed_data.get("log_source") or log_source,
        "severity": severity,
        "risk_score": float(parsed_data.get("risk_score") or 0.0),
        "is_anomaly": bool(parsed_data.get("is_anomaly") or False),
        "anomaly_score": float(parsed_data.get("anomaly_score") or 0.0),
        "detection_rule": parsed_data.get("detection_rule") or None,
    }
