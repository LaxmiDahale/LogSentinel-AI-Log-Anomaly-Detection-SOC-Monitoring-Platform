from pathlib import Path
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from src.parsers.auth_parser import parse_auth_line
from src.parsers.json_parser import parse_json_content
from src.ingestion.csv_ingestion import parse_csv_content
from src.database.models import EventModel
from src.utils.logging import logger

def ingest_raw_log_text(text_content: str, filename: str = "raw.log") -> List[Dict[str, Any]]:
    """
    Parses raw text content according to filename extension or line patterns.
    """
    ext = Path(filename).suffix.lower()
    
    if ext == ".json":
        return parse_json_content(text_content, log_source=filename)
    elif ext == ".csv":
        return parse_csv_content(text_content, log_source=filename)
    else:
        # Plain text log file (.log, .txt, syslog, auth.log)
        events = []
        for line in text_content.splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = parse_auth_line(line)
            if parsed:
                parsed["log_source"] = filename
                events.append(parsed)
        return events

def save_events_to_db(db: Session, events: List[Dict[str, Any]]) -> List[EventModel]:
    """
    Persists normalized event dicts into the database using bulk save.
    """
    db_events = []
    for ev in events:
        model = EventModel(
            event_id=ev.get("event_id"),
            timestamp=ev.get("timestamp"),
            hostname=ev.get("hostname"),
            username=ev.get("username"),
            source_ip=ev.get("source_ip"),
            destination_ip=ev.get("destination_ip"),
            source_port=ev.get("source_port"),
            destination_port=ev.get("destination_port"),
            protocol=ev.get("protocol"),
            event_type=ev.get("event_type"),
            action=ev.get("action"),
            status=ev.get("status"),
            authentication_method=ev.get("authentication_method"),
            process=ev.get("process"),
            service=ev.get("service"),
            message=ev.get("message"),
            log_source=ev.get("log_source"),
            severity=ev.get("severity", "LOW"),
            risk_score=ev.get("risk_score", 0.0),
            is_anomaly=ev.get("is_anomaly", False),
            anomaly_score=ev.get("anomaly_score", 0.0),
            detection_rule=ev.get("detection_rule")
        )
        db_events.append(model)

    if db_events:
        db.bulk_save_objects(db_events)
        db.commit()
        logger.info(f"Ingested and saved {len(db_events)} events to database.")
    return db_events

def process_and_ingest_file(db: Session, text_content: str, filename: str) -> List[EventModel]:
    events = ingest_raw_log_text(text_content, filename=filename)
    return save_events_to_db(db, events)
