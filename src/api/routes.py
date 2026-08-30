from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
import io

from src.database.database import get_db, init_db
from src.database.models import EventModel, AlertModel, InvestigationModel
from src.ingestion.file_ingestion import process_and_ingest_file
from src.detection.rule_engine import run_detection_pipeline
from src.search.query_engine import execute_search_query
from src.reporting.report_generator import generate_security_summary_report
from src.reporting.exporters import export_to_csv, export_to_json

app = FastAPI(
    title="LogSentinel AI API",
    description="REST API for LogSentinel AI - Production Log Anomaly & SOC Monitoring Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/api/health", summary="Health check endpoint")
def health_check():
    return {"status": "ok", "service": "LogSentinel AI", "version": "1.0.0"}

@app.get("/api/events", summary="Retrieve normalized security events")
def get_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(EventModel)
    if status:
        query = query.filter(EventModel.status.ilike(status))
    if severity:
        query = query.filter(EventModel.severity.ilike(severity))
    if source_ip:
        query = query.filter(EventModel.source_ip == source_ip)

    total = query.count()
    events = query.order_by(EventModel.timestamp.desc()).offset(offset).limit(limit).all()
    return {"total": total, "offset": offset, "limit": limit, "events": events}

@app.get("/api/events/{event_id}", summary="Get event by ID")
def get_event_by_id(event_id: str, db: Session = Depends(get_db)):
    event = db.query(EventModel).filter(EventModel.event_id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event

@app.get("/api/alerts", summary="Retrieve security alerts")
def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    rule_name: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    query = db.query(AlertModel)
    if severity:
        query = query.filter(AlertModel.severity == severity.upper())
    if status:
        query = query.filter(AlertModel.status == status.upper())
    if rule_name:
        query = query.filter(AlertModel.rule_name.ilike(f"%{rule_name}%"))

    alerts = query.order_by(AlertModel.timestamp.desc()).limit(limit).all()
    return {"total": len(alerts), "alerts": alerts}

@app.get("/api/alerts/{alert_id}", summary="Get alert details with evidence events")
def get_alert_by_id(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(AlertModel).filter(AlertModel.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Find evidence events matching source IP or username around alert timestamp
    evidence = []
    if alert.source_ip or alert.username:
        ev_query = db.query(EventModel)
        if alert.source_ip:
            ev_query = ev_query.filter(EventModel.source_ip == alert.source_ip)
        if alert.username:
            ev_query = ev_query.filter(EventModel.username == alert.username)
        evidence = ev_query.order_by(EventModel.timestamp.desc()).limit(20).all()

    investigation = db.query(InvestigationModel).filter(InvestigationModel.alert_id == alert_id).first()

    return {
        "alert": alert,
        "evidence_events": evidence,
        "investigation_notes": investigation.analyst_notes if investigation else None
    }

@app.get("/api/anomalies", summary="Get ML Isolation Forest anomalies")
def get_anomalies(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    anomalies = (
        db.query(EventModel)
        .filter(EventModel.is_anomaly == True)
        .order_by(EventModel.anomaly_score.desc())
        .limit(limit)
        .all()
    )
    return {"total": len(anomalies), "anomalies": anomalies}

@app.get("/api/statistics", summary="Get high level SOC dashboard stats")
def get_statistics(db: Session = Depends(get_db)):
    return generate_security_summary_report(db)

@app.get("/api/search", summary="Splunk-style query engine search")
def search_events(q: str = Query(..., description="Splunk-style query string"), limit: int = 200, db: Session = Depends(get_db)):
    return execute_search_query(db, q, limit=limit)

@app.post("/api/ingest", summary="Ingest log file")
async def ingest_log_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    db_events = process_and_ingest_file(db, text, filename=file.filename)
    return {"status": "success", "filename": file.filename, "ingested_count": len(db_events)}

@app.post("/api/analyze", summary="Trigger detection rules and ML anomaly model")
def analyze_logs(db: Session = Depends(get_db)):
    db_events = db.query(EventModel).all()
    events_dict = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp,
            "hostname": e.hostname,
            "username": e.username,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "status": e.status,
            "event_type": e.event_type
        }
        for e in db_events
    ]
    res = run_detection_pipeline(db, events_dict)
    return {
        "status": "success",
        "processed_events": res["processed_count"],
        "new_alerts_generated": len(res["alerts"]),
        "anomalies_detected": res["anomaly_count"]
    }

@app.get("/api/export/events", summary="Export events as CSV or JSON")
def export_events(format: str = Query("csv", regex="^(csv|json)$"), limit: int = 500, db: Session = Depends(get_db)):
    events = db.query(EventModel).order_by(EventModel.timestamp.desc()).limit(limit).all()
    data = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "hostname": e.hostname,
            "username": e.username,
            "source_ip": e.source_ip,
            "status": e.status,
            "severity": e.severity,
            "risk_score": e.risk_score,
            "is_anomaly": e.is_anomaly
        }
        for e in events
    ]
    if format == "csv":
        csv_str = export_to_csv(data)
        return Response(content=csv_str, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=events.csv"})
    else:
        json_str = export_to_json(data)
        return Response(content=json_str, media_type="application/json")

@app.get("/api/export/alerts", summary="Export alerts as CSV or JSON")
def export_alerts(format: str = Query("csv", regex="^(csv|json)$"), db: Session = Depends(get_db)):
    alerts = db.query(AlertModel).order_by(AlertModel.timestamp.desc()).all()
    data = [
        {
            "alert_id": a.alert_id,
            "rule_id": a.rule_id,
            "rule_name": a.rule_name,
            "timestamp": a.timestamp.isoformat() if a.timestamp else "",
            "severity": a.severity,
            "risk_score": a.risk_score,
            "source_ip": a.source_ip,
            "username": a.username,
            "description": a.description,
            "status": a.status
        }
        for a in alerts
    ]
    if format == "csv":
        csv_str = export_to_csv(data)
        return Response(content=csv_str, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})
    else:
        json_str = export_to_json(data)
        return Response(content=json_str, media_type="application/json")
