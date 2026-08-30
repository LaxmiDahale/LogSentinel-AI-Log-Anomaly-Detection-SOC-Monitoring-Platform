from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, Index
)
from sqlalchemy.orm import declarative_base
from src.utils.helpers import utc_now, generate_uuid

Base = declarative_base()

class EventModel(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(36), unique=True, nullable=False, default=generate_uuid)
    timestamp = Column(DateTime, nullable=False, index=True)
    hostname = Column(String(255), nullable=True)
    username = Column(String(255), nullable=True, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    event_type = Column(String(100), nullable=True)
    action = Column(String(100), nullable=True)
    status = Column(String(50), nullable=True, index=True)  # success, failed, etc.
    authentication_method = Column(String(100), nullable=True)
    process = Column(String(100), nullable=True)
    service = Column(String(100), nullable=True)
    message = Column(Text, nullable=True)
    log_source = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=True, default="LOW", index=True)
    risk_score = Column(Float, nullable=True, default=0.0, index=True)
    is_anomaly = Column(Boolean, nullable=True, default=False)
    anomaly_score = Column(Float, nullable=True, default=0.0)
    detection_rule = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=utc_now)

class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(36), unique=True, nullable=False, default=generate_uuid)
    rule_id = Column(String(100), nullable=False)
    rule_name = Column(String(255), nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, nullable=False, default=0.0, index=True)
    confidence = Column(Float, nullable=False, default=0.8)
    source_ip = Column(String(45), nullable=True, index=True)
    username = Column(String(255), nullable=True, index=True)
    description = Column(Text, nullable=False)
    status = Column(String(50), nullable=False, default="NEW", index=True)  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime, default=utc_now)

class InvestigationModel(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(36), nullable=False, index=True)
    analyst_notes = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="INVESTIGATING")
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
