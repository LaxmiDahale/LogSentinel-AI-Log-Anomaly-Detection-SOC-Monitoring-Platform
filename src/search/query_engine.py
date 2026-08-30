import re
import pandas as pd
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from src.database.models import EventModel
from src.utils.logging import logger

def parse_splunk_query(query_str: str) -> Dict[str, Any]:
    """
    Parses a Splunk-style query string into filters and pipe commands.
    Example: status=failed event_type=authentication | stats count by source_ip
    """
    query_str = query_str.strip()
    if not query_str:
        return {"filters": {}, "pipe_command": None, "pipe_args": []}

    parts = [p.strip() for p in query_str.split("|")]
    search_part = parts[0]
    pipe_parts = parts[1:] if len(parts) > 1 else []

    # Parse search filters (key=value pairs or bare search terms)
    filters = {}
    tokens = search_part.split()
    for token in tokens:
        if "=" in token:
            k, v = token.split("=", 1)
            filters[k.strip().lower()] = v.strip().strip("'\"")
        else:
            if token.upper() not in ["AND", "OR"]:
                filters["search_text"] = token.strip()

    # Parse pipe command
    pipe_command = None
    pipe_args = []
    if pipe_parts:
        pipe_str = pipe_parts[0]
        pipe_tokens = pipe_str.split()
        cmd = pipe_tokens[0].lower()
        
        if cmd == "stats":
            # e.g., stats count by source_ip
            pipe_command = "stats_count_by"
            if "by" in pipe_tokens:
                by_idx = pipe_tokens.index("by")
                if by_idx + 1 < len(pipe_tokens):
                    pipe_args.append(pipe_tokens[by_idx + 1])
        elif cmd == "top":
            # e.g., top source_ip
            pipe_command = "top"
            if len(pipe_tokens) > 1:
                pipe_args.append(pipe_tokens[1])
        elif cmd == "sort":
            # e.g., sort timestamp desc
            pipe_command = "sort"
            pipe_args = pipe_tokens[1:]
        elif cmd == "limit":
            # e.g., limit 50
            pipe_command = "limit"
            if len(pipe_tokens) > 1:
                pipe_args.append(pipe_tokens[1])

    return {
        "filters": filters,
        "pipe_command": pipe_command,
        "pipe_args": pipe_args
    }


def execute_search_query(db: Session, query_str: str, limit: int = 500) -> Dict[str, Any]:
    """
    Executes a Splunk-style query against the database events table.
    Returns filtered events and optional aggregated stats.
    """
    query = db.query(EventModel)
    parsed = parse_splunk_query(query_str)
    filters = parsed["filters"]

    # Apply database column filters
    for key, val in filters.items():
        if key == "status":
            query = query.filter(EventModel.status.ilike(f"%{val}%"))
        elif key == "event_type":
            query = query.filter(EventModel.event_type.ilike(f"%{val}%"))
        elif key == "source_ip":
            query = query.filter(EventModel.source_ip == val)
        elif key == "username":
            query = query.filter(EventModel.username.ilike(f"%{val}%"))
        elif key == "severity":
            query = query.filter(EventModel.severity.ilike(val))
        elif key == "hostname":
            query = query.filter(EventModel.hostname.ilike(f"%{val}%"))
        elif key == "search_text":
            query = query.filter(
                (EventModel.message.ilike(f"%{val}%")) |
                (EventModel.username.ilike(f"%{val}%")) |
                (EventModel.source_ip.ilike(f"%{val}%"))
            )

    events_models = query.order_by(EventModel.timestamp.desc()).limit(limit).all()

    # Convert to dict list
    event_dicts = []
    for em in events_models:
        event_dicts.append({
            "event_id": em.event_id,
            "timestamp": em.timestamp.isoformat() if em.timestamp else "",
            "hostname": em.hostname,
            "username": em.username,
            "source_ip": em.source_ip,
            "destination_ip": em.destination_ip,
            "event_type": em.event_type,
            "status": em.status,
            "severity": em.severity,
            "risk_score": em.risk_score,
            "is_anomaly": em.is_anomaly,
            "anomaly_score": em.anomaly_score,
            "message": em.message
        })

    pipe_command = parsed["pipe_command"]
    pipe_args = parsed["pipe_args"]
    stats_result = None

    if pipe_command and event_dicts:
        df = pd.DataFrame(event_dicts)
        if pipe_command == "stats_count_by" and pipe_args:
            col = pipe_args[0]
            if col in df.columns:
                grouped = df.groupby(col).size().reset_index(name="count").sort_values("count", ascending=False)
                stats_result = grouped.to_dict(orient="records")
        elif pipe_command == "top" and pipe_args:
            col = pipe_args[0]
            if col in df.columns:
                top_df = df[col].value_counts().reset_index()
                top_df.columns = [col, "count"]
                stats_result = top_df.head(10).to_dict(orient="records")

    return {
        "query": query_str,
        "total_results": len(event_dicts),
        "events": event_dicts,
        "stats": stats_result
    }
