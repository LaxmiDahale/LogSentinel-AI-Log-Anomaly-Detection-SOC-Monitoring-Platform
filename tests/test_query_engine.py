import pytest
from datetime import datetime
from src.database.database import SessionLocal, init_db, clear_db
from src.database.models import EventModel
from src.search.query_engine import parse_splunk_query, execute_search_query

@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    clear_db()
    db = SessionLocal()
    # Insert test events
    db.add(EventModel(
        event_id="e1", timestamp=datetime.now(), status="failed", event_type="authentication",
        source_ip="192.168.1.50", username="admin", severity="HIGH"
    ))
    db.add(EventModel(
        event_id="e2", timestamp=datetime.now(), status="success", event_type="authentication",
        source_ip="192.168.1.10", username="user1", severity="LOW"
    ))
    db.commit()
    yield db
    db.close()

def test_parse_splunk_query():
    parsed = parse_splunk_query("status=failed event_type=authentication | stats count by source_ip")
    assert parsed["filters"]["status"] == "failed"
    assert parsed["filters"]["event_type"] == "authentication"
    assert parsed["pipe_command"] == "stats_count_by"
    assert parsed["pipe_args"] == ["source_ip"]

def test_execute_search_query(setup_db):
    db = setup_db
    res = execute_search_query(db, "status=failed")
    assert res["total_results"] == 1
    assert res["events"][0]["source_ip"] == "192.168.1.50"

def test_execute_stats_query(setup_db):
    db = setup_db
    res = execute_search_query(db, "event_type=authentication | stats count by source_ip")
    assert res["total_results"] == 2
    assert res["stats"] is not None
    assert len(res["stats"]) == 2
