from datetime import datetime, timedelta
from src.detection.anomaly_detector import MLAnomalyDetector

def test_anomaly_detector_training():
    detector = MLAnomalyDetector()
    now = datetime.now()

    # Create 20 events (normal + outlier)
    events = []
    for i in range(15):
        events.append({
            "timestamp": now + timedelta(minutes=i*2),
            "source_ip": "192.168.1.10",
            "username": "user1",
            "hostname": "server01",
            "status": "success"
        })

    # Add extreme burst outlier events
    for i in range(10):
        events.append({
            "timestamp": now + timedelta(minutes=30, seconds=i),
            "source_ip": "192.168.1.99",
            "username": f"user_{i}",
            "hostname": f"host_{i}",
            "status": "failed"
        })

    scored_events = detector.train_and_predict(events)
    assert len(scored_events) == len(events)
    assert "is_anomaly" in scored_events[0]
    assert "anomaly_score" in scored_events[0]
    assert 0.0 <= scored_events[0]["anomaly_score"] <= 1.0
