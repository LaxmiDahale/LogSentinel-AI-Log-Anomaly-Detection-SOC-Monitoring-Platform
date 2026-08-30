from src.detection.risk_scoring import calculate_event_risk_score

def test_risk_scoring_normal_event():
    event = {"status": "success", "is_anomaly": False}
    res = calculate_event_risk_score(event)
    assert res["risk_score"] == 0.0
    assert res["severity"] == "LOW"

def test_risk_scoring_brute_force_event():
    event = {"status": "failed", "is_anomaly": False}
    res = calculate_event_risk_score(event, triggered_rules=["SSH_BRUTE_FORCE"])
    assert res["risk_score"] >= 25.0
    assert res["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]

def test_risk_scoring_critical_event():
    event = {"status": "success", "is_anomaly": True, "anomaly_score": 0.9}
    res = calculate_event_risk_score(event, triggered_rules=["SUCCESS_AFTER_BRUTE_FORCE", "POSSIBLE_LATERAL_MOVEMENT"])
    assert res["risk_score"] >= 75.0
    assert res["severity"] == "CRITICAL"
