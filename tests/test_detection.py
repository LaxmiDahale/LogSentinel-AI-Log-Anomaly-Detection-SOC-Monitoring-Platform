from datetime import datetime, timedelta
from src.detection.brute_force import detect_brute_force
from src.detection.password_spray import detect_password_spray
from src.detection.suspicious_login import detect_suspicious_success
from src.detection.lateral_movement import detect_lateral_movement

def test_detect_brute_force():
    now = datetime.now()
    events = [
        {
            "timestamp": now + timedelta(seconds=i*5),
            "source_ip": "192.168.1.100",
            "username": "admin",
            "status": "failed"
        }
        for i in range(7)
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) >= 1
    assert alerts[0]["rule_name"] == "SSH_BRUTE_FORCE"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["source_ip"] == "192.168.1.100"

def test_detect_password_spray():
    now = datetime.now()
    users = ["user1", "user2", "user3", "user4", "user5", "user6"]
    events = [
        {
            "timestamp": now + timedelta(seconds=i*10),
            "source_ip": "10.0.0.45",
            "username": u,
            "status": "failed"
        }
        for i, u in enumerate(users)
    ]
    alerts = detect_password_spray(events)
    assert len(alerts) >= 1
    assert alerts[0]["rule_name"] == "PASSWORD_SPRAYING"
    assert alerts[0]["source_ip"] == "10.0.0.45"

def test_detect_suspicious_success():
    now = datetime.now()
    events = [
        {
            "timestamp": now + timedelta(seconds=i*5),
            "source_ip": "192.168.1.200",
            "username": "devops",
            "status": "failed"
        }
        for i in range(6)
    ]
    # Followed by success login
    events.append({
        "timestamp": now + timedelta(seconds=35),
        "source_ip": "192.168.1.200",
        "username": "devops",
        "status": "success"
    })
    alerts = detect_suspicious_success(events)
    assert len(alerts) >= 1
    assert alerts[0]["rule_name"] == "SUCCESS_AFTER_BRUTE_FORCE"
    assert alerts[0]["severity"] == "CRITICAL"

def test_detect_lateral_movement():
    now = datetime.now()
    hosts = ["server01", "server02", "server03", "server04"]
    events = [
        {
            "timestamp": now + timedelta(seconds=i*30),
            "source_ip": "172.16.0.50",
            "hostname": h,
            "username": "admin",
            "status": "success"
        }
        for i, h in enumerate(hosts)
    ]
    alerts = detect_lateral_movement(events)
    assert len(alerts) >= 1
    assert alerts[0]["rule_name"] == "POSSIBLE_LATERAL_MOVEMENT"
    assert alerts[0]["source_ip"] == "172.16.0.50"
