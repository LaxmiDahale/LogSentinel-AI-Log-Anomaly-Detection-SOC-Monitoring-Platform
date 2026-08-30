import os
import random
import json
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent

DISCLAIMER = "# All included security events are synthetic and created solely for testing and educational purposes.\n"

NORMAL_USERS = ["alice", "bob", "charlie", "david", "emma", "frank", "grace", "helen", "ian", "jack"]
ATTACK_USERS = ["root", "admin", "test", "user", "oracle", "postgres", "guest", "support", "sysadmin", "deploy"]
SERVERS = ["web-prod-01", "db-prod-01", "auth-server", "app-stage-02", "srv-bastion"]

NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 30)]
BRUTE_FORCE_IP = "192.168.1.100"
SPRAY_IP = "10.0.0.45"
SUCCESS_AFTER_BF_IP = "192.168.1.200"
LATERAL_IP = "172.16.0.50"

def generate_datasets():
    print("Generating synthetic security dataset (~3,500 events)...")
    base_time = datetime.now() - timedelta(days=2)

    log_lines = []
    json_events = []
    csv_events = []

    current_time = base_time

    # 1. Generate Normal Background Activity (~2,500 events)
    for _ in range(2500):
        current_time += timedelta(seconds=random.randint(10, 120))
        ts_str = current_time.strftime("%b %d %H:%M:%S")
        ts_iso = current_time.isoformat()
        server = random.choice(SERVERS)
        user = random.choice(NORMAL_USERS)
        ip = random.choice(NORMAL_IPS)
        port = random.randint(30000, 65000)

        r = random.random()
        if r < 0.8:
            # Accepted SSH password
            line = f"{ts_str} {server} sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {ip} port {port} ssh2"
            status = "success"
            action = "login"
        elif r < 0.95:
            # Failed SSH password
            line = f"{ts_str} {server} sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {ip} port {port} ssh2"
            status = "failed"
            action = "login"
        else:
            # Sudo command
            line = f"{ts_str} {server} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; COMMAND=/usr/bin/apt-get update"
            status = "success"
            action = "privilege_elevation"

        log_lines.append(line)
        json_events.append({
            "timestamp": ts_iso,
            "hostname": server,
            "username": user,
            "source_ip": ip,
            "source_port": port,
            "event_type": "authentication",
            "action": action,
            "status": status,
            "message": line,
            "log_source": "synthetic_normal"
        })
        csv_events.append({
            "timestamp": ts_iso,
            "hostname": server,
            "username": user,
            "source_ip": ip,
            "source_port": port,
            "event_type": "authentication",
            "action": action,
            "status": status,
            "message": line
        })

    # 2. Inject Attack Vector #1: SSH Brute Force (25 failed attempts in 3 mins from BRUTE_FORCE_IP)
    bf_time = base_time + timedelta(hours=6)
    target_user = "root"
    target_server = "auth-server"
    for i in range(25):
        bf_time += timedelta(seconds=7)
        ts_str = bf_time.strftime("%b %d %H:%M:%S")
        line = f"{ts_str} {target_server} sshd[{1200+i}]: Failed password for invalid user {target_user} from {BRUTE_FORCE_IP} port {40000+i} ssh2"
        log_lines.append(line)
        json_events.append({
            "timestamp": bf_time.isoformat(),
            "hostname": target_server,
            "username": target_user,
            "source_ip": BRUTE_FORCE_IP,
            "source_port": 40000 + i,
            "event_type": "authentication",
            "action": "invalid_user",
            "status": "failed",
            "message": line,
            "log_source": "synthetic_attack"
        })

    # 3. Inject Attack Vector #2: Password Spraying (15 unique usernames targeted from SPRAY_IP in 5 mins)
    spray_time = base_time + timedelta(hours=12)
    for i, u in enumerate(ATTACK_USERS + ["user1", "user2", "user3", "user4", "user5"]):
        spray_time += timedelta(seconds=15)
        ts_str = spray_time.strftime("%b %d %H:%M:%S")
        line = f"{ts_str} web-prod-01 sshd[{2000+i}]: Failed password for {u} from {SPRAY_IP} port {50000+i} ssh2"
        log_lines.append(line)
        json_events.append({
            "timestamp": spray_time.isoformat(),
            "hostname": "web-prod-01",
            "username": u,
            "source_ip": SPRAY_IP,
            "source_port": 50000 + i,
            "event_type": "authentication",
            "action": "login",
            "status": "failed",
            "message": line,
            "log_source": "synthetic_attack"
        })

    # 4. Inject Attack Vector #3: Success After Brute Force (8 fails then 1 success from SUCCESS_AFTER_BF_IP)
    succ_bf_time = base_time + timedelta(hours=18)
    for i in range(8):
        succ_bf_time += timedelta(seconds=12)
        ts_str = succ_bf_time.strftime("%b %d %H:%M:%S")
        line = f"{ts_str} db-prod-01 sshd[{3000+i}]: Failed password for devops from {SUCCESS_AFTER_BF_IP} port {45000+i} ssh2"
        log_lines.append(line)
        json_events.append({
            "timestamp": succ_bf_time.isoformat(),
            "hostname": "db-prod-01",
            "username": "devops",
            "source_ip": SUCCESS_AFTER_BF_IP,
            "source_port": 45000 + i,
            "event_type": "authentication",
            "action": "login",
            "status": "failed",
            "message": line,
            "log_source": "synthetic_attack"
        })
    # Followed by success
    succ_bf_time += timedelta(seconds=10)
    ts_str = succ_bf_time.strftime("%b %d %H:%M:%S")
    line = f"{ts_str} db-prod-01 sshd[3009]: Accepted password for devops from {SUCCESS_AFTER_BF_IP} port 45009 ssh2"
    log_lines.append(line)
    json_events.append({
        "timestamp": succ_bf_time.isoformat(),
        "hostname": "db-prod-01",
        "username": "devops",
        "source_ip": SUCCESS_AFTER_BF_IP,
        "source_port": 45009,
        "event_type": "authentication",
        "action": "login",
        "status": "success",
        "message": line,
        "log_source": "synthetic_attack"
    })

    # 5. Inject Attack Vector #4: Lateral Movement (LATERAL_IP authenticating to 4 servers in 6 mins)
    lat_time = base_time + timedelta(hours=22)
    for i, srv in enumerate(SERVERS[:4]):
        lat_time += timedelta(minutes=1, seconds=15)
        ts_str = lat_time.strftime("%b %d %H:%M:%S")
        line = f"{ts_str} {srv} sshd[{4000+i}]: Accepted password for admin from {LATERAL_IP} port {35000+i} ssh2"
        log_lines.append(line)
        json_events.append({
            "timestamp": lat_time.isoformat(),
            "hostname": srv,
            "username": "admin",
            "source_ip": LATERAL_IP,
            "source_port": 35000 + i,
            "event_type": "authentication",
            "action": "login",
            "status": "success",
            "message": line,
            "log_source": "synthetic_attack"
        })

    # Write files
    os.makedirs(DATA_DIR, exist_ok=True)

    with open(DATA_DIR / "sample_auth.log", "w", encoding="utf-8") as f:
        f.write(DISCLAIMER)
        f.write("\n".join(log_lines))

    with open(DATA_DIR / "sample_secure.log", "w", encoding="utf-8") as f:
        f.write(DISCLAIMER)
        f.write("\n".join(log_lines[:1000]))

    with open(DATA_DIR / "sample_system.log", "w", encoding="utf-8") as f:
        f.write(DISCLAIMER)
        f.write("\n".join(log_lines[1000:2000]))

    with open(DATA_DIR / "sample_events.json", "w", encoding="utf-8") as f:
        json.dump(json_events, f, indent=2)

    df_csv = pd.DataFrame(csv_events)
    df_csv.to_csv(DATA_DIR / "sample_events.csv", index=False)

    print(f"Generated sample datasets successfully in {DATA_DIR}:")
    print(f"  - sample_auth.log ({len(log_lines)} lines)")
    print(f"  - sample_events.json ({len(json_events)} objects)")
    print(f"  - sample_events.csv ({len(csv_events)} rows)")

if __name__ == "__main__":
    generate_datasets()
