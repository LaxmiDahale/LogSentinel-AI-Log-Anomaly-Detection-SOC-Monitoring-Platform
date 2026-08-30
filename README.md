# LogSentinel AI — Log Anomaly Detection & SOC Monitoring Platform

> Production-style security log analysis platform for detecting brute-force attacks, suspicious authentication behavior, lateral-movement indicators, and statistical anomalies.

---

## 🎯 Overview

**LogSentinel AI** is a full-stack, production-grade cybersecurity platform built using Python, FastAPI, Streamlit, SQLAlchemy, and Scikit-Learn. It ingests Linux authentication and system logs (as well as JSON and CSV security events), parses raw logs into a standardized schema, executes rule-based detection algorithms, applies **Isolation Forest** unsupervised machine learning for anomaly detection, calculates multi-factor risk scores (0–100), and presents actionable threat intelligence via an interactive SOC dashboard and REST API.

---

## ✨ Features

- **Multi-Format Log Ingestion**: Ingests `.log`, `.txt`, `.json`, and `.csv` files supporting standard Linux `sshd`, `sudo`, and syslog line formats.
- **Normalized Event Schema**: Maps disparate log feeds into a standardized 22-field cybersecurity schema.
- **Rule-Based Threat Detection**:
  - `SSH_BRUTE_FORCE`: Detects repeated failed logins from a single IP.
  - `PASSWORD_SPRAYING`: Detects single IP targeting multiple accounts.
  - `SUCCESS_AFTER_BRUTE_FORCE`: Highlights successful logins following repeated failures (**CRITICAL**).
  - `POSSIBLE_LATERAL_MOVEMENT`: Identifies single IP authenticating across multiple hosts.
  - `UNUSUAL_LOGIN_TIME`: Flags logins during non-standard hours (00:00 – 05:00 AM).
- **Unsupervised ML Anomaly Detection**: Uses `sklearn.ensemble.IsolationForest` trained on 9 behavioral frequency features.
- **Transparent Risk Scoring Engine**: Calculates multi-factor risk scores (0–100) mapped to severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Splunk-Style Query Engine (SPL)**: Search events with filters (`status=failed source_ip=...`) and aggregations (`| stats count by source_ip`, `| top username`).
- **Analyst Investigation Workbench**: Provides step-by-step defensive analyst playbooks, evidence event timelines, and notes management.
- **Executive Reporting & Export**: Download Security Summaries and raw event datasets in CSV, JSON, or Markdown formats.
- **Demo Mode**: One-click ingestion and execution of realistic synthetic attack datasets (~2,500 events).
- **REST API**: Built with FastAPI for automated programmatic query integration.
- **Docker Support**: Containerized deployment with Dockerfile and Docker Compose.

---

## 🏗️ Architecture

```text
Log Source (auth.log / JSON / CSV)
    ↓
Parser & Normalizer
    ↓
┌─────────────────────────┴─────────────────────────┐
│                                                   │
v                                                   v
Rule-Based Detection Engine             Isolation Forest ML Model
(Rules 001 - 005)                       (Scikit-Learn Ensemble)
│                                                   │
└─────────────────────────┬─────────────────────────┘
    ↓
Multi-Factor Risk Scoring Engine (0 - 100)
    ↓
SQLite / SQLAlchemy ORM Database
    ↓
┌─────────────────────────┴─────────────────────────┐
│                                                   │
v                                                   v
FastAPI REST API Server                 Streamlit Dark SOC Dashboard
(http://localhost:8000)                 (http://localhost:8501)
```

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone Repository
git clone https://github.com/your-username/LogSentinel-AI.git
cd LogSentinel-AI

# Create Virtual Environment
python -m venv venv

# Activate Virtual Environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# Install Dependencies
pip install -r requirements.txt
```

### 2. Generate Synthetic Demo Data
```bash
python data/generate_sample_data.py
```

### 3. Run Application

**Launch Streamlit SOC Dashboard:**
```bash
streamlit run app.py
```
*Open `http://localhost:8501` in your browser.*

**Launch FastAPI REST API Server:**
```bash
uvicorn src.api.routes:app --reload --host 0.0.0.0 --port 8000
```
*Open API docs at `http://localhost:8000/docs`.*

---

## 🐳 Docker Deployment

```bash
docker compose up --build -d
```
- **SOC Dashboard**: `http://localhost:8501`
- **REST API**: `http://localhost:8000/docs`

---

## 🧪 Testing

Execute the unit test suite:
```bash
pytest
```

---

## 🔍 Supported Splunk-Style Query Syntax

| Query Example | Description |
|---|---|
| `status=failed` | Filter all failed authentication attempts |
| `source_ip=192.168.1.100` | Filter events originating from target IP |
| `severity=HIGH` | Filter HIGH severity security events |
| `event_type=authentication \| stats count by source_ip` | Aggregate event counts grouped by Source IP |
| `status=failed \| stats count by username` | Aggregate failed attempts grouped by Username |
| `event_type=authentication \| top source_ip` | Return top 10 most active Source IPs |

---

## 🛡️ Security Disclaimer

This project is intended strictly for defensive security analysis, threat hunting, and educational purposes. All datasets included are synthetic and created solely for testing. Do not use this tool on unauthorized systems or networks.

---

## 💼 Resume & Portfolio Highlights

### Resume Bullet Points (SOC Analyst / Cyber Security Analyst)
- **Built LogSentinel AI**, an open-source Log Anomaly Detection & SOC Monitoring platform using Python, FastAPI, Streamlit, and Scikit-Learn.
- **Engineered stateful detection rules** to detect SSH brute-force attacks, password spraying, lateral movement, and successful logins after brute force.
- **Implemented Isolation Forest machine learning** for unsupervised statistical anomaly detection across 9 behavioral frequency metrics.
- **Developed a Splunk-style query engine (SPL)** and interactive SOC investigation workbench complete with defensive analyst playbooks.

### Suggested LinkedIn Project Summary
> 🛡️ **LogSentinel AI — Log Anomaly Detection & SOC Monitoring Platform**  
> Excited to share my latest cybersecurity portfolio project! LogSentinel AI is a production-grade security log analytics tool built with Python, Streamlit, FastAPI, and Scikit-Learn. It parses raw Linux syslog/auth feeds, applies rule-based threat detection + Isolation Forest ML anomaly scoring, and features a dark-themed SOC dashboard with Splunk-style query syntax and incident investigation playbooks. Check out the code and Docker configuration on GitHub!
