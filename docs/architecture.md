# LogSentinel AI — System Architecture

LogSentinel AI is a high-performance, modular cybersecurity log analysis and threat monitoring platform designed for Security Operations Center (SOC) environments.

## Data Flow Architecture

```text
+-------------------+
|  Linux System /   |
|  Auth Log Sources | (auth.log, secure.log, JSON, CSV)
+---------+---------+
          |
          v
+-------------------+
| Multi-Format      | (Regex, RFC3164 Syslog, JSON, CSV Parsers)
| Log Parsers       |
+---------+---------+
          |
          v
+-------------------+
| Event Normalizer  | (Maps raw logs into Unified Normalized Schema)
+---------+---------+
          |
          +-----------------------------------+
          |                                   |
          v                                   v
+-------------------+               +-------------------+
| Deterministic     |               | Isolation Forest  |
| Rule Engine       |               | ML Anomaly Model  |
| (Rules 001 - 005) |               | (Scikit-Learn)    |
+---------+---------+               +---------+---------+
          |                                   |
          +-----------------+-----------------+
                            |
                            v
                  +-------------------+
                  | Multi-Factor Risk | (Score: 0 - 100, Severity: LOW-CRITICAL)
                  | Scoring Engine    |
                  +---------+---------+
                            |
                            v
                  +-------------------+
                  | SQLite / ORM      | (SQLAlchemy Events & Alerts Database)
                  | Database Engine   |
                  +---------+---------+
                            |
            +---------------+---------------+
            |                               |
            v                               v
  +-------------------+           +-------------------+
  | FastAPI REST      |           | Streamlit SOC     |
  | Endpoints         |           | Operations UI     |
  +-------------------+           +-------------------+
```

## Key Components

1. **Parsers & Normalizer**: Accepts raw Linux logs (`sshd`, `sudo`, `PAM`), JSON events, or CSV spreadsheets. Robust regex engines extract IPs, ports, timestamps, users, actions, and processes.
2. **Rule Engine**: Evaluates stateful sliding time windows for brute force, password spraying, success after failure, lateral movement, and unusual login hours.
3. **Isolation Forest Anomaly Detector**: Unsupervised Scikit-Learn tree ensemble trained on contextual frequency metrics (`failed_attempt_count`, `login_frequency`, `events_per_minute`, `hour_of_day`, `authentication_failure_ratio`).
4. **Risk Scoring Engine**: Combines rule triggers, ML anomaly scores, and event metadata into a normalized 0-100 risk score and mapped severity rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
5. **Database**: SQLite default via SQLAlchemy ORM.
6. **FastAPI & Streamlit**: Dual interface offering programmatic REST API endpoints and a dark-themed SOC operations dashboard.
