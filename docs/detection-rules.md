# LogSentinel AI — Detection Rules Documentation

LogSentinel AI features both deterministic security detection rules and unsupervised machine learning anomaly detection.

## Rule Definitions

| Rule ID | Rule Name | Description | Default Window | Threshold | Severity | Default Risk Points |
|---|---|---|---|---|---|---|
| **RULE_001** | `SSH_BRUTE_FORCE` | Detects repeated failed authentication attempts from a single source IP | 5 minutes | $\ge$ 5 failed attempts | **HIGH** | +25 |
| **RULE_002** | `PASSWORD_SPRAYING` | Detects a single source IP attempting authentication against multiple unique accounts | 10 minutes | $\ge$ 5 unique users | **HIGH** | +30 |
| **RULE_003** | `SUCCESS_AFTER_BRUTE_FORCE` | Detects multiple failed authentication attempts followed by a successful login from the same IP | 15 minutes | $\ge$ 5 failures + 1 success | **CRITICAL** | +40 |
| **RULE_004** | `POSSIBLE_LATERAL_MOVEMENT` | Detects a single source IP authenticating across multiple destination hosts | 15 minutes | $\ge$ 3 target hosts | **HIGH** | +35 |
| **RULE_005** | `UNUSUAL_LOGIN_TIME` | Detects successful authentication events occurring during non-standard hours (midnight to 5 AM) | N/A | 00:00 – 05:00 AM | **MEDIUM** | +15 |

## Rule Configuration

All thresholds and parameters are dynamically configurable without restarting the code via `config/detection_rules.yaml`.

```yaml
brute_force:
  enabled: true
  threshold: 5
  window_minutes: 5
  severity: HIGH
  risk_points: 25

password_spraying:
  enabled: true
  unique_users_threshold: 5
  window_minutes: 10
  severity: HIGH
  risk_points: 30
```

## Machine Learning Anomaly Detection

In addition to deterministic rules, `sklearn.ensemble.IsolationForest` flags statistical outliers using the following extracted feature matrix:
- `failed_attempt_count`
- `successful_login_count`
- `unique_users`
- `unique_source_ips`
- `unique_destination_hosts`
- `events_per_minute`
- `login_frequency`
- `hour_of_day`
- `authentication_failure_ratio`
