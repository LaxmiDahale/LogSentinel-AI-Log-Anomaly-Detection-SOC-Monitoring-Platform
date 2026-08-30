import json
import pandas as pd
from typing import List, Dict, Any

def export_to_csv(data: List[Dict[str, Any]]) -> str:
    if not data:
        return ""
    df = pd.DataFrame(data)
    return df.to_csv(index=False)

def export_to_json(data: List[Dict[str, Any]] | Dict[str, Any]) -> str:
    # Serialize datetime or unexpected objects gracefully
    def default_serializer(o):
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return str(o)
    return json.dumps(data, indent=2, default=default_serializer)

def export_report_markdown(summary: Dict[str, Any]) -> str:
    md = f"""# LogSentinel AI — Security Summary Report
**Generated At:** {summary.get('generated_at')}

## Executive Summary
- **Total Ingested Events:** {summary.get('total_events', 0):,}
- **Total Security Alerts:** {summary.get('total_alerts', 0):,}
- **Critical Severity Alerts:** {summary.get('critical_alerts', 0)}
- **High Severity Alerts:** {summary.get('high_alerts', 0)}
- **ML Anomaly Detections:** {summary.get('anomalies_count', 0)}
- **Failed Logins:** {summary.get('failed_logins', 0)}

---

## Top Targeted Entities
### Top Source IPs
"""
    for item in summary.get("top_source_ips", []):
        md += f"- **{item['ip']}**: {item['count']} events\n"

    md += "\n### Top Targeted Usernames\n"
    for item in summary.get("top_targeted_users", []):
        md += f"- **{item['username']}**: {item['count']} attempts\n"

    md += "\n---\n\n## Detection Rule Breakdown\n"
    for item in summary.get("detection_rule_breakdown", []):
        md += f"- **{item['rule']}**: {item['count']} alerts triggered\n"

    return md
