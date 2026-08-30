import json
from typing import List, Dict, Any
from src.parsers.normalizer import normalize_event

def parse_json_content(content: str, log_source: str = "json_upload") -> List[Dict[str, Any]]:
    """
    Parses JSON content (single object or list of objects) into normalized event dicts.
    """
    content = content.strip()
    if not content:
        return []

    events = []
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            events.append(normalize_event(data, log_source=log_source))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    events.append(normalize_event(item, log_source=log_source))
    except json.JSONDecodeError:
        # Fall back to line-by-line JSON parsing
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    events.append(normalize_event(item, log_source=log_source))
            except Exception:
                continue

    return events
