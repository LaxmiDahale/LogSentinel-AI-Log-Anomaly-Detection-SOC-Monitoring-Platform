import ipaddress
import re
from datetime import datetime
from typing import Optional

def validate_ip(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def sanitize_filename(filename: str) -> str:
    # Remove path traversal characters and non-alphanumeric chars (except dot, dash, underscore)
    clean_name = re.sub(r'[^a-zA-Z0-9_\.\-]', '_', filename)
    return clean_name.lstrip('/\\.')

def parse_iso_or_syslog_timestamp(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    # Try ISO formats
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%b %e %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            # If syslog standard "%b %d %H:%M:%S" which omits year, default to current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
    return None
