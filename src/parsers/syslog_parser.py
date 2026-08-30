from typing import Dict, Any, Optional
from src.parsers.auth_parser import parse_auth_line

def parse_syslog_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parses a general syslog line (RFC3164 / RFC5424 style).
    Leverages parse_auth_line as base engine.
    """
    return parse_auth_line(line)
