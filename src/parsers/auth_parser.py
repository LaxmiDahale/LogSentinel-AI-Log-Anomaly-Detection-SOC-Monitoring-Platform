import re
from typing import Dict, Any, Optional
from src.parsers.normalizer import normalize_event

# Regex patterns for SSH and auth log formats
ACCEPTED_SSH_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)'
)

FAILED_SSH_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+Failed\s+(?P<auth_method>\S+)\s+for\s+(?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)'
)

INVALID_USER_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+Invalid user\s+(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)(?:\s+port\s+(?P<source_port>\d+))?'
)

SUDO_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sudo:\s+(?P<username>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+COMMAND=(?P<command>.+)'
)

GENERIC_SYSLOG_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+(?P<process>[a-zA-Z0-9_\-\.\/]+)(?:\[\d+\])?:\s+(?P<message>.+)'
)

def parse_auth_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parses a single line of Linux authentication/secure log into a dictionary.
    Returns None if line is blank or cannot be parsed.
    Never raises an exception on malformed inputs.
    """
    line = line.strip()
    if not line:
        return None

    try:
        # Match Accepted SSH
        m = ACCEPTED_SSH_PATTERN.match(line)
        if m:
            d = m.groupdict()
            return normalize_event({
                "timestamp": d["timestamp"],
                "hostname": d["hostname"],
                "username": d["username"],
                "source_ip": d["source_ip"],
                "source_port": d["source_port"],
                "status": "success",
                "action": "login",
                "authentication_method": d["auth_method"],
                "event_type": "authentication",
                "process": "sshd",
                "service": "sshd",
                "message": line
            }, log_source="auth.log")

        # Match Failed SSH
        m = FAILED_SSH_PATTERN.match(line)
        if m:
            d = m.groupdict()
            return normalize_event({
                "timestamp": d["timestamp"],
                "hostname": d["hostname"],
                "username": d["username"],
                "source_ip": d["source_ip"],
                "source_port": d["source_port"],
                "status": "failed",
                "action": "login",
                "authentication_method": d["auth_method"],
                "event_type": "authentication",
                "process": "sshd",
                "service": "sshd",
                "message": line
            }, log_source="auth.log")

        # Match Invalid User SSH
        m = INVALID_USER_PATTERN.match(line)
        if m:
            d = m.groupdict()
            return normalize_event({
                "timestamp": d["timestamp"],
                "hostname": d["hostname"],
                "username": d["username"],
                "source_ip": d["source_ip"],
                "source_port": d.get("source_port"),
                "status": "failed",
                "action": "invalid_user",
                "authentication_method": "password",
                "event_type": "authentication",
                "process": "sshd",
                "service": "sshd",
                "message": line
            }, log_source="auth.log")

        # Match sudo activity
        m = SUDO_PATTERN.match(line)
        if m:
            d = m.groupdict()
            return normalize_event({
                "timestamp": d["timestamp"],
                "hostname": d["hostname"],
                "username": d["username"],
                "status": "success",
                "action": "privilege_elevation",
                "event_type": "sudo",
                "process": "sudo",
                "service": "sudo",
                "message": f"COMMAND={d['command']}"
            }, log_source="auth.log")

        # Fallback to Generic Syslog pattern
        m = GENERIC_SYSLOG_PATTERN.match(line)
        if m:
            d = m.groupdict()
            msg = d["message"].lower()
            status = "failed" if any(w in msg for w in ["failed", "error", "invalid", "denied", "failure"]) else "info"
            return normalize_event({
                "timestamp": d["timestamp"],
                "hostname": d["hostname"],
                "process": d["process"],
                "service": d["process"],
                "status": status,
                "action": "system_event",
                "event_type": "system",
                "message": d["message"]
            }, log_source="syslog")

        # Unmatched line: treat gracefully as raw syslog line
        return normalize_event({
            "message": line,
            "status": "unknown",
            "event_type": "raw_log"
        }, log_source="raw")

    except Exception:
        # Gracefully handle unexpected format errors
        return normalize_event({
            "message": line,
            "status": "malformed",
            "event_type": "malformed_log"
        }, log_source="malformed")
