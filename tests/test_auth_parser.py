import pytest
from src.parsers.auth_parser import parse_auth_line

def test_parse_accepted_ssh():
    line = "Aug 30 10:15:21 server sshd[1234]: Accepted password for user1 from 192.168.1.10 port 55231 ssh2"
    res = parse_auth_line(line)
    assert res is not None
    assert res["status"] == "success"
    assert res["username"] == "user1"
    assert res["source_ip"] == "192.168.1.10"
    assert res["source_port"] == 55231
    assert res["event_type"] == "authentication"

def test_parse_failed_ssh():
    line = "Aug 30 10:16:04 server sshd[1235]: Failed password for invalid user admin from 192.168.1.50 port 44121 ssh2"
    res = parse_auth_line(line)
    assert res is not None
    assert res["status"] == "failed"
    assert res["username"] == "admin"
    assert res["source_ip"] == "192.168.1.50"
    assert res["source_port"] == 44121

def test_parse_invalid_user():
    line = "Aug 30 10:17:10 server sshd[1236]: Invalid user test from 192.168.1.50"
    res = parse_auth_line(line)
    assert res is not None
    assert res["status"] == "failed"
    assert res["username"] == "test"
    assert res["source_ip"] == "192.168.1.50"

def test_parse_sudo_activity():
    line = "Aug 30 10:20:10 server sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; COMMAND=/bin/bash"
    res = parse_auth_line(line)
    assert res is not None
    assert res["status"] == "success"
    assert res["username"] == "user1"
    assert res["action"] == "privilege_elevation"

def test_parse_malformed_log():
    # Should handle malformed logs gracefully without raising exception
    line = "random corrupted data line without standard syslog header 12345"
    res = parse_auth_line(line)
    assert res is not None
    assert res["message"] == line
