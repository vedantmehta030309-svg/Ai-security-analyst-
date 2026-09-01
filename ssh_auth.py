"""
SSH authentication event parsing for Parser V2 phase 1.

This module enriches the generic journal records produced by parser.py. It does
not replace Parser V1; it only adds structured fields to logs from sshd.
"""

import re

IP_PATTERN = r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
PORT_PATTERN = r"(?P<source_port>\d+)"

FAILED_PASSWORD = re.compile(
    rf"^Failed password for (?:(?P<invalid_user>invalid user) )?"
    rf"(?P<username>\S+) from {IP_PATTERN} port {PORT_PATTERN} ssh2\b"
)

ACCEPTED_PASSWORD = re.compile(
    rf"^Accepted password for (?P<username>\S+) "
    rf"from {IP_PATTERN} port {PORT_PATTERN} ssh2\b"
)

FAILED_PUBLICKEY = re.compile(
    rf"^Failed publickey for (?:(?P<invalid_user>invalid user) )?"
    rf"(?P<username>\S+) from {IP_PATTERN} port {PORT_PATTERN} ssh2\b"
)

ACCEPTED_PUBLICKEY = re.compile(
    rf"^Accepted publickey for (?P<username>\S+) "
    rf"from {IP_PATTERN} port {PORT_PATTERN} ssh2\b"
)

SESSION_OPENED = re.compile(
    r"^pam_unix\(sshd:session\): session opened for user (?P<username>\S+)"
)

SESSION_CLOSED = re.compile(
    r"^pam_unix\(sshd:session\): session closed for user (?P<username>\S+)"
)

CONNECTION_CLOSED_PREAUTH = re.compile(
    rf"^Connection closed by authenticating user (?P<username>\S+) "
    rf"{IP_PATTERN} port {PORT_PATTERN} \[preauth\]"
)


def _authentication_event(match, auth_method, result):
    return {
        "event_type": "authentication",
        "auth_method": auth_method,
        "result": result,
        "username": match.group("username"),
        "source_ip": match.group("source_ip"),
        "source_port": int(match.group("source_port")),
        "invalid_user": bool(match.groupdict().get("invalid_user")),
    }


def _connection_event(match, result):
    return {
        "event_type": "connection",
        "result": result,
        "username": match.group("username"),
        "source_ip": match.group("source_ip"),
        "source_port": int(match.group("source_port")),
        "preauth": True,
    }


def parse_ssh_event(log):
    if log.get("process") != "sshd":
        return None

    message = log.get("message", "")

    match = FAILED_PASSWORD.search(message)
    if match:
        return _authentication_event(match, "password", "failed")

    match = ACCEPTED_PASSWORD.search(message)
    if match:
        return _authentication_event(match, "password", "success")

    match = FAILED_PUBLICKEY.search(message)
    if match:
        return _authentication_event(match, "publickey", "failed")

    match = ACCEPTED_PUBLICKEY.search(message)
    if match:
        return _authentication_event(match, "publickey", "success")

    match = SESSION_OPENED.search(message)
    if match:
        return {
            "event_type": "session",
            "result": "opened",
            "username": match.group("username"),
        }

    match = SESSION_CLOSED.search(message)
    if match:
        return {
            "event_type": "session",
            "result": "closed",
            "username": match.group("username"),
        }

    match = CONNECTION_CLOSED_PREAUTH.search(message)
    if match:
        return _connection_event(match, "closed")

    return None


def enrich_ssh_events(logs):
    enriched_count = 0

    for log in logs:
        extra_fields = parse_ssh_event(log)
        if extra_fields:
            log.update(extra_fields)
            enriched_count += 1

    print(f"Enriched {enriched_count} logs with SSH authentication fields.")
    return enriched_count
