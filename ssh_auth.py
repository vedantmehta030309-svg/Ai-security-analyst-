'''
ssh_auth.py — SSH authentication event parsing (Parser V2, Phase 1).
Enrichment layer: adds structured fields onto sshd logs.
parser.py, detector.py, report.py are all untouched.
'''

import re

FAILED_PASSWORD = re.compile(
    r"Failed password for : (?:invalid user)?(?P<username>\S+)"
    r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"port (?P<source_port>\d+) ssh2"
)

ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?P<username>\S+) "
    r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<source_port>\d+) ssh2"
)

FAILED_PUBLICKEY = re.compile(
    r"Failed publickey for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<source_port>\d+) ssh2"
)

ACCEPTED_PUBLICKEY = re.compile(
    r"Accepted publickey for (?P<username>\S+) "
    r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<source_port>\d+) ssh2"
)

SESSION_OPENED = re.compile(
    r"pam_unix\(sshd:session\): session opened for user (?P<username>\S+)"
)

SESSION_CLOSED = re.compile(
    r"pam_unix\(sshd:session\): session closed for user (?P<username>\S+)"
)


def parse_ssh_event(log):
    if log["process"] != "sshd":
        return None

    message = log["message"]
    invalid_user = "invalid user" in message

    match = FAILED_PASSWORD.search(message)
    if match:
        return {
            "event_type": "authentication", "auth_method": "password", "result": "failed",
            "username": match.group("username"), "source_ip": match.group("source_ip"),
            "source_port": int(match.group("source_port")), "invalid_user": invalid_user,
        }

    match = ACCEPTED_PASSWORD.search(message)
    if match:
        return {
            "event_type": "authentication", "auth_method": "password", "result": "success",
            "username": match.group("username"), "source_ip": match.group("source_ip"),
            "source_port": int(match.group("source_port")), "invalid_user": False,
        }

    match = FAILED_PUBLICKEY.search(message)
    if match:
        return {
            "event_type": "authentication", "auth_method": "publickey", "result": "failed",
            "username": match.group("username"), "source_ip": match.group("source_ip"),
            "source_port": int(match.group("source_port")), "invalid_user": invalid_user,
        }

    match = ACCEPTED_PUBLICKEY.search(message)
    if match:
        return {
            "event_type": "authentication", "auth_method": "publickey", "result": "success",
            "username": match.group("username"), "source_ip": match.group("source_ip"),
            "source_port": int(match.group("source_port")), "invalid_user": False,
        }

    match = SESSION_OPENED.search(message)
    if match:
        return {"event_type": "session", "result": "opened", "username": match.group("username")}

    match = SESSION_CLOSED.search(message)
    if match:
        return {"event_type": "session", "result": "closed", "username": match.group("username")}

    return None


def enrich_ssh_events(logs):
    enriched_count = 0
    for log in logs:
        extra_fields = parse_ssh_event(log)
        if extra_fields:
            log.update(extra_fields)
            enriched_count += 1
    print(f"Enriched {enriched_count} logs with SSH authentication fields.")