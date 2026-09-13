from collections import defaultdict
from config import CONFIG


def failed_then_success(events , threshold_count = CONFIG["correlation"]["threshold_count"] , windows_seconds = CONFIG["correlation"]["windows_seconds"]):
    events_by_ip = defaultdict(list)
    incidents = []
    #grp auth events by source ip
    for event in events:
        if event.get("event_type") != "authentication":
            continue
        if not event.get('source_ip'):
            continue
        if not event.get("parsed_time"):
            continue

        events_by_ip[event["source_ip"]].append(event)

    #ANALYZE each ip separetaly
    for ip , ip_events in events_by_ip.items():

        #sort events chronologically
        ip_events.sort(key = lambda event : event["parsed_time"])
        failed_events = []
        for event in ip_events:
            #failed auth attempts
            if event.get("result")=="failed":
                failed_events.append(event)
            #chewck sucessful auth
            elif event.get("result")=="success":
                #remove failiures outside the time window
                failed_events = [
                    failed
                    for failed in failed_events
                    if (
                        event['parsed_time']-failed['parsed_time']
                    ).total_seconds() <= windows_seconds
                ]

                #enou8gh failiures followed by success ????? nu logic
                if len(failed_events) >= threshold_count:
                    incidents.append(
                        {
                            "incident_type": "Possible Account Compromise",
                            "attack_type": "Possible Account Compromise",
                            "severity": "CRITICAL",
                            "source_ip": ip,
                            "username": event.get("username"),
                            "failed_attempts": len(failed_events),
                            "window_start": failed_events[0]["parsed_time"],
                            "success_time": event["parsed_time"],
                            "window_seconds": windows_seconds,
                            "description": (
                                f"{len(failed_events)} failed authentication "
                                f"attempts were followed by a successful "
                                f"authentication from {ip}"
                            )
                        }
                    )
                    # Clear failures so the same sequence doesn't create duplicate incidents
                    failed_events = []

    return incidents


def invalid_then_success(events, threshold_count = CONFIG["correlation"]["threshold_count"] , windows_seconds = CONFIG["correlation"]["windows_seconds"]):
    incidents = []
    events_by_ip = defaultdict(list)
    #grp auth events by source ip
    for event in events:
        #TODO : only auth events , source ip exists , parsed time exists
        if event.get("event_type") != "authentication":
            continue
        if not event.get('source_ip'):
            continue
        if not event.get("parsed_time"):
            continue

        events_by_ip[event["source_ip"]].append(event)

    for ip , ip_events in events_by_ip.items():
        #TODO : sort events chronologically
        invalid_user_events = []
        #through this ip timeline
        for event in ip_events:
            if event.get("result")=="failed":
                if event.get("invalid_user") is True:
                    invalid_user_events.append(event)

            #detect successful auth
            elif event.get("result")=="success":
                #remove invaliduser outside the time window
                invalid_user_events=[
                    invalid
                    for invalid in invalid_user_events
                        if(event["parsed_time"]-invalid["parsed_time"]
                        ).total_seconds() <= windows_seconds
                ]

                if len(invalid_user_events) >= threshold_count:
                    incidents.append(
                        {
                        "incident_type": "Invalid User Attack Followed By Success",
                        "severity": "CRITICAL",
                        "source_ip": ip,
                        "username": event.get("username"),
                        "invalid_user_attempts": len(invalid_user_events),
                        "window_start": invalid_user_events[0]["parsed_time"],
                        "success_time": event["parsed_time"],
                        "window_seconds": windows_seconds,
                        "description": (
                            f"{len(invalid_user_events)} invalid-user "
                            f"authentication attempts were followed by a "
                            f"successful authentication from {ip}"
                        )
                        }
                    )
                    invalid_user_events = []

    return incidents

def root_login_then_sudo(
        events,
        windows_seconds = CONFIG["correlation"]["windows_seconds"]
):
    incidents = []
    root_logins = []
    sudo_events = []

    for event in events :
        if not event.get("parsed_time"):
            continue

        # TODO: detect successful root authentication
        # TODO: make sure event_type == "authentication"
        # TODO: make sure result == "success"
        # TODO: make sure username == "root"
        if (
                event.get("event_type") == "authentication"
                and event.get("result") == "success"
                and event.get("username") == "root"
        ):
            root_logins.append(event)

        if event.get("process") == "sudo":
                    sudo_events.append(event)

    for login in root_logins:
        # TODO: get login timestamp
        login_time = login["parsed_time"]

        for sudo in sudo_events:
            # TODO: get sudo timestamp
            sudo_time = sudo["parsed_time"]

            # TODO: calculate time difference
            time_difference = (sudo_time - login_time).total_seconds()

            # TODO: only correlate sudo activity that happened
            # AFTER the root login and within windows_seconds
            if 0 <= time_difference <= windows_seconds:
                incidents.append(
                    {
                        "incident_type": "Root Login Followed By Privileged Activity",
                        "attack_type": "Root Login Followed By Sudo",
                        "severity": "HIGH",

                        "source_ip": login.get("source_ip"),
                        "username": login.get("username"),

                        "login_time": login_time,
                        "sudo_time": sudo_time,

                        "command": sudo.get("command"),

                        "window_seconds": windows_seconds,

                        "description": (
                            f"Successful root login from "
                            f"{login.get('source_ip')} was followed by "
                            f"sudo activity within {windows_seconds} seconds"
                        )
                    }
                )

            # TODO: create incident

            # TODO: append incident to incidents

    return incidents

def multiple_acc_same_ip(
        events,
        threshold_count = CONFIG["correlation"]["threshold_count"],
        windows_seconds = CONFIG["correlation"]["windows_seconds"]
):
    incidents = []
    events_by_ip = defaultdict(list)

    #grp auth events by sourceip
    for event in events:
        if event.get("event_type") != "authentication":
            continue
        if not event.get("source_ip"):
            continue

        if not event.get("parsed_time"):
            continue

        if event.get("result") != "failed":
            continue

        if not event.get("username"):
            continue

        events_by_ip[event["source_ip"]].append(event)

        #analyze each ip separately
        for ip , ip_events in events_by_ip.items():
            ip_events.sort(key= lambda event : event["parsed_time"])
            username_events= []
            for event in ip_events:
                username_events.append(event)
                #remove events outside the time window
                username_events = [
                    attempt
                    for attempt in username_events
                    if(
                        event["parsed_time"] - attempt["parsed_time"]
                    ).total_seconds() <= windows_seconds
                ]

                #get unique usernames in current window
                usernames = set(
                    attempt.get("username")
                    for attempt in username_events
                )

                #enough different account targeted
                if len(usernames) >= threshold_count:
                    incidents.append(
                        {
                            "incident_type": "Multiple Accounts From Same IP",
                            "attack_type": "Account Enumeration",
                            "severity": "HIGH",
                            "source_ip": ip,
                            "targeted_accounts": list(usernames),
                            "account_count": len(usernames),
                            "attempts": len(username_events),
                            "window_start": username_events[0]["parsed_time"],
                            "window_end": event["parsed_time"],
                            "window_seconds": windows_seconds,
                            "description": (
                                f"Source IP {ip} attempted authentication "
                                f"against {len(usernames)} different accounts "
                                f"within {windows_seconds} seconds"
                            )
                        }
                    )

                    # Prevent duplicate incident for same sequence
                    username_events = []

    return incidents


def multiple_accounts_same_ip(
        events,
        threshold_count = CONFIG["correlation"]["threshold_count"],
        windows_seconds = CONFIG["correlation"]["windows_seconds"]
):
    return multiple_acc_same_ip(events, threshold_count, windows_seconds)


def same_acc_multiple_ips(
        events,
        threshol_count = CONFIG["correlation"]["threshold_count"],
        windows_seconds = CONFIG["correlation"]["windows_seconds"]
):
    incidents = []
    events_by_username = defaultdict(list)

    #grp failed auth events by username
    for event in events:
        if event.get("event_type") != "authentication":
            continue

        if event.get("result") != "failed":
            continue

        if not event.get("username"):
            continue

        if not event.get("source_ip"):
            continue

        if not event.get("parsed_time"):
            continue

        events_by_username[event["username"]].append(event)

    #analyze each username separately
    for username , user_events in events_by_username.items():
        user_events.sort(key= lambda event : event["parsed_time"])
        window_events = []
        for event in user_events:
            window_events.append(event)

            #remove events outside the time window
            window_events = [
                attempt
                for attempt in window_events
                if(
                    event["parsed_time"] - attempt["parsed_time"]
                ).total_seconds() > windows_seconds
            ]

            #get unique source ip in curr win
            source_ips = set(
                attempt.get("source_ip")
                for attempt in window_events
            )

            #enough diffips targeting the same acc
            if len(source_ips) >= threshol_count:
                incidents.append(
                    {
                        "incident_type": "Same Account From Multiple IPs",
                        "attack_type": "Distributed Account Attack",
                        "severity": "HIGH",
                        "username": username,
                        "source_ips": list(source_ips),
                        "source_ip_count": len(source_ips),
                        "attempts": len(window_events),
                        "window_start": window_events[0]["parsed_time"],
                        "window_end": event["parsed_time"],
                        "window_seconds": windows_seconds,
                        "description": (
                            f"Account '{username}' received "
                            f"authentication attempts from "
                            f"{len(source_ips)} different IP addresses "
                            f"within {windows_seconds} seconds"
                        )
                    }

                )

                #prevent duplicate events in same winsdow
                window_events = []

    return incidents

def multiple_failed_then_root_login(
        events,
        threshold_count=CONFIG["correlation"]["threshold_count"],
        windows_seconds=CONFIG["correlation"]["windows_seconds"]
):
    incidents = []
    events_by_ip = defaultdict(list)

    # Group authentication events by source IP
    for event in events:

        if event.get("event_type") != "authentication":
            continue

        if not event.get("source_ip"):
            continue

        if not event.get("parsed_time"):
            continue

        events_by_ip[event["source_ip"]].append(event)

    # Analyze each IP separately
    for ip, ip_events in events_by_ip.items():

        ip_events.sort(key=lambda event: event["parsed_time"])

        failed_events = []

        for event in ip_events:

            # Failed authentication
            if event.get("result") == "failed":

                failed_events.append(event)

                # Keep only failures inside the time window
                failed_events = [
                    failed
                    for failed in failed_events
                    if (
                        event["parsed_time"] - failed["parsed_time"]
                    ).total_seconds() <= windows_seconds
                ]

            # Successful root login
            elif (
                event.get("result") == "success"
                and event.get("username") == "root"
            ):

                # Keep only failures before this root login
                failed_events = [
                    failed
                    for failed in failed_events
                    if (
                        event["parsed_time"] - failed["parsed_time"]
                    ).total_seconds() <= windows_seconds
                ]

                if len(failed_events) >= threshold_count:

                    incidents.append(
                        {
                            "incident_type": "Multiple Failed Logins Then Root Login",
                            "attack_type": "Possible Root Account Compromise",
                            "severity": "CRITICAL",
                            "source_ip": ip,
                            "username": "root",
                            "failed_attempts": len(failed_events),
                            "window_start": failed_events[0]["parsed_time"],
                            "root_login_time": event["parsed_time"],
                            "window_seconds": windows_seconds,
                            "description": (
                                f"{len(failed_events)} failed authentication "
                                f"attempts from {ip} were followed by a "
                                f"successful root login within "
                                f"{windows_seconds} seconds"
                            )
                        }
                    )

                    # Prevent duplicate incidents
                    failed_events = []

    return incidents

def authentication_then_suspicious_sudo(
        events,
        windows_seconds=CONFIG["correlation"]["windows_seconds"]
):
    incidents = []
    auth_events = []
    sudo_events = []

    # Separate authentication and sudo events
    for event in events:

        if not event.get("parsed_time"):
            continue

        if event.get("event_type") == "authentication":
            if event.get("result") == "success":
                auth_events.append(event)

        elif event.get("process") == "sudo":
            sudo_events.append(event)

    # Correlate authentication with sudo activity
    for auth in auth_events:

        auth_time = auth["parsed_time"]
        username = auth.get("username")
        source_ip = auth.get("source_ip")

        for sudo in sudo_events:

            sudo_time = sudo["parsed_time"]

            # Sudo must happen AFTER authentication
            if sudo_time < auth_time:
                continue

            # Sudo must happen within the correlation window
            time_difference = (
                sudo_time - auth_time
            ).total_seconds()

            if time_difference > windows_seconds:
                continue

            # Match the authenticated user
            sudo_user = sudo.get("username")

            if username and sudo_user and username != sudo_user:
                continue

            incidents.append(
                {
                    "incident_type": "Authentication Then Suspicious Sudo",
                    "attack_type": "Privilege Escalation",
                    "severity": "HIGH",
                    "username": username or sudo_user,
                    "source_ip": source_ip,
                    "authentication_time": auth_time,
                    "sudo_time": sudo_time,
                    "window_seconds": windows_seconds,
                    "description": (
                        f"Successful authentication for "
                        f"'{username}' was followed by "
                        f"suspicious sudo activity within "
                        f"{windows_seconds} seconds"
                    )
                }
            )

    return incidents

def ssh_login_then_session_activity(
        events,
        windows_seconds=CONFIG["correlation"]["windows_seconds"]
):
    incidents = []
    login_events = []
    session_events = []

    # Separate successful SSH logins and session activity
    for event in events:

        if not event.get("parsed_time"):
            continue

        if event.get("event_type") == "authentication":
            if (
                event.get("result") == "success"
                and event.get("process") == "sshd"
            ):
                login_events.append(event)

        elif event.get("event_type") == "session":
            session_events.append(event)

    # Correlate login with session activity
    for login in login_events:

        login_time = login["parsed_time"]
        username = login.get("username")
        source_ip = login.get("source_ip")

        for session in session_events:

            session_time = session["parsed_time"]

            # Session activity must happen after login
            if session_time < login_time:
                continue

            # Must happen within correlation window
            time_difference = (
                session_time - login_time
            ).total_seconds()

            if time_difference > windows_seconds:
                continue

            # Match username
            session_user = session.get("username")

            if username and session_user and username != session_user:
                continue

            incidents.append(
                {
                    "incident_type": "SSH Login Then Session Activity",
                    "attack_type": "Post-Authentication Activity",
                    "severity": "MEDIUM",
                    "username": username or session_user,
                    "source_ip": source_ip,
                    "login_time": login_time,
                    "session_time": session_time,
                    "window_seconds": windows_seconds,
                    "description": (
                        f"Successful SSH login for '{username}' "
                        f"was followed by session activity within "
                        f"{windows_seconds} seconds"
                    )
                }
            )

    return incidents


CORRELATION_RULES = [
    failed_then_success,
    invalid_then_success,
    root_login_then_sudo,
    multiple_accounts_same_ip,
    same_acc_multiple_ips,
    multiple_failed_then_root_login,
    authentication_then_suspicious_sudo,
    ssh_login_then_session_activity,
]


def run_correlations(events, rules=None):
    incidents = []
    normalized_events = [
        event
        for event in (events or [])
        if isinstance(event, dict)
    ]

    for rule in rules or CORRELATION_RULES:
        rule_incidents = rule(normalized_events)
        if rule_incidents:
            incidents.extend(rule_incidents)

    return incidents

'''
if __name__ == "__main__":
    from datetime import datetime

    test_events = [
        {
            "event_type": "authentication",
            "result": "failed",
            "source_ip": "192.168.1.100",
            "username": "root",
            "parsed_time": datetime(2026, 8, 30, 10, 0, 0)
        },
        {
            "event_type": "authentication",
            "result": "failed",
            "source_ip": "192.168.1.100",
            "username": "root",
            "parsed_time": datetime(2026, 8, 30, 10, 0, 10)
        },
        {
            "event_type": "authentication",
            "result": "failed",
            "source_ip": "192.168.1.100",
            "username": "root",
            "parsed_time": datetime(2026, 8, 30, 10, 0, 20)
        },
        {
            "event_type": "authentication",
            "result": "success",
            "source_ip": "192.168.1.100",
            "username": "root",
            "parsed_time": datetime(2026, 8, 30, 10, 0, 30)
        }
    ]

    incidents = failed_then_success(test_events)

    print(incidents)

'''
