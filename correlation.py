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
                if event.get("invalid_user") is True:
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
