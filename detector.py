'''
all the things are orchestrated in main.py ;)
'''
from email import message

from parser import IP_REGEX
from collections import Counter, defaultdict
import re
from config import CONFIG

def create_alert(log=None, severity="", attack_type="", **extra):
    if log:
        alert = log.copy()
    else:
        alert = {}

    alert["severity"] = severity
    alert["attack_type"] = attack_type

    alert.update(extra)

    return alert



def failed_login(logs):
    alerts = []

    for log in logs:
        if "Failed password" in log["message"]:

            alerts.append(
                create_alert(
                    log,
                    severity="LOW",
                    attack_type="Failed Login"
                )
            )

    return alerts

def successful_login(logs):
    alerts = []

    for log in logs:

        if "Accepted password" in log["message"]:

            message = log["message"].split()

            username = message[message.index("for") + 1]
            ip = message[message.index("from") + 1]

            alerts.append(
                create_alert(
                    log,
                    severity="INFO",
                    attack_type="Successful Login",
                    username=username,
                    ip=ip
                )
            )

    return alerts



def bruteforce(logs,threshold_count =CONFIG["bruteforce"]["threshold_count"] , window_second = CONFIG["bruteforce"]["window_seconds"]):
    alerts = []
    #attacker_count = Counter()
    attacker_timestamps = defaultdict(list)

    for log in logs:

        if "Failed password" in log["message"]:

            ip_match = IP_REGEX.search(log["message"])

            if ip_match:
                ip = ip_match.group("ip")
                attacker_timestamps[ip].append(log["parsed_time"])

    #run the sliding window SEPARATELY for each IP's own timeline.
    for ip, timestamps in attacker_timestamps.items():
        left = 0
        for right in range(len(timestamps)):
            # shrink from the left while the window is too WIDE IN TIME
            while (timestamps[right] - timestamps[left]).total_seconds() > window_second:
                left += 1

            #to check if too wide in count
            windows_size = right - left +1
            if windows_size >= threshold_count:
                alerts.append(
                    create_alert(
                        severity="HIGH",
                        attack_type="Bruteforce Attack",
                        ip=ip,
                        attempts=windows_size ,
                        window_start = timestamps[left],
                        window_end = timestamps[right]
                    )
                )
                break

    return alerts



def root_login(logs):
    alerts = []
    for log in logs:
        if "Accepted password for root" in log["message"]:
            message = log["message"].split()
            username = message[message.index("for") + 1]
            ip = message[message.index("from") + 1]

            alerts.append(
                create_alert(
                    log=log,
                    severity="HIGH",
                    attack_type="Root Login",
                    username=username,
                    ip=ip
                )
            )
    return alerts


SUDO_REGEX = re.compile(
    r"^\s*(?P<username>\w+)\s*:\s.*?COMMAND=(?P<command>.+)"
)
def sudo(logs):
    alerts = []
    for log in logs:
        if log["process"]!="sudo":
            continue
        print(repr(log["message"]))
        match = SUDO_REGEX.match(log["message"])
        if not match:
            continue
        alerts.append(
            create_alert(
                log=log,
                severity="MEDIUM",
                attack_type="Sudo Command",
                username=match.group("username"),
                command=match.group("command")
            )
        )
    return alerts


#f_l=successful_login(logs)
#print(f_l)

'''
# failed pass
if "Failed password" in message:
    # isolate ip
    ip_match = IP_REGEX.match(message)
    if ip_match:
        ip_add = ip_match.group("ip")
        raw_time = log_data["time"]
        parsed_time = datetime.strptime(f"2026 {raw_time}", "%Y %b %d %H:%M:%S")
        attacker_count[ip_add] += 1

print(f"\nAnalysis Complete. Found {sum(attacker_count.values())} failed login attempts.")
print("\nTop Attackers (IP Address : Attempt Count):")
for ip, count in attacker_count.most_common(5):
    print(f"[-] {ip:<15} : {count} malicious attempts")
'''