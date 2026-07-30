'''
all the things are orchestrated in main.py ;)
'''
from parser import IP_REGEX
from collections import Counter


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



def bruteforce(logs):

    alerts = []

    BRUTEFORCE_THRESHOLD = 5

    attacker_count = Counter()

    for log in logs:

        if "Failed password" in log["message"]:

            ip_match = IP_REGEX.search(log["message"])

            if ip_match:
                ip = ip_match.group("ip")
                attacker_count[ip] += 1

    for ip, count in attacker_count.items():

        if count >= BRUTEFORCE_THRESHOLD:

            alerts.append(
                create_alert(
                    severity="HIGH",
                    attack_type="Bruteforce Attack",
                    ip=ip,
                    attempts=count
                )
            )

    return alerts



def root_login():
    pass
def sudo():
    pass


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