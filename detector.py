'''
all the things are orchestrated in main.py ;)
'''
from parser import IP_REGEX
from collections import Counter


def failed_login(logs):
    alerts = []
    for log in logs:
        if "Failed password" in log["message"]:
            alert=log.copy()
            alert["severity"]="LOW"
            alert["attack_type"]="Failed login attempt"

            alerts.append(alert)
    return alerts


def successful_login(logs):
    alerts = []
    for log in logs :
        if "Accepted password" in log["message"]:
            alert=log.copy()
            alert["severity"]="INFO"
            alert["attack_type"]="Successful login attempt"
            message=log["message"].split()
            for_index = message.index("for")
            username = message[for_index + 1]
            from_index = message.index("from")
            ip = message[from_index + 1]
            alert["username"]=username
            alert["ip"]=ip

            alerts.append(alert)
    return alerts



def bruteforce(logs):
    alerts=[]
    BRUTEFORCE_THRESHOLD = 5
    attacker_count = Counter()
    # all malicious ip's
    for log in logs:
        if "Failed password" in log["message"]:
            #ip isolate
            ipMatch=IP_REGEX.search(log["message"])
            if ipMatch:
                ip=ipMatch.group("ip")
                attacker_count[ip] += 1


    for ip, count in attacker_count.items():
        if count >= BRUTEFORCE_THRESHOLD:
            alert = {
                "severity": "HIGH",
                "attack_type": "Bruteforce",
                "ip": ip,
                "attempts": count
            }

            alerts.append(alert)
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