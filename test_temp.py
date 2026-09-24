from risk_score import calculate_risk


test_alert = {
    "severity": "CRITICAL",
    "attack_type": "Possible Root Account Compromise",
    "username": "root",
    "failed_attempts": 3,
    "incident_type": "Multiple Failed Logins Then Root Login",
    "root_login_time": "2026-08-01 10:00:30",
}


result = calculate_risk(test_alert)

print(result)