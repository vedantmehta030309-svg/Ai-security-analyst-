SEVERITY_BASED_SCORES = {
    "INFO" : 5 ,
    "LOW" : 20 ,
    "MEDIUM" : 40 ,
    "HIGH" : 65 ,
    "CRITICAL" : 85
}


def calculate_risk(alert):
    #Calculate risk 0-100 risk score for a single alert/incident

    severity = alert.get("severity" , "LOW").upper()
    score= SEVERITY_BASED_SCORES.get(severity,20)
    risk_factors = []

    #rec base severity
    risk_factors.append(f"{severity} severity")

    #failed auth attempts
    failed_attempts = alert.get("failed_attempts", 0)
    if failed_attempts >=3 :
        score += 10
        risk_factors.append("multiple failed auth attempts")

    #successful auth after failures
    if(
        alert.get("success_time")
        or alert.get("root_login_time")
    ):
        score += 15
        risk_factors.append("successful auth after failures")

    #root auth
    if alert.get("username") == "root":
        score += 20
        risk_factors.append("root account involved")

    #privileged / sudo activity
    attack_type = str(alert.get("attack type" ,"")).lower()
    if(
        "sudo" in attack_type
        or "privilege" in attack_type
        or alert.get("command")
    ):
        score += 15
        risk_factors.append("privileged activity detected")

    #invalid-user activity
    invalid_attempts = alert.get("invalid_user_attempts", 0)
    if invalid_attempts >0 :
        score += 10
        risk_factors.append("invalid user auth activity")

    #correlation / incident
    if alert.get("incident_type"):
        score += 15
        risk_factors.append("correlated security incident")

    #clamp score
    score = min(score , 100)

    #convert score to risk
    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
    }


def score_alerts(alerts):
    #add risk scoring info to every alert
    for alert in alerts:
        risk = calculate_risk(alert)
        alert["risk_score"] = risk["risk_score"]
        alert["risk_level"] = risk["risk_level"]
        alert["risk_factors"] = risk["risk_factors"]

    return alerts