"""
Lightweight prototype anomaly detector (Isolation Forest).

This is a college-demo component, not a production IDS model.

Training data: synthetic "typical Linux authentication" feature vectors.
The bundled test logs are too small and attack-heavy to train a realistic
supervised model, so this module learns a simple baseline of low-activity
behavior and then scores real alerts as more/less unusual.

It does not replace detectors, correlation, or risk_score.py.
The existing numerical risk_score remains authoritative.
"""

from __future__ import annotations

FEATURE_NAMES = [
    "failed_attempts",
    "invalid_user_attempts",
    "success_after_failures",
    "root_account",
    "privileged_activity",
    "correlated_incident",
    "source_ip_count",
    "event_count",
    "risk_score",
    "severity_rank",
]

SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

PROTOTYPE_NOTE = (
    "Prototype Isolation Forest trained on synthetic baseline traffic, "
    "not on a large labeled production dataset. Do not treat scores as "
    "production detection accuracy."
)


def extract_features(alert):
    """Turn an existing alert/incident dict into numeric features."""
    attack = str(alert.get("attack_type") or alert.get("attack type") or "").lower()
    source_ips = alert.get("source_ips") or []
    source_ip_count = alert.get("source_ip_count")
    if source_ip_count is None:
        source_ip_count = len(source_ips) if source_ips else (1 if (alert.get("source_ip") or alert.get("ip")) else 0)

    event_count = (
        alert.get("attempts")
        or alert.get("failed_attempts")
        or alert.get("invalid_user_attempts")
        or alert.get("account_count")
        or 1
    )

    privileged = 0
    if (
        "sudo" in attack
        or "privilege" in attack
        or alert.get("command")
        or "privileged" in str(alert.get("incident_type", "")).lower()
    ):
        privileged = 1

    features = {
        "failed_attempts": int(alert.get("failed_attempts") or 0),
        "invalid_user_attempts": int(alert.get("invalid_user_attempts") or 0),
        "success_after_failures": int(bool(alert.get("success_time") or alert.get("root_login_time"))),
        "root_account": int(alert.get("username") == "root" or "root" in attack),
        "privileged_activity": privileged,
        "correlated_incident": int(bool(alert.get("incident_type"))),
        "source_ip_count": int(source_ip_count),
        "event_count": int(event_count),
        "risk_score": int(alert.get("risk_score") or 0),
        "severity_rank": SEVERITY_RANK.get(str(alert.get("severity", "LOW")).upper(), 1),
    }
    return features


def feature_vector(alert):
    features = extract_features(alert)
    return [features[name] for name in FEATURE_NAMES]


def _synthetic_baseline(n_samples=240, seed=42):
    """
    Build a simple 'normal' cloud: few failures, no root compromise chain,
    low risk_score, single source IP.
    """
    import numpy as np

    rng = np.random.RandomState(seed)
    rows = []
    for _ in range(n_samples):
        failed = int(rng.poisson(0.4))
        rows.append(
            [
                failed,
                int(rng.binomial(1, 0.05)),
                0,
                int(rng.binomial(1, 0.05)),
                int(rng.binomial(1, 0.08)),
                0,
                1,
                max(1, failed + int(rng.randint(0, 2))),
                int(rng.randint(5, 28)),
                int(rng.choice([0, 1, 1, 2])),
            ]
        )
    return rows


def _fit_forest(training_rows):
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42,
    )
    model.fit(training_rows)
    return model


def score_anomalies(alerts):
    """
    Attach ML fields to alerts. Never overwrites risk_score / risk_level / risk_factors.
    """
    if not alerts:
        return alerts

    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest  # noqa: F401
    except ImportError:
        for alert in alerts:
            alert["ml_status"] = "unavailable"
            alert["ml_note"] = "scikit-learn is not installed; ML module skipped."
        return alerts

    training = _synthetic_baseline()
    model = _fit_forest(training)
    vectors = [feature_vector(alert) for alert in alerts]
    matrix = np.array(vectors, dtype=float)

    # decision_function: higher = more normal. Convert to anomaly-oriented score.
    decision = model.decision_function(matrix)
    labels = model.predict(matrix)  # -1 anomaly, 1 inlier

    for alert, score, label, vector in zip(alerts, decision, labels, vectors):
        anomaly_score = round(float(-score), 4)
        is_anomaly = bool(label == -1)
        alert["ml_anomaly_score"] = anomaly_score
        alert["ml_is_anomaly"] = is_anomaly
        alert["ml_status"] = "anomaly" if is_anomaly else "typical"
        alert["ml_note"] = PROTOTYPE_NOTE
        alert["ml_features"] = dict(zip(FEATURE_NAMES, vector))

    return alerts
