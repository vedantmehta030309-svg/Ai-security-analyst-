import unittest

from ml_anomaly import FEATURE_NAMES, extract_features, score_anomalies
from risk_score import calculate_risk, score_alerts


class MlAnomalyTests(unittest.TestCase):
    def test_feature_extraction_uses_existing_fields(self):
        alert = {
            "severity": "CRITICAL",
            "username": "root",
            "failed_attempts": 3,
            "incident_type": "Possible Account Compromise",
            "success_time": "2026-07-18T06:10:25",
            "source_ip": "198.51.100.77",
            "risk_score": 100,
        }
        features = extract_features(alert)

        self.assertEqual(set(features), set(FEATURE_NAMES))
        self.assertEqual(features["failed_attempts"], 3)
        self.assertEqual(features["root_account"], 1)
        self.assertEqual(features["correlated_incident"], 1)
        self.assertEqual(features["success_after_failures"], 1)
        self.assertEqual(features["risk_score"], 100)

    def test_scoring_adds_ml_fields_without_changing_risk(self):
        alert = {
            "severity": "CRITICAL",
            "username": "root",
            "failed_attempts": 3,
            "incident_type": "Multiple Failed Logins Then Root Login",
            "root_login_time": "2026-08-01T10:00:30",
            "source_ip": "198.51.100.77",
        }
        expected = calculate_risk(alert)
        score_alerts([alert])
        score_anomalies([alert])

        self.assertEqual(alert["risk_score"], expected["risk_score"])
        self.assertEqual(alert["risk_level"], expected["risk_level"])
        self.assertIn("ml_anomaly_score", alert)
        self.assertIn("ml_is_anomaly", alert)
        self.assertIn("ml_status", alert)
        self.assertIn("prototype", alert["ml_note"].lower())

    def test_low_noise_alert_can_score(self):
        quiet = {
            "severity": "INFO",
            "attack_type": "Successful Login",
            "username": "devuser",
            "ip": "192.168.1.20",
            "risk_score": 5,
            "risk_level": "LOW",
        }
        score_anomalies([quiet])
        self.assertIn(quiet["ml_status"], {"anomaly", "typical", "unavailable"})


if __name__ == "__main__":
    unittest.main()
