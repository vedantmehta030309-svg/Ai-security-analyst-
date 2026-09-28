import unittest

from risk_score import calculate_risk, score_alerts


class RiskScoreTests(unittest.TestCase):
    def test_root_compromise_incident_is_high_or_critical(self):
        alert = {
            "severity": "CRITICAL",
            "attack_type": "Possible Root Account Compromise",
            "username": "root",
            "failed_attempts": 3,
            "incident_type": "Multiple Failed Logins Then Root Login",
            "root_login_time": "2026-08-01 10:00:30",
        }
        result = calculate_risk(alert)
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertIn("root account involved", result["risk_factors"])

    def test_score_alerts_writes_expected_fields(self):
        alerts = [{"severity": "LOW", "attack_type": "Failed Login"}]
        score_alerts(alerts)
        self.assertIn("risk_score", alerts[0])
        self.assertIn("risk_level", alerts[0])
        self.assertIn("risk_factors", alerts[0])


if __name__ == "__main__":
    unittest.main()
