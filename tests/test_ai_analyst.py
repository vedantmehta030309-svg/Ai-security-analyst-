import unittest

from ai_analyst import analyze_alert, analyze_alerts, offline_analysis
from risk_score import calculate_risk, score_alerts


class AiAnalystTests(unittest.TestCase):
    def test_offline_analysis_has_required_sections(self):
        alert = {
            "incident_type": "Possible Account Compromise",
            "attack_type": "Possible Account Compromise",
            "severity": "CRITICAL",
            "source_ip": "198.51.100.77",
            "username": "root",
            "failed_attempts": 3,
            "success_time": "2026-07-18T06:10:25",
        }
        score_alerts([alert])
        analysis = offline_analysis(alert)

        for key in (
            "summary",
            "why_suspicious",
            "evidence",
            "attack_pattern",
            "investigation_steps",
            "risk_explanation",
            "analyst_mode",
        ):
            self.assertIn(key, analysis)

        self.assertEqual(analysis["analyst_mode"], "offline")
        self.assertIn("risk_score.py", analysis["risk_explanation"])
        self.assertIn("100", analysis["risk_explanation"])

    def test_does_not_change_authoritative_risk_score(self):
        alert = {
            "severity": "CRITICAL",
            "username": "root",
            "failed_attempts": 3,
            "incident_type": "Multiple Failed Logins Then Root Login",
            "root_login_time": "2026-08-01T10:00:30",
        }
        expected = calculate_risk(alert)
        score_alerts([alert])
        analyze_alert(alert, mode="offline")

        self.assertEqual(alert["risk_score"], expected["risk_score"])
        self.assertEqual(alert["risk_level"], expected["risk_level"])
        self.assertEqual(alert["risk_factors"], expected["risk_factors"])

    def test_analyze_alerts_builds_export_and_priority_only(self):
        alerts = [
            {"severity": "LOW", "attack_type": "Failed Login", "risk_score": 20, "risk_level": "LOW"},
            {
                "incident_type": "Possible Account Compromise",
                "attack_type": "Possible Account Compromise",
                "severity": "CRITICAL",
                "username": "root",
                "source_ip": "198.51.100.77",
                "risk_score": 100,
                "risk_level": "CRITICAL",
                "risk_factors": ["CRITICAL severity", "root account involved"],
            },
        ]
        report = analyze_alerts(alerts, mode="offline")

        self.assertEqual(report["incident_count"], 1)
        self.assertIn("executive_summary", report)
        self.assertIn("ai_analysis", alerts[1])
        self.assertNotIn("ai_analysis", alerts[0])


if __name__ == "__main__":
    unittest.main()
