import unittest
from datetime import datetime, timedelta

from correlation import (
    CORRELATION_RULES,
    authentication_then_suspicious_sudo,
    failed_then_success,
    invalid_then_success,
    multiple_accounts_same_ip,
    multiple_acc_same_ip,
    multiple_failed_then_root_login,
    root_login_then_sudo,
    run_correlations,
    ssh_login_then_session_activity,
)


BASE_TIME = datetime(2026, 8, 30, 10, 0, 0)


def auth_event(seconds, result, username, source_ip, invalid_user=False):
    return {
        "event_type": "authentication",
        "auth_method": "password",
        "process": "sshd",
        "result": result,
        "username": username,
        "source_ip": source_ip,
        "source_port": 50000 + seconds,
        "parsed_time": BASE_TIME + timedelta(seconds=seconds),
        "invalid_user": invalid_user,
    }


def sudo_event(seconds, username="root"):
    return {
        "process": "sudo",
        "username": username,
        "command": "/usr/bin/id",
        "parsed_time": BASE_TIME + timedelta(seconds=seconds),
    }


def session_event(seconds, username):
    return {
        "event_type": "session",
        "process": "sshd",
        "result": "opened",
        "username": username,
        "parsed_time": BASE_TIME + timedelta(seconds=seconds),
    }


class CorrelationRuleTests(unittest.TestCase):
    def test_failed_then_success_detects_sequence(self):
        events = [
            auth_event(0, "failed", "root", "198.51.100.77"),
            auth_event(8, "failed", "root", "198.51.100.77"),
            auth_event(16, "failed", "root", "198.51.100.77"),
            auth_event(25, "success", "root", "198.51.100.77"),
        ]

        incidents = failed_then_success(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_type"], "Possible Account Compromise")
        self.assertEqual(incidents[0]["source_ip"], "198.51.100.77")
        self.assertEqual(incidents[0]["failed_attempts"], 3)

    def test_invalid_then_success_detects_sequence(self):
        events = [
            auth_event(0, "failed", "admin", "10.10.10.50", invalid_user=True),
            auth_event(5, "failed", "admin", "10.10.10.50", invalid_user=True),
            auth_event(10, "failed", "test", "10.10.10.50", invalid_user=True),
            auth_event(20, "success", "admin", "10.10.10.50"),
        ]

        incidents = invalid_then_success(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            incidents[0]["incident_type"],
            "Invalid User Attack Followed By Success",
        )
        self.assertEqual(incidents[0]["invalid_user_attempts"], 3)

    def test_root_login_then_sudo_detects_sequence(self):
        events = [
            auth_event(0, "success", "root", "172.16.0.25"),
            sudo_event(15, "root"),
        ]

        incidents = root_login_then_sudo(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            incidents[0]["incident_type"],
            "Root Login Followed By Privileged Activity",
        )
        self.assertEqual(incidents[0]["command"], "/usr/bin/id")

    def test_multiple_accounts_same_ip_detects_sequence(self):
        events = [
            auth_event(0, "failed", "admin", "192.168.1.80"),
            auth_event(5, "failed", "guest", "192.168.1.80"),
            auth_event(10, "failed", "test", "192.168.1.80"),
        ]

        incidents = multiple_accounts_same_ip(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_type"], "Multiple Accounts From Same IP")
        self.assertEqual(incidents[0]["account_count"], 3)
        self.assertEqual(set(incidents[0]["targeted_accounts"]), {"admin", "guest", "test"})

    def test_multiple_acc_same_ip_remains_available(self):
        events = [
            auth_event(0, "failed", "admin", "192.168.1.80"),
            auth_event(5, "failed", "guest", "192.168.1.80"),
            auth_event(10, "failed", "test", "192.168.1.80"),
        ]

        self.assertEqual(
            multiple_acc_same_ip(events),
            multiple_accounts_same_ip(events),
        )

    def test_multiple_failed_then_root_login_detects_sequence(self):
        events = [
            auth_event(0, "failed", "root", "198.51.100.77"),
            auth_event(8, "failed", "root", "198.51.100.77"),
            auth_event(16, "failed", "root", "198.51.100.77"),
            auth_event(25, "success", "root", "198.51.100.77"),
        ]

        incidents = multiple_failed_then_root_login(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            incidents[0]["incident_type"],
            "Multiple Failed Logins Then Root Login",
        )
        self.assertEqual(incidents[0]["failed_attempts"], 3)

    def test_authentication_then_suspicious_sudo_detects_sequence(self):
        events = [
            auth_event(0, "success", "alice", "192.168.1.50"),
            sudo_event(10, "alice"),
        ]

        incidents = authentication_then_suspicious_sudo(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            incidents[0]["incident_type"],
            "Authentication Then Suspicious Sudo",
        )
        self.assertEqual(incidents[0]["username"], "alice")

    def test_ssh_login_then_session_activity_detects_sequence(self):
        events = [
            auth_event(0, "success", "bob", "192.168.1.60"),
            session_event(10, "bob"),
        ]

        incidents = ssh_login_then_session_activity(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            incidents[0]["incident_type"],
            "SSH Login Then Session Activity",
        )
        self.assertEqual(incidents[0]["username"], "bob")


class CorrelationEngineTests(unittest.TestCase):
    def test_registry_contains_expected_rules(self):
        rule_names = [rule.__name__ for rule in CORRELATION_RULES]

        self.assertIn("failed_then_success", rule_names)
        self.assertIn("invalid_then_success", rule_names)
        self.assertIn("root_login_then_sudo", rule_names)
        self.assertIn("multiple_accounts_same_ip", rule_names)
        self.assertIn("multiple_failed_then_root_login", rule_names)
        self.assertIn("authentication_then_suspicious_sudo", rule_names)
        self.assertIn("ssh_login_then_session_activity", rule_names)

    def test_run_correlations_executes_registered_rules(self):
        events = [
            auth_event(0, "failed", "root", "198.51.100.77"),
            auth_event(8, "failed", "root", "198.51.100.77"),
            auth_event(16, "failed", "root", "198.51.100.77"),
            auth_event(25, "success", "root", "198.51.100.77"),
        ]

        incident_types = {
            incident["incident_type"]
            for incident in run_correlations(events)
        }

        self.assertIn("Possible Account Compromise", incident_types)
        self.assertIn("Multiple Failed Logins Then Root Login", incident_types)

    def test_run_correlations_accepts_custom_rules(self):
        events = [
            auth_event(0, "failed", "root", "198.51.100.77"),
            auth_event(8, "failed", "root", "198.51.100.77"),
            auth_event(16, "failed", "root", "198.51.100.77"),
            auth_event(25, "success", "root", "198.51.100.77"),
        ]

        incidents = run_correlations(events, rules=[failed_then_success])

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_type"], "Possible Account Compromise")

    def test_run_correlations_empty_events_returns_empty_list(self):
        self.assertEqual(run_correlations([]), [])

    def test_run_correlations_malformed_events_do_not_crash(self):
        events = [
            object(),
            None,
            {},
            {"event_type": "authentication", "result": "success", "username": "root"},
            {"process": "sudo"},
        ]

        self.assertEqual(run_correlations(events), [])


if __name__ == "__main__":
    unittest.main()
