
import json
import unittest
from pathlib import Path

from src.iam_detection import detect_iam_policy_changes


class TestIAMPolicyChanges(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project_root = Path(__file__).resolve().parent.parent
        event_file = (
            project_root
            / "sample_events"
            / "suspicious_iam_policy_change.json"
        )

        with event_file.open("r", encoding="utf-8") as file:
            cls.sample_events = json.load(file)

    def test_iam_policy_change_generates_finding(self):
        findings = detect_iam_policy_changes(self.sample_events)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "AWS-IAM-002")
        self.assertEqual(findings[0]["event_name"], "PutUserPolicy")

    def test_unrelated_event_does_not_generate_finding(self):
        unrelated_event = {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "eventTime": "2026-10-15T10:20:00Z",
            "sourceIPAddress": "198.51.100.50",
            "userIdentity": {
                "userName": "demo-admin"
            },
        }

        findings = detect_iam_policy_changes([unrelated_event])

        self.assertEqual(findings, [])

    def test_sanitized_oauth_event_does_not_generate_finding(self):
        project_root = Path(__file__).resolve().parent.parent
        event_file = (
            project_root
            / "sample_events"
            / "real_oauth_event_sanitized.json"
        )

        with event_file.open("r", encoding="utf-8") as file:
            oauth_event = json.load(file)

        findings = detect_iam_policy_changes([oauth_event])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
