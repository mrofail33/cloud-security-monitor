from pathlib import Path
import unittest

from cloud_security_monitor.detections import detect_event
from cloud_security_monitor.monitor import format_table, scan
from cloud_security_monitor.sns import build_sns_message


class DetectionTests(unittest.TestCase):
    def test_detects_failed_console_login(self):
        record = {
            "eventTime": "2026-09-22T10:42:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "userIdentity": {"userName": "test-user"},
            "responseElements": {"ConsoleLogin": "Failure"},
        }

        finding = detect_event(record)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.event, "Login or API failure")
        self.assertEqual(finding.user, "test-user")

    def test_detects_iam_policy_change(self):
        record = {
            "eventTime": "2026-09-22T11:03:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "PutUserPolicy",
            "userIdentity": {"userName": "admin"},
            "requestParameters": {"userName": "test-user", "policyName": "LabInlinePolicy"},
        }

        finding = detect_event(record)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.event, "IAM permission changed")

    def test_ignores_unmonitored_event(self):
        record = {
            "eventTime": "2026-09-22T12:30:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBuckets",
            "userIdentity": {"userName": "developer"},
        }

        self.assertIsNone(detect_event(record))

    def test_scan_sample_data_returns_expected_findings(self):
        findings = scan(Path("samples/cloudtrail_sample.json"))

        self.assertEqual(len(findings), 6)
        self.assertEqual(
            [finding.event for finding in findings],
            [
                "Login or API failure",
                "IAM permission changed",
                "Security group changed",
                "IAM user created",
                "Access key changed",
                "CloudTrail admin action",
            ],
        )

    def test_format_table_includes_expected_columns(self):
        findings = scan(Path("samples/cloudtrail_sample.json"))
        table = format_table(findings)

        self.assertIn("Time", table)
        self.assertIn("Event", table)
        self.assertIn("User", table)
        self.assertIn("Flag", table)
        self.assertIn("Security group changed", table)

    def test_sns_message_includes_findings(self):
        findings = scan(Path("samples/cloudtrail_sample.json"))
        message = build_sns_message(findings)

        self.assertIn("Cloud security monitor found 6 event(s)", message)
        self.assertIn("Security group changed", message)
        self.assertIn("CloudTrail admin action", message)


if __name__ == "__main__":
    unittest.main()
