from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud_security_monitor.detections import (
    ACCESS_KEY_CHANGE_EVENTS,
    ADMINISTRATIVE_ACTION_EVENTS,
    IAM_POLICY_CHANGE_EVENTS,
    IAM_USER_CREATION_EVENTS,
    SECURITY_GROUP_CHANGE_EVENTS,
    detect_event,
)
from cloud_security_monitor.monitor import load_cloudtrail_records, scan, write_csv


EXPECTED_FLAGGED_EVENTS = {
    "ConsoleLogin",
    "PutUserPolicy",
    "AuthorizeSecurityGroupIngress",
    "CreateUser",
    "CreateAccessKey",
    "StopLogging",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure local CloudTrail sample detection coverage.")
    parser.add_argument("--input", default="samples/cloudtrail_sample.json")
    parser.add_argument("--output-dir", default="docs/benchmark-results")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    records = load_cloudtrail_records(input_path)
    findings = scan(input_path)
    flagged_event_names = {finding.event_name for finding in findings}
    false_positive_count = sum(1 for record in records if detect_event(record) and record["eventName"] not in EXPECTED_FLAGGED_EVENTS)
    missed_expected = sorted(EXPECTED_FLAGGED_EVENTS - flagged_event_names)

    summary = {
        "benchmark_date": "2026-09-23",
        "input": str(input_path),
        "records_scanned": len(records),
        "detection_rule_groups": 6,
        "enumerated_event_names": {
            "failed_authentication_error_codes": "see cloud_security_monitor/detections.py FAILED_AUTH_ERROR_CODES",
            "iam_user_creation": sorted(IAM_USER_CREATION_EVENTS),
            "iam_policy_changes": sorted(IAM_POLICY_CHANGE_EVENTS),
            "security_group_changes": sorted(SECURITY_GROUP_CHANGE_EVENTS),
            "access_key_changes": sorted(ACCESS_KEY_CHANGE_EVENTS),
            "cloudtrail_admin_actions": sorted(ADMINISTRATIVE_ACTION_EVENTS),
        },
        "expected_flagged_events": sorted(EXPECTED_FLAGGED_EVENTS),
        "detections": len(findings),
        "misses": len(missed_expected),
        "missed_expected_events": missed_expected,
        "false_positives": false_positive_count,
        "detection_rate_on_safe_sample": len(EXPECTED_FLAGGED_EVENTS - set(missed_expected)) / len(EXPECTED_FLAGGED_EVENTS),
        "aws_lab_status": "No live AWS lab logs or credentials were present, so no AWS events were generated.",
    }

    write_csv(findings, output_dir / "cloud_security_findings_2026-09-23.csv")
    with (output_dir / "cloud_security_detection_benchmark_2026-09-23.json").open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)
    with (output_dir / "cloud_security_detection_summary_2026-09-23.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=[key for key in summary if key != "enumerated_event_names"])
        writer.writeheader()
        row = {key: value for key, value in summary.items() if key != "enumerated_event_names"}
        writer.writerow(row)

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
