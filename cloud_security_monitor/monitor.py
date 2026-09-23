"""Command-line CloudTrail monitor for local lab logs."""

from __future__ import annotations

import argparse
import gzip
import json
import logging
from pathlib import Path
from typing import Any, Iterable

from cloud_security_monitor.detections import Finding, detect_event
from cloud_security_monitor.sns import publish_findings


LOGGER = logging.getLogger("cloud_security_monitor")


def configure_logging(verbose: bool = False) -> None:
    """Configure readable console logging."""

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def load_cloudtrail_records(path: Path) -> list[dict[str, Any]]:
    """Load CloudTrail records from one JSON or JSON.GZ file."""

    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as file:
                payload = json.load(file)
        else:
            with path.open("r", encoding="utf-8") as file:
                payload = json.load(file)
    except FileNotFoundError:
        LOGGER.error("Input file was not found: %s", path)
        return []
    except json.JSONDecodeError as exc:
        LOGGER.error("Input file is not valid JSON: %s (%s)", path, exc)
        return []
    except OSError as exc:
        LOGGER.error("Could not read input file: %s (%s)", path, exc)
        return []

    records = payload.get("Records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        LOGGER.warning("Skipping %s because it does not contain a Records list.", path)
        return []

    valid_records = [record for record in records if isinstance(record, dict)]
    skipped = len(records) - len(valid_records)
    if skipped:
        LOGGER.warning("Skipped %s non-object record(s) in %s.", skipped, path)
    return valid_records


def iter_input_files(input_path: Path) -> Iterable[Path]:
    """Yield CloudTrail JSON files from a file or directory."""

    if input_path.is_file():
        yield input_path
        return

    if input_path.is_dir():
        patterns = ("*.json", "*.json.gz")
        for pattern in patterns:
            yield from sorted(input_path.rglob(pattern))
        return

    LOGGER.error("Input path is not a file or directory: %s", input_path)


def scan(input_path: Path) -> list[Finding]:
    """Scan local CloudTrail logs and return findings."""

    findings: list[Finding] = []
    files = list(iter_input_files(input_path))
    if not files:
        LOGGER.warning("No CloudTrail JSON files found in %s.", input_path)
        return findings

    LOGGER.info("Scanning %s CloudTrail file(s).", len(files))
    for file_path in files:
        records = load_cloudtrail_records(file_path)
        LOGGER.debug("Loaded %s record(s) from %s.", len(records), file_path)
        for record in records:
            finding = detect_event(record)
            if finding:
                findings.append(finding)

    return findings


def format_table(findings: list[Finding]) -> str:
    """Return a simple terminal table for findings."""

    headers = ["Time", "Event", "User", "Flag"]
    rows = [
        [short_time(finding.time), finding.event, finding.user, finding.flag]
        for finding in findings
    ]
    widths = [
        max(len(str(value)) for value in column)
        for column in zip(headers, *rows, strict=False)
    ] if rows else [len(header) for header in headers]

    def render_row(values: list[str]) -> str:
        return "| " + " | ".join(
            str(value).ljust(widths[index]) for index, value in enumerate(values)
        ) + " |"

    separator = "| " + " | ".join("-" * width for width in widths) + " |"
    lines = [render_row(headers), separator]
    lines.extend(render_row(row) for row in rows)
    return "\n".join(lines)


def short_time(value: str) -> str:
    """Show the time portion of an ISO CloudTrail timestamp when possible."""

    if "T" in value:
        return value.split("T", 1)[1].replace("Z", "")
    return value


def write_csv(findings: list[Finding], output_path: Path) -> None:
    """Write findings to a small CSV file."""

    import csv

    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["time", "event", "user", "flag", "source", "event_name", "resource", "reason"])
        for finding in findings:
            writer.writerow([
                finding.time,
                finding.event,
                finding.user,
                finding.flag,
                finding.source,
                finding.event_name,
                finding.resource,
                finding.reason,
            ])


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description="Scan local AWS CloudTrail logs for predefined security events.",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to a CloudTrail JSON file, JSON.GZ file, or directory of logs.",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        help="Optional path to save findings as CSV.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show debug logging.",
    )
    parser.add_argument(
        "--sns-topic-arn",
        help="Optional SNS topic ARN for sending a review notification.",
    )
    parser.add_argument(
        "--aws-region",
        help="Optional AWS region for SNS publishing.",
    )
    return parser


def main() -> int:
    """Run the monitor from the command line."""

    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)

    findings = scan(args.input)
    print(format_table(findings))
    LOGGER.info("Found %s event(s) flagged for review.", len(findings))

    if args.csv:
        write_csv(findings, args.csv)
        LOGGER.info("Saved CSV findings to %s.", args.csv)

    if args.sns_topic_arn:
        message_id = publish_findings(args.sns_topic_arn, findings, args.aws_region)
        LOGGER.info("Published SNS notification with MessageId %s.", message_id)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

