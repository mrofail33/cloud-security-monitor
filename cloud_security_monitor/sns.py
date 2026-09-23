"""Optional SNS notification helper for CloudTrail findings."""

from __future__ import annotations

from cloud_security_monitor.detections import Finding


def build_sns_message(findings: list[Finding]) -> str:
    """Build a short SNS message for the detected findings."""

    if not findings:
        return "Cloud security monitor completed with no findings."

    lines = [f"Cloud security monitor found {len(findings)} event(s) for review:"]
    for finding in findings:
        lines.append(
            f"- {finding.event} | user={finding.user} | resource={finding.resource} | reason={finding.reason}"
        )
    return "\n".join(lines)


def publish_findings(topic_arn: str, findings: list[Finding], region_name: str | None = None) -> str:
    """Publish findings to SNS and return the SNS MessageId.

    boto3 is imported lazily so the local detector and unit tests still run without AWS dependencies.
    """

    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("SNS publishing requires boto3. Install boto3 to use --sns-topic-arn.") from exc

    client_kwargs = {"service_name": "sns"}
    if region_name:
        client_kwargs["region_name"] = region_name
    client = boto3.client(**client_kwargs)
    response = client.publish(
        TopicArn=topic_arn,
        Subject="Cloud security monitor findings",
        Message=build_sns_message(findings),
    )
    return str(response.get("MessageId", ""))
