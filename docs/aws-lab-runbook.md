# AWS Lab Runbook

Safe interview claim:

> I built and tested the detector locally, and documented the next AWS lab path for turning it into an event-driven monitor.

## Current proof

- Local parser and detection rules.
- Sample CloudTrail-style logs.
- Unit tests for security findings.
- GitHub Actions CI.
- Detection matrix in `docs/detection-matrix.md`.

## Event-driven AWS lab design

1. CloudTrail records account activity.
2. EventBridge rule filters CloudTrail management events.
3. Lambda runs the same detection logic used locally.
4. Findings are written to CloudWatch Logs.
5. High-severity findings publish to SNS or email.

## Evidence to collect after deploying the lab

- Screenshot of the EventBridge rule.
- Screenshot of the Lambda test event and output.
- CloudWatch log line showing a detected IAM/security-group event.
- SNS/email sample for one high-severity finding.
- Cost note showing the lab stays inside free or low-cost usage.

## What not to claim yet

- Do not claim the repo is already deployed to AWS.
- Do not claim real-time production monitoring.
- Do not claim automated remediation.

## Simple implementation path

Keep the local detector as the core logic. Add a thin Lambda handler that accepts a CloudTrail event, calls the same detection function, and logs or publishes findings.
