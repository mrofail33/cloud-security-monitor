# Security Portfolio Boundary

This project is the main cybersecurity proof in the portfolio.

## Strong evidence

- Python detection logic.
- CloudTrail-style event parsing.
- IAM, access-key, security-group, and audit-logging detections.
- Unit tests for expected findings.
- CI workflow.
- Detection matrix with safe interview wording.

## Partial evidence

- Cloud security concepts are present, but the repo is still local-first.
- DevOps/SRE evidence is present through CI and runbook-style thinking, but not through live monitoring or alerting.

## Missing evidence

- Live AWS deployment.
- Lambda/EventBridge integration.
- Alert delivery through SNS, email, Slack, or a ticketing system.
- Dashboards or ongoing metrics.
- Incident-response exercise using real lab output.

## Resume-safe wording

Use:

> Built a Python CloudTrail log analyzer that flags IAM, access-key, security-group, and audit-logging events from sample AWS logs, with unit tests and a documented AWS lab path.

Avoid:

> Built a production SIEM.

Avoid:

> Deployed real-time AWS threat detection.
