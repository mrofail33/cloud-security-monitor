# Cloud Security Monitor Interview Guide

## 30-60 Second Explanation

I created an AWS security-monitoring lab using CloudTrail. CloudTrail records activity in my AWS environment, and I wrote a Python program that parses those logs and flags predefined security-related events for review.

The project looks for simple, explainable events like failed console logins, IAM user creation, IAM policy changes, security-group changes, access-key changes, and CloudTrail administrative actions. It runs locally with safe sample CloudTrail data, and it can also read logs exported from my own AWS lab.

I kept it intentionally lightweight. It is not a production SIEM; it is a hands-on lab showing that I understand CloudTrail, IAM activity, basic detection logic, Python logging, error handling, testing, and clear documentation.

## What Each File Does

| File or folder | Purpose |
| --- | --- |
| `cloud_security_monitor/detections.py` | Contains the detection rules and helper functions for extracting users and resources from CloudTrail events. |
| `cloud_security_monitor/monitor.py` | Command-line program that loads CloudTrail JSON files, applies detections, logs progress, prints a table, and optionally writes CSV output. |
| `samples/cloudtrail_sample.json` | Safe sample CloudTrail-style data so the project runs locally without AWS credentials. |
| `tests/test_detections.py` | Simple tests proving the main detections work and unmonitored events are ignored. |
| `docs/aws-architecture-diagram.md` | Mermaid architecture diagram and plain-English architecture explanation. |
| `examples/sample_output.txt` | Example terminal output showing the Time/Event/User/Flag table. |
| `screenshots/README.md` | Checklist for screenshots to capture from a controlled AWS lab. |
| `README.md` | Setup, run instructions, detection explanations, limitations, and lab guidance. |

## Detection Explanations

### Failed Authentication-Related Events

The monitor flags failed `ConsoleLogin` records and API calls with authentication or authorization error codes such as `AccessDenied` or `UnauthorizedOperation`.

Why it matters: repeated failures can indicate a misconfigured user, an expired credential, or someone attempting access.

### IAM User Creation

The monitor flags `CreateUser`.

Why it matters: new IAM users should be expected and reviewed, especially in a small lab where account activity is easy to understand.

### IAM Permission and Policy Changes

The monitor flags policy-related IAM events such as `PutUserPolicy`, `AttachUserPolicy`, `AttachRolePolicy`, `CreatePolicy`, and `SetDefaultPolicyVersion`.

Why it matters: permission changes can increase access. In a lab, these are good events to review because they show who changed access and when.

### Security-Group Changes

The monitor flags events such as `AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`, `CreateSecurityGroup`, and `DeleteSecurityGroup`.

Why it matters: security groups control network access. A rule change could expose a service if it is too broad.

### Access-Key Changes

The monitor flags `CreateAccessKey`, `DeleteAccessKey`, and `UpdateAccessKey`.

Why it matters: access keys are long-lived credentials. Creating or changing them should be intentional.

### CloudTrail Administrative Actions

The monitor flags `CreateTrail`, `UpdateTrail`, `DeleteTrail`, `StartLogging`, and `StopLogging`.

Why it matters: CloudTrail records account activity. Changes to logging should be reviewed because they affect visibility.

## Likely Interview Questions and Answers

### What problem does this project solve?

It gives me a small, understandable way to review important AWS account activity from CloudTrail logs. Instead of trying to build a full SIEM, it focuses on a few high-signal events that are easy to explain.

### Why did you use CloudTrail?

CloudTrail records AWS API activity, including who made a request, what action they took, when it happened, and which AWS service or resource was involved. That makes it a natural source for auditing AWS account activity.

### What events did you choose and why?

I chose failed authentication events, IAM changes, security-group changes, access-key changes, and CloudTrail administrative actions. These are useful in a lab because they relate to identity, permissions, network exposure, credentials, and logging visibility.

### Is this production-ready?

No. I would describe it as a security monitoring lab, not a production SIEM. A production version would need centralized ingestion, alert routing, better parsing coverage, deduplication, tuning, deployment, monitoring, and access controls.

### How would you improve it?

I would add support for reading from S3 with a tightly scoped IAM role, structured JSON output, severity levels, allowlists for expected lab actions, email or ticket notifications, and more tests using real CloudTrail examples from my own lab.

### How does the code avoid risky behavior?

It reads local CloudTrail log files only. It does not scan third-party environments, exploit anything, attempt logins, or make changes in AWS.

### What did you learn?

I practiced reading CloudTrail records, identifying useful AWS security events, writing simple Python detection logic, adding logging and error handling, and documenting a project in a way that is clear during an interview.

## What To Say On A Resume

Cloud Security Monitor: Built a Python-based AWS CloudTrail monitoring lab that parses local CloudTrail logs and flags predefined security events, including failed sign-ins, IAM changes, security-group updates, access-key changes, and CloudTrail administrative actions. Added sample data, tests, documentation, and an AWS architecture diagram.

## What Not To Overstate

Do not describe this as a production SIEM, EDR, MDR, or CrowdStrike-like platform. A better description is:

```text
A CloudTrail parsing and detection lab for reviewing selected AWS security events.
```

