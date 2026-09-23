# Detection Matrix

Safe interview claim:

> I built a Python CloudTrail log analyzer that scans local AWS lab logs and flags predefined identity, access, network, and logging events for review.

| Detection | Source | Current proof | Interview wording |
| --- | --- | --- | --- |
| Failed login/API auth failures | CloudTrail `ConsoleLogin` or AWS error codes | Unit test plus sample JSON | Flags failed sign-ins and denied API calls for review. |
| IAM user creation | `iam.amazonaws.com` `CreateUser` | Sample JSON and rule code | Flags new IAM users because identity changes should be reviewed. |
| IAM permission changes | IAM policy/group/user/role events | Unit test plus sample JSON | Flags permission changes that could expand access. |
| Security group changes | EC2 security-group events | Sample JSON and rule code | Flags network exposure changes. |
| Access key changes | IAM access-key events | Sample JSON and rule code | Flags credential creation, deletion, or updates. |
| CloudTrail admin actions | CloudTrail create/update/start/stop/delete events | Sample JSON and rule code | Flags changes to audit logging itself. |

## What not to claim yet

- This is not a SIEM.
- This is not real-time monitoring.
- This is not automated remediation.
- This is not deployed with AWS Lambda/EventBridge yet.

## Simple next upgrade

Add a Lambda/EventBridge version that reads CloudTrail events from an owned AWS lab and sends findings to SNS or email.
