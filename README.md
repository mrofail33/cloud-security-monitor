# Cloud Security Monitor

A deliberately simple, interview-friendly AWS CloudTrail monitoring project.

This project reads CloudTrail JSON logs from your own AWS lab environment and flags predefined security-related events for review. It is not a production SIEM and does not automate attacks, exploitation, or access to third-party environments.

## What It Monitors

The monitor reviews CloudTrail records and flags:

| Detection | What it means |
| --- | --- |
| Failed authentication-related events | A console sign-in failed, or an AWS API call returned an authentication or authorization error such as `AccessDenied`. |
| IAM user creation | A new IAM user was created with `CreateUser`. |
| IAM permission or policy changes | IAM policies, user policies, role policies, group policies, or policy versions were changed. |
| Security-group changes | A security group or security-group rule was created, deleted, authorized, revoked, or updated. |
| Access-key creation/deletion/update | An IAM access key was created, deleted, or updated. |
| CloudTrail administrative actions | CloudTrail logging or trail configuration was changed with actions such as `StopLogging`, `StartLogging`, `CreateTrail`, `UpdateTrail`, or `DeleteTrail`. |

## Folder Structure

```text
cloud-security-monitor/
  cloud_security_monitor/
    detections.py          Detection rules and helper functions
    monitor.py             Command-line scanner
  docs/
    aws-architecture-diagram.md
    aws-architecture-diagram.mmd
  examples/
    sample_output.txt
  samples/
    cloudtrail_sample.json Safe local sample dataset
  screenshots/
    README.md              Screenshot checklist for your own lab
  tests/
    test_detections.py
  INTERVIEW_GUIDE.md
  README.md
  requirements.txt
```

## Setup

Use Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

There are no required runtime dependencies.

## Run With Safe Sample Data

```bash
python -m cloud_security_monitor.monitor --input samples/cloudtrail_sample.json
```

Expected output:

```text
| Time     | Event                   | User      | Flag   |
| -------- | ----------------------- | --------- | ------ |
| 10:42:00 | Login or API failure    | test-user | Review |
| 11:03:00 | IAM permission changed  | admin     | Review |
| 11:30:00 | Security group changed  | admin     | Review |
| 11:45:00 | IAM user created        | admin     | Review |
| 12:05:00 | Access key changed      | admin     | Review |
| 12:15:00 | CloudTrail admin action | admin     | Review |
```

Optional CSV output:

```bash
python -m cloud_security_monitor.monitor --input samples/cloudtrail_sample.json --csv findings.csv
```

## Run Against Your Own AWS Lab Logs

Use this only with an AWS account or lab environment you own or are authorized to use.

One simple workflow:

1. Enable CloudTrail in your AWS lab account.
2. Configure CloudTrail to write logs to an S3 bucket you control.
3. Download CloudTrail JSON or `.json.gz` files from your own bucket.
4. Place them in a local folder, for example `lab-logs/`.
5. Run:

```bash
python -m cloud_security_monitor.monitor --input lab-logs/
```

The monitor supports a single `.json` file, a single `.json.gz` file, or a directory containing multiple CloudTrail log files.

## Tests

The tests use Python's built-in test runner:

```bash
python -m unittest discover -s tests
```

## Architecture

See [docs/aws-architecture-diagram.md](docs/aws-architecture-diagram.md).

Summary:

```text
AWS lab account -> CloudTrail -> S3 logs -> Local JSON export -> Python monitor -> Review table
```

## Screenshot Guidance

See [screenshots/README.md](screenshots/README.md).

Only capture screenshots from your controlled AWS lab. Redact account IDs, access keys, private details, and anything sensitive before publishing the project.

## Resume-Friendly Description

Built a Python CloudTrail monitoring lab that parses AWS activity logs and flags predefined security events such as failed sign-ins, IAM changes, security-group updates, access-key changes, and CloudTrail administrative actions. Included safe sample data, tests, documentation, and a simple architecture diagram.

## Limitations

This project is intentionally simple. It does not perform real-time alerting, anomaly detection, threat intelligence matching, automated remediation, or production-scale log ingestion. It is best described as a CloudTrail parsing and detection lab.

## Interview Proof

The repo includes:

- safe sample CloudTrail data in `samples/`
- unit tests in `tests/`
- CI in `.github/workflows/ci.yml`
- a detection matrix in `docs/detection-matrix.md`
- an AWS lab deployment plan in `docs/aws-lab-runbook.md`
- a claim-boundary guide in `docs/security-portfolio-boundary.md`

Safe resume wording:

> Built a Python CloudTrail monitoring lab that scans local AWS activity logs and flags failed authentication, IAM changes, security-group updates, access-key changes, and CloudTrail administrative actions.

## Optional SNS notification

The local flow is:

```text
CloudTrail JSON -> Python detection -> optional SNS notification
```

After configuring AWS credentials and an SNS topic, send one summary notification:

```bash
python -m cloud_security_monitor.monitor --input samples/cloudtrail_sample.json --sns-topic-arn arn:aws:sns:us-east-1:123456789012:security-findings --aws-region us-east-1
```

SNS is optional so the project still runs locally without an AWS account.
