# AWS Architecture Diagram

This is the simple lab architecture for the project.

```mermaid
flowchart LR
    A[Lab AWS Account] --> B[IAM Users and Roles]
    A --> C[Security Groups]
    A --> D[CloudTrail]
    B --> D
    C --> D
    D --> E[S3 CloudTrail Logs]
    E --> F[Local Exported JSON Files]
    F --> G[Python Cloud Security Monitor]
    G --> H[Review Table and Optional CSV]
```

Plain-English explanation:

CloudTrail records activity in the lab AWS account. The logs can be exported or downloaded as JSON files. The Python monitor reads those local files and flags predefined events for review, such as IAM changes, failed sign-ins, access-key changes, security-group updates, and CloudTrail administrative actions.

