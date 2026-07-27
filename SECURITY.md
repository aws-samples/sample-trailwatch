# Security Policy

## Reporting a Vulnerability

Do not report suspected security vulnerabilities through a public GitHub issue.
Report them to AWS Security through the
[AWS vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Include the repository name, affected revision, reproduction steps, impact, and
any suggested mitigation.

For ordinary bugs and feature requests that do not expose sensitive information
or create a security impact, use the public issue tracker.

## Deployment Scope

This repository is an AWS Samples application, not a production service. It has
no built-in user authentication and is intended for single-user or tightly
controlled evaluation environments. Keep it bound to loopback and use SSM port
forwarding, or place it behind an authenticating reverse proxy. Never expose its
API directly to the public internet.

CloudTrail data and configured provider keys are sensitive. Prefer an EC2
instance role with IMDSv2, use least-privilege S3 and Bedrock permissions, and
protect the host and its local data directory.
