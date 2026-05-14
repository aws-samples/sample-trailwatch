# CloudTrail Security Insights

Self-hosted security analytics tool that downloads AWS CloudTrail logs from S3, indexes them locally, and provides an interactive investigation dashboard with AI-powered natural language querying.

**Single Go binary. No Docker. No external databases. Deploys to EC2 in one command.**

## Quick Start (Amazon Linux 2023)

```bash
# On a fresh EC2 instance (t3.medium+ recommended)
git clone https://gitlab.aws.dev/vyakush/cloudtrail-security-insights.git
cd cloudtrail-security-insights
sudo ./deploy.sh
```

Open `http://<ec2-ip>:7070` in your browser.

## What It Does

1. **Downloads** CloudTrail logs from your S3 bucket (single account or Control Tower org trail)
2. **Indexes** logs into a fast DuckDB database for sub-second queries
3. **Provides** 40+ pre-built investigation scenarios aligned with GuardDuty finding types
4. **Supports** cross-account correlation when multiple accounts are synced
5. **Enables** AI-powered natural language queries via Bedrock, Anthropic API, OpenAI, or local Ollama

## Architecture

```
Browser (:7070)  →  Go API Server  →  DuckDB (indexed)  →  Local CloudTrail JSON
                          ↓
                    LLM Provider (optional)
                    ├── AWS Bedrock
                    ├── Anthropic API
                    ├── OpenAI / Compatible
                    └── Ollama (local, offline)
```

*Figure 1: Application architecture — browser connects to the Go API, which queries indexed CloudTrail data via DuckDB and optionally routes natural language queries to an LLM provider.*

## Features

### Security Dashboard
- Summary metrics: total events, identities, IPs, error rate
- 18 live security findings with severity scoring (Critical/High/Medium/Low)
- Click any finding to expand inline detail with evidence table
- Hourly activity charts, identity type distribution

### Investigation Scenarios (40+)
Based on [AWS GuardDuty finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html):

| Category | Examples |
|----------|----------|
| Credential Access | Credential harvesting, access key persistence |
| Defense Evasion | Logging disabled, GuardDuty disabled, password policy weakened |
| Exfiltration | Snapshot staging, S3 replication |
| Impact | Destructive actions, S3 made public |
| Privilege Escalation | IAM policy changes, suspicious role assumptions |
| Unauthorized Access | Instance credential exfil, console multi-geo login |
| Cross-Account | Lateral movement, cross-account role assumptions |
| PenTest Detection | Kali/Parrot/Pentoo/Pacu/ScoutSuite user agents |

Interactive dropdowns auto-populated from your data (access keys, IPs, roles, accounts).

### Multi-Account Support
- Control Tower org trail: select all or specific member accounts
- Cross-account correlation: detect lateral movement between accounts
- One sync session downloads all selected accounts

### AI-Powered Queries
Configure your preferred LLM provider in Settings → AI Provider:
- **AWS Bedrock** (default) — uses existing AWS credentials
- **Anthropic API** — direct API key
- **OpenAI / Compatible** — supports Azure OpenAI, corporate proxies
- **Ollama (local)** — auto-installs, fully offline, no API key needed

## Prerequisites

- **EC2 Instance**: Amazon Linux 2023 (t3.medium+ recommended)
- **IAM Role**: S3 read access to your CloudTrail bucket (`s3:GetObject`, `s3:ListBucket`)
- **Security Group**: Allow inbound on port 7070 from your IP
- **Bedrock** (optional): `bedrock:InvokeModel` permission for AI queries

## Development

```bash
# Install dependencies
make install

# Run locally (two processes: Go API + Vite frontend with hot reload)
make dev
# → API: http://localhost:7070
# → UI:  http://localhost:5173

# Build production binary (embeds frontend)
make build
# → ./dist/cloudtrail-analyzer

# Run tests
make test
```

## Configuration

On first run, a `config.json` is created with defaults. Configure through the UI:

1. **Credentials** → Select auth method (IMDS on EC2, or paste session credentials)
2. **S3 Config** → Enter bucket, detect structure, select accounts
3. **S3 Sync** → Pick date range, start download
4. **AI Provider** → Choose LLM backend (optional, dashboard works without it)

All settings are also configurable via environment variables:
- `PORT` (default: 7070)
- `DATA_DIR` (default: ./data)
- `LOG_LEVEL` (debug/info/warn/error)
- `MAX_DOWNLOAD_CONCURRENCY` (default: 4)

## Performance

Logs are auto-indexed into a DuckDB database after sync:

| Dataset | Dashboard Load | Investigation Query |
|---------|---------------|-------------------|
| 1,400 files (5MB) | 63ms | 52ms |
| Before indexing | ~2,000ms | ~1,200ms |

For GB-scale datasets, indexing can provide 50-100x speedup.

## Disclaimer

This project is provided as a sample implementation for educational and security investigation purposes. It is not intended for production use without additional security review. Users are responsible for:

- Securing access to the EC2 instance running this tool
- Protecting CloudTrail log data downloaded to the instance
- Managing and rotating any credentials configured in the application
- Complying with their organization's data handling policies

Use at your own risk. Perform your own security assessment before deploying in any environment with sensitive data.

## Security Considerations

### Data Protection
- CloudTrail logs contain sensitive data (API calls, IP addresses, identities). Treat the `data/` directory as confidential.
- `config.json` may contain AWS credentials. Never commit to version control.
- Both `config.json` and `data/` are listed in `.gitignore`.

### Network Security
- Application listens on `0.0.0.0` by default. Restrict via Security Groups to your IP only.
- For team access, place behind an ALB with authentication.
- For production, enable HTTPS via reverse proxy (nginx/caddy).

### Authentication
- No built-in authentication. Access control relies on network restrictions (Security Groups).
- For multi-user environments, add a reverse proxy with authentication.

### Credential Handling
- Recommended: Use IMDS v2 (EC2 instance role) -- no credentials on disk.
- Session credentials expire in 1-12 hours, stored in `config.json`.
- Never use root account credentials.

### LLM Provider Security
- **Bedrock**: Uses IAM role, no additional credentials.
- **Ollama**: Fully offline, no data leaves instance.
- **Anthropic/OpenAI**: API keys stored in `config.json` -- treat as secrets.
- CloudTrail data is sent to the configured LLM for queries. Verify alignment with data classification policies.

### Deployment
- Deploy on private subnets or with restricted Security Groups.
- `deploy.sh` requires sudo -- review before executing.
- Regularly update application and OS packages.

## Auth Methods

| Method | When to Use |
|--------|-------------|
| IMDS v2 | EC2 instance with IAM role attached (recommended) |
| Session Credentials | Temporary creds from SSO portal |
| SSO Profile | Named AWS CLI SSO profile |
| Static Keys | Long-lived IAM user keys (not recommended) |

## Cleanup

To remove all resources deployed by this tool:

```bash
# Stop the application
sudo systemctl stop cloudtrail-analyzer   # if deployed as a service
# or kill the process directly
pkill -f cloudtrail-analyzer

# Remove downloaded CloudTrail data and databases
rm -rf data/

# Remove the application binary and config
rm -f analyzer config.json

# If deployed on EC2 — terminate the instance via AWS Console or CLI:
aws ec2 terminate-instances --instance-ids <instance-id>
```

> **Note:** Terminating the EC2 instance removes all local data. If you configured additional AWS resources (Security Groups, IAM roles), remove those separately via the AWS Console or CLI.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
