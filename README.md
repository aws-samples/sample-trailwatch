# CloudTrail Security Insights

Self-hosted security analytics tool that downloads AWS CloudTrail logs from S3, indexes them locally, and provides an interactive investigation dashboard with AI-powered natural language querying.

**Single Go binary. No Docker. No external databases. Deploys to EC2 in one command.**

## Quick Start (Amazon Linux 2023)

```bash
# On a fresh EC2 instance (c7g.large or larger recommended — ARM64 Graviton)
git clone https://gitlab.aws.dev/vyakush/cloudtrail-security-insights.git
cd cloudtrail-security-insights
sudo ./deploy.sh
```

Open `http://<ec2-ip>:7070` in your browser.

> ⚠️ **Important Security Notice**: This application has **no built-in authentication**. Access control relies entirely on network restrictions (AWS Security Groups). Deploy only in restricted network environments or behind an authenticating reverse proxy (e.g., ALB with Cognito, nginx with OAuth2 Proxy). Never expose port 7070 to the public internet.

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
- **Ollama (local)** — auto-installs, runs locally without internet egress when configured, no API key needed

> ⚠️ **Data Privacy Notice**: When AI queries are enabled, CloudTrail log metadata (event names, IP addresses, IAM identities, timestamps) is sent to the configured LLM provider for natural language processing. Verify this aligns with your organization's data classification policies before enabling. For workloads where keeping data on the host is preferred, consider **Ollama**, which is designed to run locally without external API calls when configured that way.

## Prerequisites

- **EC2 Instance**: Amazon Linux 2023 (c7g.large+ Graviton recommended; x86 also supported)
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

With streaming indexing, first queryable results appear within ~30 seconds of starting sync, regardless of total dataset size. Data becomes progressively available as extraction proceeds.

### Infrastructure Sizing

**ARM64 (Graviton) instances are recommended** — they deliver the same DuckDB query performance as x86 at ~20% lower cost, with 50% higher memory bandwidth (DDR5). The application auto-detects the host architecture at startup and downloads the correct DuckDB CLI binary automatically — no configuration needed.

| CloudTrail Volume | Accounts | Duration | Recommended Instance | EBS Disk | Notes |
|-------------------|----------|----------|---------------------|----------|-------|
| < 2 GB | 5 | 7 days | c7g.medium (1 vCPU, 2 GB) | 20 GB gp3 | Startup, light usage |
| 2–10 GB | 10 | 14 days | c7g.large (2 vCPU, 4 GB) | 50 GB gp3 | Active development |
| 10–50 GB | 15 | 30 days | c7g.xlarge (4 vCPU, 8 GB) | 150 GB gp3 | Multi-account org |
| 50–150 GB | 20 | 30 days | r7g.xlarge (4 vCPU, 32 GB) | 400 GB gp3 | Enterprise — memory-optimized |
| 150–400 GB | 25 | 30 days | r7g.2xlarge (8 vCPU, 64 GB) | 1 TB gp3 | Enterprise high-volume |

<details>
<summary>x86 alternatives (if Graviton is unavailable in your region)</summary>

| CloudTrail Volume | Recommended Instance | Notes |
|-------------------|---------------------|-------|
| < 2 GB | t3.medium (2 vCPU, 4 GB) | Burstable, cost-effective |
| 2–10 GB | c7a.large (2 vCPU, 4 GB) | AMD EPYC, consistent perf |
| 10–50 GB | c7a.xlarge (4 vCPU, 8 GB) | AMD compute-optimized |
| 50–150 GB | r7a.xlarge (4 vCPU, 32 GB) | AMD memory-optimized |
| 150–400 GB | r7a.2xlarge (8 vCPU, 64 GB) | AMD, large aggregations |

</details>

**Why Graviton for this workload:**
- DuckDB is memory-bandwidth intensive — DDR5 on c7g/r7g provides 50% more bandwidth than DDR4
- DuckDB's official docs confirm ARM64 and AMD64 perform equivalently
- Graviton instances cost ~20% less per hour than comparable x86 instances
- The Go binary cross-compiles cleanly to `linux/arm64` with no CGO dependencies

**Disk formula:** 3x raw CloudTrail size (compressed `.json.gz` + extracted `.json` + DuckDB index).

**Query performance at scale:** DuckDB processes analytical queries efficiently on 100+ GB datasets. Memory-optimized instances (r7g) provide the bandwidth needed for large-scale aggregations. All queries run with `-readonly` mode, enabling concurrent access during active indexing.

### Multi-Architecture Support

The application supports both ARM64 (Graviton) and AMD64 (Intel/AMD) without any code changes. At startup, it detects the host architecture via `runtime.GOARCH` and auto-downloads the matching DuckDB CLI binary from GitHub releases if one isn't already installed.

```bash
# Build for your current platform
make build

# Build binaries for both architectures
make build-all
# → dist/cloudtrail-analyzer-linux-arm64  (Graviton)
# → dist/cloudtrail-analyzer-linux-amd64  (Intel/AMD)
```

## Disclaimer

This project is provided as a sample implementation for educational and security investigation purposes. It is not intended for production use without additional security review.

**By deploying this tool, you acknowledge:**

- **Cost Responsibility** — Deploying this solution may incur AWS charges (EC2 instance, S3 data transfer, Bedrock API calls). You are responsible for all costs associated with your use of AWS services. Review [AWS Pricing](https://aws.amazon.com/pricing/) and monitor usage via AWS Cost Explorer.
- **Shared Responsibility** — Security and compliance of this tool is a [shared responsibility](https://aws.amazon.com/compliance/shared-responsibility-model/) between AWS and you. AWS is responsible for the security *of* the cloud; you are responsible for security *in* the cloud, including:
  - Securing access to the EC2 instance running this tool
  - Protecting CloudTrail log data downloaded to the instance
  - Managing and rotating any credentials configured in the application
  - Restricting network access via Security Groups
  - Complying with your organization's data handling and classification policies
- **No Warranty** — This software is provided "as is" without warranty of any kind. Perform your own security assessment before deploying in any environment with sensitive data.

## Security Considerations

### Data Protection
- CloudTrail logs contain sensitive data (API calls, IP addresses, identities). Treat the `data/` directory as confidential.
- `config.json` may contain AWS credentials. Never commit to version control.
- Both `config.json` and `data/` are listed in `.gitignore`.

### Network Security
- Application binds to `127.0.0.1` (loopback) by default. To expose on a LAN or to a Security Group, set `"host": "0.0.0.0"` in `config.json` or run with `HOST=0.0.0.0`.
- HTTP server applies conservative timeouts (`ReadHeaderTimeout=10s`, `ReadTimeout=30s`, `IdleTimeout=120s`) and caps request bodies at 1 MiB.
- For team access, place behind an ALB with authentication.
- For production, enable HTTPS via reverse proxy (nginx/caddy).

### Authentication
- No built-in authentication. Access control relies on network restrictions (Security Groups, loopback bind).
- For multi-user environments, add a reverse proxy with authentication.

### Credential Handling
- Recommended: Use IMDS v2 (EC2 instance role) -- no credentials on disk.
- Static long-lived keys live in `config.json` if configured. **Session (STS) credentials applied via the Credentials view are designed to be kept in the process environment only and are not written to disk by this build**; they are lost on restart and must be re-applied.
- On startup the app scrubs any session credentials that may have been written to `config.json` by older builds.

> ⚠️ **Warning**: If you choose Static Keys, the secret access key is stored in `config.json` on the local filesystem. Set restricted permissions (`chmod 600`) and exclude this file from version control. Prefer IMDS v2 (EC2 instance role) to avoid storing credentials on disk.

- Never use root account credentials.

### LLM Provider Security
- **Bedrock**: Uses IAM role, no additional credentials.
- **Ollama**: Fully offline, no data leaves instance.
- **Anthropic/OpenAI**: API keys stored in `config.json` -- treat as secrets.
- CloudTrail data is sent to the configured LLM for queries. Verify alignment with data classification policies.

### Natural-Language Query Safety (LLM → SQL)

The Investigate / Dashboard / Lookups / NLQ paths build SQL — sometimes from handcoded scenarios, sometimes from LLM output — and run it via the local DuckDB CLI. Two threats apply:

1. **LLM hallucination.** Bedrock or another model writes incorrect SQL.
2. **Prompt injection in the data.** A CloudTrail event field contains attacker-controlled text. When the LLM is asked to summarize that data, the embedded text can attempt to alter the SQL the model generates (e.g., to read local files via `read_csv_auto('/Users/me/.aws/credentials')`).

**Mitigations in place:**

- **DuckDB `-readonly`** when querying the indexed database — designed to reject INSERT/UPDATE/DELETE/DDL, providing a layer of defense in addition to the guard.
- **`ValidateReadSQL` guard** — SQL strings passed to the read path (`internal/features/nlquery/safesql.go`) are validated before execution. The guard:
  - Strips comments and string literals so banned tokens are not hidden inside `/* ... */` or `'foo bar attach'`.
  - Requires the first keyword to be `SELECT` or `WITH`. Rejects anything else.
  - Rejects banned tokens as whole words: `read_csv*`, `read_parquet`, `read_blob`, `read_text*`, `sniff_csv`, `glob`, `list_files`, `directory_contents`, `attach`, `detach`, `install`, `load`, `pragma`, `copy`, `export`, `import`, `create`, `drop`, `alter`, `truncate`, `insert`, `update`, `delete`, `merge`, `replace`, `call`, `vacuum`, `checkpoint`.
  - Rejects multi-statement queries (`SELECT 1; ATTACH ...`).
  - Allows banned words inside quoted strings (so an event named `DeleteUser` or a search for `'%attach%'` continues to work).
- **Test coverage** — see `internal/features/nlquery/safesql_test.go` for happy-path queries plus 9 bypass-attempt regression tests (case folding, comment-hiding, multiline whitespace, schema-qualified calls, WITH-clause smuggling, etc.).

**Residual risk:**

- `read_json` is **intentionally allowed** because the handcoded scenarios depend on it. An LLM that hallucinates a non-data-dir path passed to `read_json('/tmp/secrets.json')` could read a local JSON file. DuckDB's `-readonly` flag is designed to reject writes in this scenario. For a single-user POC analyzing your own logs this is a documented trade-off; for a multi-user deployment, consider gating the read path behind a path-allowlist or running DuckDB in a sandboxed working directory.
- The guard is a denylist over a string, not a SQL parser. New DuckDB versions may add filesystem functions that are not on the list. Treat the denylist as a maintenance item when upgrading DuckDB.

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


## Deployment Notes
