# CloudTrail Security Insights

Self-hosted security analytics tool that downloads AWS CloudTrail logs from S3, indexes them locally, and provides an interactive investigation dashboard with AI-powered natural language querying.

**Embedded React UI. No Docker or external database service. Deploys to EC2 in one command.**

## Quick Start (Amazon Linux 2023)

```bash
# On a fresh EC2 instance (c7g.large or larger recommended — ARM64 Graviton)
git clone https://github.com/aws-samples/sample-trailwatch.git
cd sample-trailwatch
sudo ./deploy.sh
```

By default, the application binds to `127.0.0.1:7070` on the EC2 host — **opening `http://<ec2-public-ip>:7070` in a browser will not work** without additional setup. This is intentional: the app has no built-in authentication, so the loopback bind is the first line of defence. See [Accessing the UI on EC2](#accessing-the-ui-on-ec2) below for the recommended access patterns.

> ⚠️ **Important Security Notice**: This application has **no built-in authentication**. Access control relies entirely on network restrictions (AWS Security Groups, SSM session permissions, or an authenticating reverse proxy). Do not expose port 7070 to the public internet.

## Accessing the UI on EC2

Pick one of the following based on your environment. Listed in the order we recommend.

### Option 1 — AWS Systems Manager (SSM) port forwarding (recommended)

No SSH key, no inbound Security Group rules, no public IP needed. Access is gated by IAM, and SSM sessions are recorded in CloudTrail by default. This is the recommended option when handing the deployment over to another reviewer or QA team.

**One-time setup on the EC2 instance:**

1. Attach the AWS managed policy `AmazonSSMManagedInstanceCore` to the instance role (most AL2023 AMIs already include the SSM Agent).
2. Allow outbound HTTPS (443) from the instance to AWS service endpoints — present by default on a new VPC.

**One-time setup on the operator's laptop:**

1. Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) and the [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) (`brew install --cask session-manager-plugin` on macOS).
2. Sign in to the target AWS account with credentials that include `ssm:StartSession` and `ssm:DescribeInstanceInformation`.
3. Verify the instance is reachable:
   ```bash
   aws ssm describe-instance-information \
       --filters "Key=InstanceIds,Values=<instance-id>"
   # Look for PingStatus: Online
   ```

**Daily use — open the tunnel:**

```bash
aws ssm start-session \
    --target <instance-id> \
    --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["7070"],"localPortNumber":["7070"]}'
```

Leave the terminal open. Browse to `http://localhost:7070` on the laptop.

**Minimal IAM policy for the operator's role/user:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:StartSession",
        "ssm:DescribeInstanceInformation",
        "ssm:DescribeSessions"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["ssm:TerminateSession"],
      "Resource": "arn:aws:ssm:*:*:session/${aws:username}-*"
    }
  ]
}
```

Scope the `Resource` on `StartSession` to specific instance ARNs in production.

### Option 2 — SSH tunnel

Use this if you have SSH access already configured for the instance.

```bash
ssh -i your-key.pem -L 7070:localhost:7070 ec2-user@<ec2-public-ip>
```

Browse to `http://localhost:7070` on the laptop. Inbound Security Group needs port 22 only, scoped to the operator's IP/32.

### Option 3 — Bind to all interfaces (least preferred)

Reachable directly from the operator's laptop, but the app has no authentication of its own. Only use this when network controls outside the app are sufficient (private subnet, restrictive Security Group sourced to a single IP, or behind an authenticating reverse proxy such as ALB with Cognito or nginx with OAuth2 Proxy).

1. Edit `/opt/cloudtrail-analyzer/config.json`, set `"host": "0.0.0.0"`, and add the exact hostname or IP used in the browser to `"trusted_hosts"` (for example, `"trusted_hosts": ["10.0.1.25"]`).
2. `sudo systemctl restart cloudtrail-analyzer`
3. Add an inbound Security Group rule for port 7070 sourced to a specific IP/32 (never `0.0.0.0/0`).

**Do not deploy this configuration with port 7070 reachable from the public internet.**

### Troubleshooting access

| Symptom | Likely cause | Resolution |
|---|---|---|
| `aws ssm start-session` returns 403 / `UnauthorizedRequest` | Operator credentials expired or missing `ssm:StartSession` | `aws sts get-caller-identity` to confirm; refresh SSO with `aws sso login --profile <name>`. |
| `aws ssm describe-instance-information` returns an empty list | SSM Agent not running, or instance role missing `AmazonSSMManagedInstanceCore` | On the instance: `sudo systemctl status amazon-ssm-agent`; attach the managed policy and `sudo systemctl restart amazon-ssm-agent`. |
| Tunnel opens but browser shows "can't connect to localhost:7070" | App not running, or bound to a different port | On the instance: `sudo systemctl status cloudtrail-analyzer`; `sudo ss -tlnp \| grep 7070`. |
| Browser loads but shows the dev placeholder page ("Use Vite dev server at :5173") | Production binary built without the frontend bundle | Rebuild via `deploy.sh`, which embeds `web/dist/` into the binary. |
| `An error occurred (InvalidClientTokenId)` from any AWS CLI call | Stale or invalid laptop credentials | `aws configure list` to see which profile is active; `aws sso login --profile <name>` to refresh. |

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

SQLite stores sync/session metadata. Its numbered migrations are embedded in the
Go binary and applied transactionally at startup, so a deployed binary does not
need the source `migrations/` directory.

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
- **Ollama (local)** — runs locally, no API key needed. Install Ollama yourself before selecting this provider (https://ollama.com/download). The server does not download or install Ollama automatically.

> ⚠️ **Data Privacy Notice**: When AI queries are enabled, CloudTrail log metadata (event names, IP addresses, IAM identities, timestamps) is sent to the configured LLM provider for natural language processing. Verify this aligns with your organization's data classification policies before enabling. For workloads where keeping data on the host is preferred, consider **Ollama**, which is designed to run locally without external API calls when configured that way.

## Prerequisites

- **EC2 Instance**: Amazon Linux 2023 (c7g.large+ Graviton recommended; x86 also supported)
- **IAM Role**: S3 read access to your CloudTrail bucket (`s3:GetObject`, `s3:ListBucket`)
- **Network access**: SSM port forwarding requires no inbound rule. Direct access requires a narrowly scoped port 7070 rule and matching `trusted_hosts`.
- **Bedrock** (optional): `bedrock:InvokeModel` and `bedrock:ListFoundationModels`

## Development

Install Go 1.26+, Node.js 20+, npm, Make, and the DuckDB CLI first. `make install`
installs project dependencies; it does not install those system tools.

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

# Run tests (Go with -race, plus frontend)
make test

# Check formatting and run go vet (run before pushing)
make lint
```

The production binary embeds both `web/dist/` and the SQLite migrations. It can
therefore run independently of the source checkout once built.

## Configuration

On first run, a `config.json` is created with defaults. Configure through the UI:

1. **Credentials** → Select auth method (IMDS on EC2, or paste session credentials)
2. **S3 Config** → Enter bucket, detect structure, select accounts
3. **S3 Sync** → Pick date range, start download
4. **AI Provider** → Choose LLM backend (optional, dashboard works without it)

All settings are also configurable via environment variables:
- `PORT` (default: 7070)
- `HOST` (default: 127.0.0.1)
- `TRUSTED_HOSTS` (additional allowed Host header values)
- `DATA_DIR` (default: ./data)
- `LOG_LEVEL` (debug/info/warn/error)
- `QUERY_TIMEOUT_SECONDS` (default: 60)
- `MONITOR_INTERVAL_SECONDS` (default: 5)
- `MAX_DOWNLOAD_CONCURRENCY` (default: 16)
- `CTA_ALLOW_AUTO_INSTALL` (default: false)

Configuration writes are atomic and use mode `0600`. The application creates its
data directories with mode `0700` and its SQLite database with mode `0600`.
`deploy.sh` also runs the service as a dedicated `cloudtrail` user with
`UMask=0077`.

## Performance

Logs are auto-indexed into a DuckDB database after sync:

| Dataset | Dashboard Load | Investigation Query |
|---------|---------------|-------------------|
| 1,400 files (5MB) | 63ms | 52ms |
| Before indexing | ~2,000ms | ~1,200ms |

For GB-scale datasets, indexing can provide 50-100x speedup.

With streaming indexing, first queryable results appear within ~30 seconds of starting sync, regardless of total dataset size. Data becomes progressively available as extraction proceeds.

### Infrastructure Sizing

**ARM64 (Graviton) instances are recommended** — they deliver comparable DuckDB query performance to x86 at ~20% lower cost, with higher memory bandwidth (DDR5). The application detects the host architecture at startup (`runtime.GOARCH`) and selects the matching DuckDB CLI binary. `deploy.sh` installs the pinned DuckDB CLI during deployment; server-side download of the binary at runtime is off by default and is gated behind an explicit opt-in flag (`allow_auto_install`).

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

**Query performance at scale:** DuckDB processes analytical queries efficiently on 100+ GB datasets. Memory-optimized instances (r7g) provide the bandwidth needed for large-scale aggregations. Queries against the indexed store run with the DuckDB `-readonly` flag, which is designed to reject writes (INSERT/UPDATE/DELETE/DDL).

> **Indexing in progress:** DuckDB takes a process-level write lock while the index is being built or a micro-batch is being written. A read query issued during that window can fail with a lock error and is retried; if it does not succeed, the UI surfaces an "indexing in progress" message. Wait for the current index/micro-batch write to finish and retry. The `-readonly` flag does not bypass this lock — it limits the read connection to read-only operations.

### Multi-Architecture Support

The application supports both ARM64 (Graviton) and AMD64 (Intel/AMD) without any code changes. At startup, it detects the host architecture via `runtime.GOARCH` and selects the matching DuckDB CLI binary. `deploy.sh` installs the pinned DuckDB CLI during deployment. Server-side download of the binary at runtime is off by default and is gated behind an explicit opt-in flag (`allow_auto_install`); when disabled, the application expects the DuckDB CLI to already be present on the host.

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
- Recommended: Use IMDS v2 (EC2 instance role) -- no credentials on disk. The
  application uses a token-required IMDS v2 provider, and the deployed systemd
  service disables SDK fallback to IMDS v1.
- Static long-lived keys live in `config.json` if configured. **Session (STS) credentials applied via the Credentials view are designed to be kept in the process environment only and are not written to disk by this build**; they are lost on restart and must be re-applied.
- On startup the app scrubs any session credentials that may have been written to `config.json` by older builds.

> ⚠️ **Warning**: If you choose Static Keys, the secret access key is stored in `config.json` on the local filesystem. Set restricted permissions (`chmod 600`) and exclude this file from version control. Prefer IMDS v2 (EC2 instance role) to avoid storing credentials on disk.

- Never use root account credentials.

### LLM Provider Security
- **Bedrock**: Uses IAM role, no additional credentials.
- **Ollama**: Runs locally on the instance. Custom Ollama endpoints are limited
  to `localhost` or loopback IP addresses. When configured this way, query data
  is processed on the host and is designed to avoid an external API call for
  inference. Verify your Ollama configuration and any model-download/telemetry
  settings against your data-handling policy.
- **Anthropic/OpenAI**: API keys stored in `config.json` -- treat as secrets.
  Custom endpoints must use HTTPS; redirects are rejected.
- CloudTrail data is sent to the configured LLM for queries. Verify alignment with data classification policies.

#### Binary auto-install (supply-chain trade-off)

The application can optionally auto-install the DuckDB CLI on the host. To reduce supply-chain exposure, this is **off by default** and is gated behind an explicit opt-in flag (`allow_auto_install`, default `false`). When enabled, the DuckDB download is verified against pinned SHA-256 checksums before extraction (fail-closed).

- **Recommended:** install the DuckDB CLI and Ollama on the host yourself (or let `deploy.sh` install the pinned, checksum-verified DuckDB CLI and Node.js archives). Leave `allow_auto_install` disabled. The application fails with clear guidance if a required binary is missing.
- **Ollama:** The server never downloads or installs Ollama automatically. If Ollama is not found on PATH, the application returns instructions for manual installation.
- **deploy.sh:** Installs Go, Node.js, and DuckDB from pinned binary archives with SHA-256 verification. No third-party setup scripts are downloaded or executed.

### Natural-Language Query Safety (LLM → SQL)

The Investigate / Dashboard / Lookups / NLQ paths build SQL — sometimes from handcoded scenarios, sometimes from LLM output — and run it via the local DuckDB CLI. Two threats apply:

1. **LLM hallucination.** Bedrock or another model writes incorrect SQL.
2. **Prompt injection in the data.** A CloudTrail event field contains attacker-controlled text. When the LLM is asked to summarize that data, the embedded text can attempt to alter the SQL the model generates (e.g., to read local files via `read_csv_auto('/Users/me/.aws/credentials')`).

**Mitigations in place:**

- **DuckDB `-readonly`** when querying the indexed database — designed to reject INSERT/UPDATE/DELETE/DDL, providing a layer of defense in addition to the guard.
- **External access disabled** on indexed DuckDB query processes, blocking
  filesystem and network readers at execution time.
- **SQL validation** — SQL strings passed to the read path
  (`internal/features/nlquery/safesql.go`) are validated before execution:
  - Strips comments and string literals so banned tokens are not hidden inside `/* ... */` or `'foo bar attach'`.
  - Requires the first keyword to be `SELECT` or `WITH`. Rejects anything else.
  - Rejects banned tokens as whole words: `read_csv*`, `read_parquet`, `read_blob`, `read_text*`, `sniff_csv`, `glob`, `list_files`, `directory_contents`, `attach`, `detach`, `install`, `load`, `pragma`, `copy`, `export`, `import`, `create`, `drop`, `alter`, `truncate`, `insert`, `update`, `delete`, `merge`, `replace`, `call`, `vacuum`, `checkpoint`.
  - Rejects multi-statement queries (`SELECT 1; ATTACH ...`).
  - Allows banned words inside quoted strings (so an event named `DeleteUser` or a search for `'%attach%'` continues to work).
  - Applies a stricter policy to model-generated SQL: it must query the
    account-scoped temporary `cloudtrail_events` view, cannot reference the
    unscoped `events` table, and cannot call `read_json` or another external
    reader.
- **Test coverage** — see `internal/features/nlquery/safesql_test.go` for happy-path queries plus 9 bypass-attempt regression tests (case folding, comment-hiding, multiline whitespace, schema-qualified calls, WITH-clause smuggling, etc.).

**Residual risk:**

- Hand-authored dashboard and investigation queries still use `read_json` before
  an index is available. Their paths are assembled from validated configuration
  fields and escaped by the application; model-generated SQL never receives
  this capability.
- The guard is a purpose-built lexer and policy layer, not a full DuckDB SQL
  parser. Treat its regression tests as a required check when upgrading DuckDB
  or changing query construction.

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
# Remove an installation created by deploy.sh while retaining the EC2 instance
sudo systemctl disable --now cloudtrail-analyzer
sudo rm -f /etc/systemd/system/cloudtrail-analyzer.service
sudo systemctl daemon-reload
sudo rm -rf /opt/cloudtrail-analyzer
sudo rm -rf /var/lib/cloudtrail-analyzer
sudo userdel cloudtrail 2>/dev/null || true

# If deployed on EC2 — terminate the instance via AWS Console or CLI:
aws ec2 terminate-instances --instance-ids <instance-id>
```

> **Note:** Terminating the EC2 instance removes all local data. If you configured additional AWS resources (Security Groups, IAM roles), remove those separately via the AWS Console or CLI.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.


## Deployment Notes

### Default network posture

- The Go server binds to `127.0.0.1:7070` by default. Connections from the LAN or public internet are dropped by the kernel before the application sees them. Override via `host` in `config.json` if you understand the trade-off (see [Option 3](#option-3--bind-to-all-interfaces-least-preferred) above).
- Outbound HTTPS (443) is required to reach S3, Bedrock, STS, AWS Organizations, and the AWS systems used by SSM. A new VPC default Security Group provides this; locked-down environments may need explicit egress rules to `*.amazonaws.com`.

### Recommended access pattern for handovers

When a different reviewer / QA engineer / customer needs to drive the UI:

1. Grant them an IAM role/user with the SSM policy in [Option 1](#option-1--aws-systems-manager-ssm-port-forwarding-recommended).
2. Share the EC2 instance ID. They open the tunnel locally — no key exchange, no bastion host, no inbound Security Group changes.
3. Revoke their IAM access when the engagement ends. The application stays untouched.

SSM sessions are typically recorded as `ssm:StartSession` events in CloudTrail with the operator's identity and the target instance ID, subject to your account's CloudTrail configuration.

### Updating an existing deployment

```bash
# Pull the latest code on the instance, then re-run deploy.sh — it is idempotent.
cd ~/<source-checkout>
git pull
sudo ./deploy.sh

# Or, if you only changed Go code or the frontend bundle, a faster path.
# Remove the previous embed copy first — copying over an existing dist/
# would nest the assets at cmd/analyzer/dist/dist/. This matches the
# embed-assets step in the Makefile (rm -rf, then cp -r, then touch .gitkeep).
cd /opt/cloudtrail-analyzer
sudo rm -rf cmd/analyzer/dist
sudo cp -r web/dist cmd/analyzer/dist
sudo touch cmd/analyzer/dist/.gitkeep
sudo /usr/local/go/bin/go build -o cloudtrail-analyzer ./cmd/analyzer
sudo systemctl restart cloudtrail-analyzer
```
