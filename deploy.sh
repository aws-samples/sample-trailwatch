#!/usr/bin/env bash
# deploy.sh — Single-script deployment for CloudTrail Analyzer on Amazon Linux 2023
#
# Usage:
#   chmod +x deploy.sh && sudo ./deploy.sh
#
# This script is idempotent — safe to run multiple times.
# It installs all build-time and runtime dependencies, builds the production
# binary with embedded frontend, and sets up a systemd service.
#
# Dependencies installed:
#   - Go 1.26+          (build time, stays for future rebuilds)
#   - Node.js 20+       (build time only, used for frontend)
#   - DuckDB CLI        (runtime, for query execution)
#   - Ollama            (optional; install separately for the local LLM provider)

set -euo pipefail
umask 077

# Capture the checkout before installer functions change directory.
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Pin the installer for reproducible EC2 builds. go.mod declares the supported
# language/toolchain minimum (Go 1.26) without forcing every developer to fetch
# this exact patch release.
GO_VERSION="1.26.4"
NODE_MAJOR=20
DUCKDB_VERSION="1.2.2"

# The script installs/checks Go itself; prohibit go from downloading another
# toolchain implicitly during the build.
export GOTOOLCHAIN="local"

APP_NAME="cloudtrail-analyzer"
APP_USER="cloudtrail"
APP_DIR="/opt/cloudtrail-analyzer"
DATA_DIR="/var/lib/cloudtrail-analyzer/data"
CONFIG_FILE="${APP_DIR}/config.json"
SERVICE_NAME="cloudtrail-analyzer"
PORT=7070

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { echo -e "\n\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m    $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
fail()  { echo -e "\033[1;31m[FAIL]\033[0m  $*"; exit 1; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "This script must be run as root (use sudo)."
    fi
}

# ---------------------------------------------------------------------------
# Step 0: Preflight
# ---------------------------------------------------------------------------
require_root

DEPLOY_TMP_DIR="$(mktemp -d /tmp/cloudtrail-analyzer-deploy.XXXXXX)"
chmod 700 "${DEPLOY_TMP_DIR}"
cleanup() {
    rm -rf "${DEPLOY_TMP_DIR}"
}
trap cleanup EXIT

info "Starting CloudTrail Analyzer deployment on Amazon Linux 2023"
info "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  GOARCH="amd64"; DUCKDB_ARCH="amd64";;
    aarch64) GOARCH="arm64";  DUCKDB_ARCH="aarch64";;
    *)       fail "Unsupported architecture: $ARCH";;
esac
info "Detected architecture: $ARCH (Go: linux/$GOARCH)"

# ---------------------------------------------------------------------------
# Step 1: System packages
# ---------------------------------------------------------------------------
info "Updating system packages..."
# AL2023 ships curl-minimal which already provides /usr/bin/curl. Asking for
# 'curl' here without --allowerasing causes a hard conflict and silent exit
# under set -e. Use --allowerasing so dnf swaps curl-minimal for curl when
# needed; on systems without the conflict it is a no-op.
# Stderr is intentionally NOT redirected so failures surface during deploy.
dnf update -y || fail "dnf update failed; check network/repos"
dnf install -y --allowerasing git gcc gcc-c++ make unzip tar gzip wget curl rsync \
    || fail "dnf install failed; check the error above"
ok "System packages up to date"

# ---------------------------------------------------------------------------
# Step 2: Install Go
# ---------------------------------------------------------------------------
# verify_sha256 <file> <expected-sha256>
# Compares the SHA-256 of <file> against <expected-sha256> and aborts on
# mismatch. Used to fail closed on a tampered or truncated download.
verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual
    actual="$(sha256sum "${file}" | awk '{print $1}')"
    if [[ "${actual}" != "${expected}" ]]; then
        fail "Checksum mismatch for ${file}: expected ${expected}, got ${actual}. Aborting (possible tampering or corrupt download)."
    fi
}

install_go() {
    local go_filename="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    local go_tarball="${DEPLOY_TMP_DIR}/${go_filename}"
    local go_checksum="${go_tarball}.sha256"
    local go_url="https://go.dev/dl/${go_filename}"

    info "Downloading Go ${GO_VERSION}..."
    wget -q "${go_url}" -O "${go_tarball}"

    # Supply-chain hardening: verify the tarball against the SHA-256 that Go
    # publishes alongside every release (<tarball>.sha256). Downloading the
    # published checksum is preferred over hardcoding so this keeps working
    # across GO_VERSION bumps. Fail closed on mismatch.
    info "Verifying Go tarball checksum..."
    wget -q "${go_url}.sha256" -O "${go_checksum}" \
        || fail "Could not download Go checksum file ${go_url}.sha256"
    local go_expected
    go_expected="$(awk '{print $1}' "${go_checksum}")"
    if [[ -z "${go_expected}" ]]; then
        fail "Go checksum file ${go_checksum} was empty or malformed"
    fi
    verify_sha256 "${go_tarball}" "${go_expected}"
    ok "Go tarball checksum verified"

    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${go_tarball}"
}

# Add Go to PATH for this script
export PATH="/usr/local/go/bin:${PATH}"
export GOPATH="/root/go"
export PATH="${GOPATH}/bin:${PATH}"

if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | grep -oP '\d+\.\d+' | head -1)
    REQUIRED_GO="1.26"
    if printf '%s\n%s' "$REQUIRED_GO" "$CURRENT_GO" | sort -V | head -1 | grep -q "$REQUIRED_GO"; then
        ok "Go already installed: $(go version)"
    else
        warn "Go version too old ($CURRENT_GO < $REQUIRED_GO), upgrading..."
        install_go
    fi
else
    install_go
fi
ok "Go ready: $(go version)"

# ---------------------------------------------------------------------------
# Step 3: Install Node.js (build-time only)
# ---------------------------------------------------------------------------
# Install Node.js from the official pinned binary archive with SHA-256
# verification. No third-party setup scripts are downloaded or executed.
NODE_VERSION="20.18.1"
declare -A NODE_SHA256=(
    [amd64]="a9420224cb562e1a4bda2067925e3745e8a22fd59f168e3ad2c6a10e16e4a2f2"
    [arm64]="8b476ef14ba70a4eb2e5d9c5e618fcda1e2d0e03e86ddf9dd1c88f48c17c2e6c"
)

install_node_pinned() {
    local node_arch
    case "${GOARCH}" in
        amd64) node_arch="x64" ;;
        arm64) node_arch="arm64" ;;
        *)     fail "Unsupported architecture for Node.js: ${GOARCH}" ;;
    esac

    local node_filename="node-v${NODE_VERSION}-linux-${node_arch}.tar.xz"
    local node_tarball="${DEPLOY_TMP_DIR}/${node_filename}"
    local node_url="https://nodejs.org/dist/v${NODE_VERSION}/${node_filename}"

    # Get the expected checksum for this architecture
    local node_expected="${NODE_SHA256[${GOARCH}]:-}"
    if [[ -z "${node_expected}" ]]; then
        fail "No pinned SHA-256 for Node.js ${NODE_VERSION} arch ${GOARCH}. Update NODE_SHA256 in this script."
    fi

    info "Downloading Node.js ${NODE_VERSION} for ${node_arch}..."
    wget -q "${node_url}" -O "${node_tarball}"

    info "Verifying Node.js tarball checksum..."
    verify_sha256 "${node_tarball}" "${node_expected}"
    ok "Node.js tarball checksum verified"

    # Extract to /usr/local and symlink binaries
    tar -xJf "${node_tarball}" -C /usr/local --strip-components=1
}

if command -v node &>/dev/null; then
    NODE_VER=$(node --version | grep -oP '\d+' | head -1)
    if [[ "$NODE_VER" -ge "$NODE_MAJOR" ]]; then
        ok "Node.js already installed: $(node --version)"
    else
        warn "Node.js too old (v${NODE_VER} < v${NODE_MAJOR}), upgrading..."
        install_node_pinned
    fi
else
    info "Installing Node.js ${NODE_VERSION}..."
    # AL2023 has Node 18+ in default repos; try dnf first.
    if ! dnf install -y nodejs npm 2>/dev/null; then
        install_node_pinned
    fi
fi
ok "Node.js ready: $(node --version)"

# ---------------------------------------------------------------------------
# Step 4: Install DuckDB CLI
# ---------------------------------------------------------------------------
# Pinned SHA-256 checksums for the DuckDB CLI zip, keyed by DUCKDB_ARCH.
# DuckDB does not publish per-asset checksum files alongside its GitHub
# releases, so these are hardcoded for the pinned DUCKDB_VERSION above.
# MAINTAINER: when bumping DUCKDB_VERSION you MUST update both values. Compute
# them from the release page with:
#   curl -sSL <release-url>/duckdb_cli-linux-<arch>.zip | sha256sum
# Values below are for DuckDB v1.2.2.
declare -A DUCKDB_SHA256=(
    [amd64]="fc153822f59283e0a9374168cce5bc85a9985e699d9857842597882062fd2cb5"
    [aarch64]="04b394d4e2fa90fc135b3417a3fbadbb765de7cec01a80f179bf854f8ac702a3"
)

install_duckdb() {
    info "Installing DuckDB ${DUCKDB_VERSION} for ${DUCKDB_ARCH}..."
    local duckdb_filename="duckdb_cli-linux-${DUCKDB_ARCH}.zip"
    local duckdb_zip="${DEPLOY_TMP_DIR}/${duckdb_filename}"
    local duckdb_extract="${DEPLOY_TMP_DIR}/duckdb-extract"
    local duckdb_url="https://github.com/duckdb/duckdb/releases/download/v${DUCKDB_VERSION}/${duckdb_filename}"

    # Supply-chain hardening: fail closed if we do not have a pinned checksum
    # for this arch/version pair, then verify the download before extracting.
    local duckdb_expected="${DUCKDB_SHA256[${DUCKDB_ARCH}]:-}"
    if [[ -z "${duckdb_expected}" ]]; then
        fail "No pinned SHA-256 for DuckDB ${DUCKDB_VERSION} arch ${DUCKDB_ARCH}. Update DUCKDB_SHA256 in this script."
    fi

    wget -q "${duckdb_url}" -O "${duckdb_zip}"
    info "Verifying DuckDB zip checksum..."
    verify_sha256 "${duckdb_zip}" "${duckdb_expected}"
    ok "DuckDB zip checksum verified"

    mkdir -m 700 "${duckdb_extract}"
    unzip -q "${duckdb_zip}" -d "${duckdb_extract}"
    install -m 0755 "${duckdb_extract}/duckdb" /usr/local/bin/duckdb
}

if command -v duckdb &>/dev/null; then
    ok "DuckDB already installed: $(duckdb --version 2>/dev/null || echo 'unknown version')"
else
    install_duckdb
fi
ok "DuckDB ready: $(duckdb --version 2>/dev/null || echo 'installed')"

# ---------------------------------------------------------------------------
# Step 5: Create application user and directories
# ---------------------------------------------------------------------------
info "Setting up application user and directories..."

if ! id -u "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /sbin/nologin "$APP_USER"
    ok "Created system user: $APP_USER"
else
    ok "User $APP_USER already exists"
fi

mkdir -p "$APP_DIR" "$DATA_DIR"
chmod 700 "$DATA_DIR"
ok "Directories created: $APP_DIR, $DATA_DIR"

# ---------------------------------------------------------------------------
# Step 6: Copy source code to app directory
# ---------------------------------------------------------------------------
info "Copying source code to ${APP_DIR}..."

# Verify the source tree is complete BEFORE rsync. A surprisingly common
# breakage when teams ship the project as a zip is missing top-level
# directories (the zip archive truncates large folders, or a re-packed
# archive omits a path). Fail loudly with the missing path rather than
# letting the next "cd ${APP_DIR}/web" fail with a cryptic message.
for required in cmd internal web web/package.json go.mod; do
    if [[ ! -e "${SCRIPT_DIR}/${required}" ]]; then
        fail "Source tree is incomplete: missing ${SCRIPT_DIR}/${required}. Re-extract the project zip or re-clone the repo."
    fi
done

# Copy project files (excluding node_modules, build artifacts, data).
# SECURITY: exclude the operator's local secrets and history from the
# production deploy dir. Without these, config.json (which may hold AWS
# credentials), .env, .aws, local databases, and the full .git history would
# all propagate to ${APP_DIR}. Step 9 writes a clean default config.json
# afterwards if one is absent.
rsync -a --delete \
    --exclude='node_modules' \
    --exclude='/dist' \
    --exclude='/data' \
    --exclude='.DS_Store' \
    --exclude='/analyzer' \
    --exclude='/cloudtrail-analyzer' \
    --exclude='config.json' \
    --exclude='.env' \
    --exclude='.env.*' \
    --exclude='.git' \
    --exclude='.aws' \
    --exclude='credentials' \
    --exclude='*.db' \
    --exclude='*.duckdb' \
    "${SCRIPT_DIR}/" "${APP_DIR}/"
ok "Source code copied (local secrets and .git history excluded)"

# Belt-and-braces: confirm the destination has what Step 7+8 need.
# Catches the previous buggy excludes that skipped cmd/analyzer/ because
# 'analyzer' without a leading slash matches anywhere in the path.
if [[ ! -d "${APP_DIR}/web" || ! -f "${APP_DIR}/web/package.json" ]]; then
    fail "Copy completed but ${APP_DIR}/web is missing. Check rsync excludes and source tree."
fi
if [[ ! -f "${APP_DIR}/cmd/analyzer/main.go" ]]; then
    fail "Copy completed but ${APP_DIR}/cmd/analyzer/main.go is missing. Likely an over-broad rsync exclude."
fi

# ---------------------------------------------------------------------------
# Step 7: Build frontend
# ---------------------------------------------------------------------------
info "Installing frontend dependencies..."
cd "${APP_DIR}/web"
npm ci --prefer-offline --no-audit --no-fund 2>&1 | tail -1
ok "Frontend dependencies installed"

info "Building frontend (React + Vite)..."
npm run build
ok "Frontend built to web/dist/"

# ---------------------------------------------------------------------------
# Step 8: Build Go binary with embedded frontend
# ---------------------------------------------------------------------------
info "Preparing embedded assets..."
cd "$APP_DIR"
rm -rf cmd/analyzer/dist
cp -r web/dist cmd/analyzer/dist
# Recreate .gitkeep so the source tree stays clean (go:embed needs the
# directory to exist at compile time, and .gitkeep is what tracks it).
touch cmd/analyzer/dist/.gitkeep
ok "Frontend assets copied for embedding"

info "Downloading Go dependencies..."
go mod download
ok "Go dependencies downloaded"

info "Building production binary..."
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "deploy-$(date +%Y%m%d)")
go build -ldflags "-X main.version=${VERSION}" -o "${APP_DIR}/${APP_NAME}" ./cmd/analyzer
ok "Binary built: ${APP_DIR}/${APP_NAME} (version: ${VERSION})"

# ---------------------------------------------------------------------------
# Step 9: Write default config if missing
# ---------------------------------------------------------------------------
if [[ ! -f "$CONFIG_FILE" ]]; then
    info "Creating default configuration..."
    cat > "$CONFIG_FILE" << 'CONFIGEOF'
{
  "port": 7070,
  "data_dir": "/var/lib/cloudtrail-analyzer/data",
  "log_level": "info",
  "query_timeout_seconds": 60,
  "monitor_interval_seconds": 5,
  "max_download_concurrency": 16,
  "s3": {
    "bucket": "",
    "region": "",
    "account_id": "",
    "mode": "single"
  },
  "auth": {
    "method": "imds"
  },
  "bedrock": {
    "region": "us-east-1",
    "model_id": "us.anthropic.claude-sonnet-4-6",
    "enabled": false
  },
  "llm": {
    "provider": "bedrock",
    "max_session_spend_usd": 5.00
  }
}
CONFIGEOF
    ok "Default config written to $CONFIG_FILE"
else
    warn "Config already exists at $CONFIG_FILE — not overwriting"
fi

# ---------------------------------------------------------------------------
# Step 10: Set ownership and permissions
# ---------------------------------------------------------------------------
info "Setting file ownership..."
chown -R "$APP_USER":"$APP_USER" "$APP_DIR" "$DATA_DIR"
chmod 750 "${APP_DIR}/${APP_NAME}"
chmod 600 "$CONFIG_FILE"
find "$DATA_DIR" -type d -exec chmod 700 {} +
find "$DATA_DIR" -type f -exec chmod 600 {} +
ok "Ownership and permissions set"

# ---------------------------------------------------------------------------
# Step 11: Create systemd service
# ---------------------------------------------------------------------------
info "Creating systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=CloudTrail Security Analyzer
Documentation=https://github.com/cloudtrail-analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/${APP_NAME}
UMask=0077

# Environment
Environment=PORT=${PORT}
Environment=DATA_DIR=${DATA_DIR}
Environment=AWS_EC2_METADATA_V1_DISABLED=true

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${APP_DIR}
PrivateTmp=true

# Restart policy
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Logging (stdout/stderr go to journald)
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF
ok "Systemd unit written: /etc/systemd/system/${SERVICE_NAME}.service"

# ---------------------------------------------------------------------------
# Step 12: Enable and start the service
# ---------------------------------------------------------------------------
info "Enabling and starting service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
systemctl restart "${SERVICE_NAME}.service"

# Wait a moment for the service to start, then check status
sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    ok "Service is running"
else
    journalctl -u "${SERVICE_NAME}" -n 50 --no-pager || true
    fail "Service did not start. Review the journal output above."
fi

# ---------------------------------------------------------------------------
# Step 13: Verify
# ---------------------------------------------------------------------------
info "Running health check..."
if curl -sf --retry 10 --retry-delay 1 --retry-connrefused \
    "http://localhost:${PORT}/api/health" > /dev/null 2>&1; then
    ok "Health check passed"
    HEALTH=$(curl -s "http://localhost:${PORT}/api/health")
    echo "  $HEALTH"
else
    journalctl -u "${SERVICE_NAME}" -n 50 --no-pager || true
    fail "Health endpoint did not become ready. Review the journal output above."
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  CloudTrail Analyzer deployed successfully!"
echo "============================================================"
echo ""
echo "  Local URL on the instance: http://localhost:${PORT}"
echo "  Config:   ${CONFIG_FILE}"
echo "  Data:     ${DATA_DIR}"
echo "  Logs:     journalctl -u ${SERVICE_NAME} -f"
echo "  Service:  systemctl status ${SERVICE_NAME}"
echo ""
echo "  Next steps:"
echo "    1. From your laptop, start an SSM port-forwarding session:"
echo "       aws ssm start-session --target <instance-id> \\"
echo "         --document-name AWS-StartPortForwardingSession \\"
echo "         --parameters '{\"portNumber\":[\"${PORT}\"],\"localPortNumber\":[\"${PORT}\"]}'"
echo "    2. Open http://localhost:${PORT} in your laptop browser"
echo "    3. Configure credentials and the CloudTrail S3 bucket in the UI"
echo ""
echo "  Useful commands:"
echo "    sudo systemctl stop ${SERVICE_NAME}"
echo "    sudo systemctl start ${SERVICE_NAME}"
echo "    sudo systemctl restart ${SERVICE_NAME}"
echo "    journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
echo ""
