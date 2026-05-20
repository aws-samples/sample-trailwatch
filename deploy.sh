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
#   - Go 1.22+          (build time, stays for future rebuilds)
#   - Node.js 20+       (build time only, used for frontend)
#   - DuckDB CLI        (runtime, for query execution)
#   - Ollama            (NOT installed here — auto-installed on first use if user picks local LLM)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GO_VERSION="1.22.5"
NODE_MAJOR=20
DUCKDB_VERSION="1.2.2"

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
dnf install -y --allowerasing git gcc gcc-c++ make unzip tar gzip wget curl \
    || fail "dnf install failed; check the error above"
ok "System packages up to date"

# ---------------------------------------------------------------------------
# Step 2: Install Go
# ---------------------------------------------------------------------------
install_go() {
    local go_tarball="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    local go_url="https://go.dev/dl/${go_tarball}"

    info "Downloading Go ${GO_VERSION}..."
    cd /tmp
    wget -q "${go_url}" -O "${go_tarball}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${go_tarball}"
    rm -f "${go_tarball}"
}

# Add Go to PATH for this script
export PATH="/usr/local/go/bin:${PATH}"
export GOPATH="/root/go"
export PATH="${GOPATH}/bin:${PATH}"

if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | grep -oP '\d+\.\d+' | head -1)
    REQUIRED_GO="1.22"
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
if command -v node &>/dev/null; then
    NODE_VER=$(node --version | grep -oP '\d+' | head -1)
    if [[ "$NODE_VER" -ge "$NODE_MAJOR" ]]; then
        ok "Node.js already installed: $(node --version)"
    else
        warn "Node.js too old (v${NODE_VER} < v${NODE_MAJOR}), upgrading..."
        dnf remove -y nodejs 2>/dev/null || true
        dnf install -y nodejs 2>/dev/null || yum install -y nodejs 2>/dev/null
    fi
else
    info "Installing Node.js ${NODE_MAJOR}..."
    # AL2023 has Node 18+ in default repos; try dnf first
    if ! dnf install -y nodejs npm 2>/dev/null; then
        # Fallback: NodeSource setup — download then execute (no pipe-to-bash)
        local setup_script="/tmp/nodesource_setup_${NODE_MAJOR}.sh"
        curl -fsSL "https://rpm.nodesource.com/setup_${NODE_MAJOR}.x" -o "$setup_script"
        chmod +x "$setup_script"
        bash "$setup_script"
        rm -f "$setup_script"
        dnf install -y nodejs 2>/dev/null || yum install -y nodejs 2>/dev/null
    fi
fi
ok "Node.js ready: $(node --version)"

# ---------------------------------------------------------------------------
# Step 4: Install DuckDB CLI
# ---------------------------------------------------------------------------
install_duckdb() {
    info "Installing DuckDB ${DUCKDB_VERSION} for ${DUCKDB_ARCH}..."
    local duckdb_zip="duckdb_cli-linux-${DUCKDB_ARCH}.zip"
    local duckdb_url="https://github.com/duckdb/duckdb/releases/download/v${DUCKDB_VERSION}/${duckdb_zip}"

    cd /tmp
    wget -q "${duckdb_url}" -O "${duckdb_zip}"
    unzip -o -q "${duckdb_zip}" -d /tmp/duckdb_extract
    mv /tmp/duckdb_extract/duckdb /usr/local/bin/duckdb
    chmod +x /usr/local/bin/duckdb
    rm -rf "${duckdb_zip}" /tmp/duckdb_extract
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
ok "Directories created: $APP_DIR, $DATA_DIR"

# ---------------------------------------------------------------------------
# Step 6: Copy source code to app directory
# ---------------------------------------------------------------------------
info "Copying source code to ${APP_DIR}..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

# Copy project files (excluding node_modules, build artifacts, data)
rsync -a --delete \
    --exclude='node_modules' \
    --exclude='dist' \
    --exclude='data' \
    --exclude='.DS_Store' \
    --exclude='analyzer' \
    "${SCRIPT_DIR}/" "${APP_DIR}/"
ok "Source code copied"

# Belt-and-braces: confirm the destination has what Step 7+8 need.
if [[ ! -d "${APP_DIR}/web" || ! -f "${APP_DIR}/web/package.json" ]]; then
    fail "Copy completed but ${APP_DIR}/web is missing. Check rsync excludes and source tree."
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
  "max_download_concurrency": 4,
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
    "model_id": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "enabled": false
  },
  "llm": {
    "provider": "bedrock"
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
chmod 640 "$CONFIG_FILE"
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

# Environment
Environment=PORT=${PORT}
Environment=DATA_DIR=${DATA_DIR}

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
    warn "Service may not have started cleanly. Check: journalctl -u ${SERVICE_NAME} -n 50"
fi

# ---------------------------------------------------------------------------
# Step 13: Verify
# ---------------------------------------------------------------------------
info "Running health check..."
sleep 1
if curl -sf "http://localhost:${PORT}/api/health" > /dev/null 2>&1; then
    ok "Health check passed"
    HEALTH=$(curl -s "http://localhost:${PORT}/api/health")
    echo "  $HEALTH"
else
    warn "Health endpoint not reachable yet — the service may still be starting."
    warn "Check logs: journalctl -u ${SERVICE_NAME} -f"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  CloudTrail Analyzer deployed successfully!"
echo "============================================================"
echo ""
echo "  URL:      http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):${PORT}"
echo "  Config:   ${CONFIG_FILE}"
echo "  Data:     ${DATA_DIR}"
echo "  Logs:     journalctl -u ${SERVICE_NAME} -f"
echo "  Service:  systemctl status ${SERVICE_NAME}"
echo ""
echo "  Next steps:"
echo "    1. Edit ${CONFIG_FILE} to set your S3 bucket and credentials"
echo "    2. Restart: sudo systemctl restart ${SERVICE_NAME}"
echo "    3. Open the URL above in your browser"
echo ""
echo "  Useful commands:"
echo "    sudo systemctl stop ${SERVICE_NAME}"
echo "    sudo systemctl start ${SERVICE_NAME}"
echo "    sudo systemctl restart ${SERVICE_NAME}"
echo "    journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
echo ""
