package startup

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"cloudtrail-analyzer/internal/config"

	_ "modernc.org/sqlite"
)

const (
	duckDBVersion    = "1.2.2"
	duckDBInstallDir = "/usr/local/bin"
)

// CheckResult represents the outcome of a single startup check.
type CheckResult struct {
	Status  string `json:"status"` // "ok", "error", "unconfigured"
	Message string `json:"message,omitempty"`
}

// StartupStatus contains the results of all startup validation checks.
type StartupStatus struct {
	DataDir     CheckResult `json:"data_dir"`
	SQLite      CheckResult `json:"sqlite"`
	Credentials CheckResult `json:"credentials"`
	DuckDB      CheckResult `json:"duckdb"`
}

// Validate performs startup validation checks against the provided configuration.
// It creates required directories, verifies SQLite accessibility, and performs a
// non-blocking credential check.
//
// Blocking checks (return error on failure):
//   - Data directory writable
//   - SQLite accessible
//
// Non-blocking checks (report status, don't fail startup):
//   - Credentials availability
//   - DuckDB CLI availability (auto-installed from GitHub if missing)
func Validate(cfg *config.Config) (*StartupStatus, error) {
	status := &StartupStatus{}

	// Check 1: Data directory — create dirs and verify writable (blocking)
	if err := checkDataDir(cfg.DataDir, status); err != nil {
		return status, err
	}

	// Check 2: SQLite accessible (blocking)
	if err := checkSQLite(cfg.DataDir, status); err != nil {
		return status, err
	}

	// Check 3: Credentials — non-blocking
	checkCredentials(cfg, status)

	// Check 4: DuckDB CLI — verify present, auto-install if missing (non-blocking)
	checkDuckDB(status)

	slog.Info("startup validation complete",
		"data_dir", status.DataDir.Status,
		"sqlite", status.SQLite.Status,
		"credentials", status.Credentials.Status,
		"duckdb", status.DuckDB.Status,
	)

	return status, nil
}

// checkDataDir creates the data directory and s3 subdirectory if they don't exist,
// then verifies the directory is writable.
func checkDataDir(dataDir string, status *StartupStatus) error {
	// Create data directory
	if err := os.MkdirAll(dataDir, 0700); err != nil { // nosemgrep: incorrect-default-permission
		status.DataDir = CheckResult{
			Status:  "error",
			Message: fmt.Sprintf("failed to create data directory: %v", err),
		}
		return fmt.Errorf("creating data directory %s: %w", dataDir, err)
	}

	// Create s3 subdirectory
	s3Dir := filepath.Join(dataDir, "s3")
	if err := os.MkdirAll(s3Dir, 0700); err != nil { // nosemgrep: incorrect-default-permission
		status.DataDir = CheckResult{
			Status:  "error",
			Message: fmt.Sprintf("failed to create s3 directory: %v", err),
		}
		return fmt.Errorf("creating s3 directory %s: %w", s3Dir, err)
	}

	// Verify writable by creating and removing a temp file
	testFile := filepath.Join(dataDir, ".write_test")
	f, err := os.Create(testFile)
	if err != nil {
		status.DataDir = CheckResult{
			Status:  "error",
			Message: fmt.Sprintf("data directory not writable: %v", err),
		}
		return fmt.Errorf("data directory %s not writable: %w", dataDir, err)
	}
	f.Close()
	os.Remove(testFile)

	status.DataDir = CheckResult{
		Status:  "ok",
		Message: fmt.Sprintf("data directory ready: %s", dataDir),
	}
	return nil
}

// checkSQLite verifies that SQLite can be opened at the expected path.
func checkSQLite(dataDir string, status *StartupStatus) error {
	dbPath := filepath.Join(dataDir, "sessions.db")

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		status.SQLite = CheckResult{
			Status:  "error",
			Message: fmt.Sprintf("failed to open SQLite: %v", err),
		}
		return fmt.Errorf("opening sqlite at %s: %w", dbPath, err)
	}
	defer conn.Close()

	// Verify the connection actually works
	if err := conn.Ping(); err != nil {
		status.SQLite = CheckResult{
			Status:  "error",
			Message: fmt.Sprintf("SQLite ping failed: %v", err),
		}
		return fmt.Errorf("pinging sqlite at %s: %w", dbPath, err)
	}

	status.SQLite = CheckResult{
		Status:  "ok",
		Message: fmt.Sprintf("SQLite accessible: %s", dbPath),
	}
	return nil
}

// checkCredentials performs a non-blocking credential check.
// If credentials are not configured, it marks the status as "unconfigured"
// but does NOT return an error (non-blocking).
func checkCredentials(cfg *config.Config, status *StartupStatus) {
	// Check if any credential source is configured
	switch cfg.Auth.Method {
	case "static":
		if cfg.Auth.AccessKeyID != "" && cfg.Auth.SecretAccessKey != "" {
			status.Credentials = CheckResult{
				Status:  "ok",
				Message: "static credentials configured",
			}
		} else {
			status.Credentials = CheckResult{
				Status:  "unconfigured",
				Message: "static auth method selected but credentials not provided",
			}
		}
	case "imds":
		// IMDS will be validated at runtime when actually needed
		status.Credentials = CheckResult{
			Status:  "ok",
			Message: "IMDS v2 credential source configured",
		}
	case "session_credentials":
		// Session credentials are held in env vars, validated at runtime
		if os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "" && os.Getenv("AWS_SESSION_TOKEN") != "" {
			status.Credentials = CheckResult{
				Status:  "ok",
				Message: "session credentials applied in environment",
			}
		} else {
			status.Credentials = CheckResult{
				Status:  "unconfigured",
				Message: "session_credentials method selected but credentials not yet applied — use the UI to paste them",
			}
		}
	case "sso":
		// SSO will be validated at runtime when actually needed
		status.Credentials = CheckResult{
			Status:  "ok",
			Message: "SSO credential source configured",
		}
	default:
		status.Credentials = CheckResult{
			Status:  "unconfigured",
			Message: fmt.Sprintf("unknown auth method: %s — expected one of: imds, session_credentials, sso, static", cfg.Auth.Method),
		}
	}

	// If S3 bucket is not configured, mark as unconfigured regardless of auth method
	if cfg.S3.Bucket == "" {
		status.Credentials = CheckResult{
			Status:  "unconfigured",
			Message: "S3 bucket not configured — credentials not validated",
		}
	}
}

// checkDuckDB verifies the DuckDB CLI is available in PATH.
// If not found, it attempts to download and install it automatically.
func checkDuckDB(status *StartupStatus) {
	// Check if duckdb is already in PATH
	path, err := exec.LookPath("duckdb")
	if err == nil {
		// Found — get version for status message
		ver, verErr := getDuckDBVersion(path)
		if verErr != nil {
			ver = "unknown"
		}
		status.DuckDB = CheckResult{
			Status:  "ok",
			Message: fmt.Sprintf("DuckDB CLI available: %s (version %s)", path, ver),
		}
		return
	}

	slog.Warn("duckdb CLI not found in PATH, attempting auto-install",
		"component", "cloudtrail-analyzer",
		"version", duckDBVersion,
	)

	// Attempt auto-install
	installPath, installErr := installDuckDB()
	if installErr != nil {
		slog.Error("failed to auto-install DuckDB",
			"component", "cloudtrail-analyzer",
			"error", installErr,
		)
		status.DuckDB = CheckResult{
			Status:  "error",
			Message: fmt.Sprintf("DuckDB CLI not found and auto-install failed: %v", installErr),
		}
		return
	}

	slog.Info("DuckDB auto-installed successfully",
		"component", "cloudtrail-analyzer",
		"path", installPath,
	)
	status.DuckDB = CheckResult{
		Status:  "ok",
		Message: fmt.Sprintf("DuckDB CLI auto-installed: %s (version %s)", installPath, duckDBVersion),
	}
}

// allowedDuckDBPaths contains the set of filesystem locations where the DuckDB
// binary is permitted to reside.  Any path returned by exec.LookPath that does
// not match this list will be rejected before it is passed to exec.Command.
var allowedDuckDBPaths = map[string]bool{
	"/usr/local/bin/duckdb":    true,
	"/usr/bin/duckdb":          true,
	"/opt/homebrew/bin/duckdb": true,
}

func init() {
	// Add user-local paths derived from $HOME.
	home := os.Getenv("HOME")
	if home != "" {
		allowedDuckDBPaths[filepath.Join(home, ".local", "bin", "duckdb")] = true
		allowedDuckDBPaths[filepath.Join(home, "bin", "duckdb")] = true
	}
}

// getDuckDBVersion runs `duckdb --version` and returns the version string.
// The path is validated against an allowlist before execution.
func getDuckDBVersion(path string) (string, error) {
	// Resolve symlinks to get canonical path for allowlist check
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolving duckdb path: %w", err)
	}
	if !allowedDuckDBPaths[path] && !allowedDuckDBPaths[resolved] {
		return "", fmt.Errorf("duckdb path not in allowlist: %s", path)
	}
	out, err := exec.Command(path, "--version").Output() // nosemgrep: dangerous-exec-command
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(out)), nil
}

// installDuckDB downloads the DuckDB CLI binary from GitHub releases and
// installs it to a directory in PATH. It supports linux/amd64 and linux/arm64.
// On non-Linux systems or if the primary install directory is not writable,
// it falls back to a user-local location.
func installDuckDB() (string, error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// Map Go arch names to DuckDB release naming convention
	archMap := map[string]string{
		"amd64": "amd64",
		"arm64": "aarch64",
	}
	duckArch, ok := archMap[goarch]
	if !ok {
		return "", fmt.Errorf("unsupported architecture for DuckDB auto-install: %s/%s", goos, goarch)
	}

	// DuckDB only provides Linux and macOS CLI binaries on GitHub
	var osName string
	switch goos {
	case "linux":
		osName = "linux"
	case "darwin":
		osName = "osx"
	default:
		return "", fmt.Errorf("unsupported OS for DuckDB auto-install: %s", goos)
	}

	// Build download URL
	// Example: https://github.com/duckdb/duckdb/releases/download/v1.2.2/duckdb_cli-linux-amd64.zip
	fileName := fmt.Sprintf("duckdb_cli-%s-%s.zip", osName, duckArch)
	url := fmt.Sprintf("https://github.com/duckdb/duckdb/releases/download/v%s/%s", duckDBVersion, fileName)

	slog.Info("downloading DuckDB CLI",
		"component", "cloudtrail-analyzer",
		"url", url,
	)

	// Download the zip file
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("downloading DuckDB from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading DuckDB: HTTP %d from %s", resp.StatusCode, url)
	}

	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading DuckDB download: %w", err)
	}

	// Extract the duckdb binary from the zip
	binaryData, err := extractDuckDBFromZip(zipData)
	if err != nil {
		return "", fmt.Errorf("extracting DuckDB binary: %w", err)
	}

	// Determine install location — try system-wide first, fall back to user-local
	installDirs := []string{
		duckDBInstallDir, // /usr/local/bin (requires root)
		filepath.Join(os.Getenv("HOME"), ".local", "bin"), // ~/.local/bin
		filepath.Join(os.Getenv("HOME"), "bin"),           // ~/bin
	}

	var installPath string
	for _, dir := range installDirs {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0700); err != nil { // nosemgrep: incorrect-default-permission
			continue
		}
		candidate := filepath.Join(dir, "duckdb")
		if err := os.WriteFile(candidate, binaryData, 0755); err != nil { // nosemgrep: incorrect-default-permission
			continue
		}
		installPath = candidate
		break
	}

	if installPath == "" {
		return "", fmt.Errorf("could not write DuckDB binary to any install directory")
	}

	// Add the install directory to PATH for this process so subsequent exec.LookPath calls find it
	installDir := filepath.Dir(installPath)
	currentPath := os.Getenv("PATH")
	os.Setenv("PATH", installDir+string(os.PathListSeparator)+currentPath)

	return installPath, nil
}

// extractDuckDBFromZip extracts the "duckdb" binary from an in-memory zip archive.
func extractDuckDBFromZip(zipData []byte) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}

	for _, f := range reader.File {
		if f.Name == "duckdb" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening duckdb in zip: %w", err)
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("reading duckdb from zip: %w", err)
			}
			return data, nil
		}
	}

	return nil, fmt.Errorf("duckdb binary not found in zip archive")
}
