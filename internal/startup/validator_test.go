package startup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cloudtrail-analyzer/internal/config"
)

// duckdbOnPath reports whether the DuckDB CLI is available in PATH on the host
// running the test. The DuckDB checks behave differently depending on this, so
// tests branch their expectations rather than assuming an install state.
func duckdbOnPath() bool {
	_, err := exec.LookPath("duckdb")
	return err == nil
}

func TestValidate_Success(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		DataDir: tmpDir,
		Auth: config.AuthConfig{
			Method: "imds",
		},
		S3: config.S3Config{
			Bucket: "my-bucket",
		},
	}

	status, err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if status.DataDir.Status != "ok" {
		t.Errorf("expected DataDir status 'ok', got %q", status.DataDir.Status)
	}
	if status.SQLite.Status != "ok" {
		t.Errorf("expected SQLite status 'ok', got %q", status.SQLite.Status)
	}
	if status.Credentials.Status != "ok" {
		t.Errorf("expected Credentials status 'ok', got %q", status.Credentials.Status)
	}
	// With auto-install disabled (the default), DuckDB is "ok" only when the CLI
	// is already on PATH; otherwise it reports an actionable "error".
	if duckdbOnPath() {
		if status.DuckDB.Status != "ok" {
			t.Errorf("expected DuckDB status 'ok' (duckdb on PATH), got %q", status.DuckDB.Status)
		}
	} else if status.DuckDB.Status != "error" {
		t.Errorf("expected DuckDB status 'error' (duckdb absent, auto-install off), got %q", status.DuckDB.Status)
	}
}

func TestValidate_CreatesDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "newdata")

	cfg := &config.Config{
		DataDir: dataDir,
		Auth: config.AuthConfig{
			Method: "imds",
		},
		S3: config.S3Config{
			Bucket: "my-bucket",
		},
	}

	_, err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify data dir was created
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		t.Error("expected data directory to be created")
	}

	// Verify s3 subdir was created
	s3Dir := filepath.Join(dataDir, "s3")
	if _, err := os.Stat(s3Dir); os.IsNotExist(err) {
		t.Error("expected s3 directory to be created")
	}
}

func TestValidate_DataDirNotWritable(t *testing.T) {
	// Create a read-only directory
	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	if err := os.MkdirAll(readOnlyDir, 0555); err != nil {
		t.Fatalf("failed to create read-only dir: %v", err)
	}

	// Try to use a subdirectory of the read-only dir as data dir
	dataDir := filepath.Join(readOnlyDir, "data")

	cfg := &config.Config{
		DataDir: dataDir,
		Auth: config.AuthConfig{
			Method: "imds",
		},
	}

	status, err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for non-writable data directory")
	}

	if status.DataDir.Status != "error" {
		t.Errorf("expected DataDir status 'error', got %q", status.DataDir.Status)
	}
}

func TestValidate_CredentialsUnconfigured(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		DataDir: tmpDir,
		Auth: config.AuthConfig{
			Method: "imds",
		},
		S3: config.S3Config{
			Bucket: "", // No bucket configured
		},
	}

	status, err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Credentials should be unconfigured (non-blocking) when no bucket is set
	if status.Credentials.Status != "unconfigured" {
		t.Errorf("expected Credentials status 'unconfigured', got %q", status.Credentials.Status)
	}
}

func TestValidate_StaticCredentialsMissing(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		DataDir: tmpDir,
		Auth: config.AuthConfig{
			Method: "static",
			// No access key or secret
		},
		S3: config.S3Config{
			Bucket: "my-bucket",
		},
	}

	status, err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if status.Credentials.Status != "unconfigured" {
		t.Errorf("expected Credentials status 'unconfigured', got %q", status.Credentials.Status)
	}
}

func TestValidate_StaticCredentialsConfigured(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		DataDir: tmpDir,
		Auth: config.AuthConfig{
			Method: "imds",
		},
		S3: config.S3Config{
			Bucket: "my-bucket",
		},
	}

	status, err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if status.Credentials.Status != "ok" {
		t.Errorf("expected Credentials status 'ok', got %q", status.Credentials.Status)
	}
}

func TestValidate_SessionCredentialsUnconfigured(t *testing.T) {
	tmpDir := t.TempDir()

	// Clear env vars to ensure clean state
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")

	cfg := &config.Config{
		DataDir: tmpDir,
		Auth: config.AuthConfig{
			Method: "session_credentials",
		},
		S3: config.S3Config{
			Bucket: "my-bucket",
		},
	}

	status, err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if status.Credentials.Status != "unconfigured" {
		t.Errorf("expected Credentials status 'unconfigured', got %q", status.Credentials.Status)
	}
}

func TestValidate_SessionCredentialsApplied(t *testing.T) {
	tmpDir := t.TempDir()

	t.Setenv("AWS_ACCESS_KEY_ID", "test-key-id-for-unit-test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-for-unit-test")
	t.Setenv("AWS_SESSION_TOKEN", "test-token-for-unit-test")

	cfg := &config.Config{
		DataDir: tmpDir,
		Auth: config.AuthConfig{
			Method: "session_credentials",
		},
		S3: config.S3Config{
			Bucket: "my-bucket",
		},
	}

	status, err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if status.Credentials.Status != "ok" {
		t.Errorf("expected Credentials status 'ok', got %q", status.Credentials.Status)
	}
}

// TestValidate_DuckDBAutoInstallDisabled verifies that with the default
// (auto-install off), a missing DuckDB CLI is reported as an actionable error
// and nothing is downloaded. When the CLI is present, the check passes.
func TestValidate_DuckDBAutoInstallDisabled(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		DataDir:          tmpDir,
		AllowAutoInstall: false,
		Auth: config.AuthConfig{
			Method: "imds",
		},
		S3: config.S3Config{
			Bucket: "my-bucket",
		},
	}

	status, err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if duckdbOnPath() {
		if status.DuckDB.Status != "ok" {
			t.Errorf("expected DuckDB status 'ok' (duckdb on PATH), got %q", status.DuckDB.Status)
		}
		return
	}

	// duckdb absent: expect a non-blocking error with setup guidance and no download.
	if status.DuckDB.Status != "error" {
		t.Fatalf("expected DuckDB status 'error' when CLI absent and auto-install off, got %q", status.DuckDB.Status)
	}
	if !strings.Contains(status.DuckDB.Message, "allow_auto_install") {
		t.Errorf("expected guidance to mention allow_auto_install, got %q", status.DuckDB.Message)
	}
	if !strings.Contains(status.DuckDB.Message, "duckdb.org/docs/installation") {
		t.Errorf("expected guidance to include the install link, got %q", status.DuckDB.Message)
	}
}

// TestParseSHA256Digest checks both the bare-digest and "digest  filename"
// forms accepted from a published .sha256 file, plus rejection of bad input.
func TestParseSHA256Digest(t *testing.T) {
	valid := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"bare", valid, valid, false},
		{"with filename", valid + "  duckdb_cli-linux-amd64.zip", valid, false},
		{"trailing newline", valid + "\n", valid, false},
		{"empty", "", "", true},
		{"not hex", "zz" + valid[2:], "", true},
		{"too short", valid[:62], "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSHA256Digest([]byte(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got digest %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
