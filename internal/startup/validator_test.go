package startup

import (
	"os"
	"path/filepath"
	"testing"

	"cloudtrail-analyzer/internal/config"
)

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
	if status.DuckDB.Status != "ok" {
		t.Errorf("expected DuckDB status 'ok', got %q", status.DuckDB.Status)
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

func TestValidate_DuckDBAlwaysOk(t *testing.T) {
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

	if status.DuckDB.Status != "ok" {
		t.Errorf("expected DuckDB status 'ok', got %q", status.DuckDB.Status)
	}
}
