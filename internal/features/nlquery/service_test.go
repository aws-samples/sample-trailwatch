package nlquery

import (
	"context"
	"testing"

	"cloudtrail-analyzer/internal/config"
)

func TestExecuteDuckDB_InvalidSQL(t *testing.T) {
	cfg := &config.Config{QueryTimeoutSeconds: 5}
	svc := NewService(cfg)

	_, _, err := svc.executeDuckDB(context.Background(), "THIS IS NOT VALID SQL")
	if err == nil {
		t.Error("expected error for invalid SQL")
	}
}

func TestExecuteDuckDB_ValidSQL(t *testing.T) {
	cfg := &config.Config{QueryTimeoutSeconds: 5}
	svc := NewService(cfg)

	cols, rows, err := svc.executeDuckDB(context.Background(), "SELECT 1 as num, 'hello' as greeting;")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cols) != 2 || cols[0] != "num" || cols[1] != "greeting" {
		t.Errorf("unexpected columns: %v", cols)
	}
	if len(rows) != 1 || rows[0][0] != "1" || rows[0][1] != "hello" {
		t.Errorf("unexpected rows: %v", rows)
	}
}

func TestExecuteDuckDB_EmptyResult(t *testing.T) {
	cfg := &config.Config{QueryTimeoutSeconds: 5}
	svc := NewService(cfg)

	cols, rows, err := svc.executeDuckDB(context.Background(), "SELECT 1 WHERE false;")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cols) != 1 {
		t.Errorf("expected 1 column header, got %d", len(cols))
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows, got %d", len(rows))
	}
}

func TestExecuteDuckDB_FileNotFound(t *testing.T) {
	cfg := &config.Config{QueryTimeoutSeconds: 5}
	svc := NewService(cfg)

	_, _, err := svc.executeDuckDB(context.Background(),
		"SELECT * FROM read_json('/nonexistent/path/**/*.json', auto_detect=true);")
	if err == nil {
		t.Error("expected error for nonexistent file path")
	}
}

func TestBuildSystemPrompt_ContainsDataPath(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./data",
		S3: config.S3Config{
			Bucket:    "test-bucket",
			Region:    "us-west-2",
			AccountID: "999888777666",
			Mode:      "single",
		},
	}
	svc := NewService(cfg)
	prompt := svc.buildSystemPrompt()

	if !containsStr(prompt, "999888777666") {
		t.Error("system prompt should contain account ID")
	}
	if !containsStr(prompt, "us-west-2") {
		t.Error("system prompt should contain region")
	}
	if !containsStr(prompt, "./data/s3/test-bucket") {
		t.Error("system prompt should contain data path")
	}
}

func TestBuildSystemPrompt_DuckDBConstraints(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./data",
		S3:      config.S3Config{Bucket: "b", Region: "r", AccountID: "a", Mode: "single"},
	}
	svc := NewService(cfg)
	prompt := svc.buildSystemPrompt()

	constraints := []string{
		"NEVER use LIMIT inside aggregate",
		"string_agg",
		"list(",
		"TRY_CAST",
		"maximum_object_size",
	}
	for _, c := range constraints {
		if !containsStr(prompt, c) {
			t.Errorf("system prompt missing DuckDB constraint: %q", c)
		}
	}
}

func TestBuildDataPath_MultiAccountMode(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./data",
		S3: config.S3Config{
			Bucket:         "ct-bucket",
			Region:         "us-east-1",
			AccountID:      "111111111111",
			Mode:           "control_tower",
			OrgID:          "o-abc",
			MemberAccounts: []string{"111111111111", "222222222222"},
		},
	}

	h := NewDashboardHandler(cfg)
	path := h.buildDataPath()

	// When multi-account, should point at org root, not specific account
	expected := "./data/s3/ct-bucket/o-abc/AWSLogs/o-abc/"
	if path != expected {
		t.Errorf("expected %q for multi-account, got %q", expected, path)
	}
}

func TestBuildDataPath_SingleAccountMode(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./data",
		S3: config.S3Config{
			Bucket:         "ct-bucket",
			Region:         "us-east-1",
			AccountID:      "111111111111",
			Mode:           "control_tower",
			OrgID:          "o-abc",
			MemberAccounts: []string{"111111111111"},
		},
	}

	h := NewDashboardHandler(cfg)
	path := h.buildDataPath()

	// Single account — full path to specific account+region
	expected := "./data/s3/ct-bucket/o-abc/AWSLogs/o-abc/111111111111/CloudTrail/us-east-1/"
	if path != expected {
		t.Errorf("expected %q for single account, got %q", expected, path)
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
