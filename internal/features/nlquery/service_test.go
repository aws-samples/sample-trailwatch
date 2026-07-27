package nlquery

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestBuildSystemPrompt_UsesIndexedEventsOnly(t *testing.T) {
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
	if !containsStr(prompt, "FROM cloudtrail_events") {
		t.Error("system prompt should query the scoped CloudTrail view")
	}
	if strings.Contains(strings.ToLower(prompt), "from read_json") {
		t.Error("system prompt must not include a raw-file query pattern")
	}
	if containsStr(prompt, "./data/s3/test-bucket") {
		t.Error("system prompt should not disclose the local data path")
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
		"Query only the cloudtrail_events view",
	}
	for _, c := range constraints {
		if !containsStr(prompt, c) {
			t.Errorf("system prompt missing DuckDB constraint: %q", c)
		}
	}
}

func TestScopeAccountIDsIgnoresStaleMembersInSingleMode(t *testing.T) {
	cfg := &config.Config{S3: config.S3Config{
		Mode:           "single",
		AccountID:      "123456789012",
		MemberAccounts: []string{"999999999999"},
	}}

	ids := scopeAccountIDs(cfg)
	if len(ids) != 1 || ids[0] != "123456789012" {
		t.Fatalf("single mode used stale member accounts: %v", ids)
	}
}

func TestExecuteRequiresIndexBeforeCallingProvider(t *testing.T) {
	cfg := &config.Config{
		DataDir:             t.TempDir(),
		QueryTimeoutSeconds: 5,
		LLM:                 config.LLMConfig{Provider: "bedrock"},
	}
	svc := NewService(cfg)

	_, err := svc.Execute(context.Background(), "show failed calls")
	if !errors.Is(err, ErrIndexRequired) {
		t.Fatalf("expected ErrIndexRequired, got %v", err)
	}
}

func TestExecuteDuckDBIndexedModeBlocksRawJSON(t *testing.T) {
	if _, err := exec.LookPath("duckdb"); err != nil {
		t.Skip("duckdb CLI not installed")
	}
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, indexDBName)
	if out, err := exec.Command("duckdb", dbPath,
		`CREATE TABLE events AS SELECT {'eventName': 'ListBuckets', 'recipientAccountId': '123456789012'} AS r;`).CombinedOutput(); err != nil {
		t.Fatalf("creating test index: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dataDir, indexVersionFile), []byte(indexSchemaVersion+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		DataDir:             dataDir,
		QueryTimeoutSeconds: 5,
		S3:                  config.S3Config{AccountID: "123456789012"},
	}
	svc := NewService(cfg)
	_, _, err := svc.executeDuckDB(context.Background(),
		`SELECT * FROM read_json('/etc/passwd');`)
	if !errors.Is(err, ErrUnsafeSQL) {
		t.Fatalf("expected ErrUnsafeSQL, got %v", err)
	}

	cols, rows, err := svc.executeDuckDB(context.Background(),
		`SELECT r.eventName FROM events;`)
	if err != nil {
		t.Fatalf("indexed query failed: %v", err)
	}
	if len(cols) != 1 || len(rows) != 1 || rows[0][0] != "ListBuckets" {
		t.Fatalf("unexpected indexed result: columns=%v rows=%v", cols, rows)
	}
}

func TestExecuteGeneratedDuckDBUsesAccountScopedView(t *testing.T) {
	if _, err := exec.LookPath("duckdb"); err != nil {
		t.Skip("duckdb CLI not installed")
	}
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, indexDBName)
	createSQL := `CREATE TABLE events AS
		SELECT {'eventName': 'Allowed', 'recipientAccountId': '123456789012'} AS r
		UNION ALL
		SELECT {'eventName': 'Other', 'recipientAccountId': '999999999999'} AS r;`
	if out, err := exec.Command("duckdb", dbPath, createSQL).CombinedOutput(); err != nil {
		t.Fatalf("creating test index: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dataDir, indexVersionFile), []byte(indexSchemaVersion+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		DataDir:             dataDir,
		QueryTimeoutSeconds: 5,
		S3:                  config.S3Config{AccountID: "123456789012"},
	}
	svc := NewService(cfg)
	_, rows, err := svc.executeGeneratedDuckDB(context.Background(),
		`SELECT r.eventName FROM cloudtrail_events ORDER BY r.eventName;`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0][0] != "Allowed" {
		t.Fatalf("generated query escaped account scope: %v", rows)
	}

	_, _, err = svc.executeGeneratedDuckDB(context.Background(),
		`SELECT r.eventName FROM events;`)
	if !errors.Is(err, ErrUnsafeSQL) {
		t.Fatalf("expected direct base-table access to be rejected, got %v", err)
	}
}

func TestOrganizationReadersUseStableBucketRoot(t *testing.T) {
	for _, members := range [][]string{
		{"111111111111"},
		{"111111111111", "222222222222"},
	} {
		cfg := &config.Config{
			DataDir: "/data",
			S3: config.S3Config{
				Bucket:         "org-trail-bucket",
				Region:         "us-east-1",
				AccountID:      "111111111111",
				Mode:           "control_tower",
				OrgID:          "o-abc",
				MemberAccounts: members,
			},
		}

		want := "/data/s3/org-trail-bucket/"
		got := map[string]string{
			"service":     NewService(cfg).buildDataPath(),
			"index":       NewService(cfg).buildIndexDataPath(),
			"dashboard":   NewDashboardHandler(cfg).buildDataPath(),
			"investigate": NewInvestigateHandler(cfg).buildDataPath(),
			"lookups":     NewLookupsHandler(cfg).buildDataPath(),
		}
		for reader, path := range got {
			if path != want {
				t.Errorf("%s path with members %v = %q, want %q", reader, members, path, want)
			}
			if strings.Contains(path, "/o-abc/AWSLogs/") {
				t.Errorf("%s retained legacy Control Tower path %q", reader, path)
			}
		}
	}
}

func TestSingleAccountReadersKeepNarrowPath(t *testing.T) {
	cfg := &config.Config{
		DataDir: "/data",
		S3: config.S3Config{
			Bucket:    "account-trail-bucket",
			Region:    "bucket-region",
			LogRegion: "ap-south-1",
			AccountID: "111111111111",
			Mode:      "single",
		},
	}

	want := "/data/s3/account-trail-bucket/AWSLogs/111111111111/CloudTrail/ap-south-1/"
	for reader, path := range map[string]string{
		"service":     NewService(cfg).buildDataPath(),
		"index":       NewService(cfg).buildIndexDataPath(),
		"dashboard":   NewDashboardHandler(cfg).buildDataPath(),
		"investigate": NewInvestigateHandler(cfg).buildDataPath(),
		"lookups":     NewLookupsHandler(cfg).buildDataPath(),
	} {
		if path != want {
			t.Errorf("%s path = %q, want %q", reader, path, want)
		}
	}
}

func TestMemberAccountScopeIncludesSingleOrganizationMember(t *testing.T) {
	cfg := &config.Config{S3: config.S3Config{
		Mode:           "control_tower",
		OrgID:          "o-abc",
		AccountID:      "111111111111",
		MemberAccounts: []string{"111111111111"},
	}}

	want := " AND r.recipientAccountId IN ('111111111111')"
	if got := memberAccountScope(cfg); got != want {
		t.Fatalf("memberAccountScope() = %q, want %q", got, want)
	}

	cfg.S3.Mode = "single"
	if got := memberAccountScope(cfg); got != "" {
		t.Fatalf("single-account memberAccountScope() = %q, want empty", got)
	}
}

func TestFindingQueriesScopeSingleOrganizationMember(t *testing.T) {
	scope := " AND r.recipientAccountId IN ('111111111111')"
	queries := buildFindingQueries("/data/s3/org-trail-bucket/", scope)

	for id, query := range queries {
		for kind, sql := range map[string]string{
			"summary": query.SummarySQL,
			"detail":  query.DetailSQL,
		} {
			if !strings.Contains(sql, `WHERE r.recipientAccountId IN ('111111111111')`) {
				t.Errorf("%s %s query is not account-scoped: %s", id, kind, sql)
			}
		}
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
