package nlquery

import (
	"context"
	"errors"
	"strings"
	"testing"

	"cloudtrail-analyzer/internal/config"
)

// TestExecuteDuckDB_RejectsUnsafeSQL_BeforeShellOut confirms the guard fires
// inside executeDuckDB, before the duckdb binary is invoked. We use a Service
// pointed at a non-existent data dir so a successful pass-through would either
// hang or produce a DuckDB CLI error — instead we expect ErrUnsafeSQL.
func TestExecuteDuckDB_RejectsUnsafeSQL_BeforeShellOut(t *testing.T) {
	cfg := &config.Config{
		Port:                7070,
		DataDir:             t.TempDir(), // empty dir; no index, no data
		QueryTimeoutSeconds: 5,
	}
	svc := NewService(cfg)

	attacks := []string{
		`SELECT * FROM read_csv_auto('/etc/passwd');`,
		`ATTACH '/tmp/x.duckdb' AS evil; SELECT 1;`,
		`SELECT 1; DROP TABLE events;`,
		`SELECT * FROM /* hidden */ Read_Parquet('/etc/passwd');`,
		`INSTALL httpfs;`,
	}

	for _, sql := range attacks {
		_, _, err := svc.executeDuckDB(context.Background(), sql)
		if err == nil {
			t.Errorf("expected unsafe rejection, got nil for: %s", sql)
			continue
		}
		if !errors.Is(err, ErrUnsafeSQL) {
			t.Errorf("expected ErrUnsafeSQL, got %v\nsql: %s", err, sql)
		}
		if !strings.Contains(err.Error(), "unsafe SQL") {
			t.Errorf("error message should name 'unsafe SQL', got: %v", err)
		}
	}
}
