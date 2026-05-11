package nlquery

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"cloudtrail-analyzer/internal/config"
)

const indexDBName = "cloudtrail_index.duckdb"

type Indexer struct {
	cfg *config.Config
}

func NewIndexer(cfg *config.Config) *Indexer {
	return &Indexer{cfg: cfg}
}

func (idx *Indexer) IndexPath() string {
	return filepath.Join(idx.cfg.DataDir, indexDBName)
}

func (idx *Indexer) IsIndexed() bool {
	info, err := os.Stat(idx.IndexPath())
	return err == nil && info.Size() > 0
}

func (idx *Indexer) IndexAge() time.Duration {
	info, err := os.Stat(idx.IndexPath())
	if err != nil {
		return time.Duration(0)
	}
	return time.Since(info.ModTime())
}

func (idx *Indexer) BuildIndex(ctx context.Context, dataPath string) error {
	if dataPath == "" {
		return fmt.Errorf("no data path configured")
	}

	dbPath := idx.IndexPath()
	// Remove old index
	os.Remove(dbPath)

	slog.Info("building CloudTrail index",
		"component", "cloudtrail-analyzer",
		"data_path", dataPath,
		"index_path", dbPath,
	)

	start := time.Now()

	sql := fmt.Sprintf(`
		CREATE TABLE events AS
		SELECT unnest(Records) as r
		FROM read_json('%s**/*.json',
			maximum_object_size=16777216,
			auto_detect=true,
			union_by_name=true);
	`, dataPath)

	cmd := exec.CommandContext(ctx, "duckdb", dbPath, sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("indexing failed: %s — %w", string(out), err)
	}

	// Create indexes for common query patterns
	indexSQL := `
		CREATE INDEX IF NOT EXISTS idx_event_name ON events ((r.eventName));
		CREATE INDEX IF NOT EXISTS idx_event_source ON events ((r.eventSource));
		CREATE INDEX IF NOT EXISTS idx_error_code ON events ((r.errorCode));
	`
	cmd2 := exec.CommandContext(ctx, "duckdb", dbPath, indexSQL)
	cmd2.CombinedOutput() // Best effort — DuckDB may not support all index types on structs

	elapsed := time.Since(start)
	info, _ := os.Stat(dbPath)
	sizeBytes := int64(0)
	if info != nil {
		sizeBytes = info.Size()
	}

	slog.Info("index built",
		"component", "cloudtrail-analyzer",
		"duration_ms", elapsed.Milliseconds(),
		"index_size_bytes", sizeBytes,
	)

	return nil
}

func (idx *Indexer) QuerySQL(sql string) string {
	if idx.IsIndexed() {
		return sql
	}
	return sql
}

func BuildIndexedDataSource(cfg *config.Config) string {
	indexPath := filepath.Join(cfg.DataDir, indexDBName)
	if _, err := os.Stat(indexPath); err == nil {
		return fmt.Sprintf("'%s'", indexPath)
	}
	return ""
}
