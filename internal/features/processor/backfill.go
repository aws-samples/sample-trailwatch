package processor

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"cloudtrail-analyzer/internal/features/sessions"
)

// BackfillDiskUsage walks each session's local directory and updates
// disk_usage_bytes for sessions whose value is still 0. Intended to be called
// once on startup to repair rows that were created before the field was wired.
func BackfillDiskUsage(db *sql.DB, dataDir string) error {
	all, err := sessions.List(db)
	if err != nil {
		return fmt.Errorf("listing sessions for backfill: %w", err)
	}

	updated := 0
	for i := range all {
		s := &all[i]
		if s.DiskUsageBytes > 0 {
			continue
		}

		dir := sessionLocalDir(s, dataDir)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		var bytes int64
		walkErr := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			bytes += info.Size()
			return nil
		})
		if walkErr != nil || bytes == 0 {
			continue
		}

		if _, err := db.Exec(`UPDATE sessions SET disk_usage_bytes = ? WHERE id = ?`, bytes, s.ID); err != nil {
			slog.Warn("disk usage backfill update failed",
				"component", "cloudtrail-analyzer",
				"session_id", s.ID,
				"error", err.Error(),
			)
			continue
		}
		updated++
	}

	if updated > 0 {
		slog.Info("disk usage backfill complete",
			"component", "cloudtrail-analyzer",
			"updated_sessions", updated,
		)
	}
	return nil
}
