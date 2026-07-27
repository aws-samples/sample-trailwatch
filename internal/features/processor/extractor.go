package processor

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cloudtrail-analyzer/internal/cloudtrailpath"
	"cloudtrail-analyzer/internal/features/sessions"
)

const (
	// maxPerFileBytes is the maximum decompressed size for a single .json.gz file (256 MB).
	//
	// This is kept in lockstep with the read side: every read_json(...) call in
	// the nlquery package now passes maximum_object_size=268435456 (256 MB) via
	// the maxObjectSize constant (indexer.go), so a decompressed CloudTrail file
	// the extractor accepts up to 256 MB is no longer rejected by DuckDB's
	// per-object cap during indexing or querying (resolves N20/N30). If this cap
	// is raised, raise maxObjectSize to match; lowering this extractor cap would
	// truncate large-but-valid files mid-record and is intentionally not done.
	maxPerFileBytes int64 = 256 * 1024 * 1024
	// maxTotalExtractBytes is the maximum total decompressed output for one extraction run (4 GB).
	maxTotalExtractBytes int64 = 4 * 1024 * 1024 * 1024
)

// extractFiles walks the session's local directory and decompresses all .json.gz files.
// It is idempotent: if the .json file already exists, the .gz is skipped.
// A total extraction byte limit is enforced across all files to guard against decompression bombs.
func extractFiles(ctx context.Context, session *sessions.Session, dataDir string, progressCh chan<- ProcessingProgress, onExtracted func(path string, size int64)) error {
	sessionDirs, err := sessionDateDirs(session, dataDir)
	if err != nil {
		return err
	}

	// Count total .gz files first for progress reporting
	var gzFiles []string
	for _, sessionDir := range sessionDirs {
		err := filepath.Walk(sessionDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip inaccessible files
			}
			if !info.IsDir() && strings.HasSuffix(path, ".json.gz") {
				gzFiles = append(gzFiles, path)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("walking session directory %s: %w", sessionDir, err)
		}
	}

	totalFiles := len(gzFiles)
	completed := 0
	var totalExtractedBytes int64

	for _, gzPath := range gzFiles {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		jsonPath := strings.TrimSuffix(gzPath, ".gz")

		// Skip if already extracted (idempotent)
		if _, err := os.Stat(jsonPath); err == nil {
			completed++
			sendExtractProgress(progressCh, session.ID, completed, totalFiles)
			continue
		}

		remaining := maxTotalExtractBytes - totalExtractedBytes
		if remaining <= 0 {
			return fmt.Errorf("total extraction size limit (%d bytes) exceeded", maxTotalExtractBytes)
		}
		written, err := extractSingleFileWithLimit(gzPath, jsonPath, remaining)
		totalExtractedBytes += written
		if err != nil {
			slog.Warn("failed to extract file",
				"component", "cloudtrail-analyzer",
				"session_id", session.ID,
				"file", gzPath,
				"error", err.Error(),
			)
			// If total limit exceeded, stop the pipeline
			if totalExtractedBytes >= maxTotalExtractBytes {
				return fmt.Errorf("total extraction size limit (%d bytes) exceeded", maxTotalExtractBytes)
			}
			// Continue with other files — don't fail the whole pipeline
			completed++
			continue
		}

		completed++
		sendExtractProgress(progressCh, session.ID, completed, totalFiles)

		if onExtracted != nil {
			onExtracted(jsonPath, written)
		}
	}

	return nil
}

// extractSingleFile decompresses a .json.gz file to .json.
func extractSingleFile(gzPath, jsonPath string) error {
	_, err := extractSingleFileWithLimit(gzPath, jsonPath, maxPerFileBytes)
	return err
}

// extractSingleFileWithLimit decompresses a .json.gz file to .json, enforcing
// a per-file byte limit. It returns the number of bytes written.
func extractSingleFileWithLimit(gzPath, jsonPath string, limit int64) (int64, error) {
	if limit > maxPerFileBytes {
		limit = maxPerFileBytes
	}

	gzFile, err := os.Open(gzPath)
	if err != nil {
		return 0, fmt.Errorf("opening gz file: %w", err)
	}
	defer gzFile.Close()

	reader, err := gzip.NewReader(gzFile)
	if err != nil {
		return 0, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer reader.Close()

	// Use a unique staging file so overlapping work cannot truncate or rename a
	// different extraction attempt's fixed ".tmp" path.
	outFile, err := os.CreateTemp(filepath.Dir(jsonPath), "."+filepath.Base(jsonPath)+".*.tmp")
	if err != nil {
		return 0, fmt.Errorf("creating output file: %w", err)
	}
	tmpPath := outFile.Name()
	defer os.Remove(tmpPath)

	// Limit decompressed size to prevent decompression bombs
	written, err := io.Copy(outFile, io.LimitReader(reader, limit)) // nosemgrep: potential-dos-via-decompression-bomb
	if closeErr := outFile.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return written, fmt.Errorf("decompressing: %w", err)
	}

	if err := os.Rename(tmpPath, jsonPath); err != nil {
		return written, fmt.Errorf("renaming temp file: %w", err)
	}

	return written, nil
}

// sessionLocalDir returns the primary local directory retained for callers that
// only need the original single-account or legacy Control Tower layout.
func sessionLocalDir(session *sessions.Session, dataDir string) string {
	return cloudtrailpath.LocalRegionDirs(
		dataDir,
		session.Bucket,
		session.Mode,
		session.OrgID,
		session.AccountID,
		session.LogRegion,
	)[0]
}

// sessionDateDirs returns only the S3 delivery-date partitions selected by the
// session. Walking the account/region root mixes unrelated sessions into
// verification, extraction, and disk-usage accounting.
func sessionDateDirs(session *sessions.Session, dataDir string) ([]string, error) {
	start, err := time.Parse("2006-01-02", session.StartDate)
	if err != nil {
		return nil, fmt.Errorf("invalid session start_date: %w", err)
	}
	end, err := time.Parse("2006-01-02", session.EndDate)
	if err != nil {
		return nil, fmt.Errorf("invalid session end_date: %w", err)
	}
	if start.After(end) || end.Sub(start) > 90*24*time.Hour {
		return nil, fmt.Errorf("invalid session date range")
	}

	regionDirs := cloudtrailpath.LocalRegionDirs(
		dataDir,
		session.Bucket,
		session.Mode,
		session.OrgID,
		session.AccountID,
		session.LogRegion,
	)
	dirs := make([]string, 0, len(regionDirs)*int(end.Sub(start)/(24*time.Hour)+1))
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		for _, regionDir := range regionDirs {
			dirs = append(dirs, filepath.Join(regionDir,
				day.Format("2006"), day.Format("01"), day.Format("02")))
		}
	}
	return dirs, nil
}

// sendExtractProgress sends an extraction progress event.
func sendExtractProgress(ch chan<- ProcessingProgress, sessionID string, completed, total int) {
	var pct float64
	if total > 0 {
		pct = float64(completed) / float64(total) * 100
	}

	select {
	case ch <- ProcessingProgress{
		SessionID:      sessionID,
		Phase:          "extracting",
		FilesCompleted: completed,
		TotalFiles:     total,
		Percentage:     pct,
		Message:        fmt.Sprintf("Extracted %d/%d files", completed, total),
	}:
	default:
	}
}
