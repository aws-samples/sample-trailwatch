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

	"cloudtrail-analyzer/internal/features/sessions"
)

const (
	// maxPerFileBytes is the maximum decompressed size for a single .json.gz file (256 MB).
	maxPerFileBytes int64 = 256 * 1024 * 1024
	// maxTotalExtractBytes is the maximum total decompressed output for one extraction run (4 GB).
	maxTotalExtractBytes int64 = 4 * 1024 * 1024 * 1024
)

// extractFiles walks the session's local directory and decompresses all .json.gz files.
// It is idempotent: if the .json file already exists, the .gz is skipped.
// A total extraction byte limit is enforced across all files to guard against decompression bombs.
func extractFiles(ctx context.Context, session *sessions.Session, dataDir string, progressCh chan<- ProcessingProgress) error {
	sessionDir := sessionLocalDir(session, dataDir)

	// Count total .gz files first for progress reporting
	var gzFiles []string
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

	// Write to temp file first, then rename
	tmpPath := jsonPath + ".tmp"
	outFile, err := os.Create(tmpPath)
	if err != nil {
		return 0, fmt.Errorf("creating output file: %w", err)
	}

	// Limit decompressed size to prevent decompression bombs
	written, err := io.Copy(outFile, io.LimitReader(reader, limit)) // nosemgrep: potential-dos-via-decompression-bomb
	if closeErr := outFile.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmpPath)
		return written, fmt.Errorf("decompressing: %w", err)
	}

	if err := os.Rename(tmpPath, jsonPath); err != nil {
		os.Remove(tmpPath)
		return written, fmt.Errorf("renaming temp file: %w", err)
	}

	return written, nil
}

// sessionLocalDir returns the base local directory for a session's downloaded files.
func sessionLocalDir(session *sessions.Session, dataDir string) string {
	if session.Mode == "control_tower" && session.OrgID != "" {
		return filepath.Join(dataDir, "s3", session.Bucket,
			session.OrgID, "AWSLogs", session.OrgID, session.AccountID, "CloudTrail", session.LogRegion)
	}

	return filepath.Join(dataDir, "s3", session.Bucket,
		"AWSLogs", session.AccountID, "CloudTrail", session.LogRegion)
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
