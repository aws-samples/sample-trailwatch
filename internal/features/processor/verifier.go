package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cloudtrail-analyzer/internal/features/sessions"
)

// verifyFiles walks the session directory, counts all .json files, and validates
// each is valid JSON. Returns total count and list of failed file paths.
func verifyFiles(ctx context.Context, session *sessions.Session, dataDir string, progressCh chan<- ProcessingProgress) (int, []string, error) {
	sessionDir := sessionLocalDir(session, dataDir)

	// Collect all .json files
	var jsonFiles []string
	err := filepath.Walk(sessionDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") && !strings.HasSuffix(path, ".json.gz") {
			jsonFiles = append(jsonFiles, path)
		}
		return nil
	})
	if err != nil {
		return 0, nil, fmt.Errorf("walking session directory %s: %w", sessionDir, err)
	}

	totalFiles := len(jsonFiles)
	var failedFiles []string
	completed := 0

	for _, jsonPath := range jsonFiles {
		if ctx.Err() != nil {
			return completed, failedFiles, ctx.Err()
		}

		if err := validateJSONFile(jsonPath); err != nil {
			// Store relative path for readability
			relPath, _ := filepath.Rel(dataDir, jsonPath)
			if relPath == "" {
				relPath = jsonPath
			}
			failedFiles = append(failedFiles, relPath)
		}

		completed++
		sendVerifyProgress(progressCh, session.ID, completed, totalFiles)
	}

	return totalFiles, failedFiles, nil
}

// validateJSONFile checks if a file contains valid JSON by attempting to decode it.
func validateJSONFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	return nil
}

// sendVerifyProgress sends a verification progress event.
func sendVerifyProgress(ch chan<- ProcessingProgress, sessionID string, completed, total int) {
	var pct float64
	if total > 0 {
		pct = float64(completed) / float64(total) * 100
	}

	select {
	case ch <- ProcessingProgress{
		SessionID:      sessionID,
		Phase:          "verifying",
		FilesCompleted: completed,
		TotalFiles:     total,
		Percentage:     pct,
		Message:        fmt.Sprintf("Verified %d/%d files", completed, total),
	}:
	default:
	}
}
