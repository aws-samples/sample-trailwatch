package processor

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/features/sessions"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Service orchestrates the S3 download pipeline for sessions.
type Service struct {
	db  *sql.DB
	cfg *config.Config

	// Track active processing pipelines per session
	mu       sync.Mutex
	active   map[string]context.CancelFunc
	progress map[string]chan ProcessingProgress
}

// NewService creates a new processor Service.
func NewService(db *sql.DB, cfg *config.Config) *Service {
	return &Service{
		db:       db,
		cfg:      cfg,
		active:   make(map[string]context.CancelFunc),
		progress: make(map[string]chan ProcessingProgress),
	}
}

// StartProcessing begins the download pipeline for a session.
// It validates the session state, then runs: list → estimate → check disk → download → extract → verify.
// Progress events are sent to progressCh throughout.
func (s *Service) StartProcessing(ctx context.Context, sessionID string, progressCh chan ProcessingProgress) error {
	// Load session
	session, err := sessions.GetByID(s.db, sessionID)
	if err != nil {
		return fmt.Errorf("loading session: %w", err)
	}

	// Validate session state
	if session.State != sessions.StatePending && session.State != sessions.StateInterrupted {
		return fmt.Errorf("session is in %q state, must be 'pending' or 'interrupted' to start processing", session.State)
	}

	// Register this pipeline as active
	s.mu.Lock()
	if _, exists := s.active[sessionID]; exists {
		s.mu.Unlock()
		return fmt.Errorf("session %s already has an active pipeline", sessionID)
	}
	pipelineCtx, cancel := context.WithCancel(ctx)
	s.active[sessionID] = cancel
	s.progress[sessionID] = progressCh
	s.mu.Unlock()

	// Ensure cleanup on exit
	defer func() {
		s.mu.Lock()
		delete(s.active, sessionID)
		delete(s.progress, sessionID)
		s.mu.Unlock()
		cancel()
	}()

	// Update state to downloading
	if err := sessions.UpdateState(s.db, sessionID, sessions.StateDownloading); err != nil {
		return fmt.Errorf("updating session state to downloading: %w", err)
	}

	// Load AWS config
	awsCfg, err := s.loadAWSConfig(pipelineCtx, session.Region)
	if err != nil {
		s.failSession(sessionID, progressCh, "Failed to load AWS configuration")
		return fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	// Phase 1: List objects
	s.sendProgress(progressCh, ProcessingProgress{
		SessionID: sessionID,
		Phase:     "listing",
		Message:   "Listing S3 objects...",
	})

	objects, totalSize, err := listObjects(pipelineCtx, client, session)
	if err != nil {
		s.failSession(sessionID, progressCh, "Failed to list S3 objects")
		return fmt.Errorf("listing objects: %w", err)
	}

	if len(objects) == 0 {
		s.failSession(sessionID, progressCh, "No .json.gz files found for this session")
		return fmt.Errorf("no objects found for session %s", sessionID)
	}

	slog.Info("listed S3 objects",
		"component", "cloudtrail-analyzer",
		"session_id", sessionID,
		"object_count", len(objects),
		"total_size_bytes", totalSize,
	)

	// Phase 2: Estimate disk and check availability
	estimate := s.estimateDisk(totalSize)
	if !estimate.Sufficient {
		s.failSession(sessionID, progressCh, fmt.Sprintf(
			"Insufficient disk space: need %d bytes, have %d bytes",
			estimate.RequiredBytes, estimate.AvailableBytes))
		return fmt.Errorf("insufficient disk space: need %d, have %d",
			estimate.RequiredBytes, estimate.AvailableBytes)
	}

	s.sendProgress(progressCh, ProcessingProgress{
		SessionID:  sessionID,
		Phase:      "listing",
		TotalFiles: len(objects),
		TotalBytes: totalSize,
		Message:    fmt.Sprintf("Found %d files (%d MB). Disk check passed.", len(objects), totalSize/(1024*1024)),
	})

	// Phase 3: Download files
	concurrency := s.cfg.MaxDownloadConcurrency
	if concurrency < 1 {
		concurrency = 4
	}

	dataDir := s.cfg.DataDir
	err = downloadFiles(pipelineCtx, client, session, objects, dataDir, concurrency, progressCh)
	if err != nil {
		if pipelineCtx.Err() != nil {
			// Cancelled — mark as interrupted
			_ = sessions.UpdateState(s.db, sessionID, sessions.StateInterrupted)
			s.sendProgress(progressCh, ProcessingProgress{
				SessionID: sessionID,
				Phase:     "downloading",
				Message:   "Processing cancelled",
			})
			return fmt.Errorf("processing cancelled: %w", err)
		}
		s.failSession(sessionID, progressCh, "Download failed")
		return fmt.Errorf("downloading files: %w", err)
	}

	// Phase 4: Extract files
	if err := sessions.UpdateState(s.db, sessionID, sessions.StateExtracting); err != nil {
		return fmt.Errorf("updating session state to extracting: %w", err)
	}

	err = extractFiles(pipelineCtx, session, dataDir, progressCh)
	if err != nil {
		if pipelineCtx.Err() != nil {
			_ = sessions.UpdateState(s.db, sessionID, sessions.StateInterrupted)
			s.sendProgress(progressCh, ProcessingProgress{
				SessionID: sessionID,
				Phase:     "extracting",
				Message:   "Processing cancelled",
			})
			return fmt.Errorf("processing cancelled: %w", err)
		}
		s.failSession(sessionID, progressCh, "Extraction failed")
		return fmt.Errorf("extracting files: %w", err)
	}

	// Phase 5: Verify files
	if err := sessions.UpdateState(s.db, sessionID, sessions.StateVerifying); err != nil {
		return fmt.Errorf("updating session state to verifying: %w", err)
	}

	totalVerified, failedFiles, err := verifyFiles(pipelineCtx, session, dataDir, progressCh)
	if err != nil {
		s.failSession(sessionID, progressCh, "Verification failed")
		return fmt.Errorf("verifying files: %w", err)
	}

	// Update session with results
	if err := updateSessionResults(s.db, sessionID, totalVerified, failedFiles); err != nil {
		slog.Warn("failed to update session results",
			"component", "cloudtrail-analyzer",
			"session_id", sessionID,
			"error", err.Error(),
		)
	}

	// Determine final state
	finalState := sessions.StateQueryReady
	if len(failedFiles) > 0 {
		finalState = sessions.StatePartiallyVerified
	}

	if err := sessions.UpdateState(s.db, sessionID, finalState); err != nil {
		return fmt.Errorf("updating session state to %s: %w", finalState, err)
	}

	s.sendProgress(progressCh, ProcessingProgress{
		SessionID:      sessionID,
		Phase:          "verifying",
		FilesCompleted: totalVerified,
		TotalFiles:     totalVerified,
		Percentage:     100,
		Message:        fmt.Sprintf("Complete. %d files verified, %d failed.", totalVerified, len(failedFiles)),
	})

	slog.Info("processing complete",
		"component", "cloudtrail-analyzer",
		"session_id", sessionID,
		"total_files", totalVerified,
		"failed_files", len(failedFiles),
		"final_state", string(finalState),
	)

	return nil
}

// CancelProcessing cancels the active pipeline for a session.
func (s *Service) CancelProcessing(sessionID string) error {
	s.mu.Lock()
	cancel, exists := s.active[sessionID]
	s.mu.Unlock()

	if !exists {
		return fmt.Errorf("no active pipeline for session %s", sessionID)
	}

	cancel()
	return nil
}

// GetProgressChannel returns the progress channel for a session, if active.
func (s *Service) GetProgressChannel(sessionID string) (chan ProcessingProgress, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, exists := s.progress[sessionID]
	return ch, exists
}

// estimateDisk calculates disk space requirements (2.5x S3 size for compressed + extracted).
func (s *Service) estimateDisk(totalS3Size int64) DiskEstimate {
	required := int64(float64(totalS3Size) * 2.5)
	available := s.getAvailableDiskSpace()

	return DiskEstimate{
		S3SizeBytes:    totalS3Size,
		RequiredBytes:  required,
		AvailableBytes: available,
		Sufficient:     available >= required,
	}
}

// getAvailableDiskSpace returns available bytes on the data directory filesystem.
func (s *Service) getAvailableDiskSpace() int64 {
	var stat syscall.Statfs_t
	path := s.cfg.DataDir
	if path == "" {
		path = "."
	}

	if err := syscall.Statfs(path, &stat); err != nil {
		slog.Warn("failed to check disk space",
			"component", "cloudtrail-analyzer",
			"path", path,
			"error", err.Error(),
		)
		// Return a large value so we don't block on disk check failure
		return int64(100 * 1024 * 1024 * 1024) // 100 GB fallback
	}

	return int64(stat.Bavail) * int64(stat.Bsize)
}

// failSession updates the session state to failed and sends a progress event.
func (s *Service) failSession(sessionID string, progressCh chan<- ProcessingProgress, message string) {
	_ = sessions.UpdateState(s.db, sessionID, sessions.StateFailed)
	s.sendProgress(progressCh, ProcessingProgress{
		SessionID: sessionID,
		Phase:     "failed",
		Message:   message,
	})
}

// sendProgress sends a progress event to the channel without blocking.
func (s *Service) sendProgress(ch chan<- ProcessingProgress, progress ProcessingProgress) {
	select {
	case ch <- progress:
	default:
		// Channel full or closed — skip this event
	}
}

// updateSessionResults updates the session's total_files and failed_files in the database.
func updateSessionResults(db *sql.DB, sessionID string, totalFiles int, failedFiles []string) error {
	failedJSON := "[]"
	if len(failedFiles) > 0 {
		// Simple JSON array construction
		failedJSON = "["
		for i, f := range failedFiles {
			if i > 0 {
				failedJSON += ","
			}
			failedJSON += fmt.Sprintf("%q", f)
		}
		failedJSON += "]"
	}

	query := `UPDATE sessions SET total_files = ?, failed_files = ?, updated_at = ? WHERE id = ?`
	_, err := db.Exec(query, totalFiles, failedJSON, time.Now().UTC().Format(time.RFC3339), sessionID)
	return err
}

// loadAWSConfig builds an AWS config using the configured auth method.
func (s *Service) loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	switch s.cfg.Auth.Method {
	case "session_credentials":
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				os.Getenv("AWS_ACCESS_KEY_ID"),
				os.Getenv("AWS_SECRET_ACCESS_KEY"),
				os.Getenv("AWS_SESSION_TOKEN"),
			)),
		)
	case "imds":
		imdsProvider := ec2rolecreds.New()
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(imdsProvider),
		)
	case "sso":
		opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
		if s.cfg.Auth.SSOProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(s.cfg.Auth.SSOProfile))
		}
		return awsconfig.LoadDefaultConfig(ctx, opts...)
	case "static":
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				s.cfg.Auth.AccessKeyID,
				s.cfg.Auth.SecretAccessKey,
				"",
			)),
		)
	default:
		return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	}
}
