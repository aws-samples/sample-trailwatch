package processor

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
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

	// Live snapshot of latest progress per session (for REST polling)
	snapMu    sync.RWMutex
	snapshots map[string]*ProgressSnapshot

	// OnFileExtracted is called each time a file is successfully extracted.
	OnFileExtracted func(jsonPath string, fileSize int64)

	// OnSyncComplete is called after a session reaches query_ready or partially_verified state.
	OnSyncComplete func()
}

// ProgressSnapshot holds the latest progress state for REST polling.
type ProgressSnapshot struct {
	ProcessingProgress
	StartedAt     time.Time `json:"started_at"`
	LastUpdatedAt time.Time `json:"last_updated_at"`
	Speed         float64   `json:"speed_bytes_per_sec"`
	FilesPerSec   float64   `json:"files_per_sec"`
	ETASeconds    int       `json:"eta_seconds"`
	Concurrency   int       `json:"concurrency"`
}

// NewService creates a new processor Service.
func NewService(db *sql.DB, cfg *config.Config) *Service {
	return &Service{
		db:        db,
		cfg:       cfg,
		active:    make(map[string]context.CancelFunc),
		progress:  make(map[string]chan ProcessingProgress),
		snapshots: make(map[string]*ProgressSnapshot),
	}
}

// GetProgressSnapshot returns the latest progress snapshot for a session.
func (s *Service) GetProgressSnapshot(sessionID string) (*ProgressSnapshot, bool) {
	s.snapMu.RLock()
	defer s.snapMu.RUnlock()
	snap, ok := s.snapshots[sessionID]
	return snap, ok
}

// updateSnapshot updates the in-memory progress snapshot for REST polling.
func (s *Service) updateSnapshot(sessionID string, p ProcessingProgress) {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()

	now := time.Now()
	snap, exists := s.snapshots[sessionID]
	if !exists {
		snap = &ProgressSnapshot{
			StartedAt:   now,
			Concurrency: s.cfg.MaxDownloadConcurrency,
		}
		s.snapshots[sessionID] = snap
	}

	elapsed := now.Sub(snap.StartedAt).Seconds()
	if elapsed > 0 && p.BytesTransferred > 0 {
		snap.Speed = float64(p.BytesTransferred) / elapsed
		snap.FilesPerSec = float64(p.FilesCompleted) / elapsed

		if snap.Speed > 0 && p.TotalBytes > p.BytesTransferred {
			remaining := float64(p.TotalBytes - p.BytesTransferred)
			snap.ETASeconds = int(remaining / snap.Speed)
		}
	}

	snap.ProcessingProgress = p
	snap.LastUpdatedAt = now
	snap.Concurrency = s.cfg.MaxDownloadConcurrency
}

// clearSnapshot removes the progress snapshot when a session completes.
func (s *Service) clearSnapshot(sessionID string) {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	delete(s.snapshots, sessionID)
}

// StartProcessing begins the download pipeline for a session.
// It validates the session state, then runs a pipelined: list → estimate → (download + extract concurrently) → verify.
// Download and extraction happen in parallel — files are extracted as soon as they're downloaded.
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

	// Load AWS config with optimized HTTP transport
	awsCfg, err := s.loadAWSConfig(pipelineCtx, session.Region)
	if err != nil {
		s.failSession(sessionID, progressCh, "Failed to load AWS configuration")
		return fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.HTTPClient = s.optimizedHTTPClient()
	})

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

	// Phase 3: Pipelined download + extract
	// Downloads and extraction run concurrently — each file is extracted immediately after download.
	concurrency := s.cfg.MaxDownloadConcurrency
	if concurrency < 1 {
		concurrency = 16
	}

	dataDir := s.cfg.DataDir
	err = s.downloadAndExtract(pipelineCtx, client, session, objects, dataDir, concurrency, totalSize, progressCh)
	if err != nil {
		if pipelineCtx.Err() != nil {
			_ = sessions.UpdateState(s.db, sessionID, sessions.StateInterrupted)
			s.sendProgress(progressCh, ProcessingProgress{
				SessionID: sessionID,
				Phase:     "downloading",
				Message:   "Processing cancelled",
			})
			return fmt.Errorf("processing cancelled: %w", err)
		}
		s.failSession(sessionID, progressCh, "Download/extraction failed")
		return fmt.Errorf("download and extract: %w", err)
	}

	// Phase 4: Verify files
	if err := sessions.UpdateState(s.db, sessionID, sessions.StateVerifying); err != nil {
		return fmt.Errorf("updating session state to verifying: %w", err)
	}

	totalVerified, diskBytes, failedFiles, err := verifyFiles(pipelineCtx, session, dataDir, progressCh)
	if err != nil {
		s.failSession(sessionID, progressCh, "Verification failed")
		return fmt.Errorf("verifying files: %w", err)
	}

	// Update session with results
	if err := updateSessionResults(s.db, sessionID, totalVerified, diskBytes, failedFiles); err != nil {
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

	s.clearSnapshot(sessionID)

	if s.OnSyncComplete != nil {
		go s.OnSyncComplete()
	}

	return nil
}

// downloadAndExtract runs a pipelined download + extraction. Workers download files from S3
// and immediately extract each .json.gz to .json in the same goroutine, eliminating the idle
// time between the download and extraction phases.
func (s *Service) downloadAndExtract(ctx context.Context, client *s3.Client, session *sessions.Session, objects []S3Object, dataDir string, concurrency int, totalBytes int64, progressCh chan<- ProcessingProgress) error {
	workCh := make(chan S3Object, concurrency*2)
	var wg sync.WaitGroup

	var filesCompleted atomic.Int64
	var bytesTransferred atomic.Int64
	totalFiles := len(objects)

	var downloadErr error
	var errOnce sync.Once

	// Start workers — each worker downloads AND extracts
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for obj := range workCh {
				if ctx.Err() != nil {
					return
				}

				localPath := constructLocalPath(dataDir, session.Bucket, obj.Key)
				jsonPath := localPath[:len(localPath)-3] // strip .gz

				// Skip if already fully processed (extracted json exists)
				if info, err := os.Stat(jsonPath); err == nil && info.Size() > 0 {
					completed := filesCompleted.Add(1)
					bytesTransferred.Add(obj.Size)
					s.sendPipelineProgress(progressCh, session.ID, int(completed), totalFiles, bytesTransferred.Load(), totalBytes)
					continue
				}

				// Skip download if .gz already exists with matching size
				needsDownload := true
				if info, err := os.Stat(localPath); err == nil && info.Size() == obj.Size {
					needsDownload = false
				}

				if needsDownload {
					if err := downloadSingleFile(ctx, client, session.Bucket, obj.Key, localPath); err != nil {
						slog.Error("failed to download file",
							"component", "cloudtrail-analyzer",
							"session_id", session.ID,
							"key", obj.Key,
							"error", err.Error(),
						)
						errOnce.Do(func() {
							downloadErr = fmt.Errorf("downloading %s: %w", obj.Key, err)
						})
						return
					}
				}

				// Extract immediately after download
				if _, err := extractSingleFileWithLimit(localPath, jsonPath, maxPerFileBytes); err != nil {
					slog.Warn("failed to extract file",
						"component", "cloudtrail-analyzer",
						"session_id", session.ID,
						"file", localPath,
						"error", err.Error(),
					)
				} else if s.OnFileExtracted != nil {
					info, _ := os.Stat(jsonPath)
					if info != nil {
						s.OnFileExtracted(jsonPath, info.Size())
					}
				}

				completed := filesCompleted.Add(1)
				bytesTransferred.Add(obj.Size)
				s.sendPipelineProgress(progressCh, session.ID, int(completed), totalFiles, bytesTransferred.Load(), totalBytes)
			}
		}()
	}

	// Feed work
	for _, obj := range objects {
		if ctx.Err() != nil {
			break
		}
		workCh <- obj
	}
	close(workCh)

	wg.Wait()
	return downloadErr
}

// sendPipelineProgress sends a combined download+extract progress event and updates the snapshot.
func (s *Service) sendPipelineProgress(ch chan<- ProcessingProgress, sessionID string, completed, total int, bytesTransferred, totalBytes int64) {
	var pct float64
	if totalBytes > 0 {
		pct = float64(bytesTransferred) / float64(totalBytes) * 100
	}

	p := ProcessingProgress{
		SessionID:        sessionID,
		Phase:            "downloading",
		FilesCompleted:   completed,
		TotalFiles:       total,
		BytesTransferred: bytesTransferred,
		TotalBytes:       totalBytes,
		Percentage:       pct,
		Message:          fmt.Sprintf("Processed %d/%d files (download + extract)", completed, total),
	}

	// Always update the snapshot for REST polling
	s.updateSnapshot(sessionID, p)

	select {
	case ch <- p:
	default:
	}
}


// optimizedHTTPClient returns an HTTP client tuned for high-throughput S3 downloads.
// High connection pool limits allow many parallel requests to the same S3 endpoint,
// critical for PrivateLink and VPC endpoint scenarios where latency is minimal.
func (s *Service) optimizedHTTPClient() *http.Client {
	concurrency := s.cfg.MaxDownloadConcurrency
	if concurrency < 16 {
		concurrency = 16
	}
	poolSize := concurrency * 4

	transport := &http.Transport{
		MaxIdleConns:        poolSize,
		MaxIdleConnsPerHost: poolSize,
		MaxConnsPerHost:     poolSize,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    true, // S3 objects are already gzipped
	}

	return &http.Client{
		Transport: transport,
		Timeout:   0, // No overall timeout — context handles cancellation
	}
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

	// Update state immediately so the UI reflects cancellation without waiting
	// for the goroutine to notice the context cancellation.
	_ = sessions.UpdateState(s.db, sessionID, sessions.StateInterrupted)
	s.clearSnapshot(sessionID)

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
	s.updateSnapshot(progress.SessionID, progress)
	select {
	case ch <- progress:
	default:
	}
}

// updateSessionResults updates the session's total_files, disk_usage_bytes, and failed_files in the database.
func updateSessionResults(db *sql.DB, sessionID string, totalFiles int, diskBytes int64, failedFiles []string) error {
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

	query := `UPDATE sessions SET total_files = ?, disk_usage_bytes = ?, failed_files = ?, updated_at = ? WHERE id = ?`
	_, err := db.Exec(query, totalFiles, diskBytes, failedJSON, time.Now().UTC().Format(time.RFC3339), sessionID)
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
