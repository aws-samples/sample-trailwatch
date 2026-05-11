package sessions

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/features/settings"

	"github.com/google/uuid"
)

// Service provides session lifecycle orchestration.
type Service struct {
	db  *sql.DB
	cfg *config.Config
}

// NewService creates a new sessions Service.
func NewService(db *sql.DB, cfg *config.Config) *Service {
	return &Service{
		db:  db,
		cfg: cfg,
	}
}

// CreateSession validates the request, generates a UUID, reads bucket/region/mode
// from config, and inserts the session into SQLite.
func (s *Service) CreateSession(ctx context.Context, req *CreateSessionRequest) (*Session, error) {
	// Validate date range
	if err := settings.ValidateDateRange(req.StartDate, req.EndDate); err != nil {
		return nil, fmt.Errorf("invalid date range: %w", err)
	}

	// Validate required fields
	if req.AccountID == "" {
		return nil, fmt.Errorf("account_id is required")
	}
	if req.LogRegion == "" {
		return nil, fmt.Errorf("log_region is required")
	}

	// Read bucket/region/mode from saved config
	bucket := s.cfg.S3.Bucket
	region := s.cfg.S3.Region
	mode := s.cfg.S3.Mode
	orgID := s.cfg.S3.OrgID

	if bucket == "" {
		return nil, fmt.Errorf("S3 bucket not configured — configure it in Settings first")
	}
	if region == "" {
		return nil, fmt.Errorf("S3 region not configured — configure it in Settings first")
	}

	// Use org_id from request if provided, otherwise fall back to config
	if req.OrgID != "" {
		orgID = req.OrgID
	}

	now := time.Now().UTC()
	session := &Session{
		ID:             uuid.New().String(),
		Bucket:         bucket,
		AccountID:      req.AccountID,
		OrgID:          orgID,
		Region:         region,
		LogRegion:      req.LogRegion,
		Mode:           mode,
		StartDate:      req.StartDate,
		EndDate:        req.EndDate,
		State:          StatePending,
		TotalFiles:     0,
		DiskUsageBytes: 0,
		FailedFiles:    "[]",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := Create(s.db, session); err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	slog.Info("session created",
		"component", "cloudtrail-analyzer",
		"session_id", session.ID,
		"account_id", session.AccountID,
		"log_region", session.LogRegion,
		"start_date", session.StartDate,
		"end_date", session.EndDate,
	)

	return session, nil
}

// ListSessions returns all sessions ordered by created_at DESC.
func (s *Service) ListSessions(ctx context.Context) ([]Session, error) {
	sessions, err := List(s.db)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	return sessions, nil
}

// GetSession retrieves a session by ID.
func (s *Service) GetSession(ctx context.Context, id string) (*Session, error) {
	session, err := GetByID(s.db, id)
	if err != nil {
		return nil, fmt.Errorf("getting session: %w", err)
	}
	return session, nil
}

// DeleteSession removes a session from SQLite and deletes its local files.
func (s *Service) DeleteSession(ctx context.Context, id string) error {
	// Get session details before deleting (for file cleanup)
	session, err := GetByID(s.db, id)
	if err != nil {
		return fmt.Errorf("getting session for deletion: %w", err)
	}

	// Delete from database
	if err := Delete(s.db, id); err != nil {
		return fmt.Errorf("deleting session from database: %w", err)
	}

	// Remove local files
	localPath := s.localSessionPath(session)
	if localPath != "" {
		if err := os.RemoveAll(localPath); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to remove session files",
				"component", "cloudtrail-analyzer",
				"session_id", id,
				"path", localPath,
				"error", err.Error(),
			)
		} else {
			slog.Info("session files removed",
				"component", "cloudtrail-analyzer",
				"session_id", id,
				"path", localPath,
			)
		}
	}

	slog.Info("session deleted",
		"component", "cloudtrail-analyzer",
		"session_id", id,
	)

	return nil
}

// localSessionPath builds the local filesystem path for a session's downloaded files.
func (s *Service) localSessionPath(session *Session) string {
	if session.Bucket == "" || session.AccountID == "" || session.LogRegion == "" {
		return ""
	}

	if session.Mode == "control_tower" && session.OrgID != "" {
		return filepath.Join(s.cfg.DataDir, "s3", session.Bucket,
			session.OrgID, "AWSLogs", session.OrgID, session.AccountID, "CloudTrail", session.LogRegion)
	}

	return filepath.Join(s.cfg.DataDir, "s3", session.Bucket,
		"AWSLogs", session.AccountID, "CloudTrail", session.LogRegion)
}
