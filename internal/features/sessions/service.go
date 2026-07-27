package sessions

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloudtrail-analyzer/internal/cloudtrailpath"
	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/features/settings"

	"github.com/google/uuid"
)

// Service provides session lifecycle orchestration.
type Service struct {
	db              *sql.DB
	cfg             *config.Config
	beginDataDelete func() (func(), error)
	createMu        sync.Mutex
	deleteMu        sync.Mutex
}

var (
	ErrSessionActive     = errors.New("session is active")
	ErrSessionOverlap    = errors.New("session date range overlaps existing data")
	ErrUnsafeSessionPath = errors.New("unsafe session path")
)

// NewService creates a new sessions Service.
func NewService(db *sql.DB, cfg *config.Config) *Service {
	return &Service{
		db:  db,
		cfg: cfg,
	}
}

// SetDataDeleteLease registers a hook that invalidates derived data and keeps
// index writers excluded until raw-file and metadata deletion finishes.
func (s *Service) SetDataDeleteLease(fn func() (func(), error)) {
	s.beginDataDelete = fn
}

// SetBeforeDataDelete adapts legacy one-shot hooks used by focused tests.
func (s *Service) SetBeforeDataDelete(fn func() error) {
	s.SetDataDeleteLease(func() (func(), error) {
		if err := fn(); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
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
	if !isValidAccountID(req.AccountID) {
		return nil, fmt.Errorf("account_id must be a 12-digit AWS account ID")
	}
	if !config.IsSafePathSegment(req.LogRegion) {
		return nil, fmt.Errorf("log_region contains characters not allowed in a path segment")
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

	for field, value := range map[string]string{
		"bucket": bucket,
		"region": region,
		"org_id": orgID,
	} {
		if value != "" && !config.IsSafePathSegment(value) {
			return nil, fmt.Errorf("%s contains characters not allowed in a path segment", field)
		}
	}
	if mode == cloudtrailpath.MultiAccountMode && orgID == "" {
		return nil, fmt.Errorf("org_id must be configured for control_tower mode")
	}
	// Org ID is configuration-owned. Accept the field for compatibility with
	// existing clients, but do not let a session override the configured scope.
	if req.OrgID != "" && req.OrgID != orgID {
		return nil, fmt.Errorf("org_id does not match the saved S3 configuration")
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

	// Local files use canonical S3 paths rather than per-session copies.
	// Serialize overlap-check + insert so two concurrent requests cannot claim
	// the same date partition.
	s.createMu.Lock()
	defer s.createMu.Unlock()
	overlaps, err := HasOverlappingSession(s.db, session, session.ID)
	if err != nil {
		return nil, err
	}
	if overlaps {
		return nil, fmt.Errorf("%w: delete the existing overlapping session or choose another date range", ErrSessionOverlap)
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
	s.deleteMu.Lock()
	defer s.deleteMu.Unlock()

	session, priorState, err := ClaimForDeletion(s.db, id)
	if err != nil {
		return fmt.Errorf("claiming session for deletion: %w", err)
	}
	restoreClaim := true
	defer func() {
		if restoreClaim {
			if restoreErr := RestoreDeletionClaim(s.db, id, priorState); restoreErr != nil {
				slog.Error("failed to restore session after deletion error",
					"component", "cloudtrail-analyzer",
					"session_id", id,
					"error", restoreErr.Error(),
				)
			}
		}
	}()

	datePaths, err := s.localSessionDatePaths(session)
	if err != nil {
		return err
	}

	var releaseDataDelete func()
	if s.beginDataDelete != nil {
		releaseDataDelete, err = s.beginDataDelete()
		if err != nil {
			return fmt.Errorf("preparing index for data deletion: %w", err)
		}
		defer releaseDataDelete()
	}

	var removed int
	for _, partition := range datePaths {
		referenced, err := DateReferencedByOtherSession(s.db, session, partition.date)
		if err != nil {
			return err
		}
		if referenced {
			continue
		}

		removedDate := false
		for _, localPath := range partition.paths {
			pathRemoved, err := removeSessionPath(filepath.Join(s.cfg.DataDir, "s3"), localPath)
			if err != nil {
				return err
			}
			removedDate = removedDate || pathRemoved
		}
		if removedDate {
			removed++
		}
	}

	// Remove metadata only after filesystem cleanup succeeds. A failed cleanup
	// leaves the session visible so the user can retry rather than reporting a
	// successful deletion while data remains on disk.
	if err := Delete(s.db, id); err != nil {
		return fmt.Errorf("deleting session from database: %w", err)
	}
	restoreClaim = false

	slog.Info("session deleted",
		"component", "cloudtrail-analyzer",
		"session_id", id,
		"date_partitions_removed", removed,
	)

	return nil
}

type localSessionDatePaths struct {
	date  string
	paths []string
}

// localSessionPaths returns the delivery-date directories owned by a session.
// Deleting the account/region root would also erase unrelated sessions, so
// cleanup is constrained to YYYY/MM/DD partitions inside the session range.
func (s *Service) localSessionPaths(session *Session) ([]string, error) {
	datePaths, err := s.localSessionDatePaths(session)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, partition := range datePaths {
		paths = append(paths, partition.paths...)
	}
	return paths, nil
}

func (s *Service) localSessionDatePaths(session *Session) ([]localSessionDatePaths, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: session is nil", ErrUnsafeSessionPath)
	}
	if s.cfg == nil || s.cfg.DataDir == "" {
		return nil, fmt.Errorf("%w: data directory is empty", ErrUnsafeSessionPath)
	}
	for field, value := range map[string]string{
		"bucket":     session.Bucket,
		"account_id": session.AccountID,
		"log_region": session.LogRegion,
		"org_id":     session.OrgID,
	} {
		if value == "" && field != "org_id" {
			return nil, fmt.Errorf("%w: %s is empty", ErrUnsafeSessionPath, field)
		}
		if value != "" && !config.IsSafePathSegment(value) {
			return nil, fmt.Errorf("%w: %s is not a safe path segment", ErrUnsafeSessionPath, field)
		}
	}
	if !isValidAccountID(session.AccountID) {
		return nil, fmt.Errorf("%w: account_id must be 12 digits", ErrUnsafeSessionPath)
	}
	if session.Mode == cloudtrailpath.MultiAccountMode && session.OrgID == "" {
		return nil, fmt.Errorf("%w: org_id is empty for control_tower mode", ErrUnsafeSessionPath)
	}

	start, err := time.Parse("2006-01-02", session.StartDate)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid start_date", ErrUnsafeSessionPath)
	}
	end, err := time.Parse("2006-01-02", session.EndDate)
	if err != nil || start.After(end) || end.Sub(start) > 90*24*time.Hour {
		return nil, fmt.Errorf("%w: invalid end_date or date range", ErrUnsafeSessionPath)
	}

	root := filepath.Join(s.cfg.DataDir, "s3")
	regionDirs := cloudtrailpath.LocalRegionDirs(
		s.cfg.DataDir,
		session.Bucket,
		session.Mode,
		session.OrgID,
		session.AccountID,
		session.LogRegion,
	)

	seen := make(map[string]struct{})
	var datePaths []localSessionDatePaths
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		partition := localSessionDatePaths{date: day.Format("2006-01-02")}
		for _, regionDir := range regionDirs {
			path := filepath.Join(regionDir, day.Format("2006"), day.Format("01"), day.Format("02"))
			if err := ensurePathWithin(root, path); err != nil {
				return nil, err
			}

			key, err := filepath.Abs(path)
			if err != nil {
				return nil, fmt.Errorf("%w: resolving session path", ErrUnsafeSessionPath)
			}
			key = filepath.Clean(key)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			partition.paths = append(partition.paths, path)
		}
		datePaths = append(datePaths, partition)
	}
	return datePaths, nil
}

func ensurePathWithin(root, candidate string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("%w: resolving data root", ErrUnsafeSessionPath)
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return fmt.Errorf("%w: resolving session path", ErrUnsafeSessionPath)
	}
	if !isPathWithin(absRoot, absCandidate, false) {
		return fmt.Errorf("%w: path escapes data directory", ErrUnsafeSessionPath)
	}

	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: resolving data root", ErrUnsafeSessionPath)
	}

	existing := absCandidate
	for {
		resolved, resolveErr := filepath.EvalSymlinks(existing)
		if resolveErr == nil {
			if !isPathWithin(resolvedRoot, resolved, true) {
				return fmt.Errorf("%w: path resolves outside data directory", ErrUnsafeSessionPath)
			}
			return nil
		}
		if !os.IsNotExist(resolveErr) {
			return fmt.Errorf("%w: resolving session path", ErrUnsafeSessionPath)
		}
		if existing == absRoot {
			return nil
		}
		existing = filepath.Dir(existing)
	}
}

func isPathWithin(root, candidate string, allowRoot bool) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return allowRoot || rel != "."
}

func removeSessionPath(root, path string) (bool, error) {
	if err := ensurePathWithin(root, path); err != nil {
		return false, err
	}
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("checking session files: %w", err)
	}
	if err := os.RemoveAll(path); err != nil {
		return false, fmt.Errorf("removing session files: %w", err)
	}
	return true, nil
}

func isValidAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
