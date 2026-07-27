package sessions

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrNotFound = errors.New("session not found")

// Create inserts a new session into the database.
func Create(db *sql.DB, session *Session) error {
	query := `
		INSERT INTO sessions (id, bucket, account_id, org_id, region, log_region, mode, start_date, end_date, state, total_files, disk_usage_bytes, failed_files, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query,
		session.ID,
		session.Bucket,
		session.AccountID,
		session.OrgID,
		session.Region,
		session.LogRegion,
		session.Mode,
		session.StartDate,
		session.EndDate,
		session.State,
		session.TotalFiles,
		session.DiskUsageBytes,
		session.FailedFiles,
		session.CreatedAt.UTC().Format(time.RFC3339),
		session.UpdatedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting session: %w", err)
	}
	return nil
}

// GetByID retrieves a session by its ID.
func GetByID(db *sql.DB, id string) (*Session, error) {
	query := `
		SELECT id, bucket, account_id, org_id, region, log_region, mode, start_date, end_date, state, total_files, disk_usage_bytes, failed_files, created_at, updated_at
		FROM sessions
		WHERE id = ?
	`
	row := db.QueryRow(query, id)
	return scanSession(row)
}

// List returns all sessions ordered by created_at DESC.
func List(db *sql.DB) ([]Session, error) {
	query := `
		SELECT id, bucket, account_id, org_id, region, log_region, mode, start_date, end_date, state, total_files, disk_usage_bytes, failed_files, created_at, updated_at
		FROM sessions
		ORDER BY created_at DESC
	`
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		var createdAt, updatedAt string
		err := rows.Scan(
			&s.ID, &s.Bucket, &s.AccountID, &s.OrgID, &s.Region, &s.LogRegion,
			&s.Mode, &s.StartDate, &s.EndDate, &s.State, &s.TotalFiles,
			&s.DiskUsageBytes, &s.FailedFiles, &createdAt, &updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning session row: %w", err)
		}
		s.CreatedAt = parseSessionTime(createdAt)
		s.UpdatedAt = parseSessionTime(updatedAt)
		if s.UpdatedAt.IsZero() {
			s.UpdatedAt = s.CreatedAt
		}
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating session rows: %w", err)
	}
	return sessions, nil
}

// UpdateState updates the state of a session and sets updated_at to now.
func UpdateState(db *sql.DB, id string, state SessionState) error {
	query := `UPDATE sessions SET state = ?, updated_at = ? WHERE id = ?`
	result, err := db.Exec(query, state, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("updating session state: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("session %s not found", id)
	}
	return nil
}

// ClaimForProcessing atomically transitions a resumable session to downloading
// and returns its persisted configuration. A concurrent start or deletion can
// win the state transition, but never both.
func ClaimForProcessing(db *sql.DB, id string) (*Session, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("starting processing claim: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`UPDATE sessions SET state = ?, updated_at = ?
		 WHERE id = ? AND state IN (?, ?)`,
		StateDownloading, time.Now().UTC().Format(time.RFC3339), id,
		StatePending, StateInterrupted,
	)
	if err != nil {
		return nil, fmt.Errorf("claiming session for processing: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("checking processing claim: %w", err)
	}
	if rows != 1 {
		session, getErr := scanSession(tx.QueryRow(`
			SELECT id, bucket, account_id, org_id, region, log_region, mode,
			       start_date, end_date, state, total_files, disk_usage_bytes,
			       failed_files, created_at, updated_at
			FROM sessions WHERE id = ?`, id))
		if getErr != nil {
			return nil, getErr
		}
		return nil, fmt.Errorf("session is in %q state, must be pending or interrupted", session.State)
	}

	session, err := scanSession(tx.QueryRow(`
		SELECT id, bucket, account_id, org_id, region, log_region, mode,
		       start_date, end_date, state, total_files, disk_usage_bytes,
		       failed_files, created_at, updated_at
		FROM sessions WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing processing claim: %w", err)
	}
	return session, nil
}

// MarkInterruptedIfActive records a cancellation without overwriting a terminal
// state that may already have committed.
func MarkInterruptedIfActive(db *sql.DB, id string) error {
	_, err := db.Exec(
		`UPDATE sessions SET state = ?, updated_at = ?
		 WHERE id = ? AND state IN (?, ?, ?)`,
		StateInterrupted, time.Now().UTC().Format(time.RFC3339), id,
		StateDownloading, StateExtracting, StateVerifying,
	)
	if err != nil {
		return fmt.Errorf("marking active session interrupted: %w", err)
	}
	return nil
}

// CompleteProcessing atomically publishes verification results and the final
// state. It refuses to overwrite cancellation/deletion state.
func CompleteProcessing(
	db *sql.DB,
	id string,
	totalFiles int,
	diskBytes int64,
	failedFiles []string,
	finalState SessionState,
) error {
	failedJSON, err := json.Marshal(failedFiles)
	if err != nil {
		return fmt.Errorf("encoding failed files: %w", err)
	}
	result, err := db.Exec(
		`UPDATE sessions
		 SET total_files = ?, disk_usage_bytes = ?, failed_files = ?,
		     state = ?, updated_at = ?
		 WHERE id = ? AND state = ?`,
		totalFiles, diskBytes, string(failedJSON), finalState,
		time.Now().UTC().Format(time.RFC3339), id, StateVerifying,
	)
	if err != nil {
		return fmt.Errorf("completing session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking session completion: %w", err)
	}
	if rows != 1 {
		return fmt.Errorf("session completion lost its verifying-state claim")
	}
	return nil
}

// ClaimForDeletion atomically marks a non-active session deleted and returns
// both its metadata and prior state so callers can restore it after cleanup
// failure.
func ClaimForDeletion(db *sql.DB, id string) (*Session, SessionState, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, "", fmt.Errorf("starting deletion claim: %w", err)
	}
	defer tx.Rollback()

	session, err := scanSession(tx.QueryRow(`
		SELECT id, bucket, account_id, org_id, region, log_region, mode,
		       start_date, end_date, state, total_files, disk_usage_bytes,
		       failed_files, created_at, updated_at
		FROM sessions WHERE id = ?`, id))
	if err != nil {
		return nil, "", err
	}
	switch session.State {
	case StateDownloading, StateExtracting, StateVerifying:
		return nil, "", ErrSessionActive
	case StateDeleted:
		return nil, "", fmt.Errorf("session deletion is already in progress")
	}

	priorState := session.State
	result, err := tx.Exec(
		`UPDATE sessions SET state = ?, updated_at = ?
		 WHERE id = ? AND state = ?`,
		StateDeleted, time.Now().UTC().Format(time.RFC3339), id, priorState,
	)
	if err != nil {
		return nil, "", fmt.Errorf("claiming session for deletion: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, "", fmt.Errorf("checking deletion claim: %w", err)
	}
	if rows != 1 {
		return nil, "", fmt.Errorf("session state changed while claiming deletion")
	}
	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("committing deletion claim: %w", err)
	}
	session.State = StateDeleted
	return session, priorState, nil
}

// RestoreDeletionClaim makes a failed deletion retryable without overwriting a
// later state transition.
func RestoreDeletionClaim(db *sql.DB, id string, priorState SessionState) error {
	_, err := db.Exec(
		`UPDATE sessions SET state = ?, updated_at = ? WHERE id = ? AND state = ?`,
		priorState, time.Now().UTC().Format(time.RFC3339), id, StateDeleted,
	)
	if err != nil {
		return fmt.Errorf("restoring deletion claim: %w", err)
	}
	return nil
}

// Delete removes a session from the database.
func Delete(db *sql.DB, id string) error {
	query := `DELETE FROM sessions WHERE id = ?`
	result, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("session %s not found", id)
	}
	return nil
}

// MarkInterrupted marks all sessions left in an in-flight state as interrupted.
// It is called on startup to recover sessions that were mid-pipeline when the
// app stopped (crash, SIGTERM, or a shutdown that cancelled the pipeline). The
// in-flight states are downloading, extracting, and verifying — the pipeline
// transitions downloading -> verifying -> query-ready, so a crash during the
// verify phase would otherwise leave the session stuck forever.
func MarkInterrupted(db *sql.DB) (int64, error) {
	query := `UPDATE sessions SET state = ?, updated_at = ? WHERE state IN (?, ?, ?)`
	result, err := db.Exec(query,
		StateInterrupted,
		time.Now().UTC().Format(time.RFC3339),
		StateDownloading,
		StateExtracting,
		StateVerifying,
	)
	if err != nil {
		return 0, fmt.Errorf("marking interrupted sessions: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("checking rows affected: %w", err)
	}
	return rows, nil
}

// HasOverlappingSession reports whether another session owns any date in the
// same bucket/account/region scope.
func HasOverlappingSession(db *sql.DB, session *Session, excludeID string) (bool, error) {
	var exists int
	err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM sessions
		WHERE id <> ?
		  AND bucket = ? AND account_id = ? AND org_id = ?
		  AND log_region = ? AND mode = ?
		  AND start_date <= ? AND end_date >= ?
	)`,
		excludeID,
		session.Bucket, session.AccountID, session.OrgID,
		session.LogRegion, session.Mode,
		session.EndDate, session.StartDate,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("checking overlapping sessions: %w", err)
	}
	return exists != 0, nil
}

// DateReferencedByOtherSession reports whether another session in the same
// storage scope references a delivery-date partition.
func DateReferencedByOtherSession(db *sql.DB, session *Session, date string) (bool, error) {
	var exists int
	err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM sessions
		WHERE id <> ?
		  AND bucket = ? AND account_id = ? AND org_id = ?
		  AND log_region = ? AND mode = ?
		  AND start_date <= ? AND end_date >= ?
	)`,
		session.ID,
		session.Bucket, session.AccountID, session.OrgID,
		session.LogRegion, session.Mode,
		date, date,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("checking session date references: %w", err)
	}
	return exists != 0, nil
}

// scanSession scans a single row into a Session struct.
func scanSession(row *sql.Row) (*Session, error) {
	var s Session
	var createdAt, updatedAt string
	err := row.Scan(
		&s.ID, &s.Bucket, &s.AccountID, &s.OrgID, &s.Region, &s.LogRegion,
		&s.Mode, &s.StartDate, &s.EndDate, &s.State, &s.TotalFiles,
		&s.DiskUsageBytes, &s.FailedFiles, &createdAt, &updatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanning session: %w", err)
	}
	s.CreatedAt = parseSessionTime(createdAt)
	s.UpdatedAt = parseSessionTime(updatedAt)
	if s.UpdatedAt.IsZero() {
		s.UpdatedAt = s.CreatedAt
	}
	return &s, nil
}

// parseSessionTime accepts both RFC3339 (Go writes) and SQLite's default
// 'YYYY-MM-DD HH:MM:SS' format (when datetime('now') is used as a column default).
// Returns zero time if the value is empty or unparseable.
func parseSessionTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
