package sessions

import (
	"database/sql"
	"fmt"
	"time"
)

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

// MarkInterrupted marks all sessions in downloading or extracting state as interrupted.
// This is called on startup to handle sessions that were in progress when the app stopped.
func MarkInterrupted(db *sql.DB) error {
	query := `UPDATE sessions SET state = ?, updated_at = ? WHERE state IN (?, ?)`
	_, err := db.Exec(query,
		StateInterrupted,
		time.Now().UTC().Format(time.RFC3339),
		StateDownloading,
		StateExtracting,
	)
	if err != nil {
		return fmt.Errorf("marking interrupted sessions: %w", err)
	}
	return nil
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
			return nil, fmt.Errorf("session not found")
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
