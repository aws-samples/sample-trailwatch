package database

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB connection to the SQLite database.
type DB struct {
	Conn *sql.DB
}

// NewDB opens a SQLite database at {dataDir}/sessions.db.
// It creates the data directory if it does not exist.
func NewDB(dataDir string) (*DB, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0700); err != nil { // nosemgrep: incorrect-default-permission
		return nil, fmt.Errorf("creating data directory %s: %w", dataDir, err)
	}

	dbPath := filepath.Join(dataDir, "sessions.db")

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database at %s: %w", dbPath, err)
	}

	// Verify the connection is working
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pinging sqlite database: %w", err)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	// Enable foreign keys
	if _, err := conn.Exec("PRAGMA foreign_keys=ON"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}

	slog.Info("sqlite database opened", "path", dbPath)

	return &DB{Conn: conn}, nil
}

// RunMigrations reads and executes all .sql files from the migrations/ directory
// in alphabetical order. Migration files should be idempotent (use IF NOT EXISTS).
func (db *DB) RunMigrations() error {
	migrationsDir := "migrations"

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("reading migrations directory %s: %w", migrationsDir, err)
	}

	// Collect SQL files and sort them alphabetically
	var sqlFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".sql") {
			sqlFiles = append(sqlFiles, entry.Name())
		}
	}
	sort.Strings(sqlFiles)

	if len(sqlFiles) == 0 {
		slog.Info("no migration files found", "dir", migrationsDir)
		return nil
	}

	for _, filename := range sqlFiles {
		filePath := filepath.Join(migrationsDir, filename)

		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading migration file %s: %w", filePath, err)
		}

		if _, err := db.Conn.Exec(string(content)); err != nil {
			return fmt.Errorf("executing migration %s: %w", filename, err)
		}

		slog.Info("migration executed", "file", filename)
	}

	// Ensure sessions table has all required columns (for databases created before schema updates)
	db.ensureSessionColumns()

	return nil
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	if db.Conn != nil {
		return db.Conn.Close()
	}
	return nil
}

// ensureSessionColumns adds missing columns to the sessions table.
// This handles upgrades from older schemas where bucket, org_id, and log_region
// were not yet part of the table. Errors from "duplicate column" are ignored.
func (db *DB) ensureSessionColumns() {
	columns := []string{
		"ALTER TABLE sessions ADD COLUMN bucket TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE sessions ADD COLUMN org_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE sessions ADD COLUMN log_region TEXT NOT NULL DEFAULT ''",
	}
	for _, stmt := range columns {
		if _, err := db.Conn.Exec(stmt); err != nil {
			// Ignore "duplicate column name" errors — column already exists
			if strings.Contains(err.Error(), "duplicate column") {
				continue
			}
			slog.Warn("failed to add column to sessions table", "error", err.Error())
		}
	}
}
