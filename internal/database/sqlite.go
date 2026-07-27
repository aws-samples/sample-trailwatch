package database

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cloudtrail-analyzer/migrations"

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
	if err := os.Chmod(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("securing data directory %s: %w", dataDir, err)
	}

	dbPath := filepath.Join(dataDir, "sessions.db")
	dsnURL := &url.URL{Scheme: "file", Path: dbPath}
	query := dsnURL.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	dsnURL.RawQuery = query.Encode()

	conn, err := sql.Open("sqlite", dsnURL.String())
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database at %s: %w", dbPath, err)
	}
	conn.SetMaxOpenConns(4)
	conn.SetMaxIdleConns(4)

	// Verify the connection is working
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pinging sqlite database: %w", err)
	}
	if err := os.Chmod(dbPath, 0600); err != nil {
		conn.Close()
		return nil, fmt.Errorf("securing sqlite database at %s: %w", dbPath, err)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	slog.Info("sqlite database opened", "path", dbPath)

	return &DB{Conn: conn}, nil
}

// RunMigrations executes embedded SQL migrations in filename order.
func (db *DB) RunMigrations() error {
	return db.runMigrations(migrations.FS)
}

func (db *DB) runMigrations(migrationFS fs.FS) error {
	if _, err := db.Conn.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		return fmt.Errorf("creating migration ledger: %w", err)
	}

	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return fmt.Errorf("reading embedded migrations: %w", err)
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
		slog.Info("no migration files found")
	}

	for _, filename := range sqlFiles {
		var applied bool
		if err := db.Conn.QueryRow(
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)",
			filename,
		).Scan(&applied); err != nil {
			return fmt.Errorf("checking migration %s: %w", filename, err)
		}
		if applied {
			continue
		}

		content, err := fs.ReadFile(migrationFS, filename)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", filename, err)
		}

		tx, err := db.Conn.Begin()
		if err != nil {
			return fmt.Errorf("starting migration %s: %w", filename, err)
		}
		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("executing migration %s: %w", filename, err)
		}
		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", filename); err != nil {
			tx.Rollback()
			return fmt.Errorf("recording migration %s: %w", filename, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %s: %w", filename, err)
		}

		slog.Info("migration executed", "file", filename)
	}

	// Ensure sessions table has all required columns (for databases created before schema updates)
	if err := db.ensureSessionColumns(); err != nil {
		return fmt.Errorf("ensuring sessions columns: %w", err)
	}

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
func (db *DB) ensureSessionColumns() error {
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
			return err
		}
	}
	return nil
}
