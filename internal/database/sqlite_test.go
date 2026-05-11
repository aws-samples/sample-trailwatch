package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewDB(t *testing.T) {
	tmpDir := t.TempDir()

	db, err := NewDB(tmpDir)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	// Verify the database file was created
	dbPath := filepath.Join(tmpDir, "sessions.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatalf("expected database file at %s", dbPath)
	}

	// Verify connection is usable
	var result int
	err = db.Conn.QueryRow("SELECT 1").Scan(&result)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if result != 1 {
		t.Fatalf("expected 1, got %d", result)
	}
}

func TestNewDB_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "nested", "data")

	db, err := NewDB(nestedDir)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	// Verify nested directory was created
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Fatalf("expected directory at %s", nestedDir)
	}
}

func TestRunMigrations(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a temporary migrations directory with a test SQL file
	migrationsDir := filepath.Join(tmpDir, "migrations")
	// nosemgrep: incorrect-default-permission
	if err := os.MkdirAll(migrationsDir, 0700); err != nil {
		t.Fatalf("creating migrations dir: %v", err)
	}

	sqlContent := `CREATE TABLE IF NOT EXISTS test_table (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL
	);`
	if err := os.WriteFile(filepath.Join(migrationsDir, "001_test.sql"), []byte(sqlContent), 0644); err != nil {
		t.Fatalf("writing migration file: %v", err)
	}

	db, err := NewDB(tmpDir)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	// Change to the temp directory so RunMigrations finds the migrations/ folder
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("changing directory: %v", err)
	}
	defer os.Chdir(origDir)

	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations failed: %v", err)
	}

	// Verify the table was created
	_, err = db.Conn.Exec("INSERT INTO test_table (id, name) VALUES ('1', 'test')")
	if err != nil {
		t.Fatalf("insert into migrated table failed: %v", err)
	}

	var name string
	err = db.Conn.QueryRow("SELECT name FROM test_table WHERE id = '1'").Scan(&name)
	if err != nil {
		t.Fatalf("query migrated table failed: %v", err)
	}
	if name != "test" {
		t.Fatalf("expected 'test', got %q", name)
	}
}

func TestRunMigrations_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()

	migrationsDir := filepath.Join(tmpDir, "migrations")
	// nosemgrep: incorrect-default-permission
	if err := os.MkdirAll(migrationsDir, 0700); err != nil {
		t.Fatalf("creating migrations dir: %v", err)
	}

	sqlContent := `CREATE TABLE IF NOT EXISTS idempotent_table (
		id TEXT PRIMARY KEY
	);`
	if err := os.WriteFile(filepath.Join(migrationsDir, "001_test.sql"), []byte(sqlContent), 0644); err != nil {
		t.Fatalf("writing migration file: %v", err)
	}

	db, err := NewDB(tmpDir)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("changing directory: %v", err)
	}
	defer os.Chdir(origDir)

	// Run migrations twice — should not error
	if err := db.RunMigrations(); err != nil {
		t.Fatalf("first RunMigrations failed: %v", err)
	}
	if err := db.RunMigrations(); err != nil {
		t.Fatalf("second RunMigrations failed: %v", err)
	}
}

func TestClose(t *testing.T) {
	tmpDir := t.TempDir()

	db, err := NewDB(tmpDir)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// After close, queries should fail
	err = db.Conn.Ping()
	if err == nil {
		t.Fatal("expected error after close, got nil")
	}
}
