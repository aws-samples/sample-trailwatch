package database

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
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

	if got := db.Conn.Stats().MaxOpenConnections; got != 4 {
		t.Fatalf("expected connection pool limit 4, got %d", got)
	}
	assertFileMode(t, tmpDir, 0700)
	assertFileMode(t, dbPath, 0600)
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

func TestNewDBAppliesPragmasToEveryConnection(t *testing.T) {
	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	var conns []*sql.Conn
	for i := 0; i < 4; i++ {
		conn, err := db.Conn.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)

		var foreignKeys, busyTimeout int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatal(err)
		}
		if foreignKeys != 1 {
			t.Fatalf("connection %d has foreign_keys=%d", i, foreignKeys)
		}
		if busyTimeout != 5000 {
			t.Fatalf("connection %d has busy_timeout=%d", i, busyTimeout)
		}
	}
	for _, conn := range conns {
		conn.Close()
	}
}

func TestRunMigrations(t *testing.T) {
	tmpDir := t.TempDir()

	sqlContent := `CREATE TABLE IF NOT EXISTS test_table (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL
	);
	CREATE TABLE sessions (
		id TEXT PRIMARY KEY,
		bucket TEXT NOT NULL DEFAULT '',
		org_id TEXT NOT NULL DEFAULT '',
		log_region TEXT NOT NULL DEFAULT ''
	);`
	migrationFS := fstest.MapFS{
		"001_test.sql": &fstest.MapFile{Data: []byte(sqlContent)},
	}

	db, err := NewDB(tmpDir)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	if err := db.runMigrations(migrationFS); err != nil {
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

	sqlContent := `CREATE TABLE idempotent_table (
		id TEXT PRIMARY KEY
	);
	CREATE TABLE sessions (
		id TEXT PRIMARY KEY,
		bucket TEXT NOT NULL DEFAULT '',
		org_id TEXT NOT NULL DEFAULT '',
		log_region TEXT NOT NULL DEFAULT ''
	);`
	migrationFS := fstest.MapFS{
		"001_test.sql": &fstest.MapFile{Data: []byte(sqlContent)},
	}

	db, err := NewDB(tmpDir)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	// The SQL itself is deliberately not idempotent. The ledger must skip it.
	if err := db.runMigrations(migrationFS); err != nil {
		t.Fatalf("first RunMigrations failed: %v", err)
	}
	if err := db.runMigrations(migrationFS); err != nil {
		t.Fatalf("second RunMigrations failed: %v", err)
	}

	var applied int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("expected one applied migration, got %d", applied)
	}
}

func TestRunMigrationsFailsWhenSessionColumnRepairFails(t *testing.T) {
	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	migrationFS := fstest.MapFS{
		"001_test.sql": &fstest.MapFile{Data: []byte("CREATE TABLE unrelated (id TEXT PRIMARY KEY);")},
	}

	err = db.runMigrations(migrationFS)
	if err == nil {
		t.Fatal("expected session column repair failure")
	}
	if !strings.Contains(err.Error(), "ensuring sessions columns") {
		t.Fatalf("expected session column repair context, got %v", err)
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

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}
