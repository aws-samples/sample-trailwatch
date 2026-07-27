package database

import (
	"os"
	"testing"
)

// TestRealMigration tests the actual 001_initial.sql migration from the project.
func TestRealMigration(t *testing.T) {
	tmpDir := t.TempDir()

	db, err := NewDB(tmpDir)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	// Embedded migrations must work regardless of the process working directory.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("changing to unrelated directory: %v", err)
	}
	defer os.Chdir(origDir)

	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations with real schema failed: %v", err)
	}

	// Verify sessions table
	_, err = db.Conn.Exec(`INSERT INTO sessions (id, account_id, region, start_date, end_date)
		VALUES ('test-id', '123456789012', 'us-east-1', '2024-01-01', '2024-01-31')`)
	if err != nil {
		t.Fatalf("insert into sessions failed: %v", err)
	}

	var state string
	err = db.Conn.QueryRow("SELECT state FROM sessions WHERE id = 'test-id'").Scan(&state)
	if err != nil {
		t.Fatalf("query sessions failed: %v", err)
	}
	if state != "pending" {
		t.Fatalf("expected default state 'pending', got %q", state)
	}

	// Verify query_history table
	_, err = db.Conn.Exec(`INSERT INTO query_history (id, session_id, sql)
		VALUES ('qh-1', 'test-id', 'SELECT * FROM events')`)
	if err != nil {
		t.Fatalf("insert into query_history failed: %v", err)
	}

	// Verify chat_history table
	_, err = db.Conn.Exec(`INSERT INTO chat_history (session_id, role, content)
		VALUES ('test-id', 'user', 'What happened yesterday?')`)
	if err != nil {
		t.Fatalf("insert into chat_history failed: %v", err)
	}

	var chatID int
	err = db.Conn.QueryRow("SELECT id FROM chat_history WHERE session_id = 'test-id'").Scan(&chatID)
	if err != nil {
		t.Fatalf("query chat_history failed: %v", err)
	}
	if chatID != 1 {
		t.Fatalf("expected autoincrement id 1, got %d", chatID)
	}

	var applied int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 3 {
		t.Fatalf("expected 3 embedded migrations, got %d", applied)
	}
}
