package database

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRealMigration tests the actual 001_initial.sql migration from the project.
func TestRealMigration(t *testing.T) {
	// Find the project root by looking for go.mod
	projectRoot := findProjectRoot(t)

	tmpDir := t.TempDir()

	db, err := NewDB(tmpDir)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	// Change to project root so RunMigrations finds the real migrations/ folder
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}
	if err := os.Chdir(projectRoot); err != nil {
		t.Fatalf("changing to project root: %v", err)
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
}

func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root (no go.mod found)")
		}
		dir = parent
	}
}
