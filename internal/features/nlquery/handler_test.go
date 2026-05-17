package nlquery

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudtrail-analyzer/internal/config"

	"github.com/go-chi/chi/v5"
	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS indexed_files (file_path TEXT PRIMARY KEY, file_size INTEGER NOT NULL, mod_time TEXT NOT NULL, batch_id TEXT NOT NULL, indexed_at TEXT NOT NULL DEFAULT (datetime('now')))`)
	db.Exec(`CREATE TABLE IF NOT EXISTS index_state (id INTEGER PRIMARY KEY CHECK (id = 1), status TEXT NOT NULL DEFAULT 'idle', total_bytes INTEGER NOT NULL DEFAULT 0, processed_bytes INTEGER NOT NULL DEFAULT 0, total_files INTEGER NOT NULL DEFAULT 0, processed_files INTEGER NOT NULL DEFAULT 0, last_batch_id TEXT, started_at TEXT, updated_at TEXT NOT NULL DEFAULT (datetime('now')))`)
	db.Exec(`INSERT OR IGNORE INTO index_state (id, status) VALUES (1, 'idle')`)
	t.Cleanup(func() { db.Close() })
	return db
}

func testConfig() *config.Config {
	return &config.Config{
		Port:                7070,
		DataDir:             "./testdata",
		LogLevel:            "info",
		QueryTimeoutSeconds: 10,
		S3: config.S3Config{
			Bucket:    "test-bucket",
			Region:    "us-east-1",
			AccountID: "123456789012",
			Mode:      "single",
		},
		LLM: config.LLMConfig{
			Provider: "bedrock",
		},
		Bedrock: config.BedrockConfig{
			Region:  "us-east-1",
			ModelID: "us.anthropic.claude-sonnet-4-20250514-v1:0",
		},
	}
}

func TestExecute_EmptyPrompt(t *testing.T) {
	cfg := testConfig()
	h := NewHandler(cfg, testDB(t))

	body := `{"prompt":""}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Execute(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "missing_prompt" {
		t.Errorf("expected code 'missing_prompt', got %q", resp["code"])
	}
}

func TestExecute_InvalidJSON(t *testing.T) {
	cfg := testConfig()
	h := NewHandler(cfg, testDB(t))

	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Execute(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestExecute_MissingPromptField(t *testing.T) {
	cfg := testConfig()
	h := NewHandler(cfg, testDB(t))

	body := `{"prompt_id":"test"}`
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Execute(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRoutes_MountsExecute(t *testing.T) {
	cfg := testConfig()
	h := NewHandler(cfg, testDB(t))
	r := h.Routes()

	// Verify the route exists by calling it
	req := httptest.NewRequest("POST", "/execute", bytes.NewBufferString(`{"prompt":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Should not be 404/405 — it should attempt execution (and fail because no real LLM)
	if w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed {
		t.Errorf("route not registered, got %d", w.Code)
	}
}

func TestDashboard_NoDataPath(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./testdata",
		S3:      config.S3Config{Bucket: ""},
	}
	h := NewDashboardHandler(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	h.GetDashboard(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when no bucket configured, got %d", w.Code)
	}
}

func TestFindings_NoDataPath(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./testdata",
		S3:      config.S3Config{Bucket: ""},
	}
	h := NewDashboardHandler(cfg)

	req := httptest.NewRequest("GET", "/findings", nil)
	w := httptest.NewRecorder()

	h.GetFindings(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when no bucket configured, got %d", w.Code)
	}
}

func TestFindingDetail_NotFound(t *testing.T) {
	cfg := testConfig()
	h := NewDashboardHandler(cfg)

	r := chi.NewRouter()
	r.Get("/findings/{id}", h.GetFindingDetail)

	req := httptest.NewRequest("GET", "/findings/nonexistent-finding", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent finding, got %d", w.Code)
	}
}

func TestFindingDetail_ValidID(t *testing.T) {
	cfg := testConfig()
	h := NewDashboardHandler(cfg)

	r := chi.NewRouter()
	r.Get("/findings/{id}", h.GetFindingDetail)

	req := httptest.NewRequest("GET", "/findings/root-account-usage", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Will return 200 even if DuckDB fails (error in response body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid finding ID, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["id"] != "root-account-usage" {
		t.Errorf("expected id 'root-account-usage', got %v", resp["id"])
	}
	if resp["sql"] == nil || resp["sql"] == "" {
		t.Error("expected sql field to be populated")
	}
}
