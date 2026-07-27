package processor

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/features/sessions"

	_ "modernc.org/sqlite"
)

func TestGetProgressSnapshotReturnsCopy(t *testing.T) {
	service := NewService(nil, &config.Config{MaxDownloadConcurrency: 3})
	service.updateSnapshot("session-1", ProcessingProgress{
		SessionID:      "session-1",
		FilesCompleted: 2,
		TotalFiles:     5,
	})

	first, ok := service.GetProgressSnapshot("session-1")
	if !ok {
		t.Fatal("expected progress snapshot")
	}
	first.FilesCompleted = 99
	first.Concurrency = 99

	second, ok := service.GetProgressSnapshot("session-1")
	if !ok {
		t.Fatal("expected progress snapshot")
	}
	if first == second {
		t.Fatal("expected each caller to receive a distinct snapshot pointer")
	}
	if second.FilesCompleted != 2 {
		t.Fatalf("stored files completed = %d, want 2", second.FilesCompleted)
	}
	if second.Concurrency != 3 {
		t.Fatalf("stored concurrency = %d, want 3", second.Concurrency)
	}
}

func TestCancelProcessingWaitsForWorkerDone(t *testing.T) {
	service := NewService(nil, &config.Config{})
	workerCtx, cancel := context.WithCancel(context.Background())
	pipeline := &activePipeline{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	service.active["session-1"] = pipeline

	result := make(chan error, 1)
	go func() {
		result <- service.CancelProcessing(context.Background(), "session-1")
	}()

	select {
	case <-workerCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("CancelProcessing did not cancel the worker")
	}

	select {
	case err := <-result:
		t.Fatalf("CancelProcessing returned before worker signalled done: %v", err)
	default:
	}

	close(pipeline.done)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("CancelProcessing returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CancelProcessing did not return after worker signalled done")
	}
}

func TestShutdownWaitsForEveryWorkerDone(t *testing.T) {
	service := NewService(nil, &config.Config{})
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	first := &activePipeline{cancel: cancelFirst, done: make(chan struct{})}
	second := &activePipeline{cancel: cancelSecond, done: make(chan struct{})}
	service.active["session-1"] = first
	service.active["session-2"] = second

	result := make(chan error, 1)
	go func() {
		result <- service.Shutdown(context.Background())
	}()

	for name, workerCtx := range map[string]context.Context{
		"session-1": firstCtx,
		"session-2": secondCtx,
	} {
		select {
		case <-workerCtx.Done():
		case <-time.After(time.Second):
			t.Fatalf("Shutdown did not cancel worker %s", name)
		}
	}

	close(first.done)
	select {
	case err := <-result:
		t.Fatalf("Shutdown returned before every worker signalled done: %v", err)
	default:
	}

	close(second.done)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Shutdown returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not return after every worker signalled done")
	}
}

func TestCompleteProcessingDoesNotOverwriteInterruptedOrDeletedSession(t *testing.T) {
	for _, terminalState := range []sessions.SessionState{
		sessions.StateInterrupted,
		sessions.StateDeleted,
	} {
		t.Run(string(terminalState), func(t *testing.T) {
			db := newProcessorSessionTestDB(t)
			now := time.Now().UTC()
			session := &sessions.Session{
				ID:             "session-1",
				Bucket:         "trail-bucket",
				AccountID:      "123456789012",
				Region:         "us-east-1",
				LogRegion:      "us-east-1",
				Mode:           "single",
				StartDate:      "2026-07-01",
				EndDate:        "2026-07-02",
				State:          terminalState,
				TotalFiles:     2,
				DiskUsageBytes: 128,
				FailedFiles:    `["existing.json.gz"]`,
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			if err := sessions.Create(db, session); err != nil {
				t.Fatalf("create session: %v", err)
			}

			err := sessions.CompleteProcessing(
				db,
				session.ID,
				99,
				4096,
				[]string{"late-result.json.gz"},
				sessions.StateQueryReady,
			)
			if err == nil {
				t.Fatal("expected late completion to lose its verifying-state claim")
			}

			got, err := sessions.GetByID(db, session.ID)
			if err != nil {
				t.Fatalf("get session: %v", err)
			}
			if got.State != terminalState {
				t.Fatalf("state = %q, want %q", got.State, terminalState)
			}
			if got.TotalFiles != session.TotalFiles {
				t.Fatalf("total files = %d, want %d", got.TotalFiles, session.TotalFiles)
			}
			if got.DiskUsageBytes != session.DiskUsageBytes {
				t.Fatalf("disk usage = %d, want %d", got.DiskUsageBytes, session.DiskUsageBytes)
			}
			if got.FailedFiles != session.FailedFiles {
				t.Fatalf("failed files = %q, want %q", got.FailedFiles, session.FailedFiles)
			}
		})
	}
}

func TestDownloadFailureMessageRedactsAWSDetails(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "kms decrypt",
			err:  errors.New("AccessDenied: role/Admin cannot perform kms:Decrypt on key/secret"),
			want: "Download failed: credentials need kms:Decrypt access to the S3 bucket key",
		},
		{
			name: "s3 get object",
			err:  errors.New("AccessDenied while calling s3:GetObject for secret-key-name"),
			want: "Download failed: credentials need s3:GetObject access to the selected logs",
		},
		{
			name: "other",
			err:  errors.New("network timeout for secret-key-name"),
			want: "Download/extraction failed; check S3 access and the server log",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := downloadFailureMessage(tt.err)
			if got != tt.want {
				t.Fatalf("downloadFailureMessage() = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "secret") {
				t.Fatal("user-facing message leaked raw AWS error detail")
			}
		})
	}
}

func newProcessorSessionTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	if _, err := db.Exec(`CREATE TABLE sessions (
		id TEXT PRIMARY KEY, bucket TEXT NOT NULL, account_id TEXT NOT NULL,
		org_id TEXT NOT NULL DEFAULT '', region TEXT NOT NULL, log_region TEXT NOT NULL,
		mode TEXT NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL,
		state TEXT NOT NULL, total_files INTEGER, disk_usage_bytes INTEGER,
		failed_files TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	return db
}
