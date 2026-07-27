package processor

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/features/sessions"
)

func TestValidateJSONFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		valid   bool
	}{
		{"object", `{"Records":[]}`, true},
		{"trailing whitespace", "{\"Records\":[]}\n\t", true},
		{"trailing garbage", `{"Records":[]} garbage`, false},
		{"multiple values", `{"Records":[]} {"Records":[]}`, false},
		{"truncated", `{"Records":[`, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "event.json")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatal(err)
			}
			err := validateJSONFile(path)
			if tt.valid && err != nil {
				t.Fatalf("expected valid JSON, got %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("expected invalid JSON to be rejected")
			}
		})
	}
}

func TestMergeFailedFilesDeduplicates(t *testing.T) {
	got := mergeFailedFiles(
		[]string{"a.json.gz", "b.json"},
		[]string{"b.json", "", "c.json"},
	)
	want := []string{"a.json.gz", "b.json", "c.json"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSessionDateDirsAreRangeScoped(t *testing.T) {
	session := &sessions.Session{
		Bucket: "bucket", AccountID: "123456789012", LogRegion: "us-east-1",
		Mode: "single", StartDate: "2026-07-01", EndDate: "2026-07-02",
	}
	dirs, err := sessionDateDirs(session, "/data")
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) != 2 || filepath.Base(dirs[0]) != "01" || filepath.Base(dirs[1]) != "02" {
		t.Fatalf("unexpected date dirs: %v", dirs)
	}
}

func TestExtractAndVerifySupportedLocalLayouts(t *testing.T) {
	const (
		bucket  = "trail-bucket"
		account = "123456789012"
		org     = "o-example1234"
		region  = "us-east-1"
	)

	tests := []struct {
		name      string
		mode      string
		orgID     string
		pathParts []string
	}{
		{
			name: "single account",
			mode: "single",
			pathParts: []string{
				"AWSLogs", account,
			},
		},
		{
			name:  "legacy control tower with nested organization",
			mode:  "control_tower",
			orgID: org,
			pathParts: []string{
				org, "AWSLogs", org, account,
			},
		},
		{
			name:  "legacy control tower with organization root",
			mode:  "control_tower",
			orgID: org,
			pathParts: []string{
				org, "AWSLogs", account,
			},
		},
		{
			name:  "standard aws organizations",
			mode:  "control_tower",
			orgID: org,
			pathParts: []string{
				"AWSLogs", org, account,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			session := &sessions.Session{
				ID:        "session",
				Bucket:    bucket,
				AccountID: account,
				OrgID:     tt.orgID,
				LogRegion: region,
				Mode:      tt.mode,
				StartDate: "2026-07-26",
				EndDate:   "2026-07-26",
			}

			pathParts := append([]string{dataDir, "s3", bucket}, tt.pathParts...)
			pathParts = append(pathParts, "CloudTrail", region, "2026", "07", "26", "event.json.gz")
			gzPath := filepath.Join(pathParts...)
			writeGzipTestFile(t, gzPath, []byte(`{"Records":[]}`))

			extracted := 0
			err := extractFiles(
				context.Background(),
				session,
				dataDir,
				make(chan ProcessingProgress, 1),
				func(string, int64) { extracted++ },
			)
			if err != nil {
				t.Fatalf("extract files: %v", err)
			}
			if extracted != 1 {
				t.Fatalf("extracted files = %d, want 1", extracted)
			}

			jsonPath := gzPath[:len(gzPath)-len(".gz")]
			if _, err := os.Stat(jsonPath); err != nil {
				t.Fatalf("expected extracted file %s: %v", jsonPath, err)
			}

			total, diskBytes, failed, err := verifyFiles(
				context.Background(),
				session,
				dataDir,
				make(chan ProcessingProgress, 1),
			)
			if err != nil {
				t.Fatalf("verify files: %v", err)
			}
			if total != 1 {
				t.Fatalf("verified files = %d, want 1", total)
			}
			if diskBytes <= 0 {
				t.Fatalf("disk bytes = %d, want a positive value", diskBytes)
			}
			if len(failed) != 0 {
				t.Fatalf("failed files = %v, want none", failed)
			}
		})
	}
}

func TestDownloadAndExtractReturnsOnCancelledProducer(t *testing.T) {
	cfg := &config.Config{MaxDownloadConcurrency: 1}
	svc := NewService(nil, cfg)
	session := &sessions.Session{ID: "session", Bucket: "bucket"}
	objects := make([]S3Object, 100)
	for i := range objects {
		objects[i] = S3Object{Key: "AWSLogs/file.json.gz", Size: 1}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dataDir := t.TempDir()

	done := make(chan error, 1)
	go func() {
		_, err := svc.downloadAndExtract(ctx, nil, session, objects, dataDir, 1, 100, make(chan ProcessingProgress, 1))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancellation error")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled producer deadlocked")
	}
}

func writeGzipTestFile(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create gzip file: %v", err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write(content); err != nil {
		_ = file.Close()
		t.Fatalf("write gzip file: %v", err)
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close gzip file: %v", err)
	}
}
