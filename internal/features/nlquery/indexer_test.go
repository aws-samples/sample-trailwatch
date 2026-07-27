package nlquery

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloudtrail-analyzer/internal/config"
)

const (
	indexerConcurrencyTestTimeout   = 5 * time.Second
	indexerSubprocessStartupTimeout = 15 * time.Second
)

func TestBuildBatchSQLUsesTransactionalSourceReplacement(t *testing.T) {
	idx := NewIndexer(&config.Config{}, testDB(t))
	sql := idx.buildBatchSQL(batch{Files: []fileEntry{
		{Path: "/tmp/it's-an-event.json"},
	}})

	for _, expected := range []string{
		"BEGIN TRANSACTION;",
		"CREATE TABLE IF NOT EXISTS events",
		"DELETE FROM events WHERE source_file IN ('/tmp/it''s-an-event.json');",
		"filename=true",
		"COMMIT;",
	} {
		if !strings.Contains(sql, expected) {
			t.Errorf("batch SQL missing %q:\n%s", expected, sql)
		}
	}
	if strings.Contains(sql, "source_file IN [") {
		t.Fatalf("DELETE uses an array instead of an IN tuple:\n%s", sql)
	}
}

func TestBuildIndexIncrementalReplacesChangedSourceFile(t *testing.T) {
	if _, err := exec.LookPath("duckdb"); err != nil {
		t.Skip("duckdb CLI not installed")
	}

	dataDir := t.TempDir()
	sourceDir := filepath.Join(dataDir, "source")
	if err := os.MkdirAll(sourceDir, 0700); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(sourceDir, "events.json")
	writeCloudTrailFixture(t, sourcePath, `[
		{"eventName":"ListBuckets","eventSource":"s3.amazonaws.com","recipientAccountId":"123456789012"}
	]`)

	idx := NewIndexer(&config.Config{DataDir: dataDir}, testDB(t))
	if err := idx.BuildIndexIncremental(context.Background(), sourceDir); err != nil {
		t.Fatalf("first index build failed: %v", err)
	}
	if !idx.IsIndexed() {
		t.Fatal("index should be available after a successful build")
	}

	writeCloudTrailFixture(t, sourcePath, `[
		{"eventName":"ListBuckets","eventSource":"s3.amazonaws.com","recipientAccountId":"123456789012"},
		{"eventName":"GetObject","eventSource":"s3.amazonaws.com","recipientAccountId":"123456789012"}
	]`)
	if err := idx.BuildIndexIncremental(context.Background(), sourceDir); err != nil {
		t.Fatalf("incremental rebuild failed: %v", err)
	}

	out, err := exec.Command("duckdb", "-csv", "-noheader", idx.IndexPath(),
		"SELECT count(*), count(DISTINCT source_file), string_agg(r.eventName, ',' ORDER BY r.eventName) FROM events;").CombinedOutput()
	if err != nil {
		t.Fatalf("querying test index: %v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != `2,1,"GetObject,ListBuckets"` {
		t.Fatalf("changed source file was appended instead of replaced: %q", got)
	}

	var checkpointCount int
	if err := idx.db.QueryRow("SELECT COUNT(*) FROM indexed_files").Scan(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	if checkpointCount != 1 {
		t.Fatalf("expected one source checkpoint, got %d", checkpointCount)
	}
}

func TestStartBuildAsyncRegistersBeforeReturn(t *testing.T) {
	dataDir := t.TempDir()
	sourceDir := filepath.Join(dataDir, "source")
	if err := os.MkdirAll(sourceDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeCloudTrailFixture(t, filepath.Join(sourceDir, "events.json"), `[
		{"eventName":"ListBuckets","eventSource":"s3.amazonaws.com","recipientAccountId":"123456789012"}
	]`)

	idx := NewIndexer(&config.Config{DataDir: dataDir}, testDB(t))
	idx.writeMu.Lock()
	writeLocked := true
	defer func() {
		if writeLocked {
			idx.writeMu.Unlock()
		}
	}()

	if err := idx.StartBuildAsync(context.Background(), sourceDir, time.Minute); err != nil {
		t.Fatalf("starting asynchronous index build: %v", err)
	}

	idx.mu.Lock()
	registeredDone := idx.done
	idx.mu.Unlock()
	if registeredDone == nil {
		t.Fatal("StartBuildAsync returned before registering the worker")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), indexerConcurrencyTestTimeout)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- idx.Shutdown(shutdownCtx)
	}()

	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown missed the registered worker: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	idx.writeMu.Unlock()
	writeLocked = false
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutting down registered worker: %v", err)
		}
	case <-time.After(indexerConcurrencyTestTimeout):
		t.Fatal("registered index worker did not stop")
	}

	select {
	case <-registeredDone:
	default:
		t.Fatal("Shutdown returned before the registered worker completed")
	}
}

func TestMicroBatchBeginInvalidationBlocksAddFileUntilRelease(t *testing.T) {
	idx := NewIndexer(&config.Config{DataDir: t.TempDir()}, testDB(t))
	microBatch := NewMicroBatchIndexer(idx)

	release, err := microBatch.BeginInvalidation()
	if err != nil {
		t.Fatalf("beginning invalidation: %v", err)
	}
	t.Cleanup(release)

	addStarted := make(chan struct{})
	addDone := make(chan struct{})
	go func() {
		close(addStarted)
		microBatch.AddFile(context.Background(), "/tmp/pending-event.json", 1)
		close(addDone)
	}()
	<-addStarted

	select {
	case <-addDone:
		t.Fatal("AddFile completed while the invalidation lease was held")
	case <-time.After(100 * time.Millisecond):
	}

	release()
	select {
	case <-addDone:
	case <-time.After(indexerConcurrencyTestTimeout):
		t.Fatal("AddFile remained blocked after the invalidation lease was released")
	}

	microBatch.mu.Lock()
	defer microBatch.mu.Unlock()
	if len(microBatch.buffer) != 1 || microBatch.buffer[0].Path != "/tmp/pending-event.json" {
		t.Fatalf("AddFile did not enqueue the file after release: %#v", microBatch.buffer)
	}
}

func TestRefreshIdleStateFromCheckpointsPublishesAggregateProgress(t *testing.T) {
	idx := NewIndexer(&config.Config{DataDir: t.TempDir()}, testDB(t))
	for _, row := range []struct {
		path string
		size int64
	}{
		{path: "/tmp/first.json", size: 10},
		{path: "/tmp/second.json", size: 25},
	} {
		if _, err := idx.db.Exec(
			`INSERT INTO indexed_files (file_path, file_size, mod_time, batch_id)
			 VALUES (?, ?, ?, ?)`,
			row.path, row.size, time.Now().UTC().Format(time.RFC3339), "batch",
		); err != nil {
			t.Fatal(err)
		}
	}

	if err := idx.refreshIdleStateFromCheckpoints("batch"); err != nil {
		t.Fatal(err)
	}
	state, err := idx.GetIndexState()
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "idle" || state.TotalFiles != 2 || state.ProcessedFiles != 2 {
		t.Fatalf("unexpected file progress: %#v", state)
	}
	if state.TotalBytes != 35 || state.ProcessedBytes != 35 || state.LastBatchID != "batch" {
		t.Fatalf("unexpected byte progress: %#v", state)
	}
}

func TestRefreshIdleStateFromCheckpointsDoesNotClobberManualBuild(t *testing.T) {
	idx := NewIndexer(&config.Config{DataDir: t.TempDir()}, testDB(t))
	idx.updateState("building", 100, 40, 10, 4, "manual")

	if err := idx.refreshIdleStateFromCheckpoints("streaming"); err != nil {
		t.Fatal(err)
	}
	state, err := idx.GetIndexState()
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "building" || state.TotalBytes != 100 || state.ProcessedBytes != 40 ||
		state.TotalFiles != 10 || state.ProcessedFiles != 4 || state.LastBatchID != "manual" {
		t.Fatalf("manual build state was overwritten: %#v", state)
	}
}

func TestCancelIndexStopsBuildWorker(t *testing.T) {
	idx, result, workerDone := startBlockingIndexBuild(t)

	if err := idx.CancelIndex(); err != nil {
		t.Fatalf("cancelling index build: %v", err)
	}
	waitForIndexWorker(t, workerDone)

	if err := <-result; err == nil {
		t.Fatal("cancelled index build returned nil error")
	}
	if idx.IsRunning() {
		t.Fatal("indexer still reports a running worker after cancellation")
	}
}

func TestShutdownCancelsAndJoinsBuildWorker(t *testing.T) {
	idx, result, workerDone := startBlockingIndexBuild(t)

	idx.mu.Lock()
	indexDone := idx.done
	idx.mu.Unlock()
	if indexDone == nil {
		t.Fatal("index worker did not register its completion channel")
	}

	ctx, cancel := context.WithTimeout(context.Background(), indexerConcurrencyTestTimeout)
	defer cancel()
	if err := idx.Shutdown(ctx); err != nil {
		t.Fatalf("shutting down indexer: %v", err)
	}

	select {
	case <-indexDone:
	default:
		t.Fatal("Shutdown returned before the index worker completion signal")
	}
	waitForIndexWorker(t, workerDone)

	if err := <-result; err == nil {
		t.Fatal("shutdown-cancelled index build returned nil error")
	}
	if idx.IsRunning() {
		t.Fatal("indexer still reports a running worker after Shutdown returned")
	}
}

func startBlockingIndexBuild(t *testing.T) (*Indexer, <-chan error, <-chan struct{}) {
	t.Helper()

	binDir := t.TempDir()
	startedPath := filepath.Join(t.TempDir(), "duckdb-started")
	duckDBPath := filepath.Join(binDir, "duckdb")
	script := "#!/bin/sh\n" +
		": > \"$NLQUERY_TEST_DUCKDB_STARTED\"\n" +
		"exec /bin/sleep 30\n"
	if err := os.WriteFile(duckDBPath, []byte(script), 0700); err != nil {
		t.Fatalf("writing blocking duckdb executable: %v", err)
	}
	t.Setenv("NLQUERY_TEST_DUCKDB_STARTED", startedPath)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dataDir := t.TempDir()
	sourceDir := filepath.Join(dataDir, "source")
	if err := os.MkdirAll(sourceDir, 0700); err != nil {
		t.Fatalf("creating source directory: %v", err)
	}
	writeCloudTrailFixture(t, filepath.Join(sourceDir, "events.json"), `[
		{"eventName":"ListBuckets","eventSource":"s3.amazonaws.com","recipientAccountId":"123456789012"}
	]`)

	idx := NewIndexer(&config.Config{DataDir: dataDir}, testDB(t))
	buildCtx, cancelBuild := context.WithCancel(context.Background())
	result := make(chan error, 1)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		result <- idx.BuildIndexIncremental(buildCtx, sourceDir)
	}()

	t.Cleanup(func() {
		cancelBuild()
		ctx, cancel := context.WithTimeout(context.Background(), indexerConcurrencyTestTimeout)
		defer cancel()
		_ = idx.Shutdown(ctx)
		select {
		case <-workerDone:
		case <-time.After(indexerConcurrencyTestTimeout):
			t.Errorf("index build worker leaked during test cleanup")
		}
	})

	waitForFile(t, startedPath)
	return idx, result, workerDone
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(indexerSubprocessStartupTimeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatalf("checking subprocess marker: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for subprocess marker %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForIndexWorker(t *testing.T, workerDone <-chan struct{}) {
	t.Helper()
	select {
	case <-workerDone:
	case <-time.After(indexerConcurrencyTestTimeout):
		t.Fatal("timed out waiting for index build worker to exit")
	}
}

func writeCloudTrailFixture(t *testing.T, path, records string) {
	t.Helper()
	content := `{"Records":` + records + `}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
