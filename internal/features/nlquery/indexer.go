package nlquery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloudtrail-analyzer/internal/config"

	"github.com/google/uuid"
)

const indexDBName = "cloudtrail_index.duckdb"
const indexVersionFile = "cloudtrail_index.version"
const indexSchemaVersion = "2"
const batchSizeThreshold = 100 * 1024 * 1024 // 100 MB

const secondaryIndexesSQL = `
	CREATE INDEX IF NOT EXISTS idx_event_name ON events ((r.eventName));
	CREATE INDEX IF NOT EXISTS idx_event_source ON events ((r.eventSource));
	CREATE INDEX IF NOT EXISTS idx_error_code ON events ((r.errorCode));
`

// maxObjectSize caps read_json's per-object buffer. It is kept in lockstep with
// the extractor's maxPerFileBytes (processor/extractor.go, 256 MB) — a smaller
// cap here would abort the whole index batch on any CloudTrail file the
// extractor was willing to accept.
const maxObjectSize = 256 * 1024 * 1024 // 256 MB

var ErrAlreadyRunning = errors.New("indexing is already in progress")
var ErrIndexBusy = errors.New("index is being updated")

type IndexState struct {
	Status         string `json:"status"`
	TotalBytes     int64  `json:"total_bytes"`
	ProcessedBytes int64  `json:"processed_bytes"`
	TotalFiles     int    `json:"total_files"`
	ProcessedFiles int    `json:"processed_files"`
	LastBatchID    string `json:"last_batch_id"`
	StartedAt      string `json:"started_at"`
	UpdatedAt      string `json:"updated_at"`
}

type IndexProgress struct {
	Status         string  `json:"status"`
	TotalBytes     int64   `json:"total_bytes"`
	ProcessedBytes int64   `json:"processed_bytes"`
	TotalFiles     int     `json:"total_files"`
	ProcessedFiles int     `json:"processed_files"`
	Percentage     float64 `json:"percentage"`
	CurrentBatch   int     `json:"current_batch"`
	TotalBatches   int     `json:"total_batches"`
	Message        string  `json:"message"`
}

type fileEntry struct {
	Path    string
	Size    int64
	ModTime string
}

type batch struct {
	ID    string
	Files []fileEntry
	Size  int64
}

type Indexer struct {
	cfg *config.Config
	db  *sql.DB

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}

	// writeMu serializes every write to the DuckDB index file. DuckDB holds a
	// process-level write lock, so a micro-batch flush and a manual re-index
	// writing concurrently would corrupt the file (or fail mid-write). Hold this
	// across the full read_json/CREATE/INSERT execution, not just the metadata
	// peek. Distinct from mu, which only guards cancel/IsRunning bookkeeping.
	writeMu sync.Mutex
}

func NewIndexer(cfg *config.Config, db *sql.DB) *Indexer {
	idx := &Indexer{cfg: cfg, db: db}
	if result, err := db.Exec(
		`UPDATE index_state SET status = 'idle', updated_at = ?
		 WHERE id = 1 AND status = 'building'`,
		time.Now().UTC().Format(time.RFC3339),
	); err == nil {
		if rows, rowsErr := result.RowsAffected(); rowsErr == nil && rows > 0 {
			slog.Info("recovered stale in-progress index state",
				"component", "cloudtrail-analyzer")
		}
	}
	if idx.IsIndexed() {
		if err := idx.refreshIdleStateFromCheckpoints(""); err != nil {
			slog.Warn("failed to restore index progress from checkpoints",
				"component", "cloudtrail-analyzer",
				"error", err.Error())
		}
	}
	return idx
}

func (idx *Indexer) IndexPath() string {
	return filepath.Join(idx.cfg.DataDir, indexDBName)
}

func (idx *Indexer) indexVersionPath() string {
	return filepath.Join(idx.cfg.DataDir, indexVersionFile)
}

func (idx *Indexer) IsIndexed() bool {
	info, err := os.Stat(idx.IndexPath())
	return err == nil && info.Size() > 0 && idx.hasCurrentSchema()
}

func (idx *Indexer) IndexAge() time.Duration {
	info, err := os.Stat(idx.IndexPath())
	if err != nil {
		return time.Duration(0)
	}
	return time.Since(info.ModTime())
}

func (idx *Indexer) IsRunning() bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	return idx.cancel != nil
}

func (idx *Indexer) GetIndexState() (*IndexState, error) {
	row := idx.db.QueryRow(`SELECT status, total_bytes, processed_bytes, total_files, processed_files,
		COALESCE(last_batch_id, ''), COALESCE(started_at, ''), COALESCE(updated_at, '')
		FROM index_state WHERE id = 1`)
	var s IndexState
	err := row.Scan(&s.Status, &s.TotalBytes, &s.ProcessedBytes, &s.TotalFiles, &s.ProcessedFiles,
		&s.LastBatchID, &s.StartedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (idx *Indexer) CancelIndex() error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if idx.cancel == nil {
		return fmt.Errorf("no indexing in progress")
	}
	idx.cancel()
	return nil
}

func (idx *Indexer) Shutdown(ctx context.Context) error {
	idx.mu.Lock()
	cancel := idx.cancel
	done := idx.done
	if cancel != nil {
		cancel()
	}
	idx.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for index build to stop: %w", ctx.Err())
	}
}

// BeginInvalidation removes the shared index and keeps all index build/write
// gates held until the returned release function is called.
func (idx *Indexer) BeginInvalidation() (func(), error) {
	idx.mu.Lock()
	if idx.cancel != nil {
		idx.mu.Unlock()
		return nil, fmt.Errorf("%w: cancel or wait for the current index build before deleting data", ErrIndexBusy)
	}

	idx.writeMu.Lock()
	if err := idx.invalidateLocked(); err != nil {
		idx.writeMu.Unlock()
		idx.mu.Unlock()
		return nil, err
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			idx.writeMu.Unlock()
			idx.mu.Unlock()
		})
	}, nil
}

// Invalidate performs an immediate invalidation for callers that do not need
// to keep source-data mutation excluded afterward.
func (idx *Indexer) Invalidate() error {
	release, err := idx.BeginInvalidation()
	if err != nil {
		return err
	}
	release()
	return nil
}

// invalidateLocked resets index files and checkpoints. The caller holds both
// idx.mu and idx.writeMu.
func (idx *Indexer) invalidateLocked() error {
	for _, path := range []string{idx.IndexPath(), idx.IndexPath() + ".wal", idx.indexVersionPath()} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing DuckDB index: %w", err)
		}
	}

	tx, err := idx.db.Begin()
	if err != nil {
		return fmt.Errorf("starting index metadata reset: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM indexed_files"); err != nil {
		return fmt.Errorf("clearing indexed file checkpoints: %w", err)
	}
	if _, err := tx.Exec(`UPDATE index_state SET status = 'idle', total_bytes = 0,
		processed_bytes = 0, total_files = 0, processed_files = 0,
		last_batch_id = NULL, started_at = NULL, updated_at = ? WHERE id = 1`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("resetting index state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing index metadata reset: %w", err)
	}

	slog.Info("invalidated DuckDB index after source data deletion",
		"component", "cloudtrail-analyzer")
	return nil
}

func (idx *Indexer) BuildIndexIncremental(ctx context.Context, dataPath string) error {
	return idx.buildIndexIncremental(ctx, dataPath, nil)
}

// StartBuildAsync registers the index worker before returning so cancellation,
// duplicate-start checks, and shutdown cannot miss a newly accepted build.
func (idx *Indexer) StartBuildAsync(parent context.Context, dataPath string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	ready := make(chan error, 1)
	go func() {
		defer cancel()
		if err := idx.buildIndexIncremental(ctx, dataPath, ready); err != nil {
			slog.Error("incremental index build failed",
				"component", "cloudtrail-analyzer",
				"error", err.Error(),
			)
		}
	}()

	err := <-ready
	if err != nil {
		cancel()
	}
	return err
}

func (idx *Indexer) buildIndexIncremental(
	ctx context.Context,
	dataPath string,
	ready chan error,
) (retErr error) {
	signalReady := func(err error) {
		if ready == nil {
			return
		}
		ready <- err
		close(ready)
		ready = nil
	}
	defer func() {
		if ready != nil {
			signalReady(retErr)
		}
	}()

	if dataPath == "" {
		return fmt.Errorf("no data path configured")
	}

	idx.mu.Lock()
	if idx.cancel != nil {
		idx.mu.Unlock()
		return ErrAlreadyRunning
	}
	ctx, cancel := context.WithCancel(ctx)
	idx.cancel = cancel
	done := make(chan struct{})
	idx.done = done
	idx.mu.Unlock()
	signalReady(nil)

	defer func() {
		idx.mu.Lock()
		idx.cancel = nil
		idx.done = nil
		idx.mu.Unlock()
		cancel()
		close(done)
	}()

	// Update state to building
	idx.updateState("building", 0, 0, 0, 0, "")

	// Step 1: Scan filesystem for JSON files
	slog.Info("scanning for CloudTrail JSON files", "component", "cloudtrail-analyzer", "data_path", dataPath)
	allFiles, err := idx.scanFiles(dataPath)
	if err != nil {
		idx.updateState("error", 0, 0, 0, 0, "")
		return fmt.Errorf("scanning files: %w", err)
	}

	if len(allFiles) == 0 {
		idx.updateState("idle", 0, 0, 0, 0, "")
		return nil
	}

	// Step 2: Check DuckDB consistency
	idx.writeMu.Lock()
	dbExists, _, err := idx.reconcileIndexLocked()
	idx.writeMu.Unlock()
	if err != nil {
		idx.updateState("error", 0, 0, 0, 0, "")
		return err
	}

	// Step 3: Get already-indexed files from SQLite
	indexed, err := idx.getIndexedFiles()
	if err != nil {
		idx.updateState("error", 0, 0, 0, 0, "")
		return fmt.Errorf("reading checkpoint: %w", err)
	}

	// Step 4: Compute delta
	newFiles := idx.computeDelta(allFiles, indexed)
	if len(newFiles) == 0 {
		slog.Info("no new files to index", "component", "cloudtrail-analyzer")
		idx.setStatusOnly("idle")
		return nil
	}

	// Step 5: Compute totals and group into batches
	var totalBytes int64
	for _, f := range newFiles {
		totalBytes += f.Size
	}

	batches := idx.groupIntoBatches(newFiles)
	idx.updateState("building", totalBytes, 0, len(newFiles), 0, "")

	slog.Info("starting incremental index",
		"component", "cloudtrail-analyzer",
		"new_files", len(newFiles),
		"total_bytes", totalBytes,
		"batches", len(batches),
		"db_exists", dbExists,
	)

	// Step 6: Process batches
	var processedBytes int64
	var processedFiles int
	for i, b := range batches {
		// Check cancellation between batches
		if ctx.Err() != nil {
			slog.Info("indexing cancelled", "component", "cloudtrail-analyzer", "batches_completed", i)
			idx.updateState("paused", totalBytes, processedBytes, len(newFiles), processedFiles, b.ID)
			return nil
		}

		slog.Info("processing batch",
			"component", "cloudtrail-analyzer",
			"batch", i+1,
			"total_batches", len(batches),
			"files", len(b.Files),
			"size_bytes", b.Size,
		)

		// Keep the DuckDB write, SQLite checkpoint, and schema marker serialized
		// with every other index writer. A retry deletes and replaces rows for the
		// same source files, so a checkpoint failure cannot duplicate events.
		out, err := idx.writeBatch(ctx, b)
		if err != nil {
			slog.Error("batch failed",
				"component", "cloudtrail-analyzer",
				"batch", i+1,
				"error", err.Error(),
				"output", string(out),
			)
			idx.updateState("error", totalBytes, processedBytes, len(newFiles), processedFiles, "")
			return fmt.Errorf("batch %d failed: %s — %w", i+1, string(out), err)
		}

		processedBytes += b.Size
		processedFiles += len(b.Files)
		idx.updateState("building", totalBytes, processedBytes, len(newFiles), processedFiles, b.ID)
	}

	// Step 7: Create secondary indexes as a best-effort optimization.
	if err := idx.EnsureSecondaryIndexes(ctx); err != nil {
		slog.Warn("failed to create DuckDB secondary indexes",
			"component", "cloudtrail-analyzer",
			"error", err.Error(),
		)
	}

	idx.updateState("idle", totalBytes, processedBytes, len(newFiles), processedFiles, "")

	slog.Info("incremental index complete",
		"component", "cloudtrail-analyzer",
		"files_indexed", processedFiles,
		"bytes_indexed", processedBytes,
		"batches", len(batches),
	)

	return nil
}

func (idx *Indexer) scanFiles(dataPath string) ([]fileEntry, error) {
	var files []fileEntry
	err := filepath.Walk(dataPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".json") {
			files = append(files, fileEntry{
				Path:    path,
				Size:    info.Size(),
				ModTime: info.ModTime().UTC().Format(time.RFC3339),
			})
		}
		return nil
	})
	return files, err
}

func (idx *Indexer) getIndexedFiles() (map[string]fileEntry, error) {
	rows, err := idx.db.Query("SELECT file_path, file_size, mod_time FROM indexed_files")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]fileEntry)
	for rows.Next() {
		var f fileEntry
		if err := rows.Scan(&f.Path, &f.Size, &f.ModTime); err != nil {
			return nil, err
		}
		result[f.Path] = f
	}
	return result, rows.Err()
}

func (idx *Indexer) computeDelta(allFiles []fileEntry, indexed map[string]fileEntry) []fileEntry {
	var newFiles []fileEntry
	for _, f := range allFiles {
		existing, found := indexed[f.Path]
		if !found || existing.Size != f.Size || existing.ModTime != f.ModTime {
			newFiles = append(newFiles, f)
		}
	}
	return newFiles
}

func (idx *Indexer) groupIntoBatches(files []fileEntry) []batch {
	var batches []batch
	var current batch
	current.ID = uuid.New().String()

	for _, f := range files {
		current.Files = append(current.Files, f)
		current.Size += f.Size

		if current.Size >= batchSizeThreshold {
			batches = append(batches, current)
			current = batch{ID: uuid.New().String()}
		}
	}

	if len(current.Files) > 0 {
		batches = append(batches, current)
	}

	return batches
}

func (idx *Indexer) ExecDuckDB(ctx context.Context, dbPath string, sql string) ([]byte, error) {
	idx.writeMu.Lock()
	defer idx.writeMu.Unlock()
	return idx.execDuckDB(ctx, dbPath, sql)
}

func (idx *Indexer) EnsureSecondaryIndexes(ctx context.Context) error {
	out, err := idx.ExecDuckDB(ctx, idx.IndexPath(), secondaryIndexesSQL)
	if err != nil {
		return fmt.Errorf("creating DuckDB indexes: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (idx *Indexer) execDuckDB(ctx context.Context, dbPath string, sql string) ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "duckdb-*.sql")
	if err != nil {
		return nil, fmt.Errorf("creating temp SQL file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(sql); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("writing SQL to temp file: %w", err)
	}
	tmpFile.Close()

	// Reopen the temp file read-only as the duckdb subprocess's stdin. Without
	// closing this handle the index build leaked one file descriptor per batch
	// (the result was previously discarded). Close it once the command returns.
	stdin, err := os.Open(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("opening SQL temp file for duckdb stdin: %w", err)
	}
	defer stdin.Close()

	cmd := exec.CommandContext(ctx, "duckdb", dbPath)
	cmd.Stdin = stdin
	// Strip AWS credentials from the index subprocess environment (N23) — DuckDB
	// does not need them, and the parent holds live STS tokens in its env.
	cmd.Env = scrubbedEnv()
	return cmd.CombinedOutput()
}

// recordsSchema is the explicit DuckDB STRUCT shape for each element of the
// CloudTrail Records[] array.
//
// Why explicit instead of auto_detect: CloudTrail's per-API "variant" fields
// (`requestParameters`, `responseElements`, `additionalEventData`,
// `serviceEventDetails`, `addendum`, `resources`, `tlsDetails`) arrive as
// different STRUCT shapes per API call. When read_json's auto_detect tries to
// unify schemas across files in a batch it can hit a
// "MAP -> STRUCT cast unimplemented" error and the whole batch fails.
//
// By declaring those fields as JSON in `columns={...}`, DuckDB stores them as
// JSON strings instead of trying to unify struct shapes — other fields
// (userIdentity, eventName, errorCode, …) retain their structured type and
// remain query-friendly via dot access (`r.userIdentity.arn`).
//
// Queries that need to peek inside the JSON-typed fields use:
//
//	json_extract_string(r.requestParameters, '$.roleArn')
//
// The field set was derived from `SELECT DISTINCT key FROM unnest(json_keys(...))`
// across our actual data plus the published CloudTrail record reference. New
// top-level fields not in this list will be silently dropped at index time;
// when AWS adds a field, append it here. Order matches the alphabetical
// enumeration to make diffs easier.
const recordsSchema = `addendum JSON, additionalEventData JSON, apiVersion VARCHAR, ` +
	`awsRegion VARCHAR, errorCode VARCHAR, errorMessage VARCHAR, eventCategory VARCHAR, ` +
	`eventID VARCHAR, eventName VARCHAR, eventSource VARCHAR, eventTime VARCHAR, ` +
	`eventType VARCHAR, eventVersion VARCHAR, managementEvent VARCHAR, readOnly VARCHAR, ` +
	`recipientAccountId VARCHAR, requestID VARCHAR, requestParameters JSON, resources JSON, ` +
	`responseElements JSON, serviceEventDetails JSON, sessionCredentialFromConsole VARCHAR, ` +
	`sharedEventID VARCHAR, sourceIPAddress VARCHAR, tlsDetails JSON, userAgent VARCHAR, ` +
	`userIdentity STRUCT("type" VARCHAR, principalId VARCHAR, arn VARCHAR, accountId VARCHAR, ` +
	`accessKeyId VARCHAR, sessionContext STRUCT(sessionIssuer STRUCT("type" VARCHAR, principalId VARCHAR, ` +
	`arn VARCHAR, accountId VARCHAR, userName VARCHAR), attributes STRUCT(creationDate VARCHAR, ` +
	`mfaAuthenticated VARCHAR)), invokedBy VARCHAR), ` +
	`vpcEndpointAccountId VARCHAR, vpcEndpointId VARCHAR`

func (idx *Indexer) buildBatchSQL(b batch) string {
	// Build file list as a DuckDB array literal for read_json. Each path is a
	// filesystem path under the data dir, but it still flows into a SQL string
	// literal, so escape it with the shared safesql primitive (H6) rather than
	// hand-rolling quote-doubling here.
	var paths []string
	for _, f := range b.Files {
		paths = append(paths, quoteSQLLiteral(f.Path))
	}
	fileList := "[" + strings.Join(paths, ", ") + "]"
	fileTuple := "(" + strings.Join(paths, ", ") + ")"

	return fmt.Sprintf(`BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS events (
	source_file VARCHAR,
	r STRUCT(%s)
);
DELETE FROM events WHERE source_file IN %s;
INSERT INTO events
SELECT filename AS source_file, unnest(Records) as r
FROM read_json(%s,
	    filename=true,
	    maximum_object_size=%d,
	    columns={Records: 'STRUCT(%s)[]'});
COMMIT;`, recordsSchema, fileTuple, fileList, maxObjectSize, recordsSchema)
}

func (idx *Indexer) writeBatch(ctx context.Context, b batch) ([]byte, error) {
	idx.writeMu.Lock()
	defer idx.writeMu.Unlock()

	if _, _, err := idx.reconcileIndexLocked(); err != nil {
		return nil, err
	}

	out, err := idx.execDuckDB(ctx, idx.IndexPath(), idx.buildBatchSQL(b))
	if err != nil {
		return out, err
	}
	if err := idx.checkpointBatch(b); err != nil {
		return out, fmt.Errorf("checkpointing batch: %w", err)
	}
	if err := idx.markCurrentSchema(); err != nil {
		return out, fmt.Errorf("recording index schema version: %w", err)
	}
	return out, nil
}

func (idx *Indexer) checkpointBatch(b batch) error {
	tx, err := idx.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT OR REPLACE INTO indexed_files (file_path, file_size, mod_time, batch_id) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range b.Files {
		if _, err := stmt.Exec(f.Path, f.Size, f.ModTime, b.ID); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (idx *Indexer) updateState(status string, totalBytes, processedBytes int64, totalFiles, processedFiles int, lastBatchID string) {
	now := time.Now().UTC().Format(time.RFC3339)
	var startedAt interface{}
	if status == "building" && processedBytes == 0 {
		startedAt = now
	}

	if startedAt != nil {
		idx.db.Exec(`UPDATE index_state SET status = ?, total_bytes = ?, processed_bytes = ?,
			total_files = ?, processed_files = ?, last_batch_id = ?, started_at = ?, updated_at = ? WHERE id = 1`,
			status, totalBytes, processedBytes, totalFiles, processedFiles, lastBatchID, startedAt, now)
	} else {
		idx.db.Exec(`UPDATE index_state SET status = ?, total_bytes = ?, processed_bytes = ?,
			total_files = ?, processed_files = ?, last_batch_id = ?, updated_at = ? WHERE id = 1`,
			status, totalBytes, processedBytes, totalFiles, processedFiles, lastBatchID, now)
	}
}

func (idx *Indexer) setStatusOnly(status string) {
	now := time.Now().UTC().Format(time.RFC3339)
	idx.db.Exec("UPDATE index_state SET status = ?, updated_at = ? WHERE id = 1", status, now)
}

func (idx *Indexer) countIndexedFiles() (int, error) {
	var count int
	err := idx.db.QueryRow("SELECT COUNT(*) FROM indexed_files").Scan(&count)
	return count, err
}

func (idx *Indexer) clearIndexedFiles() error {
	_, err := idx.db.Exec("DELETE FROM indexed_files")
	return err
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

func (idx *Indexer) hasCurrentSchema() bool {
	data, err := os.ReadFile(idx.indexVersionPath())
	return err == nil && strings.TrimSpace(string(data)) == indexSchemaVersion
}

func (idx *Indexer) markCurrentSchema() error {
	return os.WriteFile(idx.indexVersionPath(), []byte(indexSchemaVersion+"\n"), 0600)
}

func (idx *Indexer) removeIndexArtifacts() error {
	for _, path := range []string{idx.IndexPath(), idx.IndexPath() + ".wal", idx.indexVersionPath()} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing index artifact %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

// reconcileIndexLocked keeps the DuckDB file and SQLite checkpoints in the
// same schema generation. The caller must hold writeMu.
func (idx *Indexer) reconcileIndexLocked() (bool, int, error) {
	dbExists := fileExists(idx.IndexPath())
	indexedCount, err := idx.countIndexedFiles()
	if err != nil {
		return false, 0, fmt.Errorf("counting indexed file checkpoints: %w", err)
	}

	if dbExists && !idx.hasCurrentSchema() {
		slog.Info("rebuilding legacy DuckDB index for source-aware schema",
			"component", "cloudtrail-analyzer")
		if err := idx.removeIndexArtifacts(); err != nil {
			return false, 0, err
		}
		if err := idx.clearIndexedFiles(); err != nil {
			return false, 0, fmt.Errorf("clearing legacy index checkpoints: %w", err)
		}
		return false, 0, nil
	}

	if !dbExists && indexedCount > 0 {
		slog.Warn("DuckDB index missing but checkpoint records exist, clearing checkpoints",
			"component", "cloudtrail-analyzer",
			"orphan_records", indexedCount,
		)
		if err := idx.clearIndexedFiles(); err != nil {
			return false, 0, fmt.Errorf("clearing orphaned index checkpoints: %w", err)
		}
		return false, 0, nil
	}

	return dbExists, indexedCount, nil
}

// MicroBatchIndexer accumulates extracted file paths and flushes to DuckDB
// when the accumulated size exceeds 10 MB. This enables queryable data
// within seconds of extraction starting.
const microBatchSizeThreshold = 10 * 1024 * 1024 // 10 MB

type MicroBatchIndexer struct {
	idx        *Indexer
	mu         sync.Mutex
	buffer     []fileEntry
	bufferSize int64
}

func NewMicroBatchIndexer(idx *Indexer) *MicroBatchIndexer {
	return &MicroBatchIndexer{idx: idx}
}

func (m *MicroBatchIndexer) AddFile(ctx context.Context, path string, size int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.buffer = append(m.buffer, fileEntry{
		Path:    path,
		Size:    size,
		ModTime: time.Now().UTC().Format(time.RFC3339),
	})
	m.bufferSize += size

	if m.bufferSize >= microBatchSizeThreshold {
		m.flushLocked(ctx)
	}
}

func (m *MicroBatchIndexer) Flush(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.buffer) > 0 {
		return m.flushLocked(ctx)
	}
	return nil
}

// BeginInvalidation serializes invalidation and the caller's subsequent source
// deletion with AddFile/Flush and all index writers.
func (m *MicroBatchIndexer) BeginInvalidation() (func(), error) {
	m.mu.Lock()
	if len(m.buffer) > 0 {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: a sync has files waiting to be indexed", ErrIndexBusy)
	}
	releaseIndex, err := m.idx.BeginInvalidation()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			releaseIndex()
			m.mu.Unlock()
		})
	}, nil
}

func (m *MicroBatchIndexer) InvalidateIndex() error {
	release, err := m.BeginInvalidation()
	if err != nil {
		return err
	}
	release()
	return nil
}

func (m *MicroBatchIndexer) flushLocked(parent context.Context) error {
	if len(m.buffer) == 0 {
		return nil
	}

	b := batch{
		ID:    uuid.New().String(),
		Files: m.buffer,
		Size:  m.bufferSize,
	}

	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()

	out, err := m.idx.writeBatch(ctx, b)
	if err != nil {
		slog.Error("micro-batch index failed",
			"component", "cloudtrail-analyzer",
			"files", len(m.buffer),
			"size_bytes", m.bufferSize,
			"error", err.Error(),
			"output", string(out),
		)
		// Do NOT clear the buffer on failure so the files can be retried.
		return fmt.Errorf("micro-batch index failed: %w", err)
	}
	if err := m.idx.refreshIdleStateFromCheckpoints(b.ID); err != nil {
		slog.Warn("micro-batch index state refresh failed",
			"component", "cloudtrail-analyzer",
			"error", err.Error(),
		)
	}

	slog.Info("micro-batch indexed",
		"component", "cloudtrail-analyzer",
		"files", len(b.Files),
		"size_bytes", b.Size,
	)
	m.buffer = nil
	m.bufferSize = 0
	return nil
}

// refreshIdleStateFromCheckpoints publishes aggregate progress for streaming
// micro-batches. Manual re-indexing owns its own delta-based progress counters,
// so do not overwrite a state that is actively building.
func (idx *Indexer) refreshIdleStateFromCheckpoints(lastBatchID string) error {
	var files int
	var bytes int64
	if err := idx.db.QueryRow(
		"SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM indexed_files",
	).Scan(&files, &bytes); err != nil {
		return fmt.Errorf("reading indexed checkpoint totals: %w", err)
	}

	_, err := idx.db.Exec(`UPDATE index_state SET status = 'idle',
		total_bytes = ?, processed_bytes = ?, total_files = ?, processed_files = ?,
		last_batch_id = COALESCE(NULLIF(?, ''), last_batch_id), updated_at = ?
		WHERE id = 1 AND status <> 'building'`,
		bytes, bytes, files, files, lastBatchID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("updating streaming index state: %w", err)
	}
	return nil
}

// BuildIndexedDataSource returns the DuckDB path if indexed, for use by other services.
func BuildIndexedDataSource(cfg *config.Config) string {
	indexPath := filepath.Join(cfg.DataDir, indexDBName)
	versionPath := filepath.Join(cfg.DataDir, indexVersionFile)
	version, versionErr := os.ReadFile(versionPath)
	if _, err := os.Stat(indexPath); err == nil &&
		versionErr == nil && strings.TrimSpace(string(version)) == indexSchemaVersion {
		return fmt.Sprintf("'%s'", indexPath)
	}
	return ""
}
