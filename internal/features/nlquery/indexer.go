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
const batchSizeThreshold = 100 * 1024 * 1024 // 100 MB

var ErrAlreadyRunning = errors.New("indexing is already in progress")

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
}

func NewIndexer(cfg *config.Config, db *sql.DB) *Indexer {
	return &Indexer{cfg: cfg, db: db}
}

func (idx *Indexer) IndexPath() string {
	return filepath.Join(idx.cfg.DataDir, indexDBName)
}

func (idx *Indexer) IsIndexed() bool {
	info, err := os.Stat(idx.IndexPath())
	return err == nil && info.Size() > 0
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

func (idx *Indexer) BuildIndexIncremental(ctx context.Context, dataPath string) error {
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
	idx.mu.Unlock()

	defer func() {
		idx.mu.Lock()
		idx.cancel = nil
		idx.mu.Unlock()
		cancel()
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
	dbPath := idx.IndexPath()
	dbExists := fileExists(dbPath)
	indexedCount, _ := idx.countIndexedFiles()

	if !dbExists && indexedCount > 0 {
		slog.Warn("DuckDB index missing but checkpoint records exist, clearing checkpoints",
			"component", "cloudtrail-analyzer",
			"orphan_records", indexedCount,
		)
		idx.clearIndexedFiles()
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
	isFirstBatch := !dbExists && indexedCount == 0

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

		// Build and execute DuckDB SQL via temp file (avoids argument list too long)
		duckSQL := idx.buildBatchSQL(b, dbPath, isFirstBatch && i == 0)
		out, err := idx.execDuckDB(ctx, dbPath, duckSQL)
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

		// Checkpoint: record indexed files in SQLite
		if err := idx.checkpointBatch(b); err != nil {
			idx.updateState("error", totalBytes, processedBytes, len(newFiles), processedFiles, "")
			return fmt.Errorf("checkpointing batch %d: %w", i+1, err)
		}

		processedBytes += b.Size
		processedFiles += len(b.Files)
		idx.updateState("building", totalBytes, processedBytes, len(newFiles), processedFiles, b.ID)
	}

	// Step 7: Create indexes (best effort)
	indexSQL := `
		CREATE INDEX IF NOT EXISTS idx_event_name ON events ((r.eventName));
		CREATE INDEX IF NOT EXISTS idx_event_source ON events ((r.eventSource));
		CREATE INDEX IF NOT EXISTS idx_error_code ON events ((r.errorCode));
	`
	idx.execDuckDB(ctx, dbPath, indexSQL)

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
	return idx.execDuckDB(ctx, dbPath, sql)
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

	cmd := exec.CommandContext(ctx, "duckdb", dbPath)
	cmd.Stdin, _ = os.Open(tmpFile.Name())
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

func (idx *Indexer) buildBatchSQL(b batch, dbPath string, createTable bool) string {
	// Build file list as DuckDB array literal
	var paths []string
	for _, f := range b.Files {
		paths = append(paths, "'"+strings.ReplaceAll(f.Path, "'", "''")+"'")
	}
	fileList := "[" + strings.Join(paths, ", ") + "]"

	if createTable {
		return fmt.Sprintf(`CREATE TABLE events AS
SELECT unnest(Records) as r
FROM read_json(%s,
    maximum_object_size=16777216,
    columns={Records: 'STRUCT(%s)[]'});`, fileList, recordsSchema)
	}

	return fmt.Sprintf(`INSERT INTO events
SELECT unnest(Records) as r
FROM read_json(%s,
    maximum_object_size=16777216,
    columns={Records: 'STRUCT(%s)[]'});`, fileList, recordsSchema)
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

func (idx *Indexer) clearIndexedFiles() {
	idx.db.Exec("DELETE FROM indexed_files")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
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
	dbCreated  bool
}

func NewMicroBatchIndexer(idx *Indexer) *MicroBatchIndexer {
	return &MicroBatchIndexer{idx: idx}
}

func (m *MicroBatchIndexer) AddFile(path string, size int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.buffer = append(m.buffer, fileEntry{
		Path:    path,
		Size:    size,
		ModTime: time.Now().UTC().Format(time.RFC3339),
	})
	m.bufferSize += size

	if m.bufferSize >= microBatchSizeThreshold {
		m.flushLocked()
	}
}

func (m *MicroBatchIndexer) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.buffer) > 0 {
		m.flushLocked()
	}
}

func (m *MicroBatchIndexer) flushLocked() {
	if len(m.buffer) == 0 {
		return
	}

	b := batch{
		ID:    uuid.New().String(),
		Files: m.buffer,
		Size:  m.bufferSize,
	}

	dbPath := m.idx.IndexPath()

	// Acquire indexer lock to prevent conflict with manual Re-index
	m.idx.mu.Lock()
	createTable := !m.dbCreated && !fileExists(dbPath)
	m.idx.mu.Unlock()

	duckSQL := m.idx.buildBatchSQL(b, dbPath, createTable)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out, err := m.idx.execDuckDB(ctx, dbPath, duckSQL)
	if err != nil {
		slog.Error("micro-batch index failed",
			"component", "cloudtrail-analyzer",
			"files", len(m.buffer),
			"size_bytes", m.bufferSize,
			"error", err.Error(),
			"output", string(out),
		)
	} else {
		m.dbCreated = true
		if err := m.idx.checkpointBatch(b); err != nil {
			slog.Warn("micro-batch checkpoint failed",
				"component", "cloudtrail-analyzer",
				"error", err.Error(),
			)
		}
		slog.Info("micro-batch indexed",
			"component", "cloudtrail-analyzer",
			"files", len(b.Files),
			"size_bytes", b.Size,
		)
	}

	m.buffer = nil
	m.bufferSize = 0
}

// BuildIndexedDataSource returns the DuckDB path if indexed, for use by other services.
func BuildIndexedDataSource(cfg *config.Config) string {
	indexPath := filepath.Join(cfg.DataDir, indexDBName)
	if _, err := os.Stat(indexPath); err == nil {
		return fmt.Sprintf("'%s'", indexPath)
	}
	return ""
}
