package nlquery

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cloudtrail-analyzer/internal/cloudtrailpath"
	"cloudtrail-analyzer/internal/config"
)

// nullSentinel is the marker DuckDB prints for SQL NULL when invoked with
// `-nullvalue`. It is an improbable token (no NUL byte — argv cannot carry one)
// chosen so it does not collide with any real CloudTrail cell value, letting
// the CSV row builder distinguish a genuine NULL from an empty field or the
// literal text "NULL". See the NULL handling in executeDuckDB (N31/N98/N103).
const nullSentinel = "\x1eCTA_NULL\x1e"

// maxFreeFormRows is the defensive upper bound applied to free-form NLQ
// (Execute path) results. The system prompt asks the LLM for `LIMIT 100`, but
// nothing enforced it, so a generated query missing the clause could stream
// millions of rows back through the API (N29). We append a bounded outer LIMIT
// as a guard; queries that already cap themselves below this are unaffected.
const maxFreeFormRows = 1000

var ErrIndexRequired = errors.New("indexed CloudTrail data is required")

// Limit the number of heavyweight DuckDB CLI readers across all handlers.
// Dashboard and findings endpoints fan out internally; without a process-wide
// cap, one browser load can spawn dozens of database processes.
const maxConcurrentDuckDBReads = 4

var duckDBReadSlots = make(chan struct{}, maxConcurrentDuckDBReads)

// DuckDB write-lock retry policy (H11). While a sync micro-batch or a manual
// re-index holds the index file's process-level write lock, a concurrent
// read query fails fast with a lock-conflict error. We retry a few times with
// a short delay so a query issued during indexing succeeds once the writer
// releases the lock, then fall back to an actionable message.
const (
	duckDBLockRetries           = 5
	duckDBLockRetryDelay        = 400 * time.Millisecond
	duckDBIndexingInProgressMsg = "The index is being updated right now (a log sync or re-index is in progress). This query was retried but the index is still busy — wait a few seconds and run it again."
)

// duckDBLockKeywords are substrings DuckDB emits when a second process cannot
// open the database file because the writer holds the lock. Matched
// case-insensitively against stderr.
var duckDBLockKeywords = []string{
	"could not set lock",
	"conflicting lock",
	"file is already open",
	"another process",
	"set lock on file",
}

// isDuckDBLockError reports whether the DuckDB stderr indicates a write-lock
// conflict (the index file is open for writing by the sync/re-index path).
func isDuckDBLockError(stderr string) bool {
	if stderr == "" {
		return false
	}
	low := strings.ToLower(stderr)
	for _, kw := range duckDBLockKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

type Service struct {
	cfg *config.Config
	db  *sql.DB
}

func NewService(cfg *config.Config) *Service {
	return &Service{cfg: cfg}
}

func NewServiceWithDB(cfg *config.Config, db *sql.DB) *Service {
	return &Service{cfg: cfg, db: db}
}

func (s *Service) Execute(ctx context.Context, prompt string) (*ExecuteResponse, error) {
	if BuildIndexedDataSource(s.cfg) == "" {
		return nil, fmt.Errorf("%w: sync logs and build the local index before running an AI query", ErrIndexRequired)
	}

	sql, err := s.generateSQL(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("bedrock SQL generation: %w", err)
	}

	slog.Info("generated SQL from Bedrock",
		"component", "cloudtrail-analyzer",
		"sql", sql,
	)

	// Defensive row cap (N29): the prompt requests LIMIT 100 but cannot enforce
	// it. Wrap the generated query in a bounded outer LIMIT so a query that omits
	// its own LIMIT cannot return an unbounded result set. The wrapped query is
	// still validated by ValidateReadSQL inside executeDuckDB. Queries that
	// already cap below the guard are unaffected.
	guarded := guardRowLimit(sql)

	columns, rows, err := s.executeGeneratedDuckDB(ctx, guarded)
	if err != nil {
		hint, detail := classifyDuckDBError(err)
		return &ExecuteResponse{
			SQL:         sql,
			Error:       hint,
			ErrorHint:   hint,
			ErrorDetail: detail,
		}, nil
	}

	return &ExecuteResponse{
		SQL:     sql,
		Columns: columns,
		Rows:    rows,
	}, nil
}

func (s *Service) generateSQL(ctx context.Context, prompt string) (string, error) {
	provider := NewProvider(s.cfg)
	systemPrompt := s.buildSystemPrompt()

	slog.Info("generating SQL via LLM",
		"component", "cloudtrail-analyzer",
		"provider", provider.Name(),
	)

	rawText, err := provider.GenerateSQL(ctx, systemPrompt, prompt)
	if err != nil {
		return "", err
	}

	return extractSQL(rawText), nil
}

// unnestReadJSONRe matches the handcoded / prompted "SELECT unnest(Records) as r
// FROM read_json(" preamble that every dataset-reading query uses. It is
// deliberately case-insensitive and whitespace-tolerant (N32): the LLM (and a
// future prompt edit) can vary spacing, newlines, and keyword casing, and a
// brittle exact-string match would silently miss the rewrite — leaving the
// query pointed at the raw read_json path glob while we believe it is hitting
// the indexed table. A miss here is not just a slow query: it changes the data
// source AND the column types (variant fields are JSON in the index, STRUCT in
// the raw files), so detection must tolerate formatting drift.
var unnestReadJSONRe = regexp.MustCompile(`(?is)select\s+unnest\s*\(\s*Records\s*\)\s+as\s+r\s+from\s+read_json\s*\(`)

// rewriteForIndex rewrites a dataset query so it reads the prebuilt DuckDB
// `events` table instead of re-parsing the raw JSON files via read_json(). The
// indexed table already stores the unnested records as column 'r'.
//
// CROSS-ACCOUNT SCOPE (H5): the only thing that scoped a raw read_json query to
// the configured account/region was the file-path glob (…/AWSLogs/<account>/…).
// The index is built across ALL synced accounts/regions, so dropping the path
// without re-applying the scope would silently widen a single-account question
// to every synced account. We therefore re-apply the configured account scope
// as a real WHERE on the indexed `recipientAccountId` column. cfg is the source
// of truth for the configured scope; scopeAccountIDs derives the member set.
func rewriteForIndex(sql string, cfg *config.Config) string {
	loc := unnestReadJSONRe.FindStringIndex(sql)
	if loc == nil {
		return sql
	}
	idx := loc[0]
	// loc[1] sits just past the opening paren of read_json( — scan from there
	// for its matching close paren so we excise the whole read_json(...) call.
	start := loc[1]
	depth := 1
	end := start
	for end < len(sql) && depth > 0 {
		if sql[end] == '(' {
			depth++
		} else if sql[end] == ')' {
			depth--
		}
		end++
	}

	// Replace the inner unnest+read_json subquery body with a scan of the
	// indexed table, re-applying the configured account scope so the index
	// path answers the same question the raw-path query would have.
	inner := "SELECT r FROM events"
	if scope := indexScopeWhere(cfg); scope != "" {
		inner += " WHERE " + scope
	}
	return sql[:idx] + inner + sql[end:]
}

// scopeAccountIDs returns the set of AWS account IDs the current config scopes
// queries to. When a member-account subset is selected it wins (the user picked
// those accounts); otherwise we fall back to the single configured account. IDs
// are filtered to the 12-digit shape so a malformed config value cannot reach
// the SQL builder.
func scopeAccountIDs(cfg *config.Config) []string {
	var raw []string
	if cfg.S3.Mode == "control_tower" && len(cfg.S3.MemberAccounts) > 0 {
		raw = cfg.S3.MemberAccounts
	} else if cfg.S3.AccountID != "" {
		raw = []string{cfg.S3.AccountID}
	}

	var ids []string
	for _, id := range raw {
		id = strings.TrimSpace(id)
		if isValidAccountID(id) {
			ids = append(ids, id)
		}
	}
	return ids
}

// indexScopeWhere builds the `recipientAccountId IN (...)` predicate that
// re-applies the configured account scope to a query against the shared index
// (H5). Returns "" when no account scope is configured (nothing to constrain).
// Each ID is emitted via quoteSQLLiteral as defense in depth even though
// scopeAccountIDs already restricts them to digits.
func indexScopeWhere(cfg *config.Config) string {
	ids := scopeAccountIDs(cfg)
	if len(ids) == 0 {
		return ""
	}
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = quoteSQLLiteral(id)
	}
	return fmt.Sprintf("r.recipientAccountId IN (%s)", strings.Join(quoted, ", "))
}

func extractSQL(text string) string {
	// Look for SQL in code blocks first
	if idx := strings.Index(text, "```sql"); idx != -1 {
		start := idx + 6
		end := strings.Index(text[start:], "```")
		if end != -1 {
			return strings.TrimSpace(text[start : start+end])
		}
	}
	if idx := strings.Index(text, "```"); idx != -1 {
		start := idx + 3
		// Skip optional language tag on same line
		if nl := strings.Index(text[start:], "\n"); nl != -1 {
			start = start + nl + 1
		}
		end := strings.Index(text[start:], "```")
		if end != -1 {
			return strings.TrimSpace(text[start : start+end])
		}
	}
	// If no code block, return the whole text trimmed (likely just SQL)
	return strings.TrimSpace(text)
}

// guardRowLimit wraps a free-form query in a bounded outer LIMIT so a missing
// LIMIT in LLM-generated SQL cannot return an unbounded result set (N29). The
// query (a single SELECT or WITH…SELECT statement, already shape-checked
// upstream by ValidateReadSQL when executed) becomes the FROM subquery of an
// outer `SELECT * FROM (<query>) LIMIT maxFreeFormRows`. A trailing semicolon
// is trimmed first because a subquery cannot contain one. This is an upper
// bound only: a query whose own LIMIT is smaller still wins.
func guardRowLimit(query string) string {
	trimmed := strings.TrimSpace(query)
	trimmed = strings.TrimRight(trimmed, "; \t\r\n")
	if trimmed == "" {
		return query
	}
	return fmt.Sprintf("SELECT * FROM (%s) LIMIT %d;", trimmed, maxFreeFormRows)
}

func (s *Service) executeDuckDB(ctx context.Context, sql string) ([]string, [][]interface{}, error) {
	return s.executeDuckDBInternal(ctx, sql, false)
}

func (s *Service) executeGeneratedDuckDB(ctx context.Context, sql string) ([]string, [][]interface{}, error) {
	return s.executeDuckDBInternal(ctx, sql, true)
}

func (s *Service) executeDuckDBInternal(ctx context.Context, sql string, generated bool) ([]string, [][]interface{}, error) {
	// Use the indexed DuckDB file if available, otherwise :memory:. Rewrite
	// hand-authored raw-data queries before validation so an indexed read is
	// guaranteed to reference the events table rather than an external file.
	dbTarget := ":memory:"
	readOnly := false
	indexPath := BuildIndexedDataSource(s.cfg)
	if indexPath != "" {
		dbTarget = filepath.Join(s.cfg.DataDir, indexDBName)
		if !generated {
			sql = rewriteForIndex(sql, s.cfg)
		}
		readOnly = true
	}
	if generated && !readOnly {
		return nil, nil, ErrIndexRequired
	}

	validate := ValidateReadSQL
	if generated {
		validate = ValidateGeneratedSQL
	} else if readOnly {
		validate = ValidateIndexedSQL
	}
	if err := validate(sql); err != nil {
		slog.Warn("rejected unsafe SQL",
			"component", "cloudtrail-analyzer",
			"reason", err.Error(),
			"sql", sql,
		)
		return nil, nil, err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.QueryTimeoutSeconds)*time.Second)
	defer cancel()

	select {
	case duckDBReadSlots <- struct{}{}:
		defer func() { <-duckDBReadSlots }()
	case <-timeoutCtx.Done():
		return nil, nil, fmt.Errorf("waiting for an available DuckDB query slot: %w", timeoutCtx.Err())
	}

	// Single DuckDB process with -csv (includes headers as first row).
	//
	// -nullvalue makes DuckDB emit a distinct sentinel for SQL NULL instead of
	// the default empty field, so we can tell a real NULL apart from an empty
	// string in the CSV (N31/N98/N103). Without it, a genuine NULL and the
	// literal text "NULL" both arrived as the same string, the nil-guards in
	// the dashboard/lookups row builders were dead, and downstream Number()
	// coercions mis-rendered. We pick a sentinel that cannot collide with real
	// data and map it back to nil in the row builder below.
	args := []string{}
	if readOnly {
		// DuckDB read-only mode blocks mutations to the index, while disabling
		// external access blocks current and future filesystem/network readers
		// even if a function is missing from the SQL token denylist.
		initSQL := "SET enable_external_access=false;"
		if generated {
			viewSQL := "CREATE TEMP VIEW cloudtrail_events AS SELECT r FROM events"
			if scope := indexScopeWhere(s.cfg); scope != "" {
				viewSQL += " WHERE " + scope
			}
			initSQL += " " + viewSQL + ";"
		}
		args = append(args, "-readonly", "-cmd", initSQL)
	}
	args = append(args, "-nullvalue", nullSentinel, "-csv", dbTarget, sql)

	// DuckDB takes a process-level write lock on the index file while a sync's
	// micro-batch or a manual re-index is writing. A concurrent read query
	// against the same file fails immediately with a lock-conflict error rather
	// than blocking. Retry a few times with a short backoff so a query issued
	// during an active index build succeeds once the writer releases the lock,
	// instead of surfacing a confusing failure (H11). If the lock is still held
	// after the retries, return an actionable "indexing in progress" message.
	var output []byte
	var err error
	for attempt := 0; ; attempt++ {
		cmd := exec.CommandContext(timeoutCtx, "duckdb", args...)
		// DuckDB has no need for the operator's AWS credentials; strip them from
		// the subprocess environment so live STS tokens don't leak into it (N23).
		cmd.Env = scrubbedEnv()
		output, err = cmd.Output()
		if err == nil {
			break
		}

		var stderr string
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}

		if isDuckDBLockError(stderr) && attempt < duckDBLockRetries && timeoutCtx.Err() == nil {
			select {
			case <-timeoutCtx.Done():
			case <-time.After(duckDBLockRetryDelay):
			}
			continue
		}

		if isDuckDBLockError(stderr) {
			return nil, nil, fmt.Errorf("%s", duckDBIndexingInProgressMsg)
		}
		if stderr != "" {
			return nil, nil, fmt.Errorf("DuckDB error: %s", stderr)
		}
		return nil, nil, fmt.Errorf("running DuckDB: %w", err)
	}

	outputStr := string(output)
	if strings.TrimSpace(outputStr) == "" {
		return []string{}, [][]interface{}{}, nil
	}

	reader := csv.NewReader(strings.NewReader(outputStr))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("parsing DuckDB CSV output: %w", err)
	}

	if len(records) == 0 {
		return []string{}, [][]interface{}{}, nil
	}

	columns := records[0]
	var rows [][]interface{}
	for _, record := range records[1:] {
		row := make([]interface{}, len(record))
		for i, val := range record {
			// Map the NULL sentinel emitted by `-nullvalue` back to a real nil
			// so the nil-guards in callers (dashboard/lookups) are live and a
			// genuine SQL NULL is no longer confused with the literal string
			// "NULL" or an empty value. Non-null cells stay strings.
			if val == nullSentinel {
				row[i] = nil
			} else {
				row[i] = val
			}
		}
		rows = append(rows, row)
	}

	return columns, rows, nil
}

// classifyDuckDBError turns a raw DuckDB error into a user-facing hint plus
// a safe detail string. Hints are tuned for the common LLM-generated SQL failures
// (missing columns, type mismatches, syntax errors, timeouts) so a non-SQL
// analyst sees an actionable next step. The detail is truncated and sanitized
// before reaching the client (the handler also applies redactErrorString).
func classifyDuckDBError(err error) (hint, detail string) {
	if err == nil {
		return "", ""
	}
	raw := err.Error()
	// Extract just the DuckDB error type/message, not the full command stderr
	// which can contain local paths and internal state.
	switch {
	case strings.Contains(raw, "Binder Error") && strings.Contains(raw, "Could not find"):
		hint = "The AI generated a query that references a field this dataset doesn't have. Try rephrasing your question or naming the field more precisely."
		detail = extractDuckDBErrorLine(raw, "Binder Error")
	case strings.Contains(raw, "Binder Error"):
		hint = "The AI generated SQL the database couldn't validate. Try rephrasing your question."
		detail = extractDuckDBErrorLine(raw, "Binder Error")
	case strings.Contains(raw, "Catalog Error"):
		hint = "The AI referenced a table or function that doesn't exist here. Try rephrasing or asking a simpler question."
		detail = extractDuckDBErrorLine(raw, "Catalog Error")
	case strings.Contains(raw, "Parser Error"), strings.Contains(raw, "Syntax Error"):
		hint = "The AI generated invalid SQL. Try rephrasing your question."
		detail = extractDuckDBErrorLine(raw, "Error")
	case strings.Contains(raw, "Conversion Error"), strings.Contains(raw, "Invalid Input"):
		hint = "The AI tried to use a value the database couldn't convert (e.g. wrong type or format). Try rephrasing."
		detail = extractDuckDBErrorLine(raw, "Error")
	case strings.Contains(raw, "context deadline exceeded"), strings.Contains(raw, "signal: killed"):
		hint = "The query took too long and was cancelled. Try narrowing the time range or filtering by account."
		detail = "Query execution timed out"
	case strings.Contains(raw, "Could not set lock"), strings.Contains(raw, "write lock"):
		hint = "The index is currently being updated. Wait a moment and retry."
		detail = "Database is busy with indexing"
	default:
		hint = "The query failed. Try rephrasing or narrowing the scope."
		detail = ""
	}
	return hint, detail
}

// extractDuckDBErrorLine extracts the first line containing the error type
// from DuckDB stderr, truncated to avoid leaking paths. Returns empty if
// the marker is not found.
func extractDuckDBErrorLine(raw, marker string) string {
	idx := strings.Index(raw, marker)
	if idx < 0 {
		return ""
	}
	// Take from the marker to the next newline (or 200 chars max)
	rest := raw[idx:]
	if nl := strings.IndexByte(rest, '\n'); nl > 0 {
		rest = rest[:nl]
	}
	if len(rest) > 200 {
		rest = rest[:200] + "..."
	}
	return rest
}

func (s *Service) buildSystemPrompt() string {
	return fmt.Sprintf(`You are a DuckDB SQL generator for AWS CloudTrail log analysis.

Given a natural language question about AWS CloudTrail logs, generate ONLY a DuckDB SQL query.
Output ONLY the SQL query inside a sql code block. No explanations, no commentary.

## Data Source
The local DuckDB database exposes a "cloudtrail_events" view. Each row has one STRUCT
column named "r" containing a CloudTrail event. Query only this table:

SELECT r.*
FROM cloudtrail_events
WHERE <your_conditions>;

## Key Rules
- Query only the cloudtrail_events view. Never reference the base events table.
- Never call read_json or any filesystem/network reader.
- Access nested fields with dot notation: r.userIdentity."type", r.userIdentity.arn
- "type" is a reserved word - always quote it: r.userIdentity."type"
- Use LIMIT 100 unless the user asks for all results
- For date filtering use: r.eventTime >= '2026-05-06' AND r.eventTime < '2026-05-07'
- Account: %s
- Region: %s

## Variant fields are JSON, not STRUCT
The fields requestParameters, responseElements, additionalEventData, serviceEventDetails, addendum, resources, and tlsDetails are stored as JSON strings in the indexed table. Do NOT use dot access on them. To read inside, use:
- json_extract_string(r.requestParameters, '$.roleArn')
- json_extract_string(r.responseElements, '$.credentials.accessKeyId')
- For arrays: json_extract(r.resources, '$[0].ARN')
All other fields including userIdentity remain STRUCT and use dot access as before.

## DuckDB-Specific Syntax Constraints (CRITICAL)
- NEVER use LIMIT inside aggregate functions (e.g. array_agg(...LIMIT N) is invalid)
- To get "top N" within a group, use a subquery or window function with ROW_NUMBER(), then aggregate
- For aggregating strings use string_agg(col, ', ') — NOT list_agg() or array_agg()
- string_agg syntax: string_agg(expression, separator) or string_agg(expression, separator ORDER BY col)
- WRONG: string_agg(DISTINCT col ORDER BY col, ', ')  CORRECT: string_agg(col, ', ' ORDER BY col)
- For creating a list use list(col) — NOT list_agg() or array_agg()
- To get distinct values in an aggregate, use a subquery with DISTINCT first, then aggregate
- For "top N items per group" patterns, use: a subquery with ROW_NUMBER() OVER (PARTITION BY ... ORDER BY ...) then filter WHERE rn <= N in an outer query
- DuckDB uses double quotes for identifiers and single quotes for strings
- Use TRY_CAST() instead of CAST() when data types might not parse cleanly
- COUNT(DISTINCT x) is valid in DuckDB
- For approximate distinct counts on large data use approx_count_distinct()`, s.cfg.S3.AccountID, s.cfg.S3.Region)
}

func usesOrganizationQueryRoot(cfg *config.Config) bool {
	return cfg != nil &&
		cfg.S3.Mode == cloudtrailpath.MultiAccountMode &&
		cfg.S3.OrgID != ""
}

func localQueryRoot(cfg *config.Config) string {
	if cfg.S3.Bucket == "" {
		return ""
	}

	region := cfg.S3.LogRegion
	if region == "" {
		region = cfg.S3.Region
	}

	return cloudtrailpath.LocalQueryRoot(
		cfg.DataDir,
		cfg.S3.Bucket,
		cfg.S3.Mode,
		cfg.S3.OrgID,
		cfg.S3.AccountID,
		region,
	)
}

func (s *Service) buildDataPath() string {
	return localQueryRoot(s.cfg)
}

// buildIndexDataPath scans the stable bucket mirror for organization trails so
// every supported Organizations/Control Tower layout can be indexed. A
// single-account configuration retains its narrow account-and-region path.
func (s *Service) buildIndexDataPath() string {
	return localQueryRoot(s.cfg)
}
