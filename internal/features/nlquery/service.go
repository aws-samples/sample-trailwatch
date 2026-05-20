package nlquery

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cloudtrail-analyzer/internal/config"
)

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
	sql, err := s.generateSQL(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("bedrock SQL generation: %w", err)
	}

	slog.Info("generated SQL from Bedrock",
		"component", "cloudtrail-analyzer",
		"sql", sql,
	)

	columns, rows, err := s.executeDuckDB(ctx, sql)
	if err != nil {
		hint, detail := classifyDuckDBError(err)
		return &ExecuteResponse{
			SQL:         sql,
			Error:       err.Error(),
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

func rewriteForIndex(sql string) string {
	// Replace the read_json + unnest pattern with a direct table scan
	// Pattern: "SELECT unnest(Records) as r FROM read_json('...'...)"  →  "SELECT r FROM events"
	// The indexed table already has unnested records stored as column 'r'
	idx := strings.Index(sql, "SELECT unnest(Records) as r")
	if idx == -1 {
		return sql
	}

	// Find the closing parenthesis of the FROM clause
	fromIdx := strings.Index(sql[idx:], "FROM read_json(")
	if fromIdx == -1 {
		return sql
	}

	// Find the matching closing paren for read_json(...)
	start := idx + fromIdx + len("FROM read_json(")
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

	// Replace the entire subquery with "events"
	replacement := sql[:idx] + "SELECT r FROM events" + sql[end:]
	return replacement
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

func (s *Service) executeDuckDB(ctx context.Context, sql string) ([]string, [][]interface{}, error) {
	// Defense-in-depth: every query routed through the read path is validated
	// before reaching DuckDB. Blocks LLM hallucinations and prompt-injection
	// payloads from invoking filesystem readers (read_csv_auto, read_parquet),
	// extension loaders (INSTALL/LOAD), and DDL/DML even when DuckDB is in
	// -readonly mode.
	if err := ValidateReadSQL(sql); err != nil {
		slog.Warn("rejected unsafe SQL",
			"component", "cloudtrail-analyzer",
			"reason", err.Error(),
			"sql", sql,
		)
		return nil, nil, err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.QueryTimeoutSeconds)*time.Second)
	defer cancel()

	// Use indexed DuckDB file if available, otherwise :memory:
	dbTarget := ":memory:"
	readOnly := false
	indexPath := BuildIndexedDataSource(s.cfg)
	if indexPath != "" {
		dbTarget = filepath.Join(s.cfg.DataDir, indexDBName)
		sql = rewriteForIndex(sql)
		readOnly = true
	}

	// Single DuckDB process with -csv (includes headers as first row)
	args := []string{}
	if readOnly {
		args = append(args, "-readonly")
	}
	args = append(args, "-csv", dbTarget, sql)

	cmd := exec.CommandContext(timeoutCtx, "duckdb", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, nil, fmt.Errorf("DuckDB error: %s", string(exitErr.Stderr))
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
			row[i] = val
		}
		rows = append(rows, row)
	}

	return columns, rows, nil
}

// classifyDuckDBError turns a raw DuckDB error into a user-facing hint plus
// the raw detail. Hints are tuned for the common LLM-generated SQL failures
// (missing columns, type mismatches, syntax errors, timeouts) so a non-SQL
// analyst sees an actionable next step without losing the underlying message.
func classifyDuckDBError(err error) (hint, detail string) {
	if err == nil {
		return "", ""
	}
	detail = err.Error()
	switch {
	case strings.Contains(detail, "Binder Error") && strings.Contains(detail, "Could not find"):
		hint = "The AI generated a query that references a field this dataset doesn't have. Try rephrasing your question or naming the field more precisely."
	case strings.Contains(detail, "Binder Error"):
		hint = "The AI generated SQL the database couldn't validate. Try rephrasing your question."
	case strings.Contains(detail, "Catalog Error"):
		hint = "The AI referenced a table or function that doesn't exist here. Try rephrasing or asking a simpler question."
	case strings.Contains(detail, "Parser Error"), strings.Contains(detail, "Syntax Error"):
		hint = "The AI generated invalid SQL. Try rephrasing your question."
	case strings.Contains(detail, "Conversion Error"), strings.Contains(detail, "Invalid Input"):
		hint = "The AI tried to use a value the database couldn't convert (e.g. wrong type or format). Try rephrasing."
	case strings.Contains(detail, "context deadline exceeded"), strings.Contains(detail, "signal: killed"):
		hint = "The query took too long and was cancelled. Try narrowing the time range or filtering by account."
	default:
		hint = "The query failed. See the technical detail for more."
	}
	return hint, detail
}

func (s *Service) buildSystemPrompt() string {
	dataPath := s.buildDataPath()

	return fmt.Sprintf(`You are a DuckDB SQL generator for AWS CloudTrail log analysis.

Given a natural language question about AWS CloudTrail logs, generate ONLY a DuckDB SQL query.
Output ONLY the SQL query inside a sql code block. No explanations, no commentary.

## Data Location
CloudTrail JSON files are at: %s

## Query Pattern
CloudTrail files have a top-level "Records" array. Always unnest it:

SELECT r.*
FROM (
  SELECT unnest(Records) as r
  FROM read_json('%s**/*.json',
    maximum_object_size=16777216,
    auto_detect=true,
    union_by_name=true)
)
WHERE <your_conditions>;

## Key Rules
- Always use read_json() with maximum_object_size=16777216, auto_detect=true, union_by_name=true
- Always unnest Records array
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
- For approximate distinct counts on large data use approx_count_distinct()`, dataPath, dataPath, s.cfg.S3.AccountID, s.cfg.S3.Region)
}

func (s *Service) buildDataPath() string {
	if s.cfg.S3.Bucket == "" {
		return ""
	}

	region := s.cfg.S3.LogRegion
	if region == "" {
		region = s.cfg.S3.Region
	}

	if s.cfg.S3.Mode == "control_tower" && s.cfg.S3.OrgID != "" {
		return fmt.Sprintf("%s/s3/%s/%s/AWSLogs/%s/%s/CloudTrail/%s/",
			s.cfg.DataDir, s.cfg.S3.Bucket,
			s.cfg.S3.OrgID, s.cfg.S3.OrgID, s.cfg.S3.AccountID, region)
	}

	return fmt.Sprintf("%s/s3/%s/AWSLogs/%s/CloudTrail/%s/",
		s.cfg.DataDir, s.cfg.S3.Bucket, s.cfg.S3.AccountID, region)
}

// buildIndexDataPath returns a broader path for indexing that covers all accounts.
// In control_tower mode, scans all accounts under the org; in single mode, same as buildDataPath.
func (s *Service) buildIndexDataPath() string {
	if s.cfg.S3.Bucket == "" {
		return ""
	}

	if s.cfg.S3.Mode == "control_tower" && s.cfg.S3.OrgID != "" {
		return fmt.Sprintf("%s/s3/%s/%s/AWSLogs/%s/",
			s.cfg.DataDir, s.cfg.S3.Bucket,
			s.cfg.S3.OrgID, s.cfg.S3.OrgID)
	}

	return s.buildDataPath()
}

