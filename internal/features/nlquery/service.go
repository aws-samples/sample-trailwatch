package nlquery

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"cloudtrail-analyzer/internal/config"
)

type Service struct {
	cfg *config.Config
}

func NewService(cfg *config.Config) *Service {
	return &Service{cfg: cfg}
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
		return &ExecuteResponse{
			SQL:   sql,
			Error: err.Error(),
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
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.QueryTimeoutSeconds)*time.Second)
	defer cancel()

	// Use indexed DuckDB file if available, otherwise :memory:
	dbTarget := ":memory:"
	indexer := NewIndexer(s.cfg)
	if indexer.IsIndexed() {
		dbTarget = indexer.IndexPath()
		// Rewrite SQL to use the events table instead of read_json
		sql = rewriteForIndex(sql)
	}

	// Run DuckDB with CSV output for easy parsing
	cmd := exec.CommandContext(timeoutCtx, "duckdb", "-csv", "-noheader", dbTarget, sql)

	// First get headers
	headerCmd := exec.CommandContext(timeoutCtx, "duckdb", "-csv", dbTarget, sql)
	headerOut, err := headerCmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, nil, fmt.Errorf("DuckDB error: %s", string(exitErr.Stderr))
		}
		return nil, nil, fmt.Errorf("running DuckDB: %w", err)
	}

	_ = cmd // we'll use headerCmd output which includes headers

	output := string(headerOut)
	if strings.TrimSpace(output) == "" {
		return []string{}, [][]interface{}{}, nil
	}

	reader := csv.NewReader(strings.NewReader(output))
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

