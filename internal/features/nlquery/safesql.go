package nlquery

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrUnsafeSQL is returned by ValidateReadSQL when a query contains a banned
// token, leading keyword, or shape that could read filesystem data outside the
// CloudTrail dataset, mutate state, or run arbitrary DuckDB extensions.
var ErrUnsafeSQL = errors.New("unsafe SQL")

// bannedTokens are DuckDB functions and statements that have no legitimate use
// in the read-only NLQ + investigate + dashboard + lookups paths and are the
// well-known escape hatches for filesystem and extension abuse.
//
// Why these:
//   - read_csv*/read_parquet/read_blob/read_text — read arbitrary files; an
//     LLM could be tricked into pointing them at /etc/passwd, ~/.aws/credentials, etc.
//   - read_ndjson*/read_json_objects — additional JSON readers that bypass
//     the scoped view; no application query uses them.
//   - sniff_csv / parquet_metadata / parquet_schema — leak file metadata.
//   - glob / list_files — directory enumeration.
//   - query / query_table — dynamic SQL execution that can hide an unscoped
//     SELECT inside a string literal stripped by the validator, bypassing
//     account-scope restrictions (see SQL-01).
//   - attach/detach/install/load/pragma — load extensions, attach databases.
//   - copy/export/import — write files or pull external data.
//   - DDL/DML keywords — defense in depth on top of duckdb -readonly.
//
// read_json and read_json_auto are intentionally NOT banned at the base level;
// the handcoded scenario/dashboard/lookups queries depend on them. They ARE
// banned by ValidateIndexedSQL and ValidateGeneratedSQL. The residual risk is
// documented in README — an LLM that hallucinates a non-data-dir path passed
// to read_json could read a local JSON file. DuckDB's -readonly flag is
// designed to reject mutations as a layer of defense.
var bannedTokens = []string{
	"read_csv", "read_csv_auto",
	"read_parquet", "parquet_metadata", "parquet_schema", "parquet_kv_metadata", "parquet_file_metadata",
	"read_blob",
	"read_text", "read_text_auto",
	"read_ndjson", "read_ndjson_auto", "read_json_objects",
	"sniff_csv",
	"glob", "list_files", "directory_contents",
	"query", "query_table",
	"attach", "detach", "install", "load", "pragma",
	"copy", "export", "import",
	"create", "drop", "alter", "truncate",
	"insert", "update", "delete", "merge", "replace",
	"call", "vacuum", "checkpoint",
}

// allowedLeadingKeywords restricts the first significant token of a query to
// read-shaped statements. Anything else is rejected even if it contains no
// banned tokens.
var allowedLeadingKeywords = map[string]struct{}{
	"select": {},
	"with":   {},
	// EXPLAIN/DESCRIBE/SHOW are read-only and could be useful, but the NLQ
	// codepath has no use for them today; allow if a real need arises.
}

var wordBoundary = regexp.MustCompile(`[A-Za-z0-9_]+`)

// ValidateReadSQL inspects an LLM-generated or handcoded SQL string before it
// reaches DuckDB. It applies a denylist + statement-shape policy suited to the
// read-only investigation paths.
//
// Returns nil when the SQL passes the policy; otherwise an error wrapping
// ErrUnsafeSQL with a human-readable reason. Callers should surface the reason
// to the user without echoing the rejected SQL (the SQL itself can be logged
// for diagnosis).
func ValidateReadSQL(sql string) error {
	_, err := validateReadSQL(sql)
	return err
}

func validateReadSQL(sql string) (string, error) {
	if strings.TrimSpace(sql) == "" {
		return "", fmt.Errorf("%w: empty query", ErrUnsafeSQL)
	}

	// Strip literals and comments in one stateful pass. Doing these as separate
	// regex operations is unsafe: a comment marker inside a quoted value could
	// otherwise hide a later statement from the validator.
	codeOnly, err := sqlCodeOnly(sql)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnsafeSQL, err)
	}

	// Reject multi-statement queries. A trailing semicolon is fine.
	if hasMultipleStatements(codeOnly) {
		return "", fmt.Errorf("%w: query must be a single statement", ErrUnsafeSQL)
	}

	lower := strings.ToLower(codeOnly)

	// First non-whitespace word must be in the allowlist.
	first := firstWord(lower)
	if _, ok := allowedLeadingKeywords[first]; !ok {
		return "", fmt.Errorf("%w: query must start with SELECT or WITH (got %q)", ErrUnsafeSQL, first)
	}

	// Reject any banned token as a whole word. We use a regex word-boundary
	// scan so substrings like 'created_at' don't match the 'create' rule.
	tokens := wordBoundary.FindAllString(lower, -1)
	for _, tok := range tokens {
		for _, banned := range bannedTokens {
			if tok == banned {
				return "", fmt.Errorf("%w: query references banned token %q", ErrUnsafeSQL, banned)
			}
		}
	}

	return codeOnly, nil
}

// ValidateIndexedSQL applies the general read policy and then rejects raw JSON
// readers. LLM-generated queries run only against the prebuilt events table;
// allowing read_json there would let a prompt point DuckDB at an arbitrary
// local JSON file.
func ValidateIndexedSQL(sql string) error {
	_, err := validateIndexedSQL(sql)
	return err
}

func validateIndexedSQL(sql string) (string, error) {
	codeOnly, err := validateReadSQL(sql)
	if err != nil {
		return "", err
	}

	codeOnly = strings.ToLower(codeOnly)
	for _, token := range wordBoundary.FindAllString(codeOnly, -1) {
		if token == "read_json" || token == "read_json_auto" {
			return "", fmt.Errorf("%w: indexed queries cannot read external JSON files", ErrUnsafeSQL)
		}
	}
	return codeOnly, nil
}

// ValidateGeneratedSQL restricts model-generated SQL to the temporary,
// account-scoped cloudtrail_events view. The underlying events table contains
// every indexed account and must never be directly addressable by model output.
//
// Note: query() and query_table() are already rejected by the base
// ValidateReadSQL banned-token check. The explicit events-table and
// scoped-view checks here are the generated-SQL-specific policy layer.
func ValidateGeneratedSQL(sql string) error {
	codeOnly, err := validateIndexedSQL(sql)
	if err != nil {
		return err
	}

	hasScopedView := false
	for _, token := range wordBoundary.FindAllString(codeOnly, -1) {
		switch token {
		case "events":
			return fmt.Errorf("%w: generated queries cannot reference the unscoped events table", ErrUnsafeSQL)
		case "cloudtrail_events":
			hasScopedView = true
		}
	}
	if !hasScopedView {
		return fmt.Errorf("%w: generated query must use the cloudtrail_events view", ErrUnsafeSQL)
	}
	return nil
}

// sqlCodeOnly replaces string literals and comments with spaces while retaining
// executable SQL and quoted identifier words. A single lexer prevents comment
// markers inside literals from changing how the validator sees later code.
func sqlCodeOnly(s string) (string, error) {
	out := make([]byte, len(s))
	for i := range out {
		out[i] = ' '
	}

	const (
		sqlCode = iota
		sqlString
		sqlQuotedIdentifier
		sqlLineComment
		sqlBlockComment
	)
	state := sqlCode
	blockDepth := 0

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch state {
		case sqlCode:
			switch {
			case c == '\'':
				state = sqlString
			case c == '"':
				state = sqlQuotedIdentifier
			case c == '-' && i+1 < len(s) && s[i+1] == '-':
				state = sqlLineComment
				i++
			case c == '/' && i+1 < len(s) && s[i+1] == '*':
				state = sqlBlockComment
				blockDepth = 1
				i++
			default:
				out[i] = c
			}
		case sqlString:
			if c != '\'' {
				continue
			}
			if i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			state = sqlCode
		case sqlQuotedIdentifier:
			if c == '"' {
				if i+1 < len(s) && s[i+1] == '"' {
					i++
					continue
				}
				state = sqlCode
				continue
			}
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '_' {
				out[i] = c
			}
		case sqlLineComment:
			if c == '\n' {
				out[i] = c
				state = sqlCode
			}
		case sqlBlockComment:
			switch {
			case c == '/' && i+1 < len(s) && s[i+1] == '*':
				blockDepth++
				i++
			case c == '*' && i+1 < len(s) && s[i+1] == '/':
				blockDepth--
				i++
				if blockDepth == 0 {
					state = sqlCode
				}
			}
		}
	}

	switch state {
	case sqlString:
		return "", fmt.Errorf("unterminated string literal")
	case sqlQuotedIdentifier:
		return "", fmt.Errorf("unterminated quoted identifier")
	case sqlBlockComment:
		return "", fmt.Errorf("unterminated block comment")
	default:
		return string(out), nil
	}
}

// hasMultipleStatements reports true if the code (after string-literal removal)
// contains a semicolon followed by more non-whitespace content.
func hasMultipleStatements(code string) bool {
	idx := strings.IndexByte(code, ';')
	if idx == -1 {
		return false
	}
	for i := idx + 1; i < len(code); i++ {
		switch code[i] {
		case ' ', '\t', '\n', '\r', ';':
			continue
		default:
			return true
		}
	}
	return false
}

// escapeSQLLiteral escapes a string for safe interpolation INSIDE a
// single-quoted DuckDB string literal. It doubles embedded single quotes (the
// SQL-standard escape) so a value containing a quote cannot break out of the
// literal and inject SQL. The caller is responsible for supplying the
// surrounding quotes — see quoteSQLLiteral for the quoted form.
//
// This is the single escaping primitive used wherever config-derived values
// (S3 bucket, org_id, account_id, region, data dir) are interpolated into the
// read_json('...') path and other handcoded query fragments. Those values were
// previously interpolated raw, so a quote in a bucket/org/account value could
// break out of the literal and bypass the read-only allowlist.
func escapeSQLLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// quoteSQLLiteral returns the value wrapped in single quotes with embedded
// quotes doubled, e.g. `O'Brien` -> `'O”Brien'`. Use this when building a
// complete quoted literal.
func quoteSQLLiteral(s string) string {
	return "'" + escapeSQLLiteral(s) + "'"
}

func firstWord(lower string) string {
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '(' {
			continue
		}
		// Found start.
		end := i
		for end < len(lower) {
			c := lower[end]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
				end++
				continue
			}
			break
		}
		if end > i {
			return lower[i:end]
		}
		break
	}
	return ""
}
