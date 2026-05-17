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
//   - sniff_csv / parquet_metadata / parquet_schema — leak file metadata.
//   - glob / list_files — directory enumeration.
//   - attach/detach/install/load/pragma — load extensions, attach databases.
//   - copy/export/import — write files or pull external data.
//   - DDL/DML keywords — defense in depth on top of duckdb -readonly.
//
// read_json and read_json_auto are intentionally NOT banned; the handcoded
// scenario/dashboard/lookups queries depend on them. The residual risk is
// documented in README — an LLM that hallucinates a non-data-dir path passed
// to read_json could read a local JSON file. DuckDB's -readonly flag is
// designed to reject mutations as a layer of defense.
var bannedTokens = []string{
	"read_csv", "read_csv_auto",
	"read_parquet", "parquet_metadata", "parquet_schema", "parquet_kv_metadata", "parquet_file_metadata",
	"read_blob",
	"read_text", "read_text_auto",
	"sniff_csv",
	"glob", "list_files", "directory_contents",
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

// commentRegex strips SQL comments so attackers can't hide a banned token
// inside `/* drop */ table` or `-- attach\nx`.
var (
	blockCommentRegex = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentRegex  = regexp.MustCompile(`--[^\n]*`)
	wordBoundary      = regexp.MustCompile(`[A-Za-z0-9_]+`)
)

// ValidateReadSQL inspects an LLM-generated or handcoded SQL string before it
// reaches DuckDB. It applies a denylist + statement-shape policy suited to the
// read-only investigation paths.
//
// Returns nil when the SQL passes the policy; otherwise an error wrapping
// ErrUnsafeSQL with a human-readable reason. Callers should surface the reason
// to the user without echoing the rejected SQL (the SQL itself can be logged
// for diagnosis).
func ValidateReadSQL(sql string) error {
	if strings.TrimSpace(sql) == "" {
		return fmt.Errorf("%w: empty query", ErrUnsafeSQL)
	}

	// 1. Strip comments. After this point the query has only code + string literals.
	stripped := blockCommentRegex.ReplaceAllString(sql, " ")
	stripped = lineCommentRegex.ReplaceAllString(stripped, " ")

	// 2. Strip string literals so a banned word inside 'foo bar attach' doesn't
	// trip the check. We walk single-quoted strings (DuckDB also accepts
	// double-quoted identifiers; those contain identifiers, not free text).
	codeOnly := stripStringLiterals(stripped)

	// 3. Reject multi-statement queries. A trailing semicolon is fine.
	if hasMultipleStatements(codeOnly) {
		return fmt.Errorf("%w: query must be a single statement", ErrUnsafeSQL)
	}

	lower := strings.ToLower(codeOnly)

	// 4. First non-whitespace word must be in the allowlist.
	first := firstWord(lower)
	if _, ok := allowedLeadingKeywords[first]; !ok {
		return fmt.Errorf("%w: query must start with SELECT or WITH (got %q)", ErrUnsafeSQL, first)
	}

	// 5. Reject any banned token as a whole word. We use a regex word-boundary
	// scan so substrings like 'created_at' don't match the 'create' rule.
	tokens := wordBoundary.FindAllString(lower, -1)
	for _, tok := range tokens {
		for _, banned := range bannedTokens {
			if tok == banned {
				return fmt.Errorf("%w: query references banned token %q", ErrUnsafeSQL, banned)
			}
		}
	}

	return nil
}

// stripStringLiterals replaces each '...' (with '' as the escape) by spaces of
// the same length, preserving offsets so subsequent regexes match positionally.
func stripStringLiterals(s string) string {
	out := make([]byte, len(s))
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case !inStr && c == '\'':
			inStr = true
			out[i] = ' '
		case inStr && c == '\'':
			// Escaped quote ('') stays inside the string.
			if i+1 < len(s) && s[i+1] == '\'' {
				out[i] = ' '
				out[i+1] = ' '
				i++
				continue
			}
			inStr = false
			out[i] = ' '
		case inStr:
			out[i] = ' '
		default:
			out[i] = c
		}
	}
	return string(out)
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
