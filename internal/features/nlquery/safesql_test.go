package nlquery

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateReadSQL_AllowsCloudTrailPatterns(t *testing.T) {
	cases := []string{
		`SELECT r.eventName FROM (SELECT unnest(Records) as r FROM read_json('data/s3/foo/**/*.json', auto_detect=true, union_by_name=true)) WHERE r.eventTime >= '2025-01-01' LIMIT 100;`,
		`SELECT COUNT(*) FROM events;`,
		`WITH x AS (SELECT 1) SELECT * FROM x;`,
		`select r.userIdentity.arn, count(*) from (select unnest(Records) as r from read_json_auto('p')) group by 1 order by 2 desc limit 50`,
		`SELECT * FROM events WHERE r.eventName = 'CreateUser' AND r.errorCode IS NULL;`,
		// Comments and whitespace
		"SELECT 1 -- a comment\n;",
		"/* leading comment */ SELECT 1;",
		// Identifier shaped like a banned word — should pass.
		`SELECT created_at, deleted_count FROM events_table;`,
	}
	for _, sql := range cases {
		if err := ValidateReadSQL(sql); err != nil {
			t.Errorf("expected safe, got %v\nsql: %s", err, sql)
		}
	}
}

func TestValidateReadSQL_BlocksFilesystemFunctions(t *testing.T) {
	cases := []string{
		`SELECT * FROM read_csv_auto('/etc/passwd');`,
		`SELECT * FROM read_csv('/Users/me/.aws/credentials');`,
		`SELECT * FROM read_parquet('/var/log/secure.parquet');`,
		`SELECT * FROM read_blob('/etc/shadow');`,
		`SELECT * FROM read_text('/Users/me/.ssh/id_rsa');`,
		`SELECT * FROM read_text_auto('/Users/me/.ssh/id_rsa');`,
		`SELECT sniff_csv('/tmp/x.csv');`,
		`SELECT * FROM glob('/Users/**');`,
		`SELECT * FROM list_files('/');`,
	}
	for _, sql := range cases {
		err := ValidateReadSQL(sql)
		if err == nil {
			t.Errorf("expected unsafe but passed: %s", sql)
			continue
		}
		if !errors.Is(err, ErrUnsafeSQL) {
			t.Errorf("expected ErrUnsafeSQL, got %v", err)
		}
	}
}

func TestValidateReadSQL_BlocksDDLAndDML(t *testing.T) {
	cases := []string{
		`DROP TABLE events;`,
		`CREATE TABLE x AS SELECT 1;`,
		`ALTER TABLE events ADD COLUMN x int;`,
		`TRUNCATE events;`,
		`INSERT INTO events VALUES (1);`,
		`UPDATE events SET errorCode = NULL;`,
		`DELETE FROM events;`,
		`MERGE INTO events USING x ON 1 = 1;`,
		`COPY events TO '/tmp/x.csv';`,
	}
	for _, sql := range cases {
		if err := ValidateReadSQL(sql); err == nil {
			t.Errorf("expected unsafe but passed: %s", sql)
		}
	}
}

func TestValidateReadSQL_BlocksAttachLoadInstall(t *testing.T) {
	cases := []string{
		`ATTACH '/tmp/x.duckdb' AS x;`,
		`DETACH x;`,
		`INSTALL httpfs;`,
		`LOAD httpfs;`,
		`PRAGMA enable_external_access;`,
	}
	for _, sql := range cases {
		if err := ValidateReadSQL(sql); err == nil {
			t.Errorf("expected unsafe but passed: %s", sql)
		}
	}
}

func TestValidateReadSQL_RejectsMultipleStatements(t *testing.T) {
	cases := []string{
		`SELECT 1; SELECT 2;`,
		`SELECT 1;DROP TABLE events;`,
		`SELECT 1; ATTACH 'x.db' AS x;`,
	}
	for _, sql := range cases {
		err := ValidateReadSQL(sql)
		if err == nil {
			t.Errorf("expected rejection of multi-statement: %s", sql)
		}
	}
}

func TestValidateReadSQL_BypassAttempts(t *testing.T) {
	// Common bypass patterns we deliberately defeat.
	cases := []struct {
		name string
		sql  string
	}{
		{"uppercase", `SELECT * FROM READ_CSV_AUTO('/etc/passwd');`},
		{"mixed case", `SELECT * FROM Read_Csv_Auto('/etc/passwd');`},
		{"line comment hides function", "SELECT * FROM /* hidden */ read_csv_auto('/etc/passwd');"},
		{"block comment hides function", "SELECT * FROM \n-- comment line\nread_csv_auto('/etc/passwd');"},
		{"multiline whitespace", "SELECT\n\t*\nFROM\n\tread_csv_auto\n('/etc/passwd');"},
		{"trailing junk after semicolon", `SELECT 1; ATTACH 'x' AS x;`},
		{"extra parens", `SELECT (SELECT * FROM read_csv_auto('p'));`},
		{"function call with explicit schema", `SELECT * FROM main.read_csv_auto('p');`},
		{"with-clause smuggling", `WITH x AS (SELECT * FROM read_csv_auto('/etc/passwd')) SELECT * FROM x;`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateReadSQL(c.sql); err == nil {
				t.Errorf("bypass not caught: %s", c.sql)
			}
		})
	}
}

func TestValidateReadSQL_RejectsNonSelectLeading(t *testing.T) {
	cases := []string{
		`EXPLAIN SELECT 1;`, // explain not in allowlist today
		`DESCRIBE events;`,
		`SHOW TABLES;`,
		``,
		`   `,
	}
	for _, sql := range cases {
		if err := ValidateReadSQL(sql); err == nil {
			t.Errorf("expected rejection: %q", sql)
		}
	}
}

func TestValidateReadSQL_AllowsBannedWordsInsideStrings(t *testing.T) {
	// A user search for the literal word "drop table" or an event name like
	// 'DeleteUser' must not trip the guard.
	cases := []string{
		`SELECT r.eventName FROM events WHERE r.eventName = 'DeleteUser';`,
		`SELECT r.eventName FROM events WHERE r.eventName LIKE '%drop%';`,
		`SELECT r.errorMessage FROM events WHERE r.errorMessage = 'attach failed';`,
		`SELECT r.userAgent FROM events WHERE r.userAgent LIKE '%install%';`,
	}
	for _, sql := range cases {
		if err := ValidateReadSQL(sql); err != nil {
			t.Errorf("expected allow (banned word inside string): got %v\nsql: %s", err, sql)
		}
	}
}

func TestValidateReadSQL_ErrorIncludesReason(t *testing.T) {
	err := ValidateReadSQL(`SELECT * FROM read_csv_auto('/etc/passwd');`)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "read_csv_auto") {
		t.Errorf("expected reason to name the banned token, got: %v", err)
	}
}
