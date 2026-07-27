package nlquery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloudtrail-analyzer/internal/config"
)

const fakeRead = `read_json('/data/**/*.json', auto_detect=true)`

func TestBuildFilteredEventsExpr_NoFiltersIsBaseExpr(t *testing.T) {
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{})
	want := `(SELECT unnest(Records) as r FROM read_json('/data/**/*.json', auto_detect=true))`
	if got != want {
		t.Errorf("no filters expr should equal base unnest\n got: %s\nwant: %s", got, want)
	}
}

func TestBuildFilteredEventsExpr_TimeStart(t *testing.T) {
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{TimeStart: "2026-05-01"})
	if !strings.Contains(got, `r.eventTime >= '2026-05-01'`) {
		t.Errorf("expected time-start predicate; got: %s", got)
	}
	// Unbounded end should not produce a TimeEnd predicate.
	if strings.Contains(got, "r.eventTime <=") {
		t.Errorf("expected no TimeEnd predicate; got: %s", got)
	}
}

func TestBuildFilteredEventsExpr_DateOnlyEndIncludesFullUTCDay(t *testing.T) {
	tests := []struct {
		end       string
		exclusive string
	}{
		{end: "2026-07-26", exclusive: "2026-07-27T00:00:00Z"},
		{end: "2024-02-29", exclusive: "2024-03-01T00:00:00Z"},
	}
	for _, tt := range tests {
		t.Run(tt.end, func(t *testing.T) {
			got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{TimeEnd: tt.end})
			if !strings.Contains(got, `r.eventTime < '`+tt.exclusive+`'`) {
				t.Fatalf("date-only end should use next UTC midnight; got: %s", got)
			}
			if strings.Contains(got, `r.eventTime <= '`+tt.end+`'`) {
				t.Fatalf("date-only end must not stop at the start of the selected day: %s", got)
			}
		})
	}
}

func TestBuildFilteredEventsExpr_TimestampEndRemainsInclusive(t *testing.T) {
	const end = "2026-07-26T12:34:56.789Z"
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{TimeEnd: end})
	if !strings.Contains(got, `r.eventTime <= '`+end+`'`) {
		t.Fatalf("timestamp end should retain inclusive semantics; got: %s", got)
	}
}

func TestBuildFilteredEventsExpr_TimeRange(t *testing.T) {
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{
		TimeStart: "2026-05-01T00:00:00Z",
		TimeEnd:   "2026-05-17T23:59:59Z",
	})
	if !strings.Contains(got, `r.eventTime >= '2026-05-01T00:00:00Z'`) {
		t.Errorf("missing TimeStart: %s", got)
	}
	if !strings.Contains(got, `r.eventTime <= '2026-05-17T23:59:59Z'`) {
		t.Errorf("missing TimeEnd: %s", got)
	}
	if !strings.Contains(got, " AND ") {
		t.Errorf("expected AND between predicates: %s", got)
	}
}

func TestBuildFilteredEventsExpr_AccountFilterMatchesEither(t *testing.T) {
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{
		AccountIDs: []string{"123456789012", "210987654321"},
	})
	if !strings.Contains(got, `r.recipientAccountId IN ('123456789012', '210987654321')`) {
		t.Errorf("missing recipientAccountId predicate: %s", got)
	}
	if !strings.Contains(got, `r.userIdentity.accountId IN ('123456789012', '210987654321')`) {
		t.Errorf("missing userIdentity.accountId predicate: %s", got)
	}
	if !strings.Contains(got, " OR ") {
		t.Errorf("expected OR inside the account-list predicate: %s", got)
	}
}

func TestBuildFilteredEventsExpr_RejectsNonNumericAccountID(t *testing.T) {
	// SQL injection payload should be silently dropped by isValidAccountID.
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{
		AccountIDs: []string{"123456789012", "'; DROP TABLE events; --"},
	})
	if !strings.Contains(got, `'123456789012'`) {
		t.Errorf("legit ID dropped: %s", got)
	}
	if strings.Contains(got, "DROP") || strings.Contains(got, "--") {
		t.Errorf("malicious payload reached SQL: %s", got)
	}
}

func TestBuildFilteredEventsExpr_AllNonNumericIDsCollapse(t *testing.T) {
	// If every account ID is invalid, the account predicate should not be
	// emitted at all (it would otherwise generate `IN ()` and trip DuckDB).
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{
		AccountIDs: []string{"bogus", "also-bogus"},
	})
	if strings.Contains(got, "IN (") {
		t.Errorf("expected no IN clause when all IDs invalid; got: %s", got)
	}
}

func TestBuildFilteredEventsExpr_TimeAndAccountTogether(t *testing.T) {
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{
		TimeStart:  "2026-05-01",
		AccountIDs: []string{"123456789012"},
	})
	// Should be one filtered subquery with two AND-joined predicates.
	if !strings.Contains(got, "WHERE r.eventTime >= '2026-05-01' AND") {
		t.Errorf("filters not AND-joined as expected: %s", got)
	}
}

func TestBuildFilteredEventsExpr_QuoteEscape(t *testing.T) {
	// Single quotes in a date string would break the SQL; we double them.
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{TimeStart: "x'y"})
	if !strings.Contains(got, "'x''y'") {
		t.Errorf("quote not doubled: %s", got)
	}
}

func TestBuildSQL_EscapesDataPathQuote(t *testing.T) {
	// H6: dataPath is assembled from config-derived values (S3 bucket, org_id,
	// account_id) that settings accept with only an emptiness check. A single
	// quote in any of them would otherwise break out of the read_json('...')
	// literal and bypass the read-only allowlist. The path must be quote-doubled
	// before it reaches the literal.
	h := &InvestigateHandler{}
	dataPath := "/data/s3/buck'et/AWSLogs/"
	sql := h.buildSQL("iam-write-ops", "", dataPath, InvestigateFilters{})
	if sql == "" {
		t.Fatal("expected SQL for known scenario, got empty string")
	}
	// The escaped form (quote doubled) must be present...
	if !strings.Contains(sql, `read_json('/data/s3/buck''et/AWSLogs/**/*.json'`) {
		t.Errorf("data path single quote not escaped in read_json literal: %s", sql)
	}
	// ...and the raw single quote must NOT appear as a literal break-out
	// (`buck'et` with a lone quote would close the literal early).
	if strings.Contains(sql, `buck'et`) {
		t.Errorf("raw unescaped quote leaked into SQL (literal break-out): %s", sql)
	}
}

func TestBuildSQL_ScopesSingleSelectedOrganizationAccount(t *testing.T) {
	h := &InvestigateHandler{cfg: &config.Config{S3: config.S3Config{
		Mode:           "control_tower",
		OrgID:          "o-example",
		AccountID:      "123456789012",
		MemberAccounts: []string{"123456789012"},
	}}}

	sql := h.buildSQL(
		"iam-write-ops",
		"",
		"/data/s3/logs/",
		InvestigateFilters{AccountIDs: []string{"123456789012"}},
	)
	if !strings.Contains(sql, `WHERE r.recipientAccountId IN ('123456789012')`) {
		t.Fatalf("configured organization account scope missing: %s", sql)
	}
	if !strings.Contains(sql, `(r.recipientAccountId IN ('123456789012') OR r.userIdentity.accountId IN ('123456789012'))`) {
		t.Fatalf("request account filter missing: %s", sql)
	}
}

func TestInstrumentInvestigationSQLReportsRowsBeyondLimit(t *testing.T) {
	displaySQL := `SELECT i FROM range(105) AS values(i) ORDER BY i DESC LIMIT 100;`
	querySQL, ok := instrumentInvestigationSQL(displaySQL)
	if !ok {
		t.Fatal("expected a hard-limited scenario query to be instrumented")
	}
	if strings.Contains(displaySQL, investigationTotalColumn) {
		t.Fatal("instrumentation must not mutate the SQL shown to users")
	}

	svc := NewService(&config.Config{QueryTimeoutSeconds: 5})
	columns, rows, err := svc.executeDuckDB(context.Background(), querySQL)
	if err != nil {
		t.Fatalf("execute instrumented query: %v", err)
	}
	columns, rows, totalRows, err := extractInvestigationMetadata(columns, rows)
	if err != nil {
		t.Fatalf("extract metadata: %v", err)
	}
	if totalRows != 105 || len(rows) != 100 {
		t.Fatalf("got total=%d returned=%d, want total=105 returned=100", totalRows, len(rows))
	}
	if len(columns) != 1 || columns[0] != "i" {
		t.Fatalf("internal metadata column leaked into visible columns: %v", columns)
	}
	if len(rows[0]) != 1 || rows[0][0] != "104" {
		t.Fatalf("visible row changed after metadata removal: %v", rows[0])
	}
}

func TestAllInvestigationScenariosTrackRowsBeyondTheirLimit(t *testing.T) {
	h := &InvestigateHandler{}
	for _, scenario := range scenarios {
		t.Run(scenario.ID, func(t *testing.T) {
			displaySQL := h.buildSQL(
				scenario.ID,
				"test-value",
				"/data/",
				InvestigateFilters{},
			)
			if displaySQL == "" {
				t.Fatal("known scenario produced no SQL")
			}
			if _, ok := instrumentInvestigationSQL(displaySQL); !ok {
				t.Fatalf("hard-limited scenario query was not instrumented: %s", displaySQL)
			}
		})
	}
}

func TestRunScenarioReportsTruthfulLimitedCounts(t *testing.T) {
	const (
		accountID = "123456789012"
		region    = "us-east-1"
		sourceIP  = "203.0.113.10"
	)
	dataDir := t.TempDir()
	logDir := filepath.Join(
		dataDir, "s3", "test-bucket", "AWSLogs", accountID,
		"CloudTrail", region, "2026", "07", "26",
	)
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}

	records := make([]map[string]interface{}, 0, 106)
	for i := 0; i < 106; i++ {
		eventTime := "2026-07-26T23:59:59Z"
		if i == 105 {
			eventTime = "2026-07-27T00:00:00Z"
		}
		records = append(records, map[string]interface{}{
			"eventName":          "GetCallerIdentity",
			"eventSource":        "sts.amazonaws.com",
			"eventTime":          eventTime,
			"sourceIPAddress":    sourceIP,
			"recipientAccountId": accountID,
			"errorCode":          nil,
			"userIdentity": map[string]interface{}{
				"arn":       "arn:aws:iam::123456789012:user/tester",
				"accountId": accountID,
			},
		})
	}
	payload, err := json.Marshal(map[string]interface{}{"Records": records})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "events.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		DataDir:             dataDir,
		QueryTimeoutSeconds: 10,
		S3: config.S3Config{
			Bucket:    "test-bucket",
			Region:    region,
			AccountID: accountID,
			Mode:      "single",
		},
	}
	body := []byte(`{
		"scenario_id": "activity-by-ip",
		"param": "203.0.113.10",
		"filters": {"time_start": "2026-07-26", "time_end": "2026-07-26"}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/nlquery/investigate/run", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	NewInvestigateHandler(cfg).RunScenario(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("RunScenario status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		SQL          string          `json:"sql"`
		Columns      []string        `json:"columns"`
		Rows         [][]interface{} `json:"rows"`
		TotalRows    int             `json:"total_rows"`
		ReturnedRows int             `json:"returned_rows"`
		Truncated    bool            `json:"truncated"`
		Error        string          `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "" {
		t.Fatalf("RunScenario error: %s", response.Error)
	}
	if response.TotalRows != 105 || response.ReturnedRows != 100 || !response.Truncated {
		t.Fatalf(
			"got total=%d returned=%d truncated=%v, want total=105 returned=100 truncated=true",
			response.TotalRows, response.ReturnedRows, response.Truncated,
		)
	}
	if len(response.Rows) != response.ReturnedRows {
		t.Fatalf("returned_rows=%d does not match response rows=%d", response.ReturnedRows, len(response.Rows))
	}
	if len(response.Columns) == 0 || response.Columns[0] == investigationTotalColumn {
		t.Fatalf("internal count column leaked into response columns: %v", response.Columns)
	}
	if strings.Contains(response.SQL, investigationTotalColumn) {
		t.Fatalf("internal count instrumentation leaked into displayed SQL: %s", response.SQL)
	}
}

func TestIsValidAccountID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"123456789012", true},
		{"000000000000", true},
		{"24708300041", false},   // 11 digits
		{"1234567890120", false}, // 13 digits
		{"24708300041a", false},  // letter
		{"", false},
		{"   123456789012   ", false}, // whitespace
	}
	for _, c := range cases {
		got := isValidAccountID(c.in)
		if got != c.want {
			t.Errorf("isValidAccountID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
