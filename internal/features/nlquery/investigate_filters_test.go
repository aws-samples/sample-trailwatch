package nlquery

import (
	"strings"
	"testing"
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
		AccountIDs: []string{"247083000413", "391114186676"},
	})
	if !strings.Contains(got, `r.recipientAccountId IN ('247083000413', '391114186676')`) {
		t.Errorf("missing recipientAccountId predicate: %s", got)
	}
	if !strings.Contains(got, `r.userIdentity.accountId IN ('247083000413', '391114186676')`) {
		t.Errorf("missing userIdentity.accountId predicate: %s", got)
	}
	if !strings.Contains(got, " OR ") {
		t.Errorf("expected OR inside the account-list predicate: %s", got)
	}
}

func TestBuildFilteredEventsExpr_RejectsNonNumericAccountID(t *testing.T) {
	// SQL injection payload should be silently dropped by isValidAccountID.
	got := buildFilteredEventsExpr(fakeRead, InvestigateFilters{
		AccountIDs: []string{"247083000413", "'; DROP TABLE events; --"},
	})
	if !strings.Contains(got, `'247083000413'`) {
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
		AccountIDs: []string{"247083000413"},
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

func TestIsValidAccountID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"247083000413", true},
		{"000000000000", true},
		{"24708300041", false},  // 11 digits
		{"2470830004130", false}, // 13 digits
		{"24708300041a", false},  // letter
		{"", false},
		{"   247083000413   ", false}, // whitespace
	}
	for _, c := range cases {
		got := isValidAccountID(c.in)
		if got != c.want {
			t.Errorf("isValidAccountID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
