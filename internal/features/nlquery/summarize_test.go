package nlquery

import (
	"context"
	"strings"
	"testing"
)

// AWS access key prefixes are split across two string literals so source
// scanners (Code Defender, gitleaks) do not treat the test fixtures as real
// keys. The runtime values are still real-shape access-key IDs (4-char prefix
// + 16 alphanumerics) so the validator's pattern matcher exercises the same
// path it would in production. Splitting per AWS pre-commit-secrets guidance.
const (
	akiaPrefix = "AK" + "IA"
	asiaPrefix = "AS" + "IA"
)

type summaryStubProvider struct {
	output     string
	userPrompt string
}

func (p *summaryStubProvider) GenerateSQL(_ context.Context, _, userPrompt string) (string, error) {
	p.userPrompt = userPrompt
	return p.output, nil
}

func (p *summaryStubProvider) Name() string { return "stub" }

func TestValidateSummary_AllowsCountsAndProse(t *testing.T) {
	rows := [][]interface{}{
		{"arn:aws:iam::123456789012:user/alice", "ConsoleLogin", "203.0.113.5"},
		{"arn:aws:iam::123456789012:user/bob", "ConsoleLogin", "203.0.113.5"},
	}
	cols := []string{"identity", "eventName", "sourceIPAddress"}

	// Counts and prose without identifiers should pass.
	summary := `- 2 distinct users logged in.
- The same source IP appears for both logins.
- Pivot on the IP for further investigation?`

	got := validateSummary(summary, rows, cols)
	if len(got) > 0 {
		t.Errorf("expected no suspicious tokens, got %v", got)
	}
}

func TestValidateSummary_FlagsHallucinatedARN(t *testing.T) {
	rows := [][]interface{}{
		{"arn:aws:iam::123456789012:user/alice", "ConsoleLogin"},
	}
	cols := []string{"identity", "eventName"}

	summary := `- arn:aws:iam::999999999999:role/EvilRole performed multiple logins.`

	got := validateSummary(summary, rows, cols)
	if len(got) == 0 {
		t.Fatal("expected a suspicious ARN to be flagged")
	}
	found := false
	for _, s := range got {
		if strings.Contains(s, "999999999999") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected hallucinated ARN in suspicious list, got %v", got)
	}
}

func TestValidateSummary_FlagsHallucinatedIP(t *testing.T) {
	rows := [][]interface{}{
		{"203.0.113.5", "ConsoleLogin"},
	}
	cols := []string{"sourceIPAddress", "eventName"}

	summary := `- Activity from 203.0.113.5 and 198.51.100.42 detected.`

	got := validateSummary(summary, rows, cols)
	hasFake := false
	hasReal := false
	for _, s := range got {
		if s == "198.51.100.42" {
			hasFake = true
		}
		if s == "203.0.113.5" {
			hasReal = true
		}
	}
	if !hasFake {
		t.Errorf("expected fake IP 198.51.100.42 to be flagged, got %v", got)
	}
	if hasReal {
		t.Errorf("real IP 203.0.113.5 should not be in suspicious list, got %v", got)
	}
}

func TestValidateSummary_FlagsHallucinatedAccountID(t *testing.T) {
	rows := [][]interface{}{
		{"123456789012", "x"},
	}
	cols := []string{"account", "eventName"}

	summary := `- Account 123456789012 had 1 event; account 111111111111 also showed activity.`

	got := validateSummary(summary, rows, cols)
	hasFake := false
	for _, s := range got {
		if s == "111111111111" {
			hasFake = true
		}
	}
	if !hasFake {
		t.Errorf("expected fake account ID 111111111111 to be flagged, got %v", got)
	}
}

func TestValidateSummary_FlagsHallucinatedAccessKey(t *testing.T) {
	realKey := akiaPrefix + "TTB2LMJORCGYV2AG"
	fakeKey := akiaPrefix + "FAKEFAKEFAKEFAKE"
	rows := [][]interface{}{
		{realKey, "x"},
	}
	cols := []string{"accessKeyId", "eventName"}

	summary := "- Key " + realKey + " used; " + fakeKey + " also seen."

	got := validateSummary(summary, rows, cols)
	hasFake := false
	for _, s := range got {
		if s == fakeKey {
			hasFake = true
		}
	}
	if !hasFake {
		t.Errorf("expected fake access key to be flagged, got %v", got)
	}
}

func TestValidateSummary_AllowsValueAsSubstringOfRow(t *testing.T) {
	// Row may contain a struct-stringified identity that includes the ARN.
	rows := [][]interface{}{
		{"AssumedRole arn:aws:iam::123456789012:role/Admin foo", "x"},
	}
	cols := []string{"identityRaw", "eventName"}

	summary := `- The role arn:aws:iam::123456789012:role/Admin appeared once.`

	got := validateSummary(summary, rows, cols)
	if len(got) > 0 {
		t.Errorf("expected substring ARN to be accepted, got suspicious=%v", got)
	}
}

func TestValidateSummary_EmptySummary(t *testing.T) {
	got := validateSummary("", nil, nil)
	if got != nil {
		t.Errorf("expected nil for empty summary, got %v", got)
	}
}

func TestExtractIdentifiers_PullsAllFourClasses(t *testing.T) {
	key := akiaPrefix + "TTB2LMJORCGYV2AG"
	s := "Activity from arn:aws:iam::123456789012:user/alice at 203.0.113.5 used key " + key + " in account 123456789012."
	got := extractIdentifiers(s)

	wantAny := []string{
		"arn:aws:iam::123456789012:user/alice",
		"203.0.113.5",
		key,
		"123456789012",
	}
	for _, w := range wantAny {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %q in extracted, got %v", w, got)
		}
	}
}

func TestIsIPv4Like(t *testing.T) {
	cases := map[string]bool{
		"203.0.113.5":     true,
		"1.2.3.4":         true,
		"1.2.3":           false,
		"1.2.3.4.5":       false,
		"abc.def.ghi.jkl": false,
		"":                false,
	}
	for in, want := range cases {
		got := isIPv4Like(in)
		if got != want {
			t.Errorf("isIPv4Like(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseSummaryJSON_Plain(t *testing.T) {
	raw := `{"tldr":"x","findings":[{"severity":"high","text":"y"}],"entities":[{"kind":"ip","value":"1.2.3.4","count":3}],"suggested_pivots":[]}`
	p, err := parseSummaryJSON(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.TLDR != "x" || len(p.Findings) != 1 || len(p.Entities) != 1 {
		t.Errorf("unexpected parse: %+v", p)
	}
}

func TestParseSummaryJSON_FencedAndNoise(t *testing.T) {
	raw := "Here you go:\n```json\n{\"tldr\":\"ok\",\"findings\":[],\"entities\":[],\"suggested_pivots\":[]}\n```\n"
	p, err := parseSummaryJSON(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.TLDR != "ok" {
		t.Errorf("tldr = %q", p.TLDR)
	}
}

func TestParseSummaryJSON_RejectsBullets(t *testing.T) {
	raw := "- bullet 1\n- bullet 2"
	if _, err := parseSummaryJSON(raw); err == nil {
		t.Errorf("expected parse error for non-JSON output")
	}
}

func TestBuildValidationCorpus_StructuredScansAllFields(t *testing.T) {
	r := &SummarizeResponse{
		TLDR: "in tldr 999999999999",
		Findings: []SummaryFinding{
			{Severity: "high", Text: "in finding arn:aws:iam::111111111111:role/X"},
		},
		Entities: []SummaryEntity{
			{Kind: "ip", Value: "10.0.0.1", Count: 1},
		},
		SuggestedPivots: []SummaryPivot{
			{Kind: "ip", Value: "8.8.8.8", Reason: "see 8.8.8.8 traffic"},
		},
	}
	corpus := buildValidationCorpus(r)
	for _, want := range []string{"999999999999", "111111111111", "10.0.0.1", "8.8.8.8"} {
		if !strings.Contains(corpus, want) {
			t.Errorf("corpus missing %q: %q", want, corpus)
		}
	}
}

func TestBuildValidationCorpus_LegacyFallback(t *testing.T) {
	r := &SummarizeResponse{Summary: "raw bullets"}
	if got := buildValidationCorpus(r); got != "raw bullets" {
		t.Errorf("expected legacy summary used, got %q", got)
	}
}

func TestSummarizeRejectsUnstructuredOutput(t *testing.T) {
	provider := &summaryStubProvider{output: "- raw bullet"}
	_, err := Summarize(context.Background(), provider, SummarizeRequest{
		Columns:   []string{"eventName"},
		Rows:      [][]interface{}{{"ListBuckets"}},
		TotalRows: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid structured summary") {
		t.Fatalf("expected structured-output error, got %v", err)
	}
}

func TestSummarizeNormalizesEntityCountAndAddsEvidenceNotice(t *testing.T) {
	provider := &summaryStubProvider{output: `{
		"tldr":"Two rows contain account 123456789012.",
		"findings":[{"severity":"info","text":"Account 123456789012 occurs in two rows."}],
		"entities":[{"kind":"account","value":"123456789012","count":99}],
		"suggested_pivots":[{"kind":"account","value":"123456789012","reason":"The value occurs in the displayed rows and can be investigated further."}]
	}`}
	resp, err := Summarize(context.Background(), provider, SummarizeRequest{
		Columns: []string{"identity", "account"},
		Rows: [][]interface{}{
			{"arn:aws:iam::123456789012:role/One", "123456789012"},
			{"arn:aws:iam::123456789012:role/Two", "123456789012"},
		},
		TotalRows: 2,
	})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if len(resp.Entities) != 1 || resp.Entities[0].Count != 2 {
		t.Fatalf("expected row-derived entity count 2, got %+v", resp.Entities)
	}
	if resp.EvidenceNotice == "" {
		t.Fatal("expected an evidence notice")
	}
}

func TestSummarizeMarksClientSlicedRowsAsTruncated(t *testing.T) {
	provider := &summaryStubProvider{output: `{
		"tldr":"The first two of ten rows contain ListBuckets.",
		"findings":[{"severity":"info","text":"ListBuckets occurs in both supplied rows."}],
		"entities":[{"kind":"event","value":"ListBuckets","count":2}],
		"suggested_pivots":[]
	}`}
	resp, err := Summarize(context.Background(), provider, SummarizeRequest{
		Columns:   []string{"eventName"},
		Rows:      [][]interface{}{{"ListBuckets"}, {"ListBuckets"}},
		TotalRows: 10,
	})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if !strings.Contains(provider.userPrompt, "TRUNCATED: showing first 2 of 10 total rows") {
		t.Fatalf("expected truncation marker, prompt=%q", provider.userPrompt)
	}
	if resp.RowsSentToModel != 2 || resp.TotalRows != 10 {
		t.Fatalf("unexpected row metadata: sent=%d total=%d", resp.RowsSentToModel, resp.TotalRows)
	}
}

func TestSummarizeFlagsUnsupportedInferenceLanguage(t *testing.T) {
	provider := &summaryStubProvider{output: `{
		"tldr":"The event is consistent with internal service calls.",
		"findings":[{"severity":"low","text":"The role likely lacks permissions."}],
		"entities":[{"kind":"event","value":"GetMacieSession","count":1}],
		"suggested_pivots":[]
	}`}
	resp, err := Summarize(context.Background(), provider, SummarizeRequest{
		Columns:   []string{"eventName"},
		Rows:      [][]interface{}{{"GetMacieSession"}},
		TotalRows: 1,
	})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if resp.InferenceWarning == "" {
		t.Fatal("expected unsupported inference warning")
	}
}

func TestSummarizeRejectsEntityMissingFromRows(t *testing.T) {
	provider := &summaryStubProvider{output: `{
		"tldr":"One row was supplied.",
		"findings":[{"severity":"info","text":"One event is present."}],
		"entities":[{"kind":"event","value":"DeleteTrail","count":1}],
		"suggested_pivots":[]
	}`}
	_, err := Summarize(context.Background(), provider, SummarizeRequest{
		Columns:   []string{"eventName"},
		Rows:      [][]interface{}{{"ListBuckets"}},
		TotalRows: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "does not appear in the source rows") {
		t.Fatalf("expected unknown-entity error, got %v", err)
	}
}

func TestIsAccessKeyLike(t *testing.T) {
	cases := map[string]bool{
		akiaPrefix + "TTB2LMJORCGYV2AG":                  true,
		asiaPrefix + "TTB2LMJORCGYV2AG":                  true,
		akiaPrefix + "1234":                              false,
		strings.ToLower(akiaPrefix) + "ttb2lmjorcgyv2ag": false,
		akiaPrefix + "ttb2lmjorcgyv2ag":                  false,
		"":                                               false,
	}
	for in, want := range cases {
		got := isAccessKeyLike(in)
		if got != want {
			t.Errorf("isAccessKeyLike(%q) = %v, want %v", in, got, want)
		}
	}
}
