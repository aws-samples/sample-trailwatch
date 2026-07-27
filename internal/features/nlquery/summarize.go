package nlquery

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// MaxSummarizeRows caps how many result rows we send to the LLM. Above this
// threshold we slice + tell the model so it can disclaim. Sized to keep
// prompts well under the input-token budget while still showing enough
// shape for the model to spot patterns.
const MaxSummarizeRows = 50

// summarizeSystemPrompt is the strict contract: only restate facts visible
// in the rows; flag patterns derivable from them; do NOT infer attribution
// or motivation; do NOT reference outside knowledge.
//
// Pattern flagging is allowed because that's what makes the summary
// genuinely useful for a responder under time pressure ("identity X has
// 5x more denied calls than the others"). The risk is the model invents
// the multiplier; the response-side validator (validateSummary) is the
// safety net that catches numerals not present in the rows.
//
// Output is JSON with a fixed shape so the frontend can render a real
// layout (TL;DR / findings / entities) instead of a prose blob. The legacy
// fallback (free-form bullets) is supported only when JSON parsing fails.
const summarizeSystemPrompt = `You are summarizing one CloudTrail investigation result for a security responder. The responder is reading a table of rows. Your job: tell them what is in the table and what is unusual about it.

ABSOLUTE RULES:
1. Use ONLY facts that appear in the rows you are given. Do not invent values, ARNs, IPs, account IDs, event names, or counts.
2. Cite specific values when you mention them: ARNs, IPs, identifiers, error codes. Quote them verbatim from the rows.
3. You may flag patterns derivable from the rows (e.g., "identity X appears in 12 of 50 rows, more than any other"). Do not flag patterns based on knowledge outside the rows.
4. NEVER attribute intent, motivation, or threat-actor identity. Do not say "this looks like a brute force attack" or "the attacker was". Stick to observed behavior.
5. NEVER reference compliance frameworks, GuardDuty findings, MITRE techniques, or any external knowledge.
6. If the table is empty, every array is empty and tldr is "No matching events".
7. If the data is truncated (you will be told), mention it in tldr.
8. Do not infer AWS resource type, role type, permission configuration, legitimacy, or cause from a name. In particular, do not use phrases such as "consistent with", "suggests", "indicates", "likely", "appears to", "service-linked role", "internal service call", or "lacks permissions" unless those exact words occur in a source row.
9. A severity is only an attention-ordering hint for the displayed rows, not a confirmed security classification. Prefer "info" or "low" when the rows do not directly establish impact.
10. Suggested pivot reasons must state only that the exact value occurs in the rows and can be investigated further. Do not predict what the pivot will prove.

OUTPUT FORMAT — RETURN ONLY A SINGLE JSON OBJECT, NO PROSE BEFORE OR AFTER:

{
  "tldr": "<one sentence headline of what's in the rows>",
  "findings": [
    {"severity": "high|medium|low|info", "text": "<one short sentence>"}
  ],
  "entities": [
    {"kind": "arn|ip|account|access_key|user|role|event", "value": "<verbatim from rows>", "count": <integer>}
  ],
  "suggested_pivots": [
    {"kind": "arn|ip|account|access_key", "value": "<verbatim>", "reason": "<short reason>"}
  ]
}

CONSTRAINTS:
- 1 to 4 findings. Lead with the most important.
- Up to 8 entities. Pick the values most worth investigating, with their occurrence counts in the rows.
- 0 to 3 suggested_pivots. Each must be a value present in entities.
- All values quoted in any field MUST appear verbatim in the source rows. Do not paraphrase ARNs.
- Do not include code fences, comments, or any text outside the JSON.`

// SummarizeRequest is the body for POST /api/nlquery/summarize.
type SummarizeRequest struct {
	ScenarioID          string          `json:"scenario_id"`
	ScenarioName        string          `json:"scenario_name"`
	ScenarioDescription string          `json:"scenario_description,omitempty"`
	Columns             []string        `json:"columns"`
	Rows                [][]interface{} `json:"rows"`
	// TotalRows is the count the backend produced, including any rows beyond
	// what the client passed in. Lets the model disclaim about truncation.
	TotalRows int `json:"total_rows"`
}

// SummaryFinding is one bulleted observation. Severity is a soft signal the
// frontend uses to color a dot/bar; it is the model's call.
type SummaryFinding struct {
	Severity string `json:"severity"`
	Text     string `json:"text"`
}

// SummaryEntity names a value present in the rows that the model thinks is
// worth investigating. Count is occurrences in the rows the model saw.
type SummaryEntity struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Count int    `json:"count"`
}

// SummaryPivot is a recommended next step keyed to one entity value.
type SummaryPivot struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// SummarizeResponse carries the structured LLM output plus a hallucination
// warning if the validator caught identifiers not present in the source.
//
// Frontend renders the structured fields. Summary (legacy) is preserved for
// the rare case where JSON parsing fails; the UI falls back to plain text.
type SummarizeResponse struct {
	// Structured payload. Empty when parsing failed and Summary is set.
	TLDR            string           `json:"tldr"`
	Findings        []SummaryFinding `json:"findings,omitempty"`
	Entities        []SummaryEntity  `json:"entities,omitempty"`
	SuggestedPivots []SummaryPivot   `json:"suggested_pivots,omitempty"`

	// Summary holds the raw model output if it did not return parseable
	// JSON. The frontend renders this as plain text and skips the layout.
	Summary string `json:"summary,omitempty"`

	// HallucinationWarning is non-empty when validateSummary flagged the
	// response for citing values not in the source rows.
	HallucinationWarning string `json:"hallucination_warning,omitempty"`
	// SuspiciousTokens lists the specific values the validator could not
	// match against the source data.
	SuspiciousTokens []string `json:"suspicious_tokens,omitempty"`
	// EvidenceNotice is always shown with an AI summary. The generated prose is
	// an investigation aid, not source evidence.
	EvidenceNotice string `json:"evidence_notice"`
	// InferenceWarning is populated when the generated findings use language
	// that claims context, cause, or intent beyond the supplied rows.
	InferenceWarning string `json:"inference_warning,omitempty"`
	// RowsSentToModel is how many rows we actually included in the prompt
	// (capped at MaxSummarizeRows).
	RowsSentToModel int `json:"rows_sent_to_model"`
	TotalRows       int `json:"total_rows"`
	// EstCostUSD is the estimated cost of this summarize call, computed
	// server-side against the same rows + system prompt that were actually
	// sent to the model. The handler fills it in. The pre-flight CostBanner is
	// only an approximation (it sends the NL-query system prompt against a
	// preview of the rows); this value is the one recorded against the session
	// spend, so the UI can show the real number once the summary returns.
	EstCostUSD float64 `json:"est_cost_usd,omitempty"`
}

// Summarize sends the result rows to the configured LLM with the strict
// system prompt above, then runs the response through validateSummary.
func Summarize(ctx context.Context, provider LLMProvider, req SummarizeRequest) (*SummarizeResponse, error) {
	rowsToSend := req.Rows
	totalRows := req.TotalRows
	if totalRows < len(req.Rows) {
		totalRows = len(req.Rows)
	}
	if len(rowsToSend) > MaxSummarizeRows {
		rowsToSend = rowsToSend[:MaxSummarizeRows]
	}
	truncated := totalRows > len(rowsToSend)
	req.TotalRows = totalRows

	userPrompt := buildSummarizeUserPrompt(req, rowsToSend, truncated)

	out, err := provider.GenerateSQL(ctx, summarizeSystemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("LLM summarize call: %w", err)
	}

	resp := &SummarizeResponse{
		RowsSentToModel: len(rowsToSend),
		TotalRows:       totalRows,
		EvidenceNotice:  "AI-generated interpretation is not source evidence. Verify every conclusion against the displayed rows and original CloudTrail logs before acting.",
	}

	// Only structured output can be validated consistently. Returning raw prose
	// as a successful response bypasses entity/count checks and makes a model
	// formatting failure look trustworthy to an investigator.
	parsed, parseErr := parseSummaryJSON(out)
	if parseErr != nil {
		return nil, fmt.Errorf("LLM returned invalid structured summary: %w", parseErr)
	}
	if err := validateAndNormalizeParsedSummary(parsed, rowsToSend); err != nil {
		return nil, fmt.Errorf("LLM returned an invalid evidence summary: %w", err)
	}
	resp.TLDR = parsed.TLDR
	resp.Findings = parsed.Findings
	resp.Entities = parsed.Entities
	resp.SuggestedPivots = parsed.SuggestedPivots

	// Validate: flag any ARN/IP/account/access-key in the summary that does
	// not appear in the source rows. Run across all prose fields plus
	// entity values so the responder catches inventions everywhere.
	validationCorpus := buildValidationCorpus(resp)
	suspicious := validateSummary(validationCorpus, rowsToSend, req.Columns)
	if len(suspicious) > 0 {
		resp.SuspiciousTokens = suspicious
		resp.HallucinationWarning = fmt.Sprintf(
			"This summary references %d value(s) that do not appear in the source rows. Treat the highlighted parts as suspect; verify against the table before acting.",
			len(suspicious),
		)
	}
	if containsUnsupportedInference(buildClaimsCorpus(resp)) {
		resp.InferenceWarning = "This summary uses interpretive language that is not directly proven by the supplied rows. Treat those statements as leads, not facts, and verify them against the original CloudTrail events."
	}

	return resp, nil
}

var allowedSummarySeverities = map[string]struct{}{
	"high":   {},
	"medium": {},
	"low":    {},
	"info":   {},
}

var allowedSummaryEntityKinds = map[string]struct{}{
	"arn":        {},
	"ip":         {},
	"account":    {},
	"access_key": {},
	"user":       {},
	"role":       {},
	"event":      {},
}

// validateAndNormalizeParsedSummary enforces the structured response contract
// and replaces model-supplied entity counts with counts computed from the
// actual rows. This keeps the model in a descriptive role rather than trusting
// it as the source of evidence metadata.
func validateAndNormalizeParsedSummary(parsed *parsedSummary, rows [][]interface{}) error {
	if parsed == nil {
		return fmt.Errorf("summary object is missing")
	}
	if strings.TrimSpace(parsed.TLDR) == "" {
		return fmt.Errorf("tldr is required")
	}
	if len(rows) > 0 && (len(parsed.Findings) < 1 || len(parsed.Findings) > 4) {
		return fmt.Errorf("findings must contain between 1 and 4 items")
	}
	if len(rows) == 0 && (len(parsed.Findings) > 0 || len(parsed.Entities) > 0 || len(parsed.SuggestedPivots) > 0) {
		return fmt.Errorf("an empty result cannot contain findings, entities, or pivots")
	}
	if len(parsed.Entities) > 8 {
		return fmt.Errorf("entities must contain at most 8 items")
	}
	if len(parsed.SuggestedPivots) > 3 {
		return fmt.Errorf("suggested_pivots must contain at most 3 items")
	}

	for i := range parsed.Findings {
		finding := &parsed.Findings[i]
		finding.Severity = strings.ToLower(strings.TrimSpace(finding.Severity))
		if _, ok := allowedSummarySeverities[finding.Severity]; !ok {
			return fmt.Errorf("finding %d has unsupported severity %q", i+1, finding.Severity)
		}
		if strings.TrimSpace(finding.Text) == "" {
			return fmt.Errorf("finding %d has empty text", i+1)
		}
	}

	entityKeys := make(map[string]struct{}, len(parsed.Entities))
	for i := range parsed.Entities {
		entity := &parsed.Entities[i]
		entity.Kind = strings.ToLower(strings.TrimSpace(entity.Kind))
		entity.Value = strings.TrimSpace(entity.Value)
		if _, ok := allowedSummaryEntityKinds[entity.Kind]; !ok {
			return fmt.Errorf("entity %d has unsupported kind %q", i+1, entity.Kind)
		}
		if entity.Value == "" {
			return fmt.Errorf("entity %d has an empty value", i+1)
		}
		count := countValueInRows(entity.Value, rows)
		if count == 0 {
			return fmt.Errorf("entity %d value %q does not appear in the source rows", i+1, entity.Value)
		}
		entity.Count = count
		entityKeys[entity.Kind+"\x00"+entity.Value] = struct{}{}
	}

	for i := range parsed.SuggestedPivots {
		pivot := &parsed.SuggestedPivots[i]
		pivot.Kind = strings.ToLower(strings.TrimSpace(pivot.Kind))
		pivot.Value = strings.TrimSpace(pivot.Value)
		if _, ok := allowedSummaryEntityKinds[pivot.Kind]; !ok {
			return fmt.Errorf("pivot %d has unsupported kind %q", i+1, pivot.Kind)
		}
		if _, ok := entityKeys[pivot.Kind+"\x00"+pivot.Value]; !ok {
			return fmt.Errorf("pivot %d must reference an entity with the same kind and value", i+1)
		}
		if strings.TrimSpace(pivot.Reason) == "" {
			return fmt.Errorf("pivot %d has an empty reason", i+1)
		}
	}

	return nil
}

func countValueInRows(value string, rows [][]interface{}) int {
	count := 0
	for _, row := range rows {
		found := false
		for _, cell := range row {
			if cell == nil {
				continue
			}
			rendered := fmt.Sprint(cell)
			if rendered == value || strings.Contains(rendered, value) {
				found = true
				break
			}
		}
		if found {
			count++
		}
	}
	return count
}

// buildClaimsCorpus intentionally excludes suggested pivot reasons. A pivot
// can explain why another query is useful; the TLDR and findings are the parts
// presented as observations and therefore need the stricter inference check.
func buildClaimsCorpus(r *SummarizeResponse) string {
	var b strings.Builder
	b.WriteString(r.TLDR)
	b.WriteString("\n")
	for _, finding := range r.Findings {
		b.WriteString(finding.Text)
		b.WriteString("\n")
	}
	return b.String()
}

var unsupportedInferencePhrases = []string{
	"consistent with",
	"suggests",
	"suggesting",
	"indicates",
	"indicating",
	"likely",
	"appears to",
	"service-linked role",
	"internal service call",
	"lacks permission",
	"attacker",
	"malicious",
	"compromised",
	"brute force",
	"exfiltration",
}

func containsUnsupportedInference(summary string) bool {
	lower := strings.ToLower(summary)
	for _, phrase := range unsupportedInferencePhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// parseSummaryJSON tolerates ```json fences and leading/trailing whitespace
// the model sometimes adds despite the prompt's "no fences" instruction.
type parsedSummary struct {
	TLDR            string           `json:"tldr"`
	Findings        []SummaryFinding `json:"findings"`
	Entities        []SummaryEntity  `json:"entities"`
	SuggestedPivots []SummaryPivot   `json:"suggested_pivots"`
}

func parseSummaryJSON(raw string) (*parsedSummary, error) {
	s := strings.TrimSpace(raw)
	// Strip ```json ... ``` or ``` ... ``` fences.
	if strings.HasPrefix(s, "```") {
		if i := strings.Index(s, "\n"); i > 0 {
			s = s[i+1:]
		}
		if j := strings.LastIndex(s, "```"); j > 0 {
			s = s[:j]
		}
		s = strings.TrimSpace(s)
	}
	// Some models wrap the object in extra prose; pick the first {...} block.
	if i := strings.Index(s, "{"); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndex(s, "}"); j > 0 && j < len(s)-1 {
		s = s[:j+1]
	}
	var p parsedSummary
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// buildValidationCorpus joins all prose + entity values into one string the
// validator can scan for hallucinated identifiers.
func buildValidationCorpus(r *SummarizeResponse) string {
	if r.Summary != "" {
		return r.Summary
	}
	var b strings.Builder
	b.WriteString(r.TLDR)
	b.WriteString("\n")
	for _, f := range r.Findings {
		b.WriteString(f.Text)
		b.WriteString("\n")
	}
	for _, e := range r.Entities {
		b.WriteString(e.Value)
		b.WriteString("\n")
	}
	for _, p := range r.SuggestedPivots {
		b.WriteString(p.Value)
		b.WriteString(" ")
		b.WriteString(p.Reason)
		b.WriteString("\n")
	}
	return b.String()
}

// buildSummarizeUserPrompt formats the rows as JSON inside the prompt so the
// model can quote exact values.
func buildSummarizeUserPrompt(req SummarizeRequest, rows [][]interface{}, truncated bool) string {
	var b strings.Builder
	b.WriteString("Scenario: ")
	b.WriteString(req.ScenarioName)
	if req.ScenarioDescription != "" {
		b.WriteString(" — ")
		b.WriteString(req.ScenarioDescription)
	}
	b.WriteString("\n\n")

	if truncated {
		fmt.Fprintf(&b, "TRUNCATED: showing first %d of %d total rows. Mention this in your summary.\n\n", len(rows), req.TotalRows)
	} else {
		fmt.Fprintf(&b, "Total rows: %d.\n\n", req.TotalRows)
	}

	b.WriteString("Columns: ")
	b.WriteString(strings.Join(req.Columns, ", "))
	b.WriteString("\n\nRows (JSON, one object per row):\n")
	for i, r := range rows {
		obj := map[string]interface{}{}
		for j, col := range req.Columns {
			if j < len(r) {
				obj[col] = r[j]
			}
		}
		bs, _ := json.Marshal(obj)
		fmt.Fprintf(&b, "%d: %s\n", i+1, bs)
	}

	b.WriteString("\nProduce the bullets per the rules.")
	return b.String()
}

// validateSummary returns suspicious-looking tokens in the summary that do
// not appear in the source rows. Specifically targets:
//   - ARNs (arn:aws:...)
//   - IPv4 addresses
//   - 12-digit AWS account IDs
//   - Access key prefixes (AKIA / ASIA followed by alphanumerics)
//
// We deliberately do NOT flag arbitrary numbers in the summary because
// counts derived from row position ("12 of 50") legitimately would not
// appear verbatim in the data.
func validateSummary(summary string, rows [][]interface{}, columns []string) []string {
	if strings.TrimSpace(summary) == "" {
		return nil
	}

	// Collect all stringified values from the source rows + column names.
	known := map[string]struct{}{}
	for _, c := range columns {
		known[c] = struct{}{}
	}
	for _, row := range rows {
		for _, cell := range row {
			if cell == nil {
				continue
			}
			s := fmt.Sprint(cell)
			known[s] = struct{}{}
		}
	}

	// Pull candidate identifiers out of the summary. Three classes:
	//   - ARN-shaped: starts with "arn:aws:" up to the next whitespace/punct
	//   - IPv4: standard dotted-quad
	//   - 12-digit account: standalone
	//   - Access key prefix: AKIA/ASIA + 12-20 alphanumerics
	candidates := extractIdentifiers(summary)

	var suspicious []string
	seen := map[string]struct{}{}
	for _, cand := range candidates {
		if _, dup := seen[cand]; dup {
			continue
		}
		// A candidate is "known" if it appears in any known row value, either
		// as a substring (for ARNs that may be present alongside other text)
		// or exactly. We use substring containment because raw row values can
		// be wrapped in nested struct stringifications.
		if isKnownValue(cand, known) {
			continue
		}
		suspicious = append(suspicious, cand)
		seen[cand] = struct{}{}
	}
	sort.Strings(suspicious)
	return suspicious
}

// extractIdentifiers pulls candidate identifiers out of free text. The four
// patterns below are the only thing the validator checks; everything else
// (counts, prose, column names) is allowed through.
func extractIdentifiers(s string) []string {
	var out []string

	// ARN: arn:aws:<service>:<region>:<account>:<resource>
	// We grab up to the first whitespace, comma, or quote.
	for {
		i := strings.Index(s, "arn:aws:")
		if i < 0 {
			break
		}
		end := i
		for end < len(s) {
			c := s[end]
			if c == ' ' || c == '\t' || c == '\n' || c == ',' || c == '"' || c == '\'' || c == ')' || c == '(' {
				break
			}
			end++
		}
		out = append(out, strings.TrimRight(s[i:end], ".,;:"))
		s = s[end:]
	}

	// IPv4: \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b — written without regex
	// to keep the dependency surface small.
	tokens := splitOnNonIdentifier(s)
	for _, tok := range tokens {
		if isIPv4Like(tok) || isAccountIDLike(tok) || isAccessKeyLike(tok) {
			out = append(out, tok)
		}
	}
	return out
}

func splitOnNonIdentifier(s string) []string {
	parts := []string{}
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		// Trim trailing sentence punctuation so "123456789012." -> "123456789012".
		// Leading dots are unusual but also stripped for symmetry.
		t := strings.Trim(cur.String(), ".,;:")
		if t != "" {
			parts = append(parts, t)
		}
		cur.Reset()
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return parts
}

func isIPv4Like(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func isAccountIDLike(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isAccessKeyLike(s string) bool {
	if len(s) < 16 || len(s) > 24 {
		return false
	}
	if !(strings.HasPrefix(s, "AKIA") || strings.HasPrefix(s, "ASIA")) {
		return false
	}
	for _, c := range s[4:] {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isKnownValue(candidate string, known map[string]struct{}) bool {
	if _, ok := known[candidate]; ok {
		return true
	}
	for k := range known {
		if strings.Contains(k, candidate) {
			return true
		}
	}
	return false
}
