package nlquery

import (
	"strings"

	"cloudtrail-analyzer/internal/config"
)

// MaxOutputTokens is the hard cap applied to outgoing Bedrock / Anthropic /
// OpenAI requests via the providers' max_tokens parameter. It bounds the
// worst-case output cost per request — see the Bedrock cost UX in README.
const MaxOutputTokens = 2048

// CostEstimate is the pre-flight estimate the UI renders before letting the
// user click Run. Numbers are calibrated for the "decide whether to spend
// $0.05 or $5" question, not for accounting accuracy.
//
// Inputs are exactly-known (we have the prompts in hand). Output is
// estimated as the configured assumption × output rate, plus an absolute cap
// based on MaxOutputTokens so the UI can communicate the worst-case bill.
type CostEstimate struct {
	ModelID            string  `json:"model_id"`
	RateSource         string  `json:"rate_source"` // "default" | "override" | "fallback"
	InputTokens        int     `json:"input_tokens"`
	EstOutputTokens    int     `json:"est_output_tokens"`
	MaxOutputTokens    int     `json:"max_output_tokens"`
	InputCostUSD       float64 `json:"input_cost_usd"`
	EstOutputCostUSD   float64 `json:"est_output_cost_usd"`
	EstTotalCostUSD    float64 `json:"est_total_cost_usd"`
	MaxOutputCostUSD   float64 `json:"max_output_cost_usd"`
	MaxTotalCostUSD    float64 `json:"max_total_cost_usd"`
	InputRatePerMUSD   float64 `json:"input_rate_per_million_usd"`
	OutputRatePerMUSD  float64 `json:"output_rate_per_million_usd"`
	WarnThresholdUSD   float64 `json:"warn_threshold_usd"`
	ExceedsWarnThresh  bool    `json:"exceeds_warn_threshold"`
}

// DefaultWarnThresholdUSD is the per-query estimate above which the UI
// renders an amber "this query is large" banner. Sized to be ~100x typical
// (a normal NLQ here costs roughly $0.02). User-overridable in Settings.
const DefaultWarnThresholdUSD = 0.50

// EstimatedOutputTokens is the assumption we pin on output tokens for the
// pre-flight estimate. NLQ outputs are typically 100-800 tokens; we use the
// upper end so the estimate trends slightly conservative (better to surprise
// the user with a smaller bill than a larger one).
const EstimatedOutputTokens = 800

// EstimateCost computes a pre-flight cost estimate for an LLM call.
//
// Tokenization heuristic: Claude (and OpenAI's tiktoken) average roughly
// 4 characters per token for English text. Computed locally — no API call,
// no round-trip.
//
// Caller-supplied threshold lets a future Settings panel raise/lower the
// "amber warning" trigger; pass 0 to use DefaultWarnThresholdUSD.
func EstimateCost(cfg *config.Config, systemPrompt, userPrompt string, warnThresholdUSD float64) CostEstimate {
	rate, modelID, source := LookupRate(cfg)
	if warnThresholdUSD <= 0 {
		warnThresholdUSD = DefaultWarnThresholdUSD
	}

	inputTokens := approxTokenCount(systemPrompt) + approxTokenCount(userPrompt)
	inputCost := costForTokens(inputTokens, rate.InputPerMillionUSD)
	estOutputCost := costForTokens(EstimatedOutputTokens, rate.OutputPerMillionUSD)
	maxOutputCost := costForTokens(MaxOutputTokens, rate.OutputPerMillionUSD)

	estTotal := inputCost + estOutputCost
	maxTotal := inputCost + maxOutputCost

	return CostEstimate{
		ModelID:           modelID,
		RateSource:        source,
		InputTokens:       inputTokens,
		EstOutputTokens:   EstimatedOutputTokens,
		MaxOutputTokens:   MaxOutputTokens,
		InputCostUSD:      inputCost,
		EstOutputCostUSD:  estOutputCost,
		EstTotalCostUSD:   estTotal,
		MaxOutputCostUSD:  maxOutputCost,
		MaxTotalCostUSD:   maxTotal,
		InputRatePerMUSD:  rate.InputPerMillionUSD,
		OutputRatePerMUSD: rate.OutputPerMillionUSD,
		WarnThresholdUSD:  warnThresholdUSD,
		ExceedsWarnThresh: estTotal >= warnThresholdUSD,
	}
}

// approxTokenCount returns a token count estimate for s using the standard
// "4 chars per token" heuristic. Works within ~10% for English; non-English
// or code-heavy text drifts a bit but stays in the right order of magnitude.
//
// Why a heuristic vs. a real tokenizer:
//   - Tokenizers add a non-trivial dependency (BPE tables) and startup cost
//     for a feature whose audience is "is this $0.02 or $2?" (orders of
//     magnitude, not three-decimal precision).
//   - Bedrock's CountTokens API exists for some Anthropic models but not
//     all, and CRIS variants would need extra plumbing. Defer until users
//     report estimates being off in practice.
func approxTokenCount(s string) int {
	// Trim leading/trailing whitespace so empty / single-newline strings
	// estimate to zero rather than to 1 from rounding.
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Round up so a 3-character prompt counts as 1 token.
	return (len(s) + 3) / 4
}

func costForTokens(tokens int, ratePerMillionUSD float64) float64 {
	return float64(tokens) / 1_000_000.0 * ratePerMillionUSD
}
