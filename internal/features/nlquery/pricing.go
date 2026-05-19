package nlquery

import (
	"strings"

	"cloudtrail-analyzer/internal/config"
)

// Rate is the per-million-token price in USD for a model's input and output
// tokens. AWS Bedrock and the upstream Anthropic / OpenAI APIs all bill on
// this shape; an "rate per million tokens" multiplied by token count divided
// by 1_000_000 gives USD.
type Rate struct {
	InputPerMillionUSD  float64 `json:"input_per_million_usd"`
	OutputPerMillionUSD float64 `json:"output_per_million_usd"`
}

// defaultRates lists USD-per-million-token prices for the models this app
// supports. Numbers come from publicly published rate cards as of 2026-05-18.
//
//   - AWS Bedrock: https://aws.amazon.com/bedrock/pricing/
//   - Anthropic API: https://www.anthropic.com/pricing
//   - OpenAI API: https://openai.com/api/pricing/
//
// Treat these as illustrative defaults for the UI's pre-flight estimate. Real
// bills can differ based on enterprise discounts, EDP commitments, BYO-cloud
// arrangements, or regional Cross-Region Inference (CRIS) routing. Users on
// non-default rate cards override per model via Settings → AI Provider.
//
// Map keys match the model IDs the app sets on outgoing requests. Lookups
// are case-insensitive and tolerate the AWS Bedrock "us." / "eu." inference
// profile prefixes.
var defaultRates = map[string]Rate{
	// --- Anthropic on Bedrock ---
	// Opus tier: $15/M input, $75/M output across versions.
	"anthropic.claude-opus-4-20250514-v1:0":     {InputPerMillionUSD: 15.00, OutputPerMillionUSD: 75.00},
	"anthropic.claude-opus-4-6":                 {InputPerMillionUSD: 15.00, OutputPerMillionUSD: 75.00},
	"anthropic.claude-opus-4-7":                 {InputPerMillionUSD: 15.00, OutputPerMillionUSD: 75.00},
	"anthropic.claude-3-opus-20240229-v1:0":     {InputPerMillionUSD: 15.00, OutputPerMillionUSD: 75.00},
	// Sonnet tier: $3/M input, $15/M output.
	"anthropic.claude-sonnet-4-20250514-v1:0":   {InputPerMillionUSD: 3.00, OutputPerMillionUSD: 15.00},
	"anthropic.claude-sonnet-4-6":               {InputPerMillionUSD: 3.00, OutputPerMillionUSD: 15.00},
	"anthropic.claude-3-5-sonnet-20241022-v2:0": {InputPerMillionUSD: 3.00, OutputPerMillionUSD: 15.00},
	// Haiku tier: $1/M input, $5/M output (Claude 4 generation); 3.5 Haiku is cheaper.
	"anthropic.claude-haiku-4-20250514-v1:0":    {InputPerMillionUSD: 1.00, OutputPerMillionUSD: 5.00},
	"anthropic.claude-haiku-4-5-20251001":       {InputPerMillionUSD: 1.00, OutputPerMillionUSD: 5.00},
	"anthropic.claude-3-5-haiku-20241022-v1:0":  {InputPerMillionUSD: 0.80, OutputPerMillionUSD: 4.00},

	// --- Anthropic API (no Bedrock provider prefix) ---
	"claude-opus-4":     {InputPerMillionUSD: 15.00, OutputPerMillionUSD: 75.00},
	"claude-opus-4-6":   {InputPerMillionUSD: 15.00, OutputPerMillionUSD: 75.00},
	"claude-opus-4-7":   {InputPerMillionUSD: 15.00, OutputPerMillionUSD: 75.00},
	"claude-3-opus":     {InputPerMillionUSD: 15.00, OutputPerMillionUSD: 75.00},
	"claude-sonnet-4":   {InputPerMillionUSD: 3.00, OutputPerMillionUSD: 15.00},
	"claude-sonnet-4-6": {InputPerMillionUSD: 3.00, OutputPerMillionUSD: 15.00},
	"claude-3-5-sonnet": {InputPerMillionUSD: 3.00, OutputPerMillionUSD: 15.00},
	"claude-haiku-4":    {InputPerMillionUSD: 1.00, OutputPerMillionUSD: 5.00},
	"claude-haiku-4-5":  {InputPerMillionUSD: 1.00, OutputPerMillionUSD: 5.00},
	"claude-3-5-haiku":  {InputPerMillionUSD: 0.80, OutputPerMillionUSD: 4.00},

	// --- OpenAI ---
	"gpt-4o":      {InputPerMillionUSD: 2.50, OutputPerMillionUSD: 10.00},
	"gpt-4o-mini": {InputPerMillionUSD: 0.15, OutputPerMillionUSD: 0.60},
	"gpt-4-turbo": {InputPerMillionUSD: 10.00, OutputPerMillionUSD: 30.00},
}

// fallbackRate is used when the configured model id matches no entry in
// defaultRates and the user has not supplied a Settings override. Picks
// Sonnet 4 numbers — middle-of-the-road for this app's typical workload —
// so the UI shows *something* honest rather than zero.
var fallbackRate = Rate{InputPerMillionUSD: 3.00, OutputPerMillionUSD: 15.00}

// LookupRate returns the per-token rate for the active model, preferring a
// user-supplied Settings override if present. Returns the rate, the
// "effective model id" actually charged, and a hint string for the UI
// ("override" | "default" | "fallback") so the cost banner can mark the
// source of its numbers.
func LookupRate(cfg *config.Config) (Rate, string, string) {
	modelID := strings.TrimSpace(activeModelID(cfg))
	if modelID == "" {
		return fallbackRate, "", "fallback"
	}

	// 1) User override beats anything else.
	if cfg.LLM.PricingOverrides != nil {
		if r, ok := cfg.LLM.PricingOverrides[modelID]; ok && (r.InputPerMillionUSD > 0 || r.OutputPerMillionUSD > 0) {
			return Rate{InputPerMillionUSD: r.InputPerMillionUSD, OutputPerMillionUSD: r.OutputPerMillionUSD}, modelID, "override"
		}
	}

	// 2) Built-in defaults. Strip Bedrock's optional inference-profile prefix
	//    ("us.", "eu.", "apac.") which is metadata about routing, not a
	//    different rate card.
	stripped := stripInferencePrefix(modelID)
	if r, ok := defaultRates[strings.ToLower(stripped)]; ok {
		return r, stripped, "default"
	}

	// 3) Last resort — illustrative fallback.
	return fallbackRate, modelID, "fallback"
}

// activeModelID picks the right id field for the currently-selected provider.
// Defaults to the Bedrock model when nothing else is set.
func activeModelID(cfg *config.Config) string {
	switch cfg.LLM.Provider {
	case "anthropic", "openai":
		if cfg.LLM.Model != "" {
			return cfg.LLM.Model
		}
	}
	if cfg.Bedrock.ModelID != "" {
		return cfg.Bedrock.ModelID
	}
	return cfg.LLM.Model
}

func stripInferencePrefix(id string) string {
	for _, p := range []string{"us.", "eu.", "apac.", "global."} {
		if strings.HasPrefix(strings.ToLower(id), p) {
			return id[len(p):]
		}
	}
	return id
}
