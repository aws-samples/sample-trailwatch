package nlquery

import (
	"math"
	"strings"
	"testing"

	"cloudtrail-analyzer/internal/config"
)

func cfgFor(modelID string) *config.Config {
	return &config.Config{
		Bedrock: config.BedrockConfig{ModelID: modelID, Region: "us-east-1"},
		LLM:     config.LLMConfig{Provider: "bedrock"},
	}
}

func TestApproxTokenCount(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"   ", 0},
		{"abcd", 1},
		{"abcde", 2},        // 5/4 rounds up
		{strings.Repeat("a", 4000), 1000}, // exact 4-char-per-token boundary
	}
	for _, c := range cases {
		got := approxTokenCount(c.in)
		if got != c.want {
			t.Errorf("approxTokenCount(%q): want %d, got %d", c.in, c.want, got)
		}
	}
}

func TestEstimateCost_Sonnet4(t *testing.T) {
	cfg := cfgFor("us.anthropic.claude-sonnet-4-20250514-v1:0")
	// 12 chars system + 8 chars user = 5 tokens (3+2 by ceil-div).
	est := EstimateCost(cfg, "system promp", "user-tok", 0)
	if est.RateSource != "default" {
		t.Errorf("rate source: want default, got %q", est.RateSource)
	}
	if est.InputTokens != 5 {
		t.Errorf("input tokens: want 5, got %d", est.InputTokens)
	}
	// Sonnet 4 input rate: $3/M. 5 tokens / 1M * 3 = 0.000015 USD
	wantInput := 0.000015
	if math.Abs(est.InputCostUSD-wantInput) > 1e-9 {
		t.Errorf("input cost: want %.9f, got %.9f", wantInput, est.InputCostUSD)
	}
	// Output assumption: 800 tokens at $15/M = 0.012 USD
	wantOutput := 0.012
	if math.Abs(est.EstOutputCostUSD-wantOutput) > 1e-9 {
		t.Errorf("est output cost: want %.6f, got %.6f", wantOutput, est.EstOutputCostUSD)
	}
	// Max output cost (cap = 2048 tokens at $15/M)
	wantMax := 2048.0 / 1_000_000.0 * 15.0
	if math.Abs(est.MaxOutputCostUSD-wantMax) > 1e-9 {
		t.Errorf("max output cost: want %.6f, got %.6f", wantMax, est.MaxOutputCostUSD)
	}
	if est.ExceedsWarnThresh {
		t.Error("a tiny prompt should not exceed the default warn threshold")
	}
}

func TestEstimateCost_HonorsOverride(t *testing.T) {
	cfg := cfgFor("anthropic.claude-sonnet-4-20250514-v1:0")
	cfg.LLM.PricingOverrides = map[string]config.PricingOverride{
		"anthropic.claude-sonnet-4-20250514-v1:0": {
			InputPerMillionUSD:  1.50, // 50% off the default $3
			OutputPerMillionUSD: 7.50, // 50% off the default $15
		},
	}
	est := EstimateCost(cfg, "x", "y", 0)
	if est.RateSource != "override" {
		t.Errorf("rate source: want override, got %q", est.RateSource)
	}
	if est.InputRatePerMUSD != 1.50 {
		t.Errorf("expected override input rate 1.50, got %v", est.InputRatePerMUSD)
	}
}

func TestEstimateCost_StripsInferencePrefix(t *testing.T) {
	cfg := cfgFor("us.anthropic.claude-haiku-4-20250514-v1:0")
	est := EstimateCost(cfg, "x", "y", 0)
	// Should resolve to the haiku rate: $1/M input, $5/M output (vs Sonnet's $3/$15).
	if est.InputRatePerMUSD != 1.00 {
		t.Errorf("expected haiku $1/M input, got %v", est.InputRatePerMUSD)
	}
	if est.OutputRatePerMUSD != 5.00 {
		t.Errorf("expected haiku $5/M output, got %v", est.OutputRatePerMUSD)
	}
	if est.RateSource != "default" {
		t.Errorf("source: want default after prefix strip, got %q", est.RateSource)
	}
}

func TestEstimateCost_FallbackForUnknownModel(t *testing.T) {
	cfg := cfgFor("some.unknown.model-v9")
	est := EstimateCost(cfg, "x", "y", 0)
	if est.RateSource != "fallback" {
		t.Errorf("rate source: want fallback, got %q", est.RateSource)
	}
	if est.InputRatePerMUSD == 0 {
		t.Error("fallback rate should be non-zero so the UI shows a real number")
	}
}

func TestEstimateCost_TripsWarnThresholdForLargePrompt(t *testing.T) {
	cfg := cfgFor("anthropic.claude-opus-4-20250514-v1:0")
	// Build a prompt large enough that input cost alone is ~$0.50:
	// Opus input rate $15/M → 0.50 USD = ~33,333 tokens = ~133,333 chars.
	huge := strings.Repeat("x ", 80_000)
	est := EstimateCost(cfg, "", huge, 0)
	if !est.ExceedsWarnThresh {
		t.Errorf("expected warn threshold tripped (cost=%.4f, threshold=%.2f)",
			est.EstTotalCostUSD, est.WarnThresholdUSD)
	}
}

func TestEstimateCost_CustomThreshold(t *testing.T) {
	cfg := cfgFor("anthropic.claude-sonnet-4-20250514-v1:0")
	// Set threshold to $0.001 — even a tiny prompt should now exceed it
	// because the +800-token output assumption alone costs $0.012.
	est := EstimateCost(cfg, "x", "y", 0.001)
	if !est.ExceedsWarnThresh {
		t.Errorf("expected to trip a $0.001 threshold (cost=%.6f)", est.EstTotalCostUSD)
	}
}
