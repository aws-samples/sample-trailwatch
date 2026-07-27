package nlquery

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"cloudtrail-analyzer/internal/config"
)

func TestReadLLMResponseRejectsOversizedBody(t *testing.T) {
	body := bytes.NewReader(bytes.Repeat([]byte("x"), maxLLMResponseBytes+1))
	if _, err := readLLMResponse(body); err == nil {
		t.Fatal("expected oversized response to be rejected")
	}
}

func TestLLMHTTPClientRejectsRedirects(t *testing.T) {
	client := llmHTTPClient(time.Second)
	err := client.CheckRedirect(nil, nil)
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("expected redirects to be rejected, got %v", err)
	}
}

func TestProvidersRejectInvalidCustomEndpointWithoutPanic(t *testing.T) {
	cfg := &config.Config{
		QueryTimeoutSeconds: 1,
		LLM: config.LLMConfig{
			APIKey:   "secret",
			Model:    "model",
			Endpoint: "://bad",
		},
	}

	for _, provider := range []LLMProvider{
		&AnthropicProvider{cfg: cfg},
		&OpenAIProvider{cfg: cfg},
	} {
		t.Run(provider.Name(), func(t *testing.T) {
			_, err := provider.GenerateSQL(t.Context(), "system", "user")
			if err == nil || !strings.Contains(err.Error(), "absolute HTTP(S) URL") {
				t.Fatalf("expected endpoint validation error, got %v", err)
			}
		})
	}
}

func TestConfiguredBedrockModelIDUsesActiveDefault(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Bedrock.ModelID = ""

	if got := configuredBedrockModelID(&cfg); got != config.DefaultBedrockModelID {
		t.Fatalf("configuredBedrockModelID() = %q, want %q", got, config.DefaultBedrockModelID)
	}

	cfg.Bedrock.ModelID = "  us.anthropic.custom-model  "
	if got := configuredBedrockModelID(&cfg); got != "us.anthropic.custom-model" {
		t.Fatalf("configuredBedrockModelID() = %q, want trimmed configured model", got)
	}
}

func TestMapBedrockInvokeErrorDistinguishesLegacyModelDenial(t *testing.T) {
	raw := errors.New(
		"operation error Bedrock Runtime: InvokeModel, api error AccessDeniedException: " +
			"You don't have access to the model with the specified model ID.",
	)

	got := mapBedrockInvokeError(raw, "legacy-model", "us-east-2").Error()
	for _, want := range []string{"legacy-model", "legacy", "us-east-2", config.DefaultBedrockModelID} {
		if !strings.Contains(got, want) {
			t.Fatalf("mapped error %q does not contain %q", got, want)
		}
	}
	if strings.Contains(got, "lack bedrock:InvokeModel permission") {
		t.Fatalf("model-specific denial was misclassified as IAM denial: %q", got)
	}
}

func TestMapBedrockInvokeErrorKeepsGenericAccessDeniedGuidance(t *testing.T) {
	raw := errors.New("AccessDeniedException: not authorized to perform bedrock:InvokeModel")
	got := mapBedrockInvokeError(raw, config.DefaultBedrockModelID, "us-east-1").Error()
	if !strings.Contains(got, "lack bedrock:InvokeModel permission") {
		t.Fatalf("generic access denial was not mapped to IAM guidance: %q", got)
	}
}
