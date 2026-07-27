package config

import "testing"

func TestDefaultConfigUsesActiveBedrockModel(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Bedrock.ModelID != DefaultBedrockModelID {
		t.Fatalf("Bedrock model = %q, want %q", cfg.Bedrock.ModelID, DefaultBedrockModelID)
	}
	if DefaultBedrockModelID != "us.anthropic.claude-sonnet-4-6" {
		t.Fatalf("unexpected default Bedrock model %q", DefaultBedrockModelID)
	}
}

func TestIsSafePathSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		safe  bool
	}{
		{"trail-logs.example", true},
		{"123456789012", true},
		{"us-east-1", true},
		{"", false},
		{"..", false},
		{"../outside", false},
		{"a/b", false},
		{`a\b`, false},
		{".hidden", false},
		{"contains..dots", false},
		{"line\nbreak", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()
			if got := IsSafePathSegment(tt.value); got != tt.safe {
				t.Fatalf("IsSafePathSegment(%q) = %v, want %v", tt.value, got, tt.safe)
			}
		})
	}
}

func TestValidateConfigRejectsUnsafeS3PathValue(t *testing.T) {
	cfg := DefaultConfig()
	cfg.S3.Bucket = "../../tmp"

	if err := validateConfig(&cfg); err == nil {
		t.Fatal("expected unsafe bucket to be rejected")
	}
}

func TestValidateLLMEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider string
		endpoint string
		valid    bool
	}{
		{"default endpoint", "openai", "", true},
		{"openai https", "openai", "https://example.openai.azure.com/v1", true},
		{"anthropic plaintext", "anthropic", "http://api.anthropic.com", false},
		{"openai loopback", "openai", "https://127.0.0.1:8443/v1", false},
		{"openai private ip", "openai", "https://169.254.169.254/latest", false},
		{"ollama localhost", "ollama", "http://localhost:11434", true},
		{"ollama ipv6 loopback", "ollama", "http://[::1]:11434", true},
		{"ollama remote", "ollama", "https://ollama.example.com", false},
		{"embedded credentials", "openai", "https://user:pass@example.com", false},
		{"malformed", "openai", "://bad", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateLLMEndpoint(tt.provider, tt.endpoint)
			if (err == nil) != tt.valid {
				t.Fatalf("ValidateLLMEndpoint(%q, %q) error = %v, valid=%v", tt.provider, tt.endpoint, err, tt.valid)
			}
		})
	}
}

func TestValidateConfigCapsDownloadConcurrency(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDownloadConcurrency = 65
	if err := validateConfig(&cfg); err == nil {
		t.Fatal("expected excessive download concurrency to be rejected")
	}
}
