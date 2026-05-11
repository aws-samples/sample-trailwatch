package nlquery

import (
	"testing"

	"cloudtrail-analyzer/internal/config"
)

func TestNewProvider_Bedrock(t *testing.T) {
	cfg := &config.Config{LLM: config.LLMConfig{Provider: "bedrock"}}
	p := NewProvider(cfg)
	if p.Name() != "bedrock" {
		t.Errorf("expected bedrock provider, got %s", p.Name())
	}
}

func TestNewProvider_Anthropic(t *testing.T) {
	cfg := &config.Config{LLM: config.LLMConfig{Provider: "anthropic"}}
	p := NewProvider(cfg)
	if p.Name() != "anthropic" {
		t.Errorf("expected anthropic provider, got %s", p.Name())
	}
}

func TestNewProvider_OpenAI(t *testing.T) {
	cfg := &config.Config{LLM: config.LLMConfig{Provider: "openai"}}
	p := NewProvider(cfg)
	if p.Name() != "openai" {
		t.Errorf("expected openai provider, got %s", p.Name())
	}
}

func TestNewProvider_Ollama(t *testing.T) {
	cfg := &config.Config{LLM: config.LLMConfig{Provider: "ollama"}}
	p := NewProvider(cfg)
	if p.Name() != "ollama" {
		t.Errorf("expected ollama provider, got %s", p.Name())
	}
}

func TestNewProvider_Default(t *testing.T) {
	cfg := &config.Config{LLM: config.LLMConfig{Provider: ""}}
	p := NewProvider(cfg)
	if p.Name() != "bedrock" {
		t.Errorf("expected bedrock as default, got %s", p.Name())
	}
}

func TestNewProvider_Unknown(t *testing.T) {
	cfg := &config.Config{LLM: config.LLMConfig{Provider: "unknown"}}
	p := NewProvider(cfg)
	if p.Name() != "bedrock" {
		t.Errorf("expected bedrock for unknown provider, got %s", p.Name())
	}
}

func TestExtractSQL_CodeBlock(t *testing.T) {
	input := "Here's the query:\n```sql\nSELECT * FROM events LIMIT 10;\n```\nThis will work."
	expected := "SELECT * FROM events LIMIT 10;"
	result := extractSQL(input)
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestExtractSQL_GenericCodeBlock(t *testing.T) {
	input := "```\nSELECT count(*) FROM t;\n```"
	expected := "SELECT count(*) FROM t;"
	result := extractSQL(input)
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestExtractSQL_NoCodeBlock(t *testing.T) {
	input := "SELECT r.eventName FROM events;"
	expected := "SELECT r.eventName FROM events;"
	result := extractSQL(input)
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestExtractSQL_Empty(t *testing.T) {
	result := extractSQL("")
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestExtractSQL_MultipleCodeBlocks(t *testing.T) {
	input := "First:\n```sql\nSELECT 1;\n```\nSecond:\n```sql\nSELECT 2;\n```"
	result := extractSQL(input)
	if result != "SELECT 1;" {
		t.Errorf("expected first SQL block, got %q", result)
	}
}

func TestBuildDataPath_SingleMode(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./data",
		S3: config.S3Config{
			Bucket:    "my-bucket",
			Region:    "us-east-1",
			AccountID: "123456789012",
			Mode:      "single",
		},
	}
	svc := NewService(cfg)
	path := svc.buildDataPath()
	expected := "./data/s3/my-bucket/AWSLogs/123456789012/CloudTrail/us-east-1/"
	if path != expected {
		t.Errorf("expected %q, got %q", expected, path)
	}
}

func TestBuildDataPath_ControlTowerMode(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./data",
		S3: config.S3Config{
			Bucket:    "ct-bucket",
			Region:    "us-east-2",
			AccountID: "111222333444",
			Mode:      "control_tower",
			OrgID:     "o-abc123",
		},
	}
	svc := NewService(cfg)
	path := svc.buildDataPath()
	expected := "./data/s3/ct-bucket/o-abc123/AWSLogs/o-abc123/111222333444/CloudTrail/us-east-2/"
	if path != expected {
		t.Errorf("expected %q, got %q", expected, path)
	}
}

func TestBuildDataPath_EmptyBucket(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./data",
		S3:      config.S3Config{Bucket: ""},
	}
	svc := NewService(cfg)
	path := svc.buildDataPath()
	if path != "" {
		t.Errorf("expected empty path, got %q", path)
	}
}

func TestBuildDataPath_LogRegionOverride(t *testing.T) {
	cfg := &config.Config{
		DataDir: "./data",
		S3: config.S3Config{
			Bucket:    "my-bucket",
			Region:    "us-east-1",
			LogRegion: "eu-west-1",
			AccountID: "123456789012",
			Mode:      "single",
		},
	}
	svc := NewService(cfg)
	path := svc.buildDataPath()
	expected := "./data/s3/my-bucket/AWSLogs/123456789012/CloudTrail/eu-west-1/"
	if path != expected {
		t.Errorf("expected %q, got %q", expected, path)
	}
}

func TestBuildFindingQueries_AllPresent(t *testing.T) {
	queries := BuildFindingQueries("./data/test/")

	expectedIDs := []string{
		"root-account-usage", "cloudtrail-changes", "unauthorized-api-calls",
		"failed-console-logins", "iam-policy-changes", "permission-boundary-changes",
		"suspicious-cross-account", "security-group-changes", "role-assumption-patterns",
		"access-key-creation", "ec2-instance-sensitive-calls", "lambda-sensitive-operations",
		"uba-activity-by-hour", "uba-high-error-rate", "uba-human-user-write-ops",
		"vpc-changes", "resource-creation-deletion", "container-serverless-data-exfil",
	}

	for _, id := range expectedIDs {
		fq, exists := queries[id]
		if !exists {
			t.Errorf("finding %q not found in queries", id)
			continue
		}
		if fq.SummarySQL == "" {
			t.Errorf("finding %q has empty SummarySQL", id)
		}
		if fq.DetailSQL == "" {
			t.Errorf("finding %q has empty DetailSQL", id)
		}
	}

	if len(queries) != len(expectedIDs) {
		t.Errorf("expected %d findings, got %d", len(expectedIDs), len(queries))
	}
}

func TestBuildFindingQueries_ContainsDataPath(t *testing.T) {
	dataPath := "./my/custom/path/"
	queries := BuildFindingQueries(dataPath)

	for id, fq := range queries {
		if !contains(fq.SummarySQL, dataPath) {
			t.Errorf("finding %q SummarySQL doesn't contain data path", id)
		}
		if !contains(fq.DetailSQL, dataPath) {
			t.Errorf("finding %q DetailSQL doesn't contain data path", id)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
