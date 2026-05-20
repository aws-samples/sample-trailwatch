package nlquery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"cloudtrail-analyzer/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

type LLMProvider interface {
	GenerateSQL(ctx context.Context, systemPrompt, userPrompt string) (string, error)
	Name() string
}

func NewProvider(cfg *config.Config) LLMProvider {
	switch cfg.LLM.Provider {
	case "anthropic":
		return &AnthropicProvider{cfg: cfg}
	case "openai":
		return &OpenAIProvider{cfg: cfg}
	case "ollama":
		return &OllamaProvider{cfg: cfg}
	default:
		return &BedrockProvider{cfg: cfg}
	}
}

// --- Bedrock Provider ---

type BedrockProvider struct {
	cfg *config.Config
}

func (p *BedrockProvider) Name() string { return "bedrock" }

func (p *BedrockProvider) GenerateSQL(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	awsCfg, err := p.loadConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("loading AWS config: %w", err)
	}

	client := bedrockruntime.NewFromConfig(awsCfg)

	body := map[string]interface{}{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        2048,
		"system":            systemPrompt,
		"messages": []map[string]interface{}{
			{"role": "user", "content": []map[string]string{{"type": "text", "text": userPrompt}}},
		},
	}

	bodyBytes, _ := json.Marshal(body)
	modelID := p.cfg.Bedrock.ModelID
	if modelID == "" {
		modelID = "us.anthropic.claude-sonnet-4-20250514-v1:0"
	}

	resp, err := client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(modelID),
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
		Body:        bodyBytes,
	})
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "ExpiredToken") {
			return "", fmt.Errorf("AWS session credentials expired. Remediation: go to Settings → Credentials and paste fresh session credentials")
		}
		if strings.Contains(errMsg, "AccessDenied") || strings.Contains(errMsg, "not authorized") {
			return "", fmt.Errorf("AWS credentials lack bedrock:InvokeModel permission. Remediation: (1) grant your IAM role bedrock:InvokeModel access, (2) or switch to Anthropic API / Ollama in Settings → AI Provider")
		}
		if strings.Contains(errMsg, "ResourceNotFoundException") {
			return "", fmt.Errorf("Bedrock model %q not available in region %s. Remediation: check model access is enabled in the Bedrock console, or change the model in config.json", modelID, p.cfg.Bedrock.Region)
		}
		// On-demand throughput is not supported for some models (e.g.,
		// Claude Opus 4.x); they require a Cross-Region Inference (CRIS)
		// profile. The fix is to prefix the model id with "us." / "eu." /
		// "apac." so Bedrock routes via CRIS. Suggest the prefixed id
		// inline so the user can fix it in Settings → AI Provider with one
		// edit. We do NOT auto-prefix in the request because CRIS routes
		// data cross-region and that consent should be explicit.
		if strings.Contains(errMsg, "on-demand throughput isn") {
			suggested := suggestedCRISModelID(modelID)
			return "", fmt.Errorf(
				"Bedrock model %q does not support on-demand invocation in this region. "+
					"This model needs a Cross-Region Inference (CRIS) profile. "+
					"Remediation: in Settings → AI Provider, switch the model to %q (acknowledge the CRIS data-residency notice), or pick an on-demand model like anthropic.claude-3-5-sonnet-20241022-v2:0.",
				modelID, suggested,
			)
		}
		return "", fmt.Errorf("Bedrock API error: %w", err)
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response from Bedrock")
	}
	return result.Content[0].Text, nil
}

func (p *BedrockProvider) loadConfig(ctx context.Context) (aws.Config, error) {
	region := p.cfg.Bedrock.Region
	if region == "" {
		region = "us-east-1"
	}

	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}

	switch p.cfg.Auth.Method {
	case "session_credentials":
		// Session/STS tokens live in process env vars (not config.json).
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			os.Getenv("AWS_ACCESS_KEY_ID"),
			os.Getenv("AWS_SECRET_ACCESS_KEY"),
			os.Getenv("AWS_SESSION_TOKEN"),
		)))
	case "sso":
		if p.cfg.Auth.SSOProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(p.cfg.Auth.SSOProfile))
		}
	}

	return awsconfig.LoadDefaultConfig(ctx, opts...)
}

// suggestedCRISModelID returns the most likely CRIS-prefixed equivalent of
// the given Bedrock model id. Used to give the user an actionable hint when
// Bedrock rejects on-demand invocation. Picks "us." as the default prefix
// since the app's typical operator is US-based; users in other regions can
// pick eu./apac./global. in Settings.
func suggestedCRISModelID(id string) string {
	id = strings.TrimSpace(id)
	for _, p := range []string{"us.", "eu.", "apac.", "global."} {
		if strings.HasPrefix(strings.ToLower(id), p) {
			return id // already prefixed; no fix to suggest
		}
	}
	return "us." + id
}

// --- Anthropic API Provider ---

type AnthropicProvider struct {
	cfg *config.Config
}

func (p *AnthropicProvider) Name() string { return "anthropic" }

func (p *AnthropicProvider) GenerateSQL(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	apiKey := p.cfg.LLM.APIKey
	if apiKey == "" {
		return "", fmt.Errorf("anthropic API key not configured")
	}

	model := p.cfg.LLM.Model
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}

	body := map[string]interface{}{
		"model":      model,
		"max_tokens": 2048,
		"system":     systemPrompt,
		"messages": []map[string]interface{}{
			{"role": "user", "content": userPrompt},
		},
	}

	bodyBytes, _ := json.Marshal(body)

	endpoint := "https://api.anthropic.com/v1/messages"
	if p.cfg.LLM.Endpoint != "" {
		endpoint = strings.TrimRight(p.cfg.LLM.Endpoint, "/") + "/v1/messages"
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling Anthropic API: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Anthropic API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response from Anthropic")
	}
	return result.Content[0].Text, nil
}

// --- OpenAI-compatible Provider ---

type OpenAIProvider struct {
	cfg *config.Config
}

func (p *OpenAIProvider) Name() string { return "openai" }

func (p *OpenAIProvider) GenerateSQL(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	apiKey := p.cfg.LLM.APIKey
	if apiKey == "" {
		return "", fmt.Errorf("OpenAI API key not configured")
	}

	model := p.cfg.LLM.Model
	if model == "" {
		model = "gpt-4o"
	}

	endpoint := "https://api.openai.com/v1/chat/completions"
	if p.cfg.LLM.Endpoint != "" {
		endpoint = strings.TrimRight(p.cfg.LLM.Endpoint, "/") + "/chat/completions"
	}

	body := map[string]interface{}{
		"model":      model,
		"max_tokens": 2048,
		"messages": []map[string]interface{}{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
	}

	bodyBytes, _ := json.Marshal(body)

	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling OpenAI API: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("OpenAI API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response from OpenAI")
	}
	return result.Choices[0].Message.Content, nil
}

// --- Ollama Provider ---

type OllamaProvider struct {
	cfg *config.Config
}

func (p *OllamaProvider) Name() string { return "ollama" }

func (p *OllamaProvider) GenerateSQL(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if err := p.ensureRunning(ctx); err != nil {
		return "", fmt.Errorf("ollama setup: %w", err)
	}

	model := p.cfg.LLM.Model
	if model == "" {
		model = "codellama:7b"
	}

	endpoint := "http://localhost:11434/api/chat"
	if p.cfg.LLM.Endpoint != "" {
		endpoint = strings.TrimRight(p.cfg.LLM.Endpoint, "/") + "/api/chat"
	}

	body := map[string]interface{}{
		"model":  model,
		"stream": false,
		"messages": []map[string]interface{}{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
	}

	bodyBytes, _ := json.Marshal(body)

	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling Ollama: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Ollama returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parsing Ollama response: %w", err)
	}
	return result.Message.Content, nil
}

func (p *OllamaProvider) ensureRunning(ctx context.Context) error {
	// Check if Ollama is already responding
	resp, err := http.Get("http://localhost:11434/api/tags")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return p.ensureModel(ctx)
		}
	}

	// Check if ollama binary exists
	ollamaPath, err := exec.LookPath("ollama")
	if err != nil {
		slog.Info("ollama not found, installing...", "component", "cloudtrail-analyzer")
		if installErr := p.installOllama(); installErr != nil {
			return fmt.Errorf("ollama not installed and auto-install failed: %w", installErr)
		}
		ollamaPath = "ollama"
	}

	// Start Ollama server
	slog.Info("starting ollama server", "component", "cloudtrail-analyzer", "path", ollamaPath)
	cmd := exec.Command(ollamaPath, "serve")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting ollama server: %w", err)
	}

	// Wait for it to be ready
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		resp, err := http.Get("http://localhost:11434/api/tags")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return p.ensureModel(ctx)
			}
		}
	}

	return fmt.Errorf("ollama server did not start within 30 seconds")
}

func (p *OllamaProvider) ensureModel(ctx context.Context) error {
	model := p.cfg.LLM.Model
	if model == "" {
		model = "codellama:7b"
	}

	// Check if model is already pulled
	resp, err := http.Get("http://localhost:11434/api/tags")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &tags)

	for _, m := range tags.Models {
		if m.Name == model || strings.HasPrefix(m.Name, model) {
			return nil
		}
	}

	// Pull the model
	slog.Info("pulling ollama model", "component", "cloudtrail-analyzer", "model", model)
	pullBody := map[string]interface{}{"name": model, "stream": false}
	pullBytes, _ := json.Marshal(pullBody)

	pullReq, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost:11434/api/pull", bytes.NewReader(pullBytes))
	pullReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Minute}
	pullResp, err := client.Do(pullReq)
	if err != nil {
		return fmt.Errorf("pulling model %s: %w", model, err)
	}
	defer pullResp.Body.Close()

	if pullResp.StatusCode != 200 {
		respBody, _ := io.ReadAll(pullResp.Body)
		return fmt.Errorf("failed to pull model %s: %s", model, string(respBody))
	}

	slog.Info("ollama model ready", "component", "cloudtrail-analyzer", "model", model)
	return nil
}

func (p *OllamaProvider) installOllama() error {
	// Check internet connectivity first
	if !p.hasInternet() {
		return fmt.Errorf("no internet connectivity detected. Ollama requires internet to install and download models. " +
			"Remediation: (1) Ensure this instance has outbound internet access, " +
			"(2) Or pre-install Ollama manually: https://ollama.com/download, " +
			"(3) Or switch to AWS Bedrock or Anthropic API provider in Settings → AI Provider")
	}

	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("brew"); err != nil {
			return fmt.Errorf("Homebrew not found. Install Ollama manually: https://ollama.com/download " +
				"Or run: curl -fsSL https://ollama.com/install.sh | sh")
		}
		cmd := exec.Command("brew", "install", "ollama")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("brew install ollama failed: %s. Remediation: install manually from https://ollama.com/download", string(out))
		}
		return nil
	case "linux":
		cmd := exec.Command("sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("ollama install script failed: %s. Remediation: check internet access, or install manually from https://ollama.com/download", string(out))
		}
		return nil
	default:
		return fmt.Errorf("automatic Ollama installation not supported on %s. "+
			"Remediation: install manually from https://ollama.com/download, "+
			"or switch to AWS Bedrock or Anthropic API in Settings → AI Provider", runtime.GOOS)
	}
}

func (p *OllamaProvider) hasInternet() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://ollama.com")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}
