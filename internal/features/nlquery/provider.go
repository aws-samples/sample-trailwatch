package nlquery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"cloudtrail-analyzer/internal/awsutil"
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

const maxLLMResponseBytes = 4 << 20

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

// llmHTTPTimeout returns the per-request timeout for the HTTP-based LLM
// providers (Anthropic, OpenAI, Ollama). A bounded client timeout keeps a hung
// or wedged endpoint from holding the single-flight LLM slot open forever,
// which would 429-block every subsequent NL query until the server restarts.
// We honor QueryTimeoutSeconds when the operator has raised it, but keep a
// floor: LLM generation (especially a cold local Ollama model) routinely takes
// longer than a DuckDB query, so a too-small QueryTimeoutSeconds should not cut
// off a legitimately in-progress completion.
func llmHTTPTimeout(cfg *config.Config) time.Duration {
	const floor = 120 * time.Second
	if cfg != nil && cfg.QueryTimeoutSeconds > 0 {
		if d := time.Duration(cfg.QueryTimeoutSeconds) * time.Second; d > floor {
			return d
		}
	}
	return floor
}

func llmHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func readLLMResponse(body io.Reader) ([]byte, error) {
	limited := &io.LimitedReader{R: body, N: maxLLMResponseBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxLLMResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxLLMResponseBytes)
	}
	return data, nil
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
	modelID := configuredBedrockModelID(p.cfg)

	callCtx, cancel := context.WithTimeout(ctx, llmHTTPTimeout(p.cfg))
	defer cancel()
	resp, err := client.InvokeModel(callCtx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(modelID),
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
		Body:        bodyBytes,
	})
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("Bedrock request timed out after %s", llmHTTPTimeout(p.cfg))
		}
		return "", mapBedrockInvokeError(err, modelID, p.cfg.Bedrock.Region)
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response from Bedrock")
	}
	// stop_reason == "max_tokens" means the model hit the 2048-token cap and
	// the SQL is likely truncated mid-statement. We surface a warning rather
	// than failing: the validator downstream rejects malformed SQL anyway, but
	// the log line helps explain an otherwise-confusing parse failure.
	if result.StopReason == "max_tokens" {
		slog.Warn("Bedrock response truncated at max_tokens cap; generated SQL may be incomplete",
			"component", "cloudtrail-analyzer", "max_tokens", 2048)
	}
	return result.Content[0].Text, nil
}

func configuredBedrockModelID(cfg *config.Config) string {
	if cfg != nil {
		if modelID := strings.TrimSpace(cfg.Bedrock.ModelID); modelID != "" {
			return modelID
		}
	}
	return config.DefaultBedrockModelID
}

func mapBedrockInvokeError(err error, modelID, region string) error {
	errMsg := err.Error()
	lowerErr := strings.ToLower(errMsg)
	if strings.TrimSpace(region) == "" {
		region = "us-east-1"
	}

	switch {
	case strings.Contains(errMsg, "ExpiredToken"):
		return fmt.Errorf("AWS session credentials expired. Remediation: go to Settings → Credentials and paste fresh session credentials")
	case strings.Contains(lowerErr, "you don't have access to the model with the specified model id"):
		// Bedrock uses AccessDeniedException for retired or unavailable model
		// IDs as well as IAM failures. Handle its model-specific wording first
		// so administrators are not told to add a permission they already have.
		return fmt.Errorf(
			"Bedrock model %q is not available to this account. The configured model may be legacy, retired, or unavailable in %s. "+
				"Remediation: in Settings → AI Provider, select an available Anthropic model (recommended default: %q) and retry",
			modelID, region, config.DefaultBedrockModelID,
		)
	case strings.Contains(errMsg, "AccessDenied") || strings.Contains(lowerErr, "not authorized"):
		return fmt.Errorf("AWS credentials lack bedrock:InvokeModel permission. Remediation: (1) grant your IAM role bedrock:InvokeModel access, (2) or switch to Anthropic API / Ollama in Settings → AI Provider")
	case strings.Contains(errMsg, "ResourceNotFoundException"):
		return fmt.Errorf("Bedrock model %q not available in region %s. Remediation: check model access is enabled in the Bedrock console, or change the model in config.json", modelID, region)
	case strings.Contains(errMsg, "ThrottlingException") || strings.Contains(errMsg, "TooManyRequests"):
		return fmt.Errorf("Bedrock throttled this request (ThrottlingException). Remediation: (1) wait a few seconds and retry, (2) request a higher Bedrock requests-per-minute quota for model %q in Service Quotas, or (3) switch to a less contended model in Settings → AI Provider", modelID)
	case strings.Contains(lowerErr, "on-demand throughput isn"):
		// Some models require a Cross-Region Inference (CRIS) profile. Do not
		// auto-prefix because CRIS can route data to another region.
		suggested := suggestedCRISModelID(modelID)
		return fmt.Errorf(
			"Bedrock model %q does not support on-demand invocation in this region. "+
				"This model needs a Cross-Region Inference (CRIS) profile. "+
				"Remediation: in Settings → AI Provider, switch the model to %q (acknowledge the CRIS data-residency notice), or pick an on-demand Anthropic model.",
			modelID, suggested,
		)
	default:
		return fmt.Errorf("Bedrock API error: %w", err)
	}
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
	case "static":
		// Long-lived IAM user keys stored in config.json. Bedrock previously
		// ignored this method and silently fell back to the default chain;
		// wire it through so the configured keys are actually used.
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			p.cfg.Auth.AccessKeyID,
			p.cfg.Auth.SecretAccessKey,
			p.cfg.Auth.SessionToken,
		)))
	case "imds":
		opts = append(opts, awsconfig.WithCredentialsProvider(awsutil.NewIMDSv2Provider()))
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

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encoding Anthropic request: %w", err)
	}

	endpoint := "https://api.anthropic.com/v1/messages"
	if p.cfg.LLM.Endpoint != "" {
		if err := config.ValidateLLMEndpoint(p.Name(), p.cfg.LLM.Endpoint); err != nil {
			return "", err
		}
		endpoint = strings.TrimRight(p.cfg.LLM.Endpoint, "/") + "/v1/messages"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("creating Anthropic request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	// A hung endpoint must not pin the single-flight LLM slot indefinitely (it
	// would 429-block every NL query until restart). Bound the call with a
	// client timeout in addition to the request context so cancellation
	// propagates both from the caller and from the deadline.
	client := llmHTTPClient(llmHTTPTimeout(p.cfg))
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling Anthropic API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readLLMResponse(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading Anthropic response: %w", err)
	}
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
		if err := config.ValidateLLMEndpoint(p.Name(), p.cfg.LLM.Endpoint); err != nil {
			return "", err
		}
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

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encoding OpenAI request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("creating OpenAI request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	// Bound the call so a hung endpoint can't wedge the single-flight LLM slot.
	client := llmHTTPClient(llmHTTPTimeout(p.cfg))
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling OpenAI API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readLLMResponse(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading OpenAI response: %w", err)
	}
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
		if err := config.ValidateLLMEndpoint(p.Name(), p.cfg.LLM.Endpoint); err != nil {
			return "", err
		}
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

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encoding Ollama request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("creating Ollama request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Bound the call so a hung local model can't wedge the single-flight LLM slot.
	client := llmHTTPClient(llmHTTPTimeout(p.cfg))
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling Ollama: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readLLMResponse(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading Ollama response: %w", err)
	}
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
	resp, err := p.get(ctx, "http://localhost:11434/api/tags")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return p.ensureModel(ctx)
		}
	}

	// Check if ollama binary exists
	ollamaPath, err := exec.LookPath("ollama")
	if err != nil {
		// Server-side auto-install has been removed (SUPPLY-01). The server
		// never downloads or executes third-party installers. Return clear
		// instructions for the operator to install Ollama themselves.
		return fmt.Errorf("Ollama is not installed. " +
			"Remediation: (1) install Ollama manually from https://ollama.com/download, " +
			"(2) or switch to AWS Bedrock or the Anthropic API in Settings → AI Provider")
	}

	// Start Ollama server
	slog.Info("starting ollama server", "component", "cloudtrail-analyzer", "path", ollamaPath)
	cmd := exec.Command(ollamaPath, "serve")
	// Ollama is a local LLM server and has no need for the operator's AWS
	// credentials; strip them from its environment so live STS tokens don't
	// leak into the long-running subprocess (N23).
	cmd.Env = scrubbedEnv()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting ollama server: %w", err)
	}

	// Wait for it to be ready
	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		resp, err := p.get(ctx, "http://localhost:11434/api/tags")
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
	resp, err := p.get(ctx, "http://localhost:11434/api/tags")
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

func (p *OllamaProvider) get(ctx context.Context, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return (&http.Client{Timeout: 5 * time.Second}).Do(req)
}
