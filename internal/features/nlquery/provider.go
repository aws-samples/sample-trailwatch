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
		if strings.Contains(errMsg, "ThrottlingException") || strings.Contains(errMsg, "TooManyRequests") {
			return "", fmt.Errorf("Bedrock throttled this request (ThrottlingException). Remediation: (1) wait a few seconds and retry, (2) request a higher Bedrock requests-per-minute quota for model %q in Service Quotas, or (3) switch to a less contended model in Settings → AI Provider", modelID)
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
		// imds resolves credentials from the EC2 Instance Metadata Service.
		// LoadDefaultConfig's default chain already queries IMDS when no
		// static/profile credentials are present, so we add no explicit
		// provider here and let the chain resolve the instance role.
		//
		// NOTE: imds is EC2-only. It does NOT work in ECS / EKS / Fargate or
		// with IRSA — those container environments expose credentials via the
		// container credential endpoint or web-identity token, both of which
		// the default chain also handles automatically. If you run there,
		// leave auth.method on the default chain rather than forcing imds.
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

	// A hung endpoint must not pin the single-flight LLM slot indefinitely (it
	// would 429-block every NL query until restart). Bound the call with a
	// client timeout in addition to the request context so cancellation
	// propagates both from the caller and from the deadline.
	client := &http.Client{Timeout: llmHTTPTimeout(p.cfg)}
	resp, err := client.Do(req)
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

	// Bound the call so a hung endpoint can't wedge the single-flight LLM slot.
	client := &http.Client{Timeout: llmHTTPTimeout(p.cfg)}
	resp, err := client.Do(req)
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

	// Bound the call so a hung local model can't wedge the single-flight LLM slot.
	client := &http.Client{Timeout: llmHTTPTimeout(p.cfg)}
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
		// Auto-install fetches and runs a third-party installer from inside the
		// running server. That is convenient but a real supply-chain risk, so
		// it is OFF by default (cfg.AllowAutoInstall). When disabled we stop
		// here with setup guidance instead of silently downloading code.
		if p.cfg == nil || !p.cfg.AllowAutoInstall {
			return fmt.Errorf("Ollama is not installed and server-side auto-install is disabled. " +
				"Remediation: (1) install Ollama manually from https://ollama.com/download, " +
				"(2) or set allow_auto_install: true in config.json to opt into the auto-install path, " +
				"(3) or switch to AWS Bedrock or the Anthropic API in Settings → AI Provider")
		}
		slog.Info("ollama not found, auto-install enabled, installing...", "component", "cloudtrail-analyzer")
		if installErr := p.installOllama(); installErr != nil {
			return fmt.Errorf("ollama not installed and auto-install failed: %w", installErr)
		}
		ollamaPath = "ollama"
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
	// Reaching here means the operator has explicitly set allow_auto_install:
	// true (gated in ensureRunning). Even then we avoid the classic
	// `curl … | sh` pattern: piping a remote script straight into a shell runs
	// whatever the network served, with no chance to inspect or pin it. Instead
	// we download the installer to a temp file and execute that file — mirroring
	// the deploy.sh NodeSource pattern. The trade-off: we still run a remote
	// installer (Ollama publishes no per-release checksum we can pin here), but
	// the script lands on disk first so it can be logged/inspected and is not
	// fed to a shell from a live socket. To avoid running a remote installer at
	// all, pre-install Ollama manually from https://ollama.com/download and
	// leave allow_auto_install off.

	// Check internet connectivity first
	if !p.hasInternet() {
		return fmt.Errorf("no internet connectivity detected. Ollama requires internet to install and download models. " +
			"Remediation: (1) Ensure this instance has outbound internet access, " +
			"(2) Or pre-install Ollama manually: https://ollama.com/download, " +
			"(3) Or switch to AWS Bedrock or Anthropic API provider in Settings → AI Provider")
	}

	switch runtime.GOOS {
	case "darwin":
		// On macOS we install via Homebrew (a verified package manager with its
		// own integrity checks) rather than running the upstream shell script.
		if _, err := exec.LookPath("brew"); err != nil {
			return fmt.Errorf("Homebrew not found. Install Ollama manually: https://ollama.com/download")
		}
		cmd := exec.Command("brew", "install", "ollama")
		cmd.Env = scrubbedEnv() // installer needs no AWS credentials (N23)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("brew install ollama failed: %s. Remediation: install manually from https://ollama.com/download", string(out))
		}
		return nil
	case "linux":
		scriptPath, err := p.downloadInstallScript("https://ollama.com/install.sh")
		if err != nil {
			return fmt.Errorf("downloading ollama install script: %w. Remediation: check internet access, or install manually from https://ollama.com/download", err)
		}
		defer os.Remove(scriptPath)

		// Execute the downloaded script with sh <file> rather than piping the
		// HTTP response into a shell. The script is on disk and could be
		// inspected before this runs in a more locked-down deployment.
		cmd := exec.Command("sh", scriptPath)
		cmd.Env = scrubbedEnv() // installer needs no AWS credentials (N23)
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

// downloadInstallScript fetches url into a private temp file and returns its
// path. The caller is responsible for removing the file. Writing to disk first
// (instead of curl|sh) keeps a fetched-from-network script out of a live shell
// pipe and leaves an artifact that can be inspected or logged.
func (p *OllamaProvider) downloadInstallScript(url string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("installer download returned HTTP %d", resp.StatusCode)
	}

	// 0600 so only this user can read/execute the fetched script.
	f, err := os.CreateTemp("", "ollama-install-*.sh")
	if err != nil {
		return "", err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
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
