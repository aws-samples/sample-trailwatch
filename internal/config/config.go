package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/kelseyhightower/envconfig"
)

const (
	defaultConfigFile = "config.json"
	envPrefix         = ""
)

// Config holds all application configuration.
type Config struct {
	Port int `json:"port" envconfig:"PORT"`
	// Host is the bind address. Defaults to 127.0.0.1 (loopback only) so a
	// single-user local tool isn't reachable from the LAN. Set to "0.0.0.0"
	// to expose the API on all interfaces.
	Host string `json:"host" envconfig:"HOST"`
	// TrustedHosts is the allowlist of Host header values the server accepts.
	// It defends against DNS-rebinding: a website the user visits cannot make
	// their browser send authenticated requests to the loopback server unless
	// the Host header matches an entry here. localhost / 127.0.0.1 / [::1] (with
	// or without the configured port) are always accepted; add extra hostnames
	// here when fronting the app with an authenticating reverse proxy. Set a
	// single entry "*" to disable the check (not recommended).
	TrustedHosts []string `json:"trusted_hosts,omitempty" envconfig:"TRUSTED_HOSTS"`
	// AllowAutoInstall gates the convenience auto-download of third-party
	// binaries (DuckDB CLI, Ollama) by the running server. It defaults to
	// false: the server will NOT fetch-and-execute installers on its own.
	// When the binary is missing, startup reports an error with setup
	// guidance instead. Set to true (or env CTA_ALLOW_AUTO_INSTALL=true) to
	// opt back into the verified, checksum-pinned auto-install path.
	AllowAutoInstall       bool          `json:"allow_auto_install,omitempty" envconfig:"CTA_ALLOW_AUTO_INSTALL"`
	DataDir                string        `json:"data_dir" envconfig:"DATA_DIR"`
	LogLevel               string        `json:"log_level" envconfig:"LOG_LEVEL"`
	QueryTimeoutSeconds    int           `json:"query_timeout_seconds" envconfig:"QUERY_TIMEOUT_SECONDS"`
	MonitorIntervalSeconds int           `json:"monitor_interval_seconds" envconfig:"MONITOR_INTERVAL_SECONDS"`
	MaxDownloadConcurrency int           `json:"max_download_concurrency" envconfig:"MAX_DOWNLOAD_CONCURRENCY"`
	S3                     S3Config      `json:"s3"`
	Auth                   AuthConfig    `json:"auth"`
	Bedrock                BedrockConfig `json:"bedrock"`
	LLM                    LLMConfig     `json:"llm"`
}

// TrustedHostAllowed reports whether the given Host header (which may include a
// port) is permitted. Loopback names are always allowed; configured
// TrustedHosts add to that set. A TrustedHosts entry of "*" disables the check.
// This is the single source of truth used by the trusted-host middleware.
func (c *Config) TrustedHostAllowed(hostHeader string) bool {
	if hostHeader == "" {
		// No Host header at all (HTTP/1.0 or a raw client). Reject — every
		// real browser sends one, and an empty value can't be matched safely.
		return false
	}

	// Split host:port if present. net.SplitHostPort fails on a bare host, so
	// fall back to the raw value in that case.
	host := hostHeader
	if h, _, err := splitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	// Always-allowed loopback identities.
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}

	for _, t := range c.TrustedHosts {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if t == "*" {
			return true
		}
		// Allow either a bare hostname or a host:port entry to match.
		if th, _, err := splitHostPort(t); err == nil {
			t = th
		}
		if t == host {
			return true
		}
	}
	return false
}

// splitHostPort is a thin wrapper that only treats a value as host:port when it
// genuinely parses as one, so IPv6 literals and bare hostnames are handled
// without pulling the net import into every caller.
func splitHostPort(hostport string) (host, port string, err error) {
	// Reuse strconv to detect a trailing :port cheaply for the common case,
	// but defer to net.SplitHostPort semantics via a minimal reimplementation
	// to correctly handle bracketed IPv6 ([::1]:7070).
	if strings.HasPrefix(hostport, "[") {
		end := strings.IndexByte(hostport, ']')
		if end < 0 {
			return "", "", errNoPort
		}
		host = hostport[1:end]
		rest := hostport[end+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return host, port, nil
	}
	i := strings.LastIndexByte(hostport, ':')
	if i < 0 {
		return "", "", errNoPort
	}
	// Guard against unbracketed IPv6 (multiple colons) being misread.
	if strings.IndexByte(hostport, ':') != i {
		return "", "", errNoPort
	}
	host = hostport[:i]
	port = hostport[i+1:]
	if _, convErr := strconv.Atoi(port); convErr != nil {
		return "", "", errNoPort
	}
	return host, port, nil
}

var errNoPort = errors.New("no port in host header")

// S3Config holds S3 bucket configuration.
type S3Config struct {
	Bucket         string   `json:"bucket"`
	Region         string   `json:"region"`
	AccountID      string   `json:"account_id"`
	Mode           string   `json:"mode"`
	OrgID          string   `json:"org_id,omitempty"`
	LogRegion      string   `json:"log_region,omitempty"`
	StartDate      string   `json:"start_date,omitempty"`
	EndDate        string   `json:"end_date,omitempty"`
	MemberAccounts []string `json:"member_accounts,omitempty"`
}

// AuthConfig holds AWS authentication configuration.
type AuthConfig struct {
	Method          string `json:"method"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	SSOProfile      string `json:"sso_profile,omitempty"`
	RoleARN         string `json:"role_arn,omitempty"`
	ExternalID      string `json:"external_id,omitempty"`
}

// BedrockConfig holds AWS Bedrock configuration.
type BedrockConfig struct {
	Region  string `json:"region"`
	ModelID string `json:"model_id"`
	Enabled bool   `json:"enabled"`
}

// LLMConfig holds the LLM provider configuration.
type LLMConfig struct {
	Provider string `json:"provider"` // bedrock, anthropic, openai, ollama
	APIKey   string `json:"api_key,omitempty"`
	Model    string `json:"model,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	// MaxSessionSpendUSD is the maximum cumulative estimated LLM spend (in
	// USD) allowed per application session. Once reached, paid-provider LLM
	// endpoints return 429 until the counter is reset or the app restarts.
	// Set to 0 to disable the cap. Default: 5.00.
	// Ollama (local) is exempt — it has no API cost.
	MaxSessionSpendUSD float64 `json:"max_session_spend_usd,omitempty"`
	// PricingOverrides lets users replace the built-in per-model rate card
	// with their actual contract pricing. Keyed by model id (matching whatever
	// is set in Bedrock.ModelID or Model above), values are dollars per
	// million tokens. Used by the cost-estimation pre-flight; falls back to
	// hard-coded defaults when absent.
	PricingOverrides map[string]PricingOverride `json:"pricing_overrides,omitempty"`
}

// PricingOverride represents a user-supplied rate card for one model.
type PricingOverride struct {
	InputPerMillionUSD  float64 `json:"input_per_million_usd"`
	OutputPerMillionUSD float64 `json:"output_per_million_usd"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:                   7070,
		Host:                   "127.0.0.1",
		DataDir:                "./data",
		LogLevel:               "info",
		QueryTimeoutSeconds:    60,
		MonitorIntervalSeconds: 5,
		MaxDownloadConcurrency: 16,
		S3: S3Config{
			Bucket:    "",
			Region:    "",
			AccountID: "",
			Mode:      "single",
		},
		Auth: AuthConfig{
			Method: "imds",
		},
		Bedrock: BedrockConfig{
			Region:  "us-east-1",
			ModelID: "us.anthropic.claude-sonnet-4-20250514-v1:0",
			Enabled: false,
		},
		LLM: LLMConfig{
			Provider:           "bedrock",
			MaxSessionSpendUSD: 5.00,
		},
	}
}

// LoadConfig loads configuration using the hierarchy:
// 1. Start with defaults
// 2. Override with config.json values (if file exists)
// 3. Override with environment variables
// 4. Validate the final config
//
// On first run (no config.json), creates a default config file.
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	configPath := configFilePath()

	// Attempt to read config.json
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// First run: create default config file
			if writeErr := SaveConfig(&cfg); writeErr != nil {
				return nil, fmt.Errorf("creating default config file: %w", writeErr)
			}
		} else {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	} else {
		// Parse JSON into config struct (overrides defaults)
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	// Apply environment variable overrides
	if err := envconfig.Process(envPrefix, &cfg); err != nil {
		return nil, fmt.Errorf("processing environment variables: %w", err)
	}

	// Backfill Host on configs created before the field existed.
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}

	// Validate final configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// SaveConfig writes the configuration to config.json with indented formatting.
func SaveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	configPath := configFilePath()

	// Ensure the directory exists
	dir := filepath.Dir(configPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil { // nosemgrep: incorrect-default-permission
			return fmt.Errorf("creating config directory: %w", err)
		}
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	return nil
}

// validateConfig validates the configuration using struct tag validation.
func validateConfig(cfg *Config) error {
	validate := validator.New()

	// Port must be in valid range
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", cfg.Port)
	}

	// DataDir must not be empty
	if cfg.DataDir == "" {
		return fmt.Errorf("data_dir must not be empty")
	}

	// LogLevel must be valid
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[cfg.LogLevel] {
		return fmt.Errorf("log_level must be one of: debug, info, warn, error; got %q", cfg.LogLevel)
	}

	// QueryTimeoutSeconds must be positive
	if cfg.QueryTimeoutSeconds < 1 {
		return fmt.Errorf("query_timeout_seconds must be at least 1, got %d", cfg.QueryTimeoutSeconds)
	}

	// MonitorIntervalSeconds must be positive
	if cfg.MonitorIntervalSeconds < 1 {
		return fmt.Errorf("monitor_interval_seconds must be at least 1, got %d", cfg.MonitorIntervalSeconds)
	}

	// MaxDownloadConcurrency must be positive
	if cfg.MaxDownloadConcurrency < 1 {
		return fmt.Errorf("max_download_concurrency must be at least 1, got %d", cfg.MaxDownloadConcurrency)
	}

	// S3 mode validation
	if cfg.S3.Mode != "" {
		validModes := map[string]bool{"single": true, "control_tower": true}
		if !validModes[cfg.S3.Mode] {
			return fmt.Errorf("s3.mode must be 'single' or 'control_tower', got %q", cfg.S3.Mode)
		}
	}

	// Auth method validation
	if cfg.Auth.Method != "" {
		validMethods := map[string]bool{"imds": true, "session_credentials": true, "sso": true, "static": true}
		if !validMethods[cfg.Auth.Method] {
			return fmt.Errorf("auth.method must be one of: imds, session_credentials, sso, static; got %q", cfg.Auth.Method)
		}
	}

	// Use validator for any struct-tag based validation (extensible for future use)
	_ = validate

	return nil
}

// configFilePath returns the path to the config file.
func configFilePath() string {
	return defaultConfigFile
}
