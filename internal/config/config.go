package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
	Host                   string        `json:"host" envconfig:"HOST"`
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
			Provider: "bedrock",
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
