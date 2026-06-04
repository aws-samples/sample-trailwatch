package settings

import (
	"log/slog"
	"net/http"
	"os"
	"strings"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

// Handler provides HTTP handlers for settings endpoints.
type Handler struct {
	cfg              *config.Config
	saveFn           func(*config.Config) error
	service          *Service
	onAuthChangedFns []func() // observers notified when the user applies new credentials
}

// NewHandler creates a new settings Handler.
func NewHandler(cfg *config.Config, saveFn func(*config.Config) error) *Handler {
	return &Handler{
		cfg:     cfg,
		saveFn:  saveFn,
		service: NewService(cfg, saveFn),
	}
}

// Service returns the underlying settings service. Other packages use this to
// reuse the shared AWS-config loader without duplicating credential logic.
func (h *Handler) Service() *Service {
	return h.service
}

// OnAuthChanged registers a callback fired in a goroutine whenever the user
// applies new credentials (e.g., paste-and-apply session credentials in the
// UI). Used by the accounts package to retry an Organizations refresh that
// failed pre-credentials and would otherwise stay sticky-failed.
func (h *Handler) OnAuthChanged(fn func()) {
	h.onAuthChangedFns = append(h.onAuthChangedFns, fn)
}

func (h *Handler) notifyAuthChanged() {
	for _, fn := range h.onAuthChangedFns {
		go fn()
	}
}

// Routes returns a Chi router with all settings routes mounted.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.GetSettings)
	r.Put("/", h.UpdateSettings)
	r.Post("/validate-bucket", h.ValidateBucket)
	r.Get("/accounts", h.ListAccounts)
	r.Post("/validate-credentials", h.ValidateCredentials)
	r.Post("/apply-session-credentials", h.ApplySessionCredentials)
	r.Get("/caller-identity", h.GetCallerIdentity)
	r.Post("/detect-structure", h.DetectStructure)
	r.Post("/discover-regions", h.DiscoverRegions)
	r.Post("/verify-logs", h.VerifyLogs)
	r.Post("/bedrock-models", h.ListBedrockModels)

	return r
}

// GetSettings returns the current application configuration.
// The secret_access_key is redacted in the response.
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	// Build a response that redacts the secret access key
	type llmResponse struct {
		Provider string `json:"provider"`
		Model    string `json:"model,omitempty"`
		Endpoint string `json:"endpoint,omitempty"`
		HasKey   bool   `json:"has_key"`
	}

	type settingsResponse struct {
		Port                   int                  `json:"port"`
		DataDir                string               `json:"data_dir"`
		LogLevel               string               `json:"log_level"`
		QueryTimeoutSeconds    int                  `json:"query_timeout_seconds"`
		MonitorIntervalSeconds int                  `json:"monitor_interval_seconds"`
		MaxDownloadConcurrency int                  `json:"max_download_concurrency"`
		S3                     config.S3Config      `json:"s3"`
		Auth                   redactedAuthConfig   `json:"auth"`
		Bedrock                config.BedrockConfig `json:"bedrock"`
		LLM                    llmResponse          `json:"llm"`
	}

	resp := settingsResponse{
		Port:                   h.cfg.Port,
		DataDir:                h.cfg.DataDir,
		LogLevel:               h.cfg.LogLevel,
		QueryTimeoutSeconds:    h.cfg.QueryTimeoutSeconds,
		MonitorIntervalSeconds: h.cfg.MonitorIntervalSeconds,
		MaxDownloadConcurrency: h.cfg.MaxDownloadConcurrency,
		S3:                     h.cfg.S3,
		Auth: redactedAuthConfig{
			Method:      h.cfg.Auth.Method,
			AccessKeyID: h.cfg.Auth.AccessKeyID,
			SSOProfile:  h.cfg.Auth.SSOProfile,
			RoleARN:     h.cfg.Auth.RoleARN,
			ExternalID:  h.cfg.Auth.ExternalID,
		},
		Bedrock: h.cfg.Bedrock,
		LLM: llmResponse{
			Provider: h.cfg.LLM.Provider,
			Model:    h.cfg.LLM.Model,
			Endpoint: h.cfg.LLM.Endpoint,
			HasKey:   h.cfg.LLM.APIKey != "",
		},
	}

	// Indicate if a secret key is configured without revealing it
	if h.cfg.Auth.SecretAccessKey != "" {
		resp.Auth.SecretAccessKey = "********"
	}

	render.JSON(w, http.StatusOK, resp)
}

// redactedAuthConfig is the auth config with secret_access_key redacted.
type redactedAuthConfig struct {
	Method          string `json:"method"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SSOProfile      string `json:"sso_profile,omitempty"`
	RoleARN         string `json:"role_arn,omitempty"`
	ExternalID      string `json:"external_id,omitempty"`
}

// UpdateSettings updates the application configuration and persists it.
func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req UpdateConfigRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}

	// Validate date range if provided
	if req.StartDate != "" && req.EndDate != "" {
		if err := ValidateDateRange(req.StartDate, req.EndDate); err != nil {
			render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), map[string]string{
				"field": "date_range",
			})
			return
		}
	}

	// Validate mode
	if req.Mode != "" && req.Mode != "single" && req.Mode != "control_tower" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "mode must be 'single' or 'control_tower'", map[string]string{
			"field": "mode",
		})
		return
	}

	// Validate auth method
	if req.AuthMethod != "" {
		validMethods := map[string]bool{"imds": true, "session_credentials": true, "sso": true, "static": true}
		if !validMethods[req.AuthMethod] {
			render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "auth_method must be one of: imds, session_credentials, sso, static", map[string]string{
				"field": "auth_method",
			})
			return
		}
	}

	// Validate path-bearing fields against path traversal (N91). bucket,
	// account_id, org_id, log_region, and each member account ID are
	// interpolated into local filesystem paths (constructLocalPath,
	// sessionLocalDir) and into S3 prefixes. A value containing a slash, a
	// ".." segment, a null byte, or a leading "." could redirect a write
	// outside the data dir or escape the intended prefix. Reject them here so
	// the values that reach the path-construction code are already sanitized.
	pathFields := map[string]string{
		"bucket":     req.Bucket,
		"account_id": req.AccountID,
		"org_id":     req.OrgID,
		"log_region": req.LogRegion,
	}
	for field, val := range pathFields {
		if val == "" {
			continue
		}
		if !isSafePathSegment(val) {
			render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "value contains characters not allowed in a path segment (no '/', '\\', '..', or control characters)", map[string]string{
				"field": field,
			})
			return
		}
	}
	for _, acct := range req.MemberAccounts {
		if acct != "" && !isSafePathSegment(acct) {
			render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "member account ID contains characters not allowed in a path segment", map[string]string{
				"field": "member_accounts",
			})
			return
		}
	}

	// Apply updates to config
	if req.Bucket != "" {
		h.cfg.S3.Bucket = req.Bucket
	}
	if req.Region != "" {
		h.cfg.S3.Region = req.Region
	}
	if req.AccountID != "" {
		h.cfg.S3.AccountID = req.AccountID
	}
	if req.Mode != "" {
		h.cfg.S3.Mode = req.Mode
	}
	if req.AuthMethod != "" {
		h.cfg.Auth.Method = req.AuthMethod
	}
	if req.AccessKeyID != "" {
		h.cfg.Auth.AccessKeyID = req.AccessKeyID
	}
	if req.SecretAccessKey != "" {
		h.cfg.Auth.SecretAccessKey = req.SecretAccessKey
	}
	if req.RoleARN != "" {
		h.cfg.Auth.RoleARN = req.RoleARN
	}
	if req.ExternalID != "" {
		h.cfg.Auth.ExternalID = req.ExternalID
	}
	if req.SSOProfile != "" {
		h.cfg.Auth.SSOProfile = req.SSOProfile
	}
	if req.StartDate != "" {
		h.cfg.S3.StartDate = req.StartDate
	}
	if req.EndDate != "" {
		h.cfg.S3.EndDate = req.EndDate
	}
	if req.OrgID != "" {
		h.cfg.S3.OrgID = req.OrgID
	}
	if req.MemberAccounts != nil {
		h.cfg.S3.MemberAccounts = req.MemberAccounts
	}
	if req.LogRegion != "" {
		h.cfg.S3.LogRegion = req.LogRegion
	}
	if req.LLMProvider != "" {
		h.cfg.LLM.Provider = req.LLMProvider
	}
	if req.LLMAPIKey != "" {
		h.cfg.LLM.APIKey = req.LLMAPIKey
	}
	if req.LLMModel != "" {
		h.cfg.LLM.Model = req.LLMModel
		// Sync to Bedrock config when provider is bedrock
		if h.cfg.LLM.Provider == "bedrock" {
			h.cfg.Bedrock.ModelID = req.LLMModel
		}
	}
	if req.LLMEndpoint != "" {
		h.cfg.LLM.Endpoint = req.LLMEndpoint
	}
	if req.BedrockRegion != "" {
		h.cfg.Bedrock.Region = req.BedrockRegion
	}

	// Persist configuration
	if err := h.saveFn(h.cfg); err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save configuration", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	// Return updated config (with redacted secret)
	h.GetSettings(w, r)
}

// ValidateBucket tests S3 bucket accessibility via HeadBucket.
func (h *Handler) ValidateBucket(w http.ResponseWriter, r *http.Request) {
	var req ValidateBucketRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}

	if req.Bucket == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "bucket is required", map[string]string{
			"field": "bucket",
		})
		return
	}

	if req.Region == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "region is required", map[string]string{
			"field": "region",
		})
		return
	}

	result, err := h.service.ValidateBucket(r.Context(), req.Bucket, req.Region)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Bucket validation failed", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, result)
}

// ListAccounts lists Control Tower member accounts by discovering S3 prefixes.
func (h *Handler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	bucket := h.cfg.S3.Bucket
	region := h.cfg.S3.Region

	if bucket == "" || region == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "S3 bucket and region must be configured before listing accounts", nil)
		return
	}

	accounts, err := h.service.ListControlTowerAccounts(r.Context(), bucket, region)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "S3_ACCESS_DENIED", "Failed to list accounts", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, AccountListResponse{
		Accounts: accounts,
	})
}

// ValidateCredentials tests the credential chain resolution.
func (h *Handler) ValidateCredentials(w http.ResponseWriter, r *http.Request) {
	status, err := h.service.ResolveCredentials(r.Context(), h.cfg)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Credential validation failed", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, status)
}

// ApplySessionCredentials sets temporary STS session credentials as environment
// variables for the running process only. They are intentionally NOT persisted
// to config.json — session tokens are short-lived and writing them to disk
// extends their lifetime past their useful window and complicates revocation.
// Users re-apply via the Credentials view after a restart.
func (h *Handler) ApplySessionCredentials(w http.ResponseWriter, r *http.Request) {
	var req SessionCredentialsRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}
	if req.AccessKeyID == "" || req.SecretAccessKey == "" || req.SessionToken == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "All three fields are required: access_key_id, secret_access_key, session_token", nil)
		return
	}

	// Session credentials are stored in the process environment so the AWS SDK
	// credential chain can pick them up (see Service.loadAWSConfig). NOTE on
	// credential exposure (N23): once these AWS_* vars are set on the process,
	// a child process spawned via exec.Command inherits them by default
	// (os/exec copies os.Environ when cmd.Env is nil). The DuckDB and Ollama
	// subprocesses spawned in the nlquery package do NOT need AWS credentials —
	// they read local files / a local model server — so those exec sites should
	// pass a filtered cmd.Env that drops AWS_* to avoid leaking live credentials
	// into unrelated subprocesses. That scrubbing belongs at the exec.Command
	// call sites (internal/features/nlquery/{service.go,indexer.go,provider.go}
	// and internal/startup/validator.go), which are owned elsewhere; flagged for
	// the orchestrator.
	os.Setenv("AWS_ACCESS_KEY_ID", req.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", req.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", req.SessionToken)

	// Mark the active method in config but do NOT store the credential values.
	h.cfg.Auth.Method = "session_credentials"
	h.cfg.Auth.AccessKeyID = ""
	h.cfg.Auth.SecretAccessKey = ""
	h.cfg.Auth.SessionToken = ""

	if err := h.saveFn(h.cfg); err != nil {
		slog.Warn("failed to persist auth method",
			"component", "cloudtrail-analyzer",
			"error", err.Error(),
		)
	}

	slog.Info("session credentials applied via UI (env-only, not persisted)",
		"component", "cloudtrail-analyzer",
		"access_key_prefix", req.AccessKeyID[:4]+"...",
	)

	// Notify observers (e.g., the accounts resolver) that the auth surface has
	// changed. The resolver's sticky-failure flag would otherwise keep skipping
	// refreshes that initially failed because credentials were not yet applied.
	h.notifyAuthChanged()

	status, _ := h.service.ResolveCredentials(r.Context(), h.cfg)

	render.JSON(w, http.StatusOK, map[string]interface{}{
		"applied":    true,
		"message":    "Session credentials applied to environment (not written to disk)",
		"validation": status,
	})
}

// GetCallerIdentity returns the AWS identity of the active credentials via STS.
func (h *Handler) GetCallerIdentity(w http.ResponseWriter, r *http.Request) {
	result, err := h.service.GetCallerIdentity(r.Context())
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "STS_ERROR", "Failed to get caller identity", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, result)
}

// DetectStructure detects the S3 bucket structure (single account vs Control Tower).
func (h *Handler) DetectStructure(w http.ResponseWriter, r *http.Request) {
	var req DetectStructureRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}

	if req.Bucket == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "bucket is required", map[string]string{
			"field": "bucket",
		})
		return
	}

	if req.Region == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "region is required", map[string]string{
			"field": "region",
		})
		return
	}

	result, err := h.service.DetectBucketStructure(r.Context(), req.Bucket, req.Region)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "S3_ERROR", "Failed to detect bucket structure", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, result)
}

// DiscoverRegions discovers available CloudTrail regions for a given account.
func (h *Handler) DiscoverRegions(w http.ResponseWriter, r *http.Request) {
	var req DiscoverRegionsRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}

	if req.Bucket == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "bucket is required", map[string]string{
			"field": "bucket",
		})
		return
	}

	if req.Region == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "region is required", map[string]string{
			"field": "region",
		})
		return
	}

	if req.AccountID == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "account_id is required", map[string]string{
			"field": "account_id",
		})
		return
	}

	result, err := h.service.DiscoverRegions(r.Context(), req.Bucket, req.Region, req.AccountID, req.OrgID)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "S3_ERROR", "Failed to discover regions", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, result)
}

// ListBedrockModels returns available Bedrock foundation models for a given region.
func (h *Handler) ListBedrockModels(w http.ResponseWriter, r *http.Request) {
	var req ListBedrockModelsRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}

	if req.Region == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "region is required", map[string]string{
			"field": "region",
		})
		return
	}

	result, err := h.service.ListBedrockModels(r.Context(), req.Region)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "BEDROCK_ERROR", "Failed to list Bedrock models", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, result)
}

// VerifyLogs checks if CloudTrail log files exist for the specified parameters.
func (h *Handler) VerifyLogs(w http.ResponseWriter, r *http.Request) {
	var req VerifyLogsRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}

	if req.Bucket == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "bucket is required", map[string]string{
			"field": "bucket",
		})
		return
	}

	if req.Region == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "region is required", map[string]string{
			"field": "region",
		})
		return
	}

	if req.AccountID == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "account_id is required", map[string]string{
			"field": "account_id",
		})
		return
	}

	if req.LogRegion == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "log_region is required", map[string]string{
			"field": "log_region",
		})
		return
	}

	if req.StartDate == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "start_date is required", map[string]string{
			"field": "start_date",
		})
		return
	}

	if req.EndDate == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "end_date is required", map[string]string{
			"field": "end_date",
		})
		return
	}

	// Validate date range
	if err := ValidateDateRange(req.StartDate, req.EndDate); err != nil {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), map[string]string{
			"field": "date_range",
		})
		return
	}

	result, err := h.service.VerifyLogs(r.Context(), &req)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "S3_ERROR", "Failed to verify logs", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, result)
}

// isSafePathSegment reports whether v is safe to interpolate into a single
// filesystem path segment or S3 prefix component. It rejects path separators
// ("/" or "\"), parent-directory references (".."), a leading "." (hidden /
// relative markers), and control characters including the null byte. This is a
// conservative allowlist of shape rather than a per-field format check: bucket,
// account_id, org_id, log_region, and member account IDs all flow into local
// write paths, so any value that could redirect a write is refused before it is
// persisted (N91 / pairs with the path-traversal guard in constructLocalPath).
func isSafePathSegment(v string) bool {
	if v == "" {
		return false
	}
	if v == ".." || strings.HasPrefix(v, ".") {
		return false
	}
	if strings.Contains(v, "..") {
		return false
	}
	for _, r := range v {
		if r == '/' || r == '\\' || r == 0 || r < 0x20 {
			return false
		}
	}
	return true
}
