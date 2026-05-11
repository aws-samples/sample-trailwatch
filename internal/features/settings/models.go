// Package settings provides S3 configuration management, credential validation,
// and bucket accessibility endpoints for the CloudTrail Analyzer.
package settings

// UpdateConfigRequest represents a request to update the application configuration.
type UpdateConfigRequest struct {
	Bucket         string   `json:"bucket"`
	Region         string   `json:"region"`
	AccountID      string   `json:"account_id"`
	Mode           string   `json:"mode"`
	OrgID          string   `json:"org_id,omitempty"`
	LogRegion      string   `json:"log_region,omitempty"`
	MemberAccounts []string `json:"member_accounts,omitempty"`
	// Auth fields
	AuthMethod      string `json:"auth_method"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SSOProfile      string `json:"sso_profile,omitempty"`
	RoleARN         string `json:"role_arn,omitempty"`
	ExternalID      string `json:"external_id,omitempty"`
	// Date range
	StartDate string `json:"start_date,omitempty"`
	EndDate   string `json:"end_date,omitempty"`
	// LLM provider
	LLMProvider string `json:"llm_provider,omitempty"`
	LLMAPIKey   string `json:"llm_api_key,omitempty"`
	LLMModel    string `json:"llm_model,omitempty"`
	LLMEndpoint string `json:"llm_endpoint,omitempty"`
}

// ValidateBucketRequest represents a request to validate S3 bucket accessibility.
type ValidateBucketRequest struct {
	Bucket string `json:"bucket"`
	Region string `json:"region"`
}

// ValidationResult represents the result of a bucket validation check.
type ValidationResult struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// CredentialStatus represents the result of credential chain resolution.
type CredentialStatus struct {
	Source   string              `json:"source"`
	Valid    bool                `json:"valid"`
	Message  string              `json:"message"`
	Attempts []CredentialAttempt `json:"attempts"`
}

// CredentialAttempt represents a single credential source resolution attempt.
type CredentialAttempt struct {
	Source  string `json:"source"`
	Success bool   `json:"success"`
	Reason  string `json:"reason"`
}

// AccountListResponse represents the list of discovered Control Tower member accounts.
type AccountListResponse struct {
	Accounts []string `json:"accounts"`
}

// SessionCredentialsRequest represents temporary SSO session credentials.
// These are set as environment variables and NOT persisted to disk.
type SessionCredentialsRequest struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

// CallerIdentityResponse represents the result of STS GetCallerIdentity.
type CallerIdentityResponse struct {
	AccountID string `json:"account_id"`
	ARN       string `json:"arn"`
	UserID    string `json:"user_id"`
}

// DetectStructureRequest represents a request to detect S3 bucket structure.
type DetectStructureRequest struct {
	Bucket string `json:"bucket"`
	Region string `json:"region"`
}

// BucketStructure represents the detected S3 bucket structure.
type BucketStructure struct {
	Mode     string   `json:"mode"` // "single" or "control_tower"
	OrgID    string   `json:"org_id"`
	Accounts []string `json:"accounts"`
	Message  string   `json:"message"`
}

// DiscoverRegionsRequest represents a request to discover available CloudTrail regions.
type DiscoverRegionsRequest struct {
	Bucket    string `json:"bucket"`
	Region    string `json:"region"`
	AccountID string `json:"account_id"`
	OrgID     string `json:"org_id"`
}

// DiscoverRegionsResponse represents the list of discovered CloudTrail regions.
type DiscoverRegionsResponse struct {
	Regions []string `json:"regions"`
	Message string   `json:"message"`
}

// VerifyLogsRequest represents a request to verify CloudTrail log existence.
type VerifyLogsRequest struct {
	Bucket    string `json:"bucket"`
	Region    string `json:"region"`
	AccountID string `json:"account_id"`
	OrgID     string `json:"org_id"`
	LogRegion string `json:"log_region"`
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date"`
}

// VerifyLogsResponse represents the result of log verification.
type VerifyLogsResponse struct {
	Found      bool   `json:"found"`
	FileCount  int    `json:"file_count"`
	SampleDate string `json:"sample_date"`
	Message    string `json:"message"`
}
