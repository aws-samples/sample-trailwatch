package settings

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"cloudtrail-analyzer/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// orgIDPattern matches AWS Organization IDs (e.g., "o-hr33oy48b4").
var orgIDPattern = regexp.MustCompile(`^o-[a-z0-9]+$`)

// Service provides settings-related business logic including bucket validation,
// credential resolution, and Control Tower account discovery.
type Service struct {
	cfg    *config.Config
	saveFn func(*config.Config) error
}

// NewService creates a new settings Service.
func NewService(cfg *config.Config, saveFn func(*config.Config) error) *Service {
	return &Service{cfg: cfg, saveFn: saveFn}
}

// ---------------------------------------------------------------------------
// AWS Config
// ---------------------------------------------------------------------------

// loadAWSConfig builds an AWS config using ONLY the selected auth method.
func (s *Service) loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	switch s.cfg.Auth.Method {
	case "session_credentials":
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				s.cfg.Auth.AccessKeyID,
				s.cfg.Auth.SecretAccessKey,
				s.cfg.Auth.SessionToken,
			)),
		)
	case "imds":
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(ec2rolecreds.New()),
		)
	case "sso":
		opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
		if s.cfg.Auth.SSOProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(s.cfg.Auth.SSOProfile))
		}
		return awsconfig.LoadDefaultConfig(ctx, opts...)
	case "static":
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				s.cfg.Auth.AccessKeyID,
				s.cfg.Auth.SecretAccessKey,
				"",
			)),
		)
	default:
		return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	}
}

// ---------------------------------------------------------------------------
// Bucket Validation
// ---------------------------------------------------------------------------

// ValidateBucket performs a HeadBucket call to verify S3 bucket accessibility.
func (s *Service) ValidateBucket(ctx context.Context, bucket, region string) (*ValidationResult, error) {
	awsCfg, err := s.loadAWSConfig(ctx, region)
	if err != nil {
		return &ValidationResult{
			Valid:   false,
			Message: "Failed to load AWS configuration",
			Error:   err.Error(),
		}, nil
	}

	client := s3.NewFromConfig(awsCfg)
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return &ValidationResult{
			Valid:   false,
			Message: fmt.Sprintf("Bucket %q in region %q is not accessible", bucket, region),
			Error:   err.Error(),
		}, nil
	}

	return &ValidationResult{
		Valid:   true,
		Message: fmt.Sprintf("Bucket %q in region %q is accessible", bucket, region),
	}, nil
}

// ---------------------------------------------------------------------------
// STS Caller Identity
// ---------------------------------------------------------------------------

// GetCallerIdentity calls STS GetCallerIdentity using the active credentials.
func (s *Service) GetCallerIdentity(ctx context.Context) (*CallerIdentityResponse, error) {
	region := s.cfg.S3.Region
	if region == "" {
		region = "us-east-1"
	}

	awsCfg, err := s.loadAWSConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := sts.NewFromConfig(awsCfg)
	output, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("STS GetCallerIdentity: %w", err)
	}

	return &CallerIdentityResponse{
		AccountID: aws.ToString(output.Account),
		ARN:       aws.ToString(output.Arn),
		UserID:    aws.ToString(output.UserId),
	}, nil
}

// ---------------------------------------------------------------------------
// Control Tower Account Discovery
// ---------------------------------------------------------------------------

// ListControlTowerAccounts discovers member accounts by listing S3 prefixes.
//
// Control Tower path: {org_id}/AWSLogs/{account_id}/...
// Single account path: AWSLogs/{account_id}/...
func (s *Service) ListControlTowerAccounts(ctx context.Context, bucket, region string) ([]string, error) {
	awsCfg, err := s.loadAWSConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	// Control Tower: org_id is at bucket root, BEFORE AWSLogs/
	var prefix string
	if s.cfg.S3.OrgID != "" {
		prefix = fmt.Sprintf("%s/AWSLogs/%s/", s.cfg.S3.OrgID, s.cfg.S3.OrgID)
	} else {
		prefix = "AWSLogs/"
	}

	output, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
		MaxKeys:   aws.Int32(100),
	})
	if err != nil {
		return nil, fmt.Errorf("listing S3 prefixes at %s: %w", prefix, err)
	}

	var accounts []string
	for _, cp := range output.CommonPrefixes {
		if cp.Prefix == nil {
			continue
		}
		trimmed := strings.TrimPrefix(*cp.Prefix, prefix)
		parts := strings.Split(trimmed, "/")
		if len(parts) > 0 && len(parts[0]) == 12 && isNumeric(parts[0]) {
			accounts = append(accounts, parts[0])
		}
	}

	slog.Info("discovered accounts",
		"component", "cloudtrail-analyzer",
		"bucket", bucket,
		"prefix", prefix,
		"count", len(accounts),
	)

	return accounts, nil
}

// ---------------------------------------------------------------------------
// Bucket Structure Detection
// ---------------------------------------------------------------------------

// DetectBucketStructure lists the bucket root to determine if it uses a
// single-account or Control Tower (multi-account) structure.
//
// Control Tower buckets have the org_id at the ROOT level (before AWSLogs/):
//
//	{bucket}/o-hr33oy48b4/AWSLogs/{account_id}/CloudTrail/...
//
// Single account buckets have AWSLogs/ at the root:
//
//	{bucket}/AWSLogs/{account_id}/CloudTrail/...
func (s *Service) DetectBucketStructure(ctx context.Context, bucket, region string) (*BucketStructure, error) {
	awsCfg, err := s.loadAWSConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	// List at bucket root with delimiter to see top-level prefixes
	output, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(""),
		Delimiter: aws.String("/"),
		MaxKeys:   aws.Int32(20),
	})
	if err != nil {
		return nil, fmt.Errorf("listing bucket root: %w", err)
	}

	if len(output.CommonPrefixes) == 0 {
		return nil, fmt.Errorf("no prefixes found at bucket root in %q", bucket)
	}

	// Check the first CommonPrefix to determine structure
	firstPrefix := aws.ToString(output.CommonPrefixes[0].Prefix)
	firstEntry := strings.TrimSuffix(firstPrefix, "/")

	// Control Tower: root entry starts with "o-" (org ID)
	if strings.HasPrefix(firstEntry, "o-") && orgIDPattern.MatchString(firstEntry) {
		orgID := firstEntry

		// List accounts at {org_id}/AWSLogs/{org_id}/
		accounts, err := s.listAccountsAtPrefix(ctx, client, bucket, fmt.Sprintf("%s/AWSLogs/%s/", orgID, orgID))
		if err != nil {
			return nil, fmt.Errorf("listing accounts under org %s: %w", orgID, err)
		}

		slog.Info("detected Control Tower structure",
			"component", "cloudtrail-analyzer",
			"bucket", bucket,
			"org_id", orgID,
			"account_count", len(accounts),
		)

		return &BucketStructure{
			Mode:     "control_tower",
			OrgID:    orgID,
			Accounts: accounts,
			Message:  fmt.Sprintf("Control Tower structure detected (org: %s, %d member accounts)", orgID, len(accounts)),
		}, nil
	}

	// Single account: root entry is "AWSLogs/"
	if firstEntry == "AWSLogs" {
		accounts, err := s.listAccountsAtPrefix(ctx, client, bucket, "AWSLogs/")
		if err != nil {
			return nil, fmt.Errorf("listing accounts under AWSLogs/: %w", err)
		}

		slog.Info("detected single account structure",
			"component", "cloudtrail-analyzer",
			"bucket", bucket,
			"account_count", len(accounts),
		)

		return &BucketStructure{
			Mode:     "single",
			OrgID:    "",
			Accounts: accounts,
			Message:  "Single account structure detected",
		}, nil
	}

	return nil, fmt.Errorf("unrecognized bucket structure — root entry is %q (expected org ID starting with o- or AWSLogs/)", firstEntry)
}

// listAccountsAtPrefix lists 12-digit account IDs under a given S3 prefix.
func (s *Service) listAccountsAtPrefix(ctx context.Context, client *s3.Client, bucket, prefix string) ([]string, error) {
	output, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
		MaxKeys:   aws.Int32(100),
	})
	if err != nil {
		return nil, fmt.Errorf("listing S3 prefixes at %s: %w", prefix, err)
	}

	var accounts []string
	for _, cp := range output.CommonPrefixes {
		if cp.Prefix == nil {
			continue
		}
		trimmed := strings.TrimPrefix(*cp.Prefix, prefix)
		parts := strings.Split(trimmed, "/")
		if len(parts) > 0 && len(parts[0]) == 12 && isNumeric(parts[0]) {
			accounts = append(accounts, parts[0])
		}
	}

	return accounts, nil
}

// ---------------------------------------------------------------------------
// Region Discovery
// ---------------------------------------------------------------------------

// DiscoverRegions lists available CloudTrail regions for a given account.
//
// Control Tower: {orgID}/AWSLogs/{accountID}/CloudTrail/
// Single:        AWSLogs/{accountID}/CloudTrail/
func (s *Service) DiscoverRegions(ctx context.Context, bucket, region, accountID, orgID string) (*DiscoverRegionsResponse, error) {
	awsCfg, err := s.loadAWSConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	var prefix string
	if orgID != "" {
		prefix = fmt.Sprintf("%s/AWSLogs/%s/%s/CloudTrail/", orgID, orgID, accountID)
	} else {
		prefix = fmt.Sprintf("AWSLogs/%s/CloudTrail/", accountID)
	}

	output, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
		MaxKeys:   aws.Int32(50),
	})
	if err != nil {
		return nil, fmt.Errorf("listing regions at %s: %w", prefix, err)
	}

	var regions []string
	for _, cp := range output.CommonPrefixes {
		if cp.Prefix == nil {
			continue
		}
		trimmed := strings.TrimPrefix(*cp.Prefix, prefix)
		parts := strings.Split(trimmed, "/")
		if len(parts) > 0 && parts[0] != "" {
			regions = append(regions, parts[0])
		}
	}

	slog.Info("discovered CloudTrail regions",
		"component", "cloudtrail-analyzer",
		"bucket", bucket,
		"account_id", accountID,
		"region_count", len(regions),
	)

	return &DiscoverRegionsResponse{
		Regions: regions,
		Message: fmt.Sprintf("Found %d regions with CloudTrail logs", len(regions)),
	}, nil
}

// ---------------------------------------------------------------------------
// Log Verification
// ---------------------------------------------------------------------------

// VerifyLogs checks if CloudTrail log files exist for the specified parameters.
// Uses start_date as the sample date.
func (s *Service) VerifyLogs(ctx context.Context, req *VerifyLogsRequest) (*VerifyLogsResponse, error) {
	awsCfg, err := s.loadAWSConfig(ctx, req.Region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	sampleDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return nil, fmt.Errorf("invalid start_date: %w", err)
	}

	// Build path for sample date
	dateStr := sampleDate.Format("2006/01/02")
	var prefix string
	if req.OrgID != "" {
		prefix = fmt.Sprintf("%s/AWSLogs/%s/%s/CloudTrail/%s/%s/",
			req.OrgID, req.OrgID, req.AccountID, req.LogRegion, dateStr)
	} else {
		prefix = fmt.Sprintf("AWSLogs/%s/CloudTrail/%s/%s/",
			req.AccountID, req.LogRegion, dateStr)
	}

	output, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(req.Bucket),
		Prefix: aws.String(prefix),
	})
	if err != nil {
		return nil, fmt.Errorf("listing objects at %s: %w", prefix, err)
	}

	fileCount := len(output.Contents)

	if fileCount == 0 {
		return &VerifyLogsResponse{
			Found:      false,
			FileCount:  0,
			SampleDate: req.StartDate,
			Message:    fmt.Sprintf("No log files found for %s in %s on %s", req.AccountID, req.LogRegion, req.StartDate),
		}, nil
	}

	return &VerifyLogsResponse{
		Found:      true,
		FileCount:  fileCount,
		SampleDate: req.StartDate,
		Message:    fmt.Sprintf("Found %d log files for %s in %s on %s", fileCount, req.AccountID, req.LogRegion, req.StartDate),
	}, nil
}

// ---------------------------------------------------------------------------
// Credential Resolution
// ---------------------------------------------------------------------------

// ResolveCredentials tests the configured auth method.
func (s *Service) ResolveCredentials(ctx context.Context, cfg *config.Config) (*CredentialStatus, error) {
	var attempt CredentialAttempt

	switch cfg.Auth.Method {
	case "imds":
		attempt = s.tryIMDS(ctx)
	case "session_credentials":
		attempt = s.trySessionCredentials(ctx)
	case "sso":
		attempt = s.trySSO(ctx, cfg.Auth.SSOProfile)
	case "static":
		attempt = s.tryStatic(ctx, cfg)
	default:
		return &CredentialStatus{
			Source:   "",
			Valid:    false,
			Message:  fmt.Sprintf("Unknown auth method: %s", cfg.Auth.Method),
			Attempts: nil,
		}, nil
	}

	if attempt.Success {
		return &CredentialStatus{
			Source:   cfg.Auth.Method,
			Valid:    true,
			Message:  fmt.Sprintf("Credentials active via %s", cfg.Auth.Method),
			Attempts: []CredentialAttempt{attempt},
		}, nil
	}

	return &CredentialStatus{
		Source:   "",
		Valid:    false,
		Message:  fmt.Sprintf("%s credentials failed", cfg.Auth.Method),
		Attempts: []CredentialAttempt{attempt},
	}, nil
}

// tryIMDS attempts to retrieve credentials from EC2 Instance Metadata Service v2.
func (s *Service) tryIMDS(ctx context.Context) CredentialAttempt {
	provider := ec2rolecreds.New()
	_, err := provider.Retrieve(ctx)
	if err != nil {
		return CredentialAttempt{
			Source:  "imds",
			Success: false,
			Reason:  fmt.Sprintf("IMDS v2 unavailable: %s", err.Error()),
		}
	}
	return CredentialAttempt{
		Source:  "imds",
		Success: true,
		Reason:  "IMDS v2 credentials retrieved successfully",
	}
}

// trySessionCredentials validates session credentials from the config struct.
func (s *Service) trySessionCredentials(ctx context.Context) CredentialAttempt {
	accessKey := s.cfg.Auth.AccessKeyID
	secretKey := s.cfg.Auth.SecretAccessKey
	token := s.cfg.Auth.SessionToken

	if accessKey == "" || secretKey == "" || token == "" {
		return CredentialAttempt{
			Source:  "session_credentials",
			Success: false,
			Reason:  "Session credentials incomplete — access_key_id, secret_access_key, and session_token are all required",
		}
	}

	provider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, token)
	creds, err := provider.Retrieve(ctx)
	if err != nil || creds.AccessKeyID == "" {
		return CredentialAttempt{
			Source:  "session_credentials",
			Success: false,
			Reason:  fmt.Sprintf("Session credentials invalid: %v", err),
		}
	}

	return CredentialAttempt{
		Source:  "session_credentials",
		Success: true,
		Reason:  fmt.Sprintf("Session credentials active (key: %s...)", accessKey[:4]),
	}
}

// trySSO attempts to resolve credentials via shared config profile.
func (s *Service) trySSO(ctx context.Context, profile string) CredentialAttempt {
	opts := []func(*awsconfig.LoadOptions) error{}
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return CredentialAttempt{
			Source:  "sso",
			Success: false,
			Reason:  fmt.Sprintf("Failed to load config with profile %q: %s", profile, err.Error()),
		}
	}

	creds, err := awsCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return CredentialAttempt{
			Source:  "sso",
			Success: false,
			Reason:  fmt.Sprintf("SSO credentials failed: %s", err.Error()),
		}
	}

	if creds.AccessKeyID == "" {
		return CredentialAttempt{
			Source:  "sso",
			Success: false,
			Reason:  "SSO returned empty credentials",
		}
	}

	return CredentialAttempt{
		Source:  "sso",
		Success: true,
		Reason:  fmt.Sprintf("SSO credentials active (source: %s)", creds.Source),
	}
}

// tryStatic attempts to use static access keys from the config.
func (s *Service) tryStatic(ctx context.Context, cfg *config.Config) CredentialAttempt {
	if cfg.Auth.AccessKeyID == "" || cfg.Auth.SecretAccessKey == "" {
		return CredentialAttempt{
			Source:  "static",
			Success: false,
			Reason:  "No static credentials configured (access_key_id or secret_access_key missing)",
		}
	}

	provider := credentials.NewStaticCredentialsProvider(
		cfg.Auth.AccessKeyID,
		cfg.Auth.SecretAccessKey,
		"",
	)

	creds, err := provider.Retrieve(ctx)
	if err != nil || creds.AccessKeyID == "" {
		return CredentialAttempt{
			Source:  "static",
			Success: false,
			Reason:  fmt.Sprintf("Static credentials invalid: %v", err),
		}
	}

	return CredentialAttempt{
		Source:  "static",
		Success: true,
		Reason:  "Static credentials configured and valid",
	}
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// ValidateDateRange validates that start <= end and duration does not exceed 90 days.
func ValidateDateRange(startDate, endDate string) error {
	start, err := time.Parse("2006-01-02", startDate)
	if err != nil {
		return fmt.Errorf("invalid start_date format (expected YYYY-MM-DD): %w", err)
	}

	end, err := time.Parse("2006-01-02", endDate)
	if err != nil {
		return fmt.Errorf("invalid end_date format (expected YYYY-MM-DD): %w", err)
	}

	if start.After(end) {
		return fmt.Errorf("start_date (%s) must not be after end_date (%s)", startDate, endDate)
	}

	duration := end.Sub(start)
	if duration > 90*24*time.Hour {
		return fmt.Errorf("date range exceeds 90 days (got %d days)", int(duration.Hours()/24))
	}

	return nil
}

// ConstructS3Prefix builds the CloudTrail S3 prefix for a given mode, org, account, region, and date.
//
// Control Tower: {orgID}/AWSLogs/{accountID}/CloudTrail/{region}/{YYYY}/{MM}/{DD}/
// Single:        AWSLogs/{accountID}/CloudTrail/{region}/{YYYY}/{MM}/{DD}/
func ConstructS3Prefix(mode, orgID, accountID, region string, date time.Time) string {
	dateStr := date.Format("2006/01/02")

	if mode == "control_tower" && orgID != "" {
		return fmt.Sprintf("%s/AWSLogs/%s/%s/CloudTrail/%s/%s/", orgID, orgID, accountID, region, dateStr)
	}

	return fmt.Sprintf("AWSLogs/%s/CloudTrail/%s/%s/", accountID, region, dateStr)
}

// isNumeric checks if a string contains only digits.
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
