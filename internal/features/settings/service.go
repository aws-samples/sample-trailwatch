package settings

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"cloudtrail-analyzer/internal/awsutil"
	"cloudtrail-analyzer/internal/cloudtrailpath"
	"cloudtrail-analyzer/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// orgIDPattern matches AWS Organization IDs (e.g., "o-hr33oy48b4").
var orgIDPattern = regexp.MustCompile(`^o-[a-z0-9]+$`)

// Service provides settings-related business logic including bucket validation,
// credential resolution, and Control Tower account discovery.
type Service struct {
	cfg             *config.Config
	saveFn          func(*config.Config) error
	identityCheckFn func(context.Context, *config.Config) (*CallerIdentityResponse, error)
}

// NewService creates a new settings Service.
func NewService(cfg *config.Config, saveFn func(*config.Config) error) *Service {
	return &Service{cfg: cfg, saveFn: saveFn}
}

// ---------------------------------------------------------------------------
// AWS Config
// ---------------------------------------------------------------------------

// LoadAWSConfig is an exported wrapper around loadAWSConfig so peers
// (e.g., the accounts package) can build clients using whichever auth method
// the user has configured without duplicating the credential-chain logic.
func (s *Service) LoadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	return s.loadAWSConfig(ctx, region)
}

// loadAWSConfig builds an AWS config using ONLY the selected auth method.
func (s *Service) loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	return loadAWSConfigFor(ctx, region, s.cfg)
}

func loadAWSConfigFor(ctx context.Context, region string, cfg *config.Config) (aws.Config, error) {
	switch cfg.Auth.Method {
	case "session_credentials":
		// Session/STS tokens are kept in process env vars only (not in
		// config.json), so read them from there. Mirrors the contract set in
		// settings.Handler.ApplySessionCredentials.
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				os.Getenv("AWS_ACCESS_KEY_ID"),
				os.Getenv("AWS_SECRET_ACCESS_KEY"),
				os.Getenv("AWS_SESSION_TOKEN"),
			)),
		)
	case "imds":
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(awsutil.NewIMDSv2Provider()),
		)
	case "sso":
		opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
		if cfg.Auth.SSOProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Auth.SSOProfile))
		}
		return awsconfig.LoadDefaultConfig(ctx, opts...)
	case "static":
		return awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.Auth.AccessKeyID,
				cfg.Auth.SecretAccessKey,
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
		slog.Error("failed to load AWS config for bucket validation",
			"component", "cloudtrail-analyzer", "region", region, "error", err.Error())
		return &ValidationResult{
			Valid:   false,
			Message: "Failed to load AWS configuration",
			Error:   "Check credentials and region configuration",
		}, nil
	}

	client := s3.NewFromConfig(awsCfg)
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		slog.Warn("bucket validation failed",
			"component", "cloudtrail-analyzer", "bucket", bucket, "region", region, "error", err.Error())
		return &ValidationResult{
			Valid:   false,
			Message: fmt.Sprintf("Bucket %q in region %q is not accessible", bucket, region),
			Error:   classifyAWSError(err),
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
	return s.getCallerIdentity(ctx, s.cfg)
}

func (s *Service) getCallerIdentity(ctx context.Context, cfg *config.Config) (*CallerIdentityResponse, error) {
	if s.identityCheckFn != nil {
		return s.identityCheckFn(ctx, cfg)
	}

	region := cfg.S3.Region
	if region == "" {
		region = "us-east-1"
	}

	awsCfg, err := loadAWSConfigFor(ctx, region, cfg)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	return getCallerIdentityWithAWSConfig(ctx, awsCfg)
}

func getCallerIdentityWithAWSConfig(ctx context.Context, awsCfg aws.Config) (*CallerIdentityResponse, error) {
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

// ValidateSessionCredentials checks supplied temporary credentials against STS
// without publishing them to the process environment.
func (s *Service) ValidateSessionCredentials(
	ctx context.Context,
	accessKeyID, secretAccessKey, sessionToken string,
) (*CallerIdentityResponse, error) {
	region := s.cfg.S3.Region
	if region == "" {
		region = "us-east-1"
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			accessKeyID,
			secretAccessKey,
			sessionToken,
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return getCallerIdentityWithAWSConfig(ctx, awsCfg)
}

// ---------------------------------------------------------------------------
// Organization Account Discovery
// ---------------------------------------------------------------------------

// ListControlTowerAccounts discovers member accounts across supported
// Organizations and Control Tower prefix layouts.
func (s *Service) ListControlTowerAccounts(ctx context.Context, bucket, region string) ([]string, error) {
	awsCfg, err := s.loadAWSConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	prefixes := cloudtrailpath.AccountDiscoveryPrefixes(s.cfg.S3.OrgID)
	accounts, err := s.listAccountsAtFirstPopulatedPrefix(ctx, client, bucket, prefixes)
	if err != nil {
		return nil, err
	}

	slog.Info("discovered accounts",
		"component", "cloudtrail-analyzer",
		"bucket", bucket,
		"prefixes", prefixes,
		"count", len(accounts),
	)

	return accounts, nil
}

// ---------------------------------------------------------------------------
// Bucket Structure Detection
// ---------------------------------------------------------------------------

// DetectBucketStructure determines whether the bucket contains a single
// account, a standard AWS Organizations trail, or a Control Tower layout.
//
// Supported multi-account layouts include both a root organization prefix:
//
//	{bucket}/o-hr33oy48b4/AWSLogs/{account_id}/CloudTrail/...
//
// and the standard AWS Organizations trail layout:
//
//	{bucket}/AWSLogs/o-hr33oy48b4/{account_id}/CloudTrail/...
//
// Single-account buckets have AWSLogs/ at the root:
//
//	{bucket}/AWSLogs/{account_id}/CloudTrail/...
func (s *Service) DetectBucketStructure(ctx context.Context, bucket, region string) (*BucketStructure, error) {
	awsCfg, err := s.loadAWSConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	rootEntries, err := s.listChildNames(ctx, client, bucket, "")
	if err != nil {
		return nil, fmt.Errorf("listing bucket root: %w", err)
	}

	if len(rootEntries) == 0 {
		return nil, fmt.Errorf("no prefixes found at bucket root in %q", bucket)
	}

	var rootOrgIDs []string
	hasAWSLogs := false
	for _, entry := range rootEntries {
		if strings.HasPrefix(entry, "o-") && orgIDPattern.MatchString(entry) {
			rootOrgIDs = append(rootOrgIDs, entry)
		}
		if entry == "AWSLogs" {
			hasAWSLogs = true
		}
	}

	sort.Strings(rootOrgIDs)
	for _, orgID := range rootOrgIDs {
		accounts, err := s.listOrganizationAccounts(ctx, client, bucket, orgID)
		if err != nil {
			return nil, fmt.Errorf("listing accounts under org %s: %w", orgID, err)
		}
		if len(accounts) > 0 {
			return organizationBucketStructure(bucket, orgID, accounts, "Control Tower")
		}
	}

	if hasAWSLogs {
		children, err := s.listChildNames(ctx, client, bucket, "AWSLogs/")
		if err != nil {
			return nil, fmt.Errorf("listing prefixes under AWSLogs/: %w", err)
		}
		var nestedOrgIDs []string
		for _, child := range children {
			if orgIDPattern.MatchString(child) {
				nestedOrgIDs = append(nestedOrgIDs, child)
			}
		}
		sort.Strings(nestedOrgIDs)
		for _, orgID := range nestedOrgIDs {
			accounts, err := s.listAccountsAtPrefix(ctx, client, bucket, fmt.Sprintf("AWSLogs/%s/", orgID))
			if err != nil {
				return nil, fmt.Errorf("listing organization accounts under AWSLogs/%s/: %w", orgID, err)
			}
			if len(accounts) > 0 {
				return organizationBucketStructure(bucket, orgID, accounts, "AWS Organizations trail")
			}
		}

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

	return nil, fmt.Errorf("unrecognized bucket structure — root entries are %q (expected an org ID starting with o- or an AWSLogs/ prefix)", rootEntries)
}

func organizationBucketStructure(bucket, orgID string, accounts []string, layout string) (*BucketStructure, error) {
	slog.Info("detected multi-account CloudTrail structure",
		"component", "cloudtrail-analyzer",
		"bucket", bucket,
		"layout", layout,
		"org_id", orgID,
		"account_count", len(accounts),
	)
	return &BucketStructure{
		Mode:     "control_tower",
		OrgID:    orgID,
		Accounts: accounts,
		Message:  fmt.Sprintf("%s structure detected (org: %s, %d member accounts)", layout, orgID, len(accounts)),
	}, nil
}

func (s *Service) listOrganizationAccounts(
	ctx context.Context,
	client s3.ListObjectsV2APIClient,
	bucket, orgID string,
) ([]string, error) {
	return s.listAccountsAtFirstPopulatedPrefix(
		ctx,
		client,
		bucket,
		cloudtrailpath.AccountDiscoveryPrefixes(orgID),
	)
}

func (s *Service) listAccountsAtFirstPopulatedPrefix(
	ctx context.Context,
	client s3.ListObjectsV2APIClient,
	bucket string,
	prefixes []string,
) ([]string, error) {
	var firstErr error
	listedCandidate := false
	for _, prefix := range prefixes {
		accounts, err := s.listAccountsAtPrefix(ctx, client, bucket, prefix)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		listedCandidate = true
		if len(accounts) == 0 {
			continue
		}
		seen := make(map[string]struct{}, len(accounts))
		for _, account := range accounts {
			seen[account] = struct{}{}
		}
		return sortedKeys(seen), nil
	}
	if !listedCandidate && firstErr != nil {
		return nil, firstErr
	}
	return []string{}, nil
}

func (s *Service) listChildNames(ctx context.Context, client s3.ListObjectsV2APIClient, bucket, prefix string) ([]string, error) {
	var names []string
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing S3 prefixes at %s: %w", prefix, err)
		}
		for _, cp := range page.CommonPrefixes {
			trimmed := strings.TrimPrefix(aws.ToString(cp.Prefix), prefix)
			if name := strings.TrimSuffix(trimmed, "/"); name != "" {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

// listAccountsAtPrefix lists 12-digit account IDs under a given S3 prefix.
func (s *Service) listAccountsAtPrefix(ctx context.Context, client s3.ListObjectsV2APIClient, bucket, prefix string) ([]string, error) {
	// Follow the continuation token so orgs with many member accounts are not
	// silently truncated to the first page of results.
	var accounts []string
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing S3 prefixes at %s: %w", prefix, err)
		}
		for _, cp := range page.CommonPrefixes {
			if cp.Prefix == nil {
				continue
			}
			trimmed := strings.TrimPrefix(*cp.Prefix, prefix)
			parts := strings.Split(trimmed, "/")
			if len(parts) > 0 && len(parts[0]) == 12 && isNumeric(parts[0]) {
				accounts = append(accounts, parts[0])
			}
		}
	}

	return accounts, nil
}

// ---------------------------------------------------------------------------
// Region Discovery
// ---------------------------------------------------------------------------

// DiscoverRegions lists available CloudTrail regions for a given account.
//
// Multi-account: one of the supported organization account prefixes.
// Single:        AWSLogs/{accountID}/CloudTrail/
func (s *Service) DiscoverRegions(ctx context.Context, bucket, region, accountID, orgID string) (*DiscoverRegionsResponse, error) {
	awsCfg, err := s.loadAWSConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	// Page through all region prefixes; an account with CloudTrail enabled in
	// many regions can return more than one page of CommonPrefixes.
	mode := "single"
	if orgID != "" {
		mode = cloudtrailpath.MultiAccountMode
	}
	var firstErr error
	listedCandidate := false
	for _, prefix := range cloudtrailpath.CloudTrailPrefixes(mode, orgID, accountID) {
		regions, err := s.listChildNames(ctx, client, bucket, prefix)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("listing regions at %s: %w", prefix, err)
			}
			continue
		}
		listedCandidate = true
		if len(regions) == 0 {
			continue
		}
		seen := make(map[string]struct{}, len(regions))
		for _, region := range regions {
			seen[region] = struct{}{}
		}
		regions = sortedKeys(seen)
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
	if !listedCandidate && firstErr != nil {
		return nil, firstErr
	}

	return &DiscoverRegionsResponse{
		Regions: []string{},
		Message: "Found 0 regions with CloudTrail logs",
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

	mode := "single"
	if req.OrgID != "" {
		mode = cloudtrailpath.MultiAccountMode
	}
	fileCount := 0
	sampleKey := ""
	var firstErr error
	listedCandidate := false
	for _, prefix := range cloudtrailpath.DatePrefixes(mode, req.OrgID, req.AccountID, req.LogRegion, sampleDate) {
		count, key, err := findCloudTrailLogObjects(ctx, client, req.Bucket, prefix)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("listing objects at %s: %w", prefix, err)
			}
			continue
		}
		listedCandidate = true
		if count > 0 {
			fileCount = count
			sampleKey = key
			break
		}
	}
	if !listedCandidate && firstErr != nil {
		return nil, firstErr
	}

	if fileCount == 0 {
		return &VerifyLogsResponse{
			Found:      false,
			FileCount:  0,
			SampleDate: req.StartDate,
			Message:    fmt.Sprintf("No log files found for %s in %s on %s", req.AccountID, req.LogRegion, req.StartDate),
		}, nil
	}

	// Listing proves the prefix exists, but not that the caller can decrypt an
	// SSE-KMS object. Read one byte so setup fails before a sync is started.
	output, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(req.Bucket),
		Key:    aws.String(sampleKey),
		Range:  aws.String("bytes=0-0"),
	})
	if err != nil {
		return nil, fmt.Errorf(
			"sample log is not readable; credentials need s3:GetObject and, for SSE-KMS logs, kms:Decrypt: %w",
			err,
		)
	}
	if output.Body != nil {
		_ = output.Body.Close()
	}

	return &VerifyLogsResponse{
		Found:      true,
		FileCount:  fileCount,
		SampleDate: req.StartDate,
		Message:    fmt.Sprintf("Found and confirmed read access to %d log files for %s in %s on %s", fileCount, req.AccountID, req.LogRegion, req.StartDate),
	}, nil
}

func findCloudTrailLogObjects(
	ctx context.Context,
	client s3.ListObjectsV2APIClient,
	bucket, prefix string,
) (int, string, error) {
	count := 0
	sampleKey := ""
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return 0, "", err
		}
		for _, object := range page.Contents {
			key := aws.ToString(object.Key)
			if !strings.HasSuffix(key, ".json.gz") {
				continue
			}
			if sampleKey == "" {
				sampleKey = key
			}
			count++
		}
	}
	return count, sampleKey, nil
}

func verifyLogsFailureMessage(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "kms:decrypt"),
		strings.Contains(message, "kms accessdenied"),
		strings.Contains(message, "kms access denied"):
		return "A log was found but cannot be decrypted. Grant kms:Decrypt on the bucket's KMS key."
	case strings.Contains(message, "s3:getobject"):
		return "A log was found but cannot be read. Grant s3:GetObject on the selected log prefix."
	case strings.Contains(message, "listing objects"),
		strings.Contains(message, "listobjectsv2"):
		return "Log objects could not be listed. Grant s3:ListBucket for the selected log prefix."
	default:
		return "Unable to verify sample log access. Check S3 and KMS permissions in the server log."
	}
}

// classifyAWSError maps an AWS SDK error to a client-safe description.
// Used in ValidationResult.Error fields that are returned in HTTP 200 bodies.
func classifyAWSError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "accessdenied"), strings.Contains(msg, "access denied"):
		return "Access denied. Check IAM permissions and bucket policy."
	case strings.Contains(msg, "nosuchbucket"):
		return "Bucket does not exist or is not accessible."
	case strings.Contains(msg, "expiredtoken"), strings.Contains(msg, "expired"):
		return "Credentials have expired. Refresh in Settings."
	case strings.Contains(msg, "throttl"), strings.Contains(msg, "rate exceeded"):
		return "Request was throttled. Try again shortly."
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "connection refused"):
		return "Could not reach AWS. Check network connectivity."
	default:
		return "An AWS error occurred. Check server logs for details."
	}
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
		if _, err := s.getCallerIdentity(ctx, cfg); err != nil {
			attempt.Success = false
			attempt.Reason = fmt.Sprintf("Credentials resolved locally but STS rejected them: %s", err.Error())
		}
	}

	if attempt.Success {
		return &CredentialStatus{
			Source:   cfg.Auth.Method,
			Valid:    true,
			Message:  fmt.Sprintf("Credentials verified with STS via %s", cfg.Auth.Method),
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
	provider := awsutil.NewIMDSv2Provider()
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

// trySessionCredentials validates session credentials from the process
// environment. Session/STS tokens are intentionally not persisted to
// config.json (they are short-lived and writing them to disk extends their
// lifetime past their useful window), so the source of truth is the env vars
// that ApplySessionCredentials sets.
func (s *Service) trySessionCredentials(ctx context.Context) CredentialAttempt {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	token := os.Getenv("AWS_SESSION_TOKEN")

	if accessKey == "" || secretKey == "" || token == "" {
		return CredentialAttempt{
			Source:  "session_credentials",
			Success: false,
			Reason:  "Session credentials not applied to environment yet — paste fresh STS credentials via the Credentials view (they are kept in-process only, lost on restart)",
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
// Bedrock Model Discovery
// ---------------------------------------------------------------------------

// ListBedrockModels returns Anthropic text-generation models available in the
// given region. BedrockProvider sends Anthropic's native request schema, so
// advertising models from other providers would create configurations that
// cannot be invoked by this application. Two AWS calls are merged:
//
//  1. ListFoundationModels — direct on-demand-eligible models. These show
//     in the picker without a CRIS badge.
//  2. ListInferenceProfiles — Cross-Region Inference (CRIS) profiles, such
//     as "us.anthropic.claude-opus-4-20250514-v1:0". These models cannot be
//     invoked on-demand and require the responder to acknowledge the
//     cross-region data-residency notice before selecting them.
//
// The earlier version of this function only called ListFoundationModels, so
// users on accounts where Opus / certain Sonnet variants are CRIS-only saw
// no usable model in the picker.
func (s *Service) ListBedrockModels(ctx context.Context, region string) (*ListBedrockModelsResponse, error) {
	if region == "" {
		region = "us-east-1"
	}

	awsCfg, err := s.loadAWSConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config for region %s: %w", region, err)
	}

	client := bedrock.NewFromConfig(awsCfg)

	output, err := client.ListFoundationModels(ctx, &bedrock.ListFoundationModelsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing Bedrock models in %s: %w", region, err)
	}

	models := make([]BedrockModel, 0)
	for _, m := range output.ModelSummaries {
		modelID := aws.ToString(m.ModelId)
		modelName := aws.ToString(m.ModelName)
		providerName := aws.ToString(m.ProviderName)
		if !supportsAnthropicNativeSchema(providerName) {
			continue
		}

		// Only include text-generating models useful for SQL generation
		hasTextOutput := false
		var outputModes []string
		for _, mode := range m.OutputModalities {
			outputModes = append(outputModes, string(mode))
			if string(mode) == "TEXT" {
				hasTextOutput = true
			}
		}
		if !hasTextOutput {
			continue
		}

		var inputModes []string
		for _, mode := range m.InputModalities {
			inputModes = append(inputModes, string(mode))
		}

		// Detect CRIS: models with region prefix like "us.", "eu.", "ap."
		isCRIS := false
		crisNote := ""
		if len(modelID) > 3 && modelID[2] == '.' {
			prefix := modelID[:2]
			crisRegions := map[string]string{
				"us": "US regions (us-east-1, us-west-2)",
				"eu": "EU regions (eu-west-1, eu-central-1)",
				"ap": "AP regions (ap-southeast-1, ap-northeast-1)",
			}
			if regionDesc, ok := crisRegions[prefix]; ok {
				isCRIS = true
				crisNote = fmt.Sprintf("Cross-Region Inference: requests may be routed to %s for processing", regionDesc)
			}
		}

		models = append(models, BedrockModel{
			ModelID:     modelID,
			ModelName:   modelName,
			Provider:    providerName,
			InputModes:  inputModes,
			OutputModes: outputModes,
			IsCRIS:      isCRIS,
			CRISNote:    crisNote,
		})
	}

	// Append CRIS profiles. These are NOT returned by ListFoundationModels;
	// without this call, accounts whose only access to Opus/Sonnet 4.x is via
	// inference profiles would see an empty or insufficient picker. We build
	// a set of foundation model IDs we already added so a profile that
	// happens to share a base model name does not produce a duplicate row.
	seen := map[string]struct{}{}
	for _, m := range models {
		seen[m.ModelID] = struct{}{}
	}
	profilesCount := 0
	// Page through the inference profiles: ListInferenceProfiles returns a
	// NextToken when there are more profiles than fit in one response, so a CRIS
	// model on page 2+ (e.g. Opus when an account has many profiles) would
	// otherwise vanish from the picker. We follow the token until it is empty.
	var nextToken *string
	for {
		profilesOut, perr := client.ListInferenceProfiles(ctx, &bedrock.ListInferenceProfilesInput{
			NextToken: nextToken,
		})
		if perr != nil {
			// Profiles call may fail with AccessDeniedException on tightly-scoped
			// roles. Log once and continue with whatever foundation models we
			// already collected — better to show a partial list than an error.
			slog.Warn("list inference profiles failed; CRIS variants may be missing from picker",
				"component", "cloudtrail-analyzer",
				"region", region,
				"error", perr.Error(),
			)
			break
		}
		for _, p := range profilesOut.InferenceProfileSummaries {
			pid := aws.ToString(p.InferenceProfileId)
			if pid == "" {
				continue
			}
			if _, dup := seen[pid]; dup {
				continue
			}
			providerName := providerFromProfileID(pid)
			if !supportsAnthropicNativeSchema(providerName) {
				continue
			}
			pname := aws.ToString(p.InferenceProfileName)
			if pname == "" {
				pname = pid
			}
			models = append(models, BedrockModel{
				ModelID:     pid,
				ModelName:   pname,
				Provider:    providerName,
				InputModes:  []string{"TEXT"},
				OutputModes: []string{"TEXT"},
				IsCRIS:      true,
				CRISNote:    "Cross-Region Inference profile: routes invocation across regions for higher availability",
			})
			seen[pid] = struct{}{}
			profilesCount++
		}
		if profilesOut.NextToken == nil || aws.ToString(profilesOut.NextToken) == "" {
			break
		}
		nextToken = profilesOut.NextToken
	}

	slog.Info("listed Bedrock models",
		"component", "cloudtrail-analyzer",
		"region", region,
		"total_returned", len(output.ModelSummaries),
		"text_models", len(models),
		"cris_profiles", profilesCount,
	)

	return &ListBedrockModelsResponse{
		Region: region,
		Models: models,
	}, nil
}

func supportsAnthropicNativeSchema(providerName string) bool {
	return strings.EqualFold(strings.TrimSpace(providerName), "Anthropic")
}

// providerFromProfileID returns the model provider name guessed from the
// inference-profile ID. Profile IDs follow patterns like
// "us.anthropic.claude-opus-4-20250514-v1:0" — the second dot-segment is
// the provider. Falls back to "AWS" if the shape doesn't match.
func providerFromProfileID(pid string) string {
	parts := strings.Split(pid, ".")
	if len(parts) >= 2 {
		switch parts[1] {
		case "anthropic":
			return "Anthropic"
		case "amazon":
			return "Amazon"
		case "meta":
			return "Meta"
		case "ai21":
			return "AI21"
		case "cohere":
			return "Cohere"
		case "mistral":
			return "Mistral"
		}
	}
	return "AWS"
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
// Multi-account: the first supported organization layout.
// Single:        AWSLogs/{accountID}/CloudTrail/{region}/{YYYY}/{MM}/{DD}/
func ConstructS3Prefix(mode, orgID, accountID, region string, date time.Time) string {
	return ConstructS3Prefixes(mode, orgID, accountID, region, date)[0]
}

// ConstructS3Prefixes returns all supported candidate prefixes for a date.
func ConstructS3Prefixes(mode, orgID, accountID, region string, date time.Time) []string {
	return cloudtrailpath.DatePrefixes(mode, orgID, accountID, region, date)
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

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}
