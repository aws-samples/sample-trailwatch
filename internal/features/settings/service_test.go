package settings

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"cloudtrail-analyzer/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type settingsListStub struct {
	calls   []string
	outputs map[string]*s3.ListObjectsV2Output
	errs    map[string]error
}

func (s *settingsListStub) ListObjectsV2(
	_ context.Context,
	input *s3.ListObjectsV2Input,
	_ ...func(*s3.Options),
) (*s3.ListObjectsV2Output, error) {
	prefix := aws.ToString(input.Prefix)
	s.calls = append(s.calls, prefix)
	if err := s.errs[prefix]; err != nil {
		return nil, err
	}
	if output := s.outputs[prefix]; output != nil {
		return output, nil
	}
	return &s3.ListObjectsV2Output{}, nil
}

func TestResolveCredentialsRequiresSTSValidation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.Method = "static"
	cfg.Auth.AccessKeyID = "AKIAEXAMPLEKEY12345"
	cfg.Auth.SecretAccessKey = "secret"

	service := NewService(&cfg, func(*config.Config) error { return nil })
	service.identityCheckFn = func(
		context.Context, *config.Config,
	) (*CallerIdentityResponse, error) {
		return nil, errors.New("invalid client token")
	}

	status, err := service.ResolveCredentials(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("ResolveCredentials returned error: %v", err)
	}
	if status.Valid {
		t.Fatal("locally retrievable credentials must not be valid when STS rejects them")
	}
	if len(status.Attempts) != 1 || status.Attempts[0].Success {
		t.Fatalf("expected failed STS attempt, got %+v", status.Attempts)
	}
	if !strings.Contains(status.Attempts[0].Reason, "STS rejected") {
		t.Fatalf("expected actionable STS reason, got %q", status.Attempts[0].Reason)
	}
}

func TestResolveCredentialsReportsSTSVerifiedSuccess(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.Method = "static"
	cfg.Auth.AccessKeyID = "AKIAEXAMPLEKEY12345"
	cfg.Auth.SecretAccessKey = "secret"

	service := NewService(&cfg, func(*config.Config) error { return nil })
	service.identityCheckFn = func(
		context.Context, *config.Config,
	) (*CallerIdentityResponse, error) {
		return &CallerIdentityResponse{AccountID: "123456789012"}, nil
	}

	status, err := service.ResolveCredentials(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("ResolveCredentials returned error: %v", err)
	}
	if !status.Valid {
		t.Fatalf("expected STS-verified credentials, got %+v", status)
	}
	if !strings.Contains(status.Message, "verified with STS") {
		t.Fatalf("expected verification message, got %q", status.Message)
	}
}

func TestListAccountsUsesFirstPopulatedAccessibleLayout(t *testing.T) {
	cfg := config.DefaultConfig()
	service := NewService(&cfg, func(*config.Config) error { return nil })
	prefixes := []string{"standard/", "legacy-empty/", "legacy/"}
	stub := &settingsListStub{
		outputs: map[string]*s3.ListObjectsV2Output{
			prefixes[2]: {
				CommonPrefixes: []types.CommonPrefix{
					{Prefix: aws.String(prefixes[2] + "222222222222/")},
					{Prefix: aws.String(prefixes[2] + "111111111111/")},
				},
			},
		},
		errs: map[string]error{prefixes[0]: errors.New("access denied")},
	}

	accounts, err := service.listAccountsAtFirstPopulatedPrefix(
		context.Background(), stub, "bucket", prefixes,
	)
	if err != nil {
		t.Fatalf("listing accounts: %v", err)
	}
	if !slices.Equal(stub.calls, prefixes) {
		t.Fatalf("calls = %v, want %v", stub.calls, prefixes)
	}
	want := []string{"111111111111", "222222222222"}
	if !slices.Equal(accounts, want) {
		t.Fatalf("accounts = %v, want %v", accounts, want)
	}
}

func TestFindCloudTrailLogObjectsIgnoresNonLogs(t *testing.T) {
	const prefix = "AWSLogs/o-example/123456789012/CloudTrail/us-east-1/2026/07/26/"
	stub := &settingsListStub{outputs: map[string]*s3.ListObjectsV2Output{
		prefix: {
			Contents: []types.Object{
				{Key: aws.String(prefix + "event-1.json.gz")},
				{Key: aws.String(prefix + "event-2.json.gz")},
				{Key: aws.String(prefix)},
				{Key: aws.String(prefix + "README.txt")},
			},
		},
	}}

	count, sampleKey, err := findCloudTrailLogObjects(context.Background(), stub, "bucket", prefix)
	if err != nil {
		t.Fatalf("counting logs: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	if sampleKey != prefix+"event-1.json.gz" {
		t.Fatalf("sample key = %q, want first log object", sampleKey)
	}
}

func TestVerifyLogsFailureMessageRedactsAWSDetails(t *testing.T) {
	raw := errors.New("AccessDenied: arn:aws:sts::123:role/Admin cannot perform kms:Decrypt on key/secret")
	got := verifyLogsFailureMessage(raw)
	if !strings.Contains(got, "kms:Decrypt") {
		t.Fatalf("message = %q, want KMS guidance", got)
	}
	for _, secret := range []string{"arn:aws", "role/Admin", "key/secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("message leaked %q: %q", secret, got)
		}
	}
}

func TestSupportsAnthropicNativeSchema(t *testing.T) {
	t.Parallel()

	tests := []struct {
		provider string
		want     bool
	}{
		{provider: "Anthropic", want: true},
		{provider: " anthropic ", want: true},
		{provider: "Amazon", want: false},
		{provider: "Meta", want: false},
		{provider: "", want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.provider, func(t *testing.T) {
			t.Parallel()
			if got := supportsAnthropicNativeSchema(tt.provider); got != tt.want {
				t.Fatalf("supportsAnthropicNativeSchema(%q) = %v, want %v", tt.provider, got, tt.want)
			}
		})
	}
}

func TestInferenceProfileProviderFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		profileID string
		want      bool
	}{
		{profileID: "us.anthropic.claude-sonnet-4-6", want: true},
		{profileID: "global.anthropic.claude-sonnet-4-6", want: true},
		{profileID: "us.amazon.nova-pro-v1:0", want: false},
		{profileID: "us.meta.llama4-maverick-17b-instruct-v1:0", want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.profileID, func(t *testing.T) {
			t.Parallel()
			provider := providerFromProfileID(tt.profileID)
			if got := supportsAnthropicNativeSchema(provider); got != tt.want {
				t.Fatalf("profile %q resolved to %q: compatible = %v, want %v", tt.profileID, provider, got, tt.want)
			}
		})
	}
}
