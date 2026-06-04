package nlquery

import (
	"strings"
	"testing"
)

func TestIsAWSCredEnv(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"AWS_ACCESS_KEY_ID", true},
		{"AWS_SECRET_ACCESS_KEY", true},
		{"AWS_SESSION_TOKEN", true},
		{"AWS_SECURITY_TOKEN", true},
		{"AWS_CREDENTIAL_EXPIRATION", true},
		{"AWS_PROFILE", true},
		{"AWS_WEB_IDENTITY_TOKEN_FILE", true},
		{"AWS_CONTAINER_CREDENTIALS_FULL_URI", true},
		{"AWS_SHARED_CREDENTIALS_FILE", true},
		{"aws_access_key_id", true}, // case-insensitive
		// Non-credential values must survive.
		{"AWS_REGION", false},
		{"AWS_DEFAULT_REGION", false},
		{"PATH", false},
		{"HOME", false},
		{"AWSOME_UNRELATED", false},
	}
	for _, tc := range cases {
		if got := isAWSCredEnv(tc.name); got != tc.want {
			t.Errorf("isAWSCredEnv(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestScrubbedEnvDropsAWSCreds(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "token")
	t.Setenv("AWS_REGION", "us-east-1")

	env := scrubbedEnv()
	for _, kv := range env {
		if strings.HasPrefix(strings.ToUpper(kv), "AWS_ACCESS_KEY_ID=") ||
			strings.HasPrefix(strings.ToUpper(kv), "AWS_SECRET_ACCESS_KEY=") ||
			strings.HasPrefix(strings.ToUpper(kv), "AWS_SESSION_TOKEN=") {
			t.Errorf("scrubbedEnv leaked credential var: %q", kv)
		}
	}
	// AWS_REGION (non-credential) must be preserved.
	var foundRegion bool
	for _, kv := range env {
		if kv == "AWS_REGION=us-east-1" {
			foundRegion = true
		}
	}
	if !foundRegion {
		t.Error("scrubbedEnv dropped AWS_REGION, which should be preserved")
	}
}
