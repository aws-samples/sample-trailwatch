package settings

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"cloudtrail-analyzer/internal/config"
)

const validSessionAccessKey = "ASIAEXAMPLEKEY12345"

func TestApplySessionCredentialsRejectsInvalidAccessKeyBeforeEnvironmentMutation(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ORIGINALACCESSKEY123")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "original-secret")
	t.Setenv("AWS_SESSION_TOKEN", "original-token")

	saveCalled := false
	h := NewHandler(&config.Config{}, func(*config.Config) error {
		saveCalled = true
		return nil
	})
	body := []byte(`{
		"access_key_id":"ABC",
		"secret_access_key":"replacement-secret",
		"session_token":"replacement-token"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/apply-session-credentials", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ApplySessionCredentials(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if got := os.Getenv("AWS_ACCESS_KEY_ID"); got != "ORIGINALACCESSKEY123" {
		t.Fatalf("access key environment changed on invalid input: %q", got)
	}
	if got := os.Getenv("AWS_SECRET_ACCESS_KEY"); got != "original-secret" {
		t.Fatalf("secret environment changed on invalid input: %q", got)
	}
	if got := os.Getenv("AWS_SESSION_TOKEN"); got != "original-token" {
		t.Fatalf("session token environment changed on invalid input: %q", got)
	}
	if saveCalled {
		t.Fatal("invalid credentials should not update configuration")
	}
}

func TestApplySessionCredentialsRejectsSTSFailureBeforeEnvironmentMutation(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ORIGINALACCESSKEY123")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "original-secret")
	t.Setenv("AWS_SESSION_TOKEN", "original-token")

	saveCalled := false
	h := NewHandler(&config.Config{}, func(*config.Config) error {
		saveCalled = true
		return nil
	})
	h.validateSessionCredentialsFn = func(
		context.Context, string, string, string,
	) (*CallerIdentityResponse, error) {
		return nil, errors.New("expired token")
	}

	req := httptest.NewRequest(http.MethodPost, "/apply-session-credentials", bytes.NewBufferString(
		`{"access_key_id":"`+validSessionAccessKey+`","secret_access_key":"replacement-secret","session_token":"replacement-token"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ApplySessionCredentials(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if got := os.Getenv("AWS_ACCESS_KEY_ID"); got != "ORIGINALACCESSKEY123" {
		t.Fatalf("access key environment changed after STS rejection: %q", got)
	}
	if got := os.Getenv("AWS_SECRET_ACCESS_KEY"); got != "original-secret" {
		t.Fatalf("secret environment changed after STS rejection: %q", got)
	}
	if got := os.Getenv("AWS_SESSION_TOKEN"); got != "original-token" {
		t.Fatalf("session token environment changed after STS rejection: %q", got)
	}
	if saveCalled {
		t.Fatal("rejected credentials should not update configuration")
	}
}

func TestApplySessionCredentialsRestoresEnvironmentWhenSaveFails(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ORIGINALACCESSKEY123")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "original-secret")
	t.Setenv("AWS_SESSION_TOKEN", "original-token")

	cfg := config.DefaultConfig()
	h := NewHandler(&cfg, func(*config.Config) error {
		return errors.New("disk full")
	})
	h.validateSessionCredentialsFn = func(
		context.Context, string, string, string,
	) (*CallerIdentityResponse, error) {
		return &CallerIdentityResponse{AccountID: "123456789012"}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/apply-session-credentials", bytes.NewBufferString(
		`{"access_key_id":"`+validSessionAccessKey+`","secret_access_key":"replacement-secret","session_token":"replacement-token"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ApplySessionCredentials(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	if got := os.Getenv("AWS_ACCESS_KEY_ID"); got != "ORIGINALACCESSKEY123" {
		t.Fatalf("access key environment was not restored: %q", got)
	}
	if got := os.Getenv("AWS_SECRET_ACCESS_KEY"); got != "original-secret" {
		t.Fatalf("secret environment was not restored: %q", got)
	}
	if got := os.Getenv("AWS_SESSION_TOKEN"); got != "original-token" {
		t.Fatalf("session token environment was not restored: %q", got)
	}
	if cfg.Auth.Method != "imds" {
		t.Fatalf("live config changed after failed save: %q", cfg.Auth.Method)
	}
}

func TestUpdateSettingsRejectsUnsafeLLMEndpointBeforeSave(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.LLM.Provider = "openai"
	saveCalled := false
	h := NewHandler(&cfg, func(*config.Config) error {
		saveCalled = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(
		`{"llm_endpoint":"http://169.254.169.254/latest"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.UpdateSettings(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if saveCalled {
		t.Fatal("invalid endpoint should not be persisted")
	}
	if cfg.LLM.Endpoint != "" {
		t.Fatalf("live config changed after validation failure: %q", cfg.LLM.Endpoint)
	}
}

func TestUpdateSettingsDoesNotPublishFailedSave(t *testing.T) {
	cfg := config.DefaultConfig()
	h := NewHandler(&cfg, func(*config.Config) error {
		return errors.New("disk full")
	})
	req := httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(
		`{"auth_method":"sso","sso_profile":"sample"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.UpdateSettings(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	if cfg.Auth.Method != "imds" || cfg.Auth.SSOProfile != "" {
		t.Fatalf("live config changed after failed save: %+v", cfg.Auth)
	}
}

func TestUpdateSettingsCanClearLLMEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.LLM.Provider = "openai"
	cfg.LLM.Endpoint = "https://example.com/v1"
	h := NewHandler(&cfg, func(*config.Config) error { return nil })
	req := httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(
		`{"llm_endpoint":""}`,
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.UpdateSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if cfg.LLM.Endpoint != "" {
		t.Fatalf("expected endpoint to be cleared, got %q", cfg.LLM.Endpoint)
	}
}

func TestUpdateSettingsCanClearOrgID(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.S3.Mode = "control_tower"
	cfg.S3.OrgID = "o-example1234"
	h := NewHandler(&cfg, func(*config.Config) error { return nil })
	req := httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(
		`{"mode":"single","org_id":"","member_accounts":[]}`,
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.UpdateSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if cfg.S3.OrgID != "" {
		t.Fatalf("expected org ID to be cleared, got %q", cfg.S3.OrgID)
	}
	if cfg.S3.Mode != "single" {
		t.Fatalf("expected single mode, got %q", cfg.S3.Mode)
	}
}
