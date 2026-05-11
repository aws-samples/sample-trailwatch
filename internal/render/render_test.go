package render

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSON_SetsContentType(t *testing.T) {
	w := httptest.NewRecorder()
	JSON(w, http.StatusOK, map[string]string{"hello": "world"})

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestJSON_SetsStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	JSON(w, http.StatusCreated, map[string]string{"id": "123"})

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", w.Code)
	}
}

func TestJSON_EncodesBody(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	JSON(w, http.StatusOK, data)

	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("expected key=value, got key=%s", result["key"])
	}
}

func TestJSON_NilData(t *testing.T) {
	w := httptest.NewRecorder()
	JSON(w, http.StatusNoContent, nil)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("expected empty body for nil data, got %q", w.Body.String())
	}
}

func TestError_SetsContentType(t *testing.T) {
	w := httptest.NewRecorder()
	Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid input")

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestError_SetsStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	Error(w, http.StatusNotFound, "NOT_FOUND", "session not found")

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestError_ContainsCodeAndMessage(t *testing.T) {
	w := httptest.NewRecorder()
	Error(w, http.StatusForbidden, "S3_ACCESS_DENIED", "bucket access denied")

	var apiErr APIError
	if err := json.NewDecoder(w.Body).Decode(&apiErr); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if apiErr.Code != "S3_ACCESS_DENIED" {
		t.Errorf("expected code S3_ACCESS_DENIED, got %q", apiErr.Code)
	}
	if apiErr.Message != "bucket access denied" {
		t.Errorf("expected message 'bucket access denied', got %q", apiErr.Message)
	}
}

func TestError_WithDetails(t *testing.T) {
	w := httptest.NewRecorder()
	details := map[string]string{"field": "bucket", "reason": "bucket name is required"}
	Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid input", details)

	var apiErr APIError
	if err := json.NewDecoder(w.Body).Decode(&apiErr); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if apiErr.Details == nil {
		t.Fatal("expected details to be present")
	}
	detailsMap, ok := apiErr.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("expected details to be a map, got %T", apiErr.Details)
	}
	if detailsMap["field"] != "bucket" {
		t.Errorf("expected field=bucket, got %v", detailsMap["field"])
	}
}

func TestError_WithoutDetails(t *testing.T) {
	w := httptest.NewRecorder()
	Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "something went wrong")

	var raw map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if _, exists := raw["details"]; exists {
		t.Error("expected details to be omitted when not provided")
	}
}

func TestError_WithNilDetails(t *testing.T) {
	w := httptest.NewRecorder()
	Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "something went wrong", nil)

	var raw map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if _, exists := raw["details"]; exists {
		t.Error("expected details to be omitted when nil is passed")
	}
}

func TestError_AllErrorCodes(t *testing.T) {
	codes := []string{
		"VALIDATION_ERROR",
		"NOT_FOUND",
		"S3_ACCESS_DENIED",
		"TIMEOUT",
		"CREDENTIAL_ERROR",
		"INTERNAL_ERROR",
		"DISK_SPACE_INSUFFICIENT",
		"SERVICE_UNAVAILABLE",
		"CONFLICT",
	}

	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			w := httptest.NewRecorder()
			Error(w, http.StatusBadRequest, code, "test message")

			var apiErr APIError
			if err := json.NewDecoder(w.Body).Decode(&apiErr); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}
			if apiErr.Code != code {
				t.Errorf("expected code %q, got %q", code, apiErr.Code)
			}
			if apiErr.Message != "test message" {
				t.Errorf("expected message 'test message', got %q", apiErr.Message)
			}
		})
	}
}
