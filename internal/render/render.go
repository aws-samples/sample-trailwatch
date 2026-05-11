// Package render provides JSON response helpers for HTTP handlers.
// It is importable by all feature handlers and uses only the Go standard library.
package render

import (
	"encoding/json"
	"net/http"
)

// APIError is the standard error response schema for all 4xx/5xx responses.
type APIError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// JSON writes a success JSON response with the given status code and data.
func JSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// Error writes a JSON error response matching the APIError schema.
// The optional details parameter allows attaching structured error details.
func Error(w http.ResponseWriter, status int, code string, message string, details ...interface{}) {
	apiErr := APIError{
		Code:    code,
		Message: message,
	}
	if len(details) > 0 && details[0] != nil {
		apiErr.Details = details[0]
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apiErr)
}
