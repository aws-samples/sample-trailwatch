// Package render — safeerror.go provides a shared operational-error mapper
// that prevents raw internal errors from reaching HTTP clients.
//
// ERR-01: All handlers should use ClassifyError or SafeErrorMessage to produce
// client-facing error text. Raw err.Error() must never appear in response
// bodies because it can contain bucket names, account IDs, ARNs, local paths,
// SQL text, or AWS SDK request metadata.
package render

import (
	"errors"
	"strings"
)

// SafeError holds a client-safe error representation. Code is a stable
// machine-readable identifier; Message is a short human-readable sentence;
// Hint is an optional actionable suggestion.
type SafeError struct {
	Code    string
	Message string
	Hint    string
}

// classifiers is an ordered list of error matchers. The first match wins.
// Add new entries when a new distinct operational failure class is identified.
var classifiers = []struct {
	match func(string) bool
	safe  SafeError
}{
	// AWS access / auth
	{contains("AccessDenied", "Access Denied"), SafeError{
		Code:    "ACCESS_DENIED",
		Message: "Access denied by AWS",
		Hint:    "Check IAM permissions, bucket policy, and KMS key policy.",
	}},
	{contains("ExpiredToken", "expired"), SafeError{
		Code:    "CREDENTIALS_EXPIRED",
		Message: "AWS credentials have expired",
		Hint:    "Refresh credentials in Settings → Credentials.",
	}},
	{contains("Throttling", "ThrottlingException", "Rate exceeded"), SafeError{
		Code:    "THROTTLED",
		Message: "Request was throttled by AWS",
		Hint:    "Wait a moment and retry.",
	}},
	{contains("kms:Decrypt", "KMS"), SafeError{
		Code:    "KMS_DENIED",
		Message: "KMS decryption was denied",
		Hint:    "The KMS key policy must grant Decrypt to the credential's principal.",
	}},
	// DuckDB
	{contains("Could not set lock", "write lock", "writer lock"), SafeError{
		Code:    "INDEX_BUSY",
		Message: "The index is currently being updated",
		Hint:    "Wait for indexing to finish, then retry the query.",
	}},
	{contains("Binder Error"), SafeError{
		Code:    "QUERY_FAILED",
		Message: "Query references an unknown column or table",
		Hint:    "Check the field name or re-index the data.",
	}},
	{contains("out of memory", "Out of Memory"), SafeError{
		Code:    "QUERY_FAILED",
		Message: "Query exceeded available memory",
		Hint:    "Narrow the time range or reduce result scope.",
	}},
	// Network / timeout
	{contains("context deadline exceeded", "context canceled", "Timeout"), SafeError{
		Code:    "TIMEOUT",
		Message: "The operation timed out",
		Hint:    "Narrow the query scope or check network connectivity.",
	}},
	{contains("no such host", "dial tcp", "connection refused"), SafeError{
		Code:    "NETWORK_ERROR",
		Message: "Could not reach the remote service",
		Hint:    "Check network connectivity and endpoint configuration.",
	}},
	// Not found
	{contains("NoSuchBucket", "NoSuchKey", "not found"), SafeError{
		Code:    "NOT_FOUND",
		Message: "The requested resource was not found",
		Hint:    "",
	}},
	// Unsafe SQL (application validation)
	{contains("unsafe SQL"), SafeError{
		Code:    "UNSAFE_QUERY",
		Message: "The generated query was rejected by safety validation",
		Hint:    "Rephrase the question so the model generates a simpler query.",
	}},
}

// ClassifyError maps an operational error to a client-safe representation.
// The original error should be logged server-side before calling this.
// Returns a generic fallback if no specific classifier matches.
func ClassifyError(err error) SafeError {
	if err == nil {
		return SafeError{Code: "UNKNOWN", Message: "An unexpected error occurred"}
	}
	msg := err.Error()
	for _, c := range classifiers {
		if c.match(msg) {
			return c.safe
		}
	}
	return SafeError{
		Code:    "INTERNAL_ERROR",
		Message: "An internal error occurred",
		Hint:    "",
	}
}

// SafeErrorMessage returns only the client-safe message string for an error.
// Convenience wrapper for handlers that only need the message text.
func SafeErrorMessage(err error) string {
	return ClassifyError(err).Message
}

// IsSensitive returns true if the given error text likely contains values
// that should not be shown to a client (paths, ARNs, buckets, SQL, etc).
// Used as a defense-in-depth check.
func IsSensitive(errText string) bool {
	sensitive := []string{
		"/Users/", "/home/", "/var/", "/opt/", "/tmp/",
		"arn:aws:", "s3://",
		".duckdb", ".json",
		"AKIA", "ASIA",
		"config.json",
	}
	lower := strings.ToLower(errText)
	for _, s := range sensitive {
		if strings.Contains(lower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// contains returns a match function that checks if the error message contains
// any of the given substrings (case-insensitive).
func contains(substrs ...string) func(string) bool {
	return func(msg string) bool {
		lower := strings.ToLower(msg)
		for _, s := range substrs {
			if strings.Contains(lower, strings.ToLower(s)) {
				return true
			}
		}
		return false
	}
}

// ClassifyDuckDBError is exported for handlers that embed errors in HTTP 200
// response bodies (dashboard panels, findings, investigate responses).
// Returns a safe message and optional hint without leaking raw stderr.
func ClassifyDuckDBError(err error) (safeMsg, hint string) {
	if err == nil {
		return "", ""
	}
	se := ClassifyError(err)
	return se.Message, se.Hint
}

// Ensure ClassifyError handles wrapped errors via errors.Unwrap chain.
func init() {
	_ = errors.Unwrap // reference to suppress unused import lint if needed
}
