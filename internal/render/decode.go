package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// MaxRequestBodyBytes caps JSON request bodies. Prevents accidental or
// malicious oversized payloads from exhausting memory.
const MaxRequestBodyBytes = 1 << 20 // 1 MiB

// uuidRegex matches the canonical 8-4-4-4-12 UUID form used by google/uuid.
// Case-insensitive; rejects empty strings, dashes-only, traversal sequences.
var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsValidUUID reports whether s is a canonical UUID.
func IsValidUUID(s string) bool {
	return uuidRegex.MatchString(s)
}

// DecodeStrictJSON reads a size-limited body and decodes it into out, rejecting
// unknown fields and trailing junk. On failure it writes a 400 response and
// returns false so the caller can `if !DecodeStrictJSON(...) { return }`.
func DecodeStrictJSON(w http.ResponseWriter, r *http.Request, out interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(out); err != nil {
		Error(w, http.StatusBadRequest, "VALIDATION_ERROR", decodeErrorMessage(err), nil)
		return false
	}
	// Reject extra JSON tokens after the first value (e.g. two objects concatenated).
	if dec.More() {
		Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "request body must contain a single JSON value", nil)
		return false
	}
	return true
}

// decodeErrorMessage normalises common decoder errors into user-readable text
// without leaking internals.
func decodeErrorMessage(err error) string {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return fmt.Sprintf("request body exceeds %d bytes", MaxRequestBodyBytes)
	}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return fmt.Sprintf("malformed JSON at byte %d", syntaxErr.Offset)
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		field := typeErr.Field
		if field == "" {
			field = typeErr.Type.String()
		}
		return fmt.Sprintf("invalid type for field %q: expected %s", field, typeErr.Type.String())
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "request body is empty or truncated"
	}

	msg := err.Error()
	// json.Decoder reports unknown fields as: 'json: unknown field "Foo"'
	if strings.HasPrefix(msg, "json: unknown field") {
		return strings.TrimPrefix(msg, "json: ")
	}
	return "invalid request body"
}
