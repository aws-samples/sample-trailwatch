// Package middleware provides HTTP middleware for the CloudTrail Analyzer.
// It includes structured request logging, CORS for development, and panic recovery.
package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter for middleware compatibility.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// StructuredLogger returns middleware that logs each request with slog.
// Log fields: method, path, status_code (int), duration_ms (float64), component.
func StructuredLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := newResponseWriter(w)

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		slog.Info("http request",
			"component", "cloudtrail-analyzer",
			"method", r.Method,
			"path", r.URL.Path,
			"status_code", rw.statusCode,
			"duration_ms", float64(duration.Nanoseconds())/1e6,
		)
	})
}

// CORS returns middleware that sets CORS headers for development mode.
// Allows requests from localhost Vite dev server and the analyzer itself.
func CORS(next http.Handler) http.Handler {
	allowedOrigins := map[string]bool{
		"http://localhost:5173": true,
		"http://localhost:7070": true,
	}
	allowedMethods := "GET, POST, PUT, DELETE, OPTIONS"
	allowedHeaders := "Content-Type, Authorization"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
			w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
		}

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Recoverer returns middleware that catches panics, logs the stack trace via slog,
// and returns a 500 JSON error response. It wraps Chi's middleware.Recoverer pattern
// with structured logging.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// Use Chi's middleware package to get the request ID if available
				reqID := middleware.GetReqID(r.Context())

				stack := debug.Stack()
				slog.Error("panic recovered",
					"component", "cloudtrail-analyzer",
					"method", r.Method,
					"path", r.URL.Path,
					"panic", rec,
					"stack", string(stack),
					"request_id", reqID,
				)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"code":    "INTERNAL_ERROR",
					"message": "An internal error occurred",
				})
			}
		}()

		next.ServeHTTP(w, r)
	})
}
