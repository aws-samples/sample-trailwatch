package processor

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

// Handler provides HTTP handlers for processor endpoints.
type Handler struct {
	service *Service
}

// NewHandler creates a new processor Handler.
func NewHandler(db *sql.DB, cfg *config.Config) *Handler {
	return &Handler{
		service: NewService(db, cfg),
	}
}

// Service returns the underlying processor service for callback wiring.
func (h *Handler) Service() *Service {
	return h.service
}

// StartProcess starts the download pipeline for a session.
// POST /api/sessions/{id}/process
func (h *Handler) StartProcess(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if !render.IsValidUUID(sessionID) {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "session id must be a UUID", map[string]string{
			"field": "id",
		})
		return
	}

	// Create a buffered progress channel
	progressCh := make(chan ProcessingProgress, 100)

	// Register the progress channel before starting the goroutine
	h.service.mu.Lock()
	if _, exists := h.service.active[sessionID]; exists {
		h.service.mu.Unlock()
		render.Error(w, http.StatusConflict, "CONFLICT", "Session already has an active pipeline", nil)
		return
	}
	h.service.mu.Unlock()

	// Start processing in a background goroutine
	// Use a detached context since the HTTP request context will be cancelled
	// after we send the 202 response.
	go func() {
		defer close(progressCh)
		if err := h.service.StartProcessing(context.Background(), sessionID, progressCh); err != nil {
			slog.Error("processing pipeline failed",
				"component", "cloudtrail-analyzer",
				"session_id", sessionID,
				"error", err.Error(),
			)
		}
	}()

	render.JSON(w, http.StatusAccepted, map[string]string{
		"message":    "Processing started",
		"session_id": sessionID,
	})
}

// CancelProcess cancels the active pipeline for a session.
// POST /api/sessions/{id}/cancel
func (h *Handler) CancelProcess(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if !render.IsValidUUID(sessionID) {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "session id must be a UUID", map[string]string{
			"field": "id",
		})
		return
	}

	if err := h.service.CancelProcessing(sessionID); err != nil {
		render.Error(w, http.StatusNotFound, "NOT_FOUND", err.Error(), nil)
		return
	}

	render.JSON(w, http.StatusOK, map[string]string{
		"message":    "Processing cancelled",
		"session_id": sessionID,
	})
}

// GetProgress returns the latest progress snapshot as JSON (REST polling fallback).
// GET /api/sessions/{id}/progress/snapshot
func (h *Handler) GetProgress(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if !render.IsValidUUID(sessionID) {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "session id must be a UUID", map[string]string{
			"field": "id",
		})
		return
	}

	snap, exists := h.service.GetProgressSnapshot(sessionID)
	if !exists {
		render.JSON(w, http.StatusOK, map[string]interface{}{
			"session_id": sessionID,
			"phase":      "idle",
			"percentage": 0,
		})
		return
	}

	render.JSON(w, http.StatusOK, snap)
}

// StreamProgress streams processing progress via Server-Sent Events.
// GET /api/sessions/{id}/progress
func (h *Handler) StreamProgress(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if !render.IsValidUUID(sessionID) {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "session id must be a UUID", map[string]string{
			"field": "id",
		})
		return
	}

	// Check for active pipeline FIRST — return JSON for idle sessions
	progressCh, exists := h.service.GetProgressChannel(sessionID)
	if !exists {
		render.JSON(w, http.StatusOK, map[string]interface{}{
			"session_id": sessionID,
			"phase":      "idle",
			"message":    "No active pipeline — session may have completed or not started",
		})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		// Flusher not available (e.g., behind a proxy) — return a single JSON snapshot
		// by draining the latest event from the channel without blocking
		select {
		case p, open := <-progressCh:
			if open {
				render.JSON(w, http.StatusOK, p)
			} else {
				render.JSON(w, http.StatusOK, map[string]interface{}{
					"session_id": sessionID,
					"phase":      "done",
					"message":    "Pipeline completed",
				})
			}
		default:
			render.JSON(w, http.StatusOK, map[string]interface{}{
				"session_id": sessionID,
				"phase":      "processing",
				"message":    "Pipeline active, no new events",
			})
		}
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case progress, ok := <-progressCh:
			if !ok {
				// Channel closed — pipeline complete
				data, _ := json.Marshal(map[string]string{
					"event": "done",
				})
				w.Write([]byte("event: done\ndata: "))  //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
				w.Write(data)                            //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
				w.Write([]byte("\n\n"))                   //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
				flusher.Flush()
				return
			}

			data, err := json.Marshal(progress)
			if err != nil {
				continue
			}
			w.Write([]byte("event: progress\ndata: "))  //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
			w.Write(data)                                //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
			w.Write([]byte("\n\n"))                       //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
			flusher.Flush()
		}
	}
}
