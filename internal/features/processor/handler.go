package processor

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

// StartProcess starts the download pipeline for a session.
// POST /api/sessions/{id}/process
func (h *Handler) StartProcess(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "session id is required", nil)
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
	if sessionID == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "session id is required", nil)
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

// StreamProgress streams processing progress via Server-Sent Events.
// GET /api/sessions/{id}/progress
func (h *Handler) StreamProgress(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "session id is required", nil)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Streaming not supported", nil)
		return
	}

	// Get the progress channel for this session
	progressCh, exists := h.service.GetProgressChannel(sessionID)
	if !exists {
		render.Error(w, http.StatusNotFound, "NOT_FOUND",
			fmt.Sprintf("No active pipeline for session %s", sessionID), nil)
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
