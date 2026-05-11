package sessions

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

// Handler provides HTTP handlers for session endpoints.
type Handler struct {
	service *Service
}

// NewHandler creates a new sessions Handler.
func NewHandler(db *sql.DB, cfg *config.Config) *Handler {
	return &Handler{
		service: NewService(db, cfg),
	}
}

// Routes returns a Chi router with all session routes mounted.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListSessions)
	r.Post("/", h.CreateSession)
	r.Get("/{id}", h.GetSession)
	r.Delete("/{id}", h.DeleteSession)

	return r
}

// ListSessions returns all sessions ordered by created_at DESC.
func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := h.service.ListSessions(r.Context())
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list sessions", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, sessions)
}

// CreateSession creates a new sync session.
func (h *Handler) CreateSession(w http.ResponseWriter, r *http.Request) {
	var req CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	if req.AccountID == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "account_id is required", map[string]string{
			"field": "account_id",
		})
		return
	}

	if req.LogRegion == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "log_region is required", map[string]string{
			"field": "log_region",
		})
		return
	}

	if req.StartDate == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "start_date is required", map[string]string{
			"field": "start_date",
		})
		return
	}

	if req.EndDate == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "end_date is required", map[string]string{
			"field": "end_date",
		})
		return
	}

	session, err := h.service.CreateSession(r.Context(), &req)
	if err != nil {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), nil)
		return
	}

	render.JSON(w, http.StatusCreated, session)
}

// GetSession returns a session by ID.
func (h *Handler) GetSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "session id is required", nil)
		return
	}

	session, err := h.service.GetSession(r.Context(), id)
	if err != nil {
		render.Error(w, http.StatusNotFound, "NOT_FOUND", "Session not found", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, session)
}

// DeleteSession deletes a session and its local files.
func (h *Handler) DeleteSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "session id is required", nil)
		return
	}

	if err := h.service.DeleteSession(r.Context(), id); err != nil {
		render.Error(w, http.StatusNotFound, "NOT_FOUND", "Session not found or could not be deleted", map[string]string{
			"reason": err.Error(),
		})
		return
	}

	render.JSON(w, http.StatusOK, map[string]string{
		"message": "Session deleted successfully",
	})
}
