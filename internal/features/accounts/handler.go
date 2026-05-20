package accounts

import (
	"net/http"
	"strings"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

// Handler exposes the resolver as HTTP endpoints.
type Handler struct {
	resolver *Resolver
	cfg      *config.Config
}

// NewHandler creates a Handler bound to the given resolver. cfg is read at
// request time so changes to S3.MemberAccounts via Settings reflect on
// subsequent /discoverable calls without a server restart.
func NewHandler(resolver *Resolver, cfg *config.Config) *Handler {
	return &Handler{resolver: resolver, cfg: cfg}
}

// Routes mounts under /api/accounts.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/resolve", h.Resolve)              // GET  /api/accounts/resolve?ids=111,222
	r.Get("/status", h.Status)                // GET  /api/accounts/status          (resolver state for UI hints)
	r.Get("/discoverable", h.ListDiscoverable) // GET  /api/accounts/discoverable    (toolbar account picker payload)
	r.Post("/refresh", h.RefreshOrg)          // POST /api/accounts/refresh         (force AWS Organizations refresh)
	r.Get("/manual", h.ListManual)            // GET  /api/accounts/manual          (list overrides)
	r.Put("/manual/{id}", h.UpsertManual)     // PUT  /api/accounts/manual/{id}     (set or clear an override)
	r.Delete("/manual/{id}", h.DeleteManual)  // DELETE /api/accounts/manual/{id}
	return r
}

// ListDiscoverable returns the union of synced accounts and configured
// member accounts, each enriched with name + has_data flag, for the
// Investigate toolbar's account picker.
func (h *Handler) ListDiscoverable(w http.ResponseWriter, r *http.Request) {
	configured := []string{}
	if h.cfg != nil {
		configured = append(configured, h.cfg.S3.MemberAccounts...)
		if h.cfg.S3.AccountID != "" {
			configured = append(configured, h.cfg.S3.AccountID)
		}
	}
	out, err := h.resolver.ListDiscoverable(r.Context(), configured)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list discoverable accounts", map[string]string{
			"reason": err.Error(),
		})
		return
	}
	render.JSON(w, http.StatusOK, map[string]interface{}{"accounts": out})
}

// Status returns a snapshot of resolver state so the UI can decide whether to
// nudge the user toward manual mappings.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	st, err := h.resolver.Status(r.Context())
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to read resolver status", map[string]string{
			"reason": err.Error(),
		})
		return
	}
	render.JSON(w, http.StatusOK, st)
}

type resolveResponse struct {
	Entries []Entry `json:"entries"`
}

// Resolve returns names for the given comma-separated account IDs.
//   GET /api/accounts/resolve?ids=247083000413,391114186676
func (h *Handler) Resolve(w http.ResponseWriter, r *http.Request) {
	idsParam := r.URL.Query().Get("ids")
	if idsParam == "" {
		render.JSON(w, http.StatusOK, resolveResponse{Entries: []Entry{}})
		return
	}
	ids := splitAndTrim(idsParam, ",")
	entries, err := h.resolver.ResolveMany(r.Context(), ids)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve account names", map[string]string{
			"reason": err.Error(),
		})
		return
	}
	if entries == nil {
		entries = []Entry{}
	}
	render.JSON(w, http.StatusOK, resolveResponse{Entries: entries})
}

type refreshResponse struct {
	Refreshed bool   `json:"refreshed"`
	Count     int    `json:"count"`
	Error     string `json:"error,omitempty"`
}

// RefreshOrg forces an AWS Organizations refresh. Failure is reported in the
// body but returns HTTP 200 — the caller can read the cache that exists.
func (h *Handler) RefreshOrg(w http.ResponseWriter, r *http.Request) {
	count, err := h.resolver.RefreshOrganizations(r.Context(), true)
	resp := refreshResponse{Refreshed: err == nil, Count: count}
	if err != nil {
		resp.Error = err.Error()
	}
	render.JSON(w, http.StatusOK, resp)
}

// ListManual returns every manual override.
func (h *Handler) ListManual(w http.ResponseWriter, r *http.Request) {
	entries, err := h.resolver.ListManual(r.Context())
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list manual mappings", map[string]string{
			"reason": err.Error(),
		})
		return
	}
	render.JSON(w, http.StatusOK, resolveResponse{Entries: entries})
}

type upsertManualRequest struct {
	Name string `json:"name"`
}

// UpsertManual sets a manual mapping. Empty name is rejected here; use DELETE.
func (h *Handler) UpsertManual(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !isValidAccountID(id) {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "account_id must be a 12-digit AWS account number", nil)
		return
	}
	var req upsertManualRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required (use DELETE to clear)", nil)
		return
	}
	if err := h.resolver.SetManual(r.Context(), id, name); err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save mapping", map[string]string{
			"reason": err.Error(),
		})
		return
	}
	entry, _ := h.resolver.ResolveOne(r.Context(), id)
	render.JSON(w, http.StatusOK, entry)
}

// DeleteManual removes a manual mapping. Idempotent: deleting a non-existent
// entry returns 200 with the resolved entry (which may be unresolved or fall
// back to the org name).
func (h *Handler) DeleteManual(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !isValidAccountID(id) {
		render.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", "account_id must be a 12-digit AWS account number", nil)
		return
	}
	if err := h.resolver.SetManual(r.Context(), id, ""); err != nil {
		render.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete mapping", map[string]string{
			"reason": err.Error(),
		})
		return
	}
	entry, _ := h.resolver.ResolveOne(r.Context(), id)
	render.JSON(w, http.StatusOK, entry)
}

// splitAndTrim returns the non-empty trimmed segments of s split by sep.
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// isValidAccountID checks the canonical 12-digit AWS account ID shape.
func isValidAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
