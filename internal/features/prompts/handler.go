package prompts

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

// Handler handles pre-built prompt template endpoints.
type Handler struct {
	cfg *config.Config
}

// NewHandler creates a new prompts handler.
func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

// Routes returns the Chi router for prompt endpoints.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.ListPrompts)
	r.Get("/system-prompt", h.GetSystemPrompt)
	r.Get("/{id}", h.GetPrompt)
	return r
}

// ListPromptsResponse is the response for listing all templates.
type ListPromptsResponse struct {
	Templates  []PromptTemplate `json:"templates"`
	Categories []string         `json:"categories"`
}

// GetPromptResponse is the response for a single template with substituted values.
type GetPromptResponse struct {
	Template       PromptTemplate    `json:"template"`
	RenderedPrompt string            `json:"rendered_prompt"`
	Substitutions  map[string]string `json:"substitutions"`
	DataPath       string            `json:"data_path"`
}

// ListPrompts returns all prompt templates grouped by category.
func (h *Handler) ListPrompts(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, http.StatusOK, ListPromptsResponse{
		Templates:  Templates,
		Categories: Categories,
	})
}

// GetSystemPrompt returns the system prompt with placeholders substituted from config.
func (h *Handler) GetSystemPrompt(w http.ResponseWriter, r *http.Request) {
	dataPath := h.buildDataPath()
	subs := map[string]string{
		"account_id": h.cfg.S3.AccountID,
		"region":     h.cfg.S3.LogRegion,
		"start_date": h.cfg.S3.StartDate,
		"end_date":   h.cfg.S3.EndDate,
		"data_path":  dataPath,
		"bucket":     h.cfg.S3.Bucket,
		"org_id":     h.cfg.S3.OrgID,
	}

	if subs["region"] == "" {
		subs["region"] = h.cfg.S3.Region
	}

	rendered := SystemPrompt
	for key, val := range subs {
		rendered = strings.ReplaceAll(rendered, "{"+key+"}", val)
	}

	render.JSON(w, http.StatusOK, map[string]string{
		"system_prompt": rendered,
	})
}

// GetPrompt returns a single template with placeholders substituted from config.
func (h *Handler) GetPrompt(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var tmpl *PromptTemplate
	for i := range Templates {
		if Templates[i].ID == id {
			tmpl = &Templates[i]
			break
		}
	}

	if tmpl == nil {
		render.JSON(w, http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("template %q not found", id),
		})
		return
	}

	// Build substitution map from config
	dataPath := h.buildDataPath()
	subs := map[string]string{
		"account_id": h.cfg.S3.AccountID,
		"region":     h.cfg.S3.LogRegion,
		"start_date": h.cfg.S3.StartDate,
		"end_date":   h.cfg.S3.EndDate,
		"data_path":  dataPath,
		"bucket":     h.cfg.S3.Bucket,
		"org_id":     h.cfg.S3.OrgID,
	}

	// If log_region is empty, fall back to bucket region
	if subs["region"] == "" {
		subs["region"] = h.cfg.S3.Region
	}

	// Render the prompt with substitutions
	rendered := tmpl.Prompt
	for key, val := range subs {
		rendered = strings.ReplaceAll(rendered, "{"+key+"}", val)
	}

	render.JSON(w, http.StatusOK, GetPromptResponse{
		Template:       *tmpl,
		RenderedPrompt: rendered,
		Substitutions:  subs,
		DataPath:       dataPath,
	})
}

// buildDataPath constructs the local filesystem path for CloudTrail logs.
func (h *Handler) buildDataPath() string {
	if h.cfg.S3.Bucket == "" {
		return ""
	}

	region := h.cfg.S3.LogRegion
	if region == "" {
		region = h.cfg.S3.Region
	}

	// Mirror S3 structure: {data_dir}/s3/{bucket}/{org_id}/AWSLogs/{org_id}/{account_id}/CloudTrail/{region}/
	if h.cfg.S3.Mode == "control_tower" && h.cfg.S3.OrgID != "" {
		return filepath.Join(h.cfg.DataDir, "s3", h.cfg.S3.Bucket,
			h.cfg.S3.OrgID, "AWSLogs", h.cfg.S3.OrgID, h.cfg.S3.AccountID, "CloudTrail", region) + "/"
	}

	return filepath.Join(h.cfg.DataDir, "s3", h.cfg.S3.Bucket,
		"AWSLogs", h.cfg.S3.AccountID, "CloudTrail", region) + "/"
}
