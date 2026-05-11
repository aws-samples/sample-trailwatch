package nlquery

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	svc *Service
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{svc: NewService(cfg)}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/execute", h.Execute)
	r.Post("/index", h.BuildIndex)
	r.Get("/index/status", h.IndexStatus)
	return r
}

func (h *Handler) BuildIndex(w http.ResponseWriter, r *http.Request) {
	indexer := NewIndexer(h.svc.cfg)
	dataPath := h.svc.buildDataPath()
	if dataPath == "" {
		render.Error(w, http.StatusBadRequest, "no_data", "No data path configured. Sync CloudTrail logs first.")
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := indexer.BuildIndex(ctx, dataPath); err != nil {
			slog.Error("index build failed", "component", "cloudtrail-analyzer", "error", err.Error())
		}
	}()

	render.JSON(w, http.StatusAccepted, map[string]string{
		"status":  "building",
		"message": "Index build started in background",
	})
}

func (h *Handler) IndexStatus(w http.ResponseWriter, r *http.Request) {
	indexer := NewIndexer(h.svc.cfg)
	indexed := indexer.IsIndexed()
	age := indexer.IndexAge()

	resp := map[string]interface{}{
		"indexed": indexed,
	}
	if indexed {
		resp["age_seconds"] = int(age.Seconds())
		info, _ := os.Stat(indexer.IndexPath())
		if info != nil {
			resp["size_bytes"] = info.Size()
		}
	}
	render.JSON(w, http.StatusOK, resp)
}

type ExecuteRequest struct {
	PromptID string `json:"prompt_id"`
	Prompt   string `json:"prompt"`
}

type ExecuteResponse struct {
	SQL     string          `json:"sql"`
	Columns []string        `json:"columns"`
	Rows    [][]interface{} `json:"rows"`
	Error   string          `json:"error,omitempty"`
}

func (h *Handler) Execute(w http.ResponseWriter, r *http.Request) {
	var req ExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		render.Error(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.Prompt == "" {
		render.Error(w, http.StatusBadRequest, "missing_prompt", "prompt field is required")
		return
	}

	result, err := h.svc.Execute(r.Context(), req.Prompt)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "execution_error", err.Error())
		return
	}

	render.JSON(w, http.StatusOK, result)
}
