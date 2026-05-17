package nlquery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	svc        *Service
	indexer    *Indexer
	microBatch *MicroBatchIndexer
}

func NewHandler(cfg *config.Config, db *sql.DB) *Handler {
	idx := NewIndexer(cfg, db)
	return &Handler{
		svc:        NewService(cfg),
		indexer:    idx,
		microBatch: NewMicroBatchIndexer(idx),
	}
}

func (h *Handler) Indexer() *Indexer {
	return h.indexer
}

func (h *Handler) MicroBatch() *MicroBatchIndexer {
	return h.microBatch
}

func (h *Handler) BuildDataPath() string {
	return h.svc.buildIndexDataPath()
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/execute", h.Execute)
	r.Post("/index", h.BuildIndex)
	r.Get("/index/status", h.IndexStatus)
	r.Get("/index/progress", h.StreamIndexProgress)
	r.Post("/index/cancel", h.CancelIndex)
	return r
}

func (h *Handler) BuildIndex(w http.ResponseWriter, r *http.Request) {
	dataPath := h.svc.buildIndexDataPath()
	if dataPath == "" {
		render.Error(w, http.StatusBadRequest, "no_data", "No data path configured. Sync CloudTrail logs first.")
		return
	}

	if h.indexer.IsRunning() {
		render.Error(w, http.StatusConflict, "already_running", "Indexing is already in progress")
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if err := h.indexer.BuildIndexIncremental(ctx, dataPath); err != nil {
			slog.Error("incremental index build failed", "component", "cloudtrail-analyzer", "error", err.Error())
		}
	}()

	render.JSON(w, http.StatusAccepted, map[string]string{
		"status":  "building",
		"message": "Incremental index build started in background",
	})
}

func (h *Handler) CancelIndex(w http.ResponseWriter, r *http.Request) {
	if err := h.indexer.CancelIndex(); err != nil {
		render.Error(w, http.StatusNotFound, "not_running", err.Error())
		return
	}
	render.JSON(w, http.StatusOK, map[string]string{
		"status":  "cancelling",
		"message": "Index build cancellation requested",
	})
}

func (h *Handler) StreamIndexProgress(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		render.Error(w, http.StatusInternalServerError, "streaming_unsupported", "Streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state, err := h.indexer.GetIndexState()
			if err != nil {
				return
			}

			var pct float64
			if state.TotalBytes > 0 {
				pct = float64(state.ProcessedBytes) / float64(state.TotalBytes) * 100
			}

			progress := IndexProgress{
				Status:         state.Status,
				TotalBytes:     state.TotalBytes,
				ProcessedBytes: state.ProcessedBytes,
				TotalFiles:     state.TotalFiles,
				ProcessedFiles: state.ProcessedFiles,
				Percentage:     pct,
				Message:        fmt.Sprintf("Indexed %d of %d files", state.ProcessedFiles, state.TotalFiles),
			}

			data, _ := json.Marshal(progress)
			fmt.Fprintf(w, "event: progress\ndata: %s\n\n", data)
			flusher.Flush()

			if state.Status == "idle" || state.Status == "error" || state.Status == "paused" {
				fmt.Fprintf(w, "event: done\ndata: {}\n\n")
				flusher.Flush()
				return
			}
		}
	}
}

func (h *Handler) IndexStatus(w http.ResponseWriter, r *http.Request) {
	indexed := h.indexer.IsIndexed()
	age := h.indexer.IndexAge()

	resp := map[string]interface{}{
		"indexed": indexed,
	}
	if indexed {
		resp["age_seconds"] = int(age.Seconds())
		info, _ := os.Stat(h.indexer.IndexPath())
		if info != nil {
			resp["size_bytes"] = info.Size()
		}
	}

	state, err := h.indexer.GetIndexState()
	if err == nil {
		resp["index_status"] = state.Status
		resp["total_files_indexed"] = state.ProcessedFiles
		resp["total_bytes_indexed"] = state.ProcessedBytes
		if state.StartedAt != "" {
			resp["started_at"] = state.StartedAt
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
	if !render.DecodeStrictJSON(w, r, &req) {
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
