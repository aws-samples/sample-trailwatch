package nlquery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	svc          *Service
	cfg          *config.Config
	indexer      *Indexer
	microBatch   *MicroBatchIndexer
	sessionSpend *SessionSpend
	llmInFlight  atomic.Bool // concurrency gate: only 1 LLM call at a time
}

func NewHandler(cfg *config.Config, db *sql.DB) *Handler {
	idx := NewIndexer(cfg, db)
	return &Handler{
		svc:          NewService(cfg),
		cfg:          cfg,
		indexer:      idx,
		microBatch:   NewMicroBatchIndexer(idx),
		sessionSpend: NewSessionSpend(),
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
	r.Post("/estimate", h.Estimate)
	r.Post("/summarize", h.Summarize)
	r.Get("/spend", h.Spend)
	r.Delete("/spend", h.ResetSpend)
	r.Post("/index", h.BuildIndex)
	r.Get("/index/status", h.IndexStatus)
	r.Get("/index/progress", h.StreamIndexProgress)
	r.Post("/index/cancel", h.CancelIndex)
	return r
}

// ---------------------------------------------------------------------------
// LLM rate-limit guards
// ---------------------------------------------------------------------------

// acquireLLM attempts to acquire the single-flight LLM slot. If another LLM
// request is already in progress, it writes a 429 response and returns false.
// Callers should `if !h.acquireLLM(w) { return }` and defer releaseLLM().
func (h *Handler) acquireLLM(w http.ResponseWriter) bool {
	if !h.llmInFlight.CompareAndSwap(false, true) {
		render.Error(w, http.StatusTooManyRequests, "LLM_BUSY",
			"An AI query is already in progress. Wait for it to complete.")
		return false
	}
	return true
}

// releaseLLM releases the single-flight LLM slot.
func (h *Handler) releaseLLM() {
	h.llmInFlight.Store(false)
}

// checkSpendCap verifies the session spend has not exceeded the configured cap.
// Only enforced for paid providers (bedrock, anthropic, openai). Ollama is
// exempt because it runs locally with zero API cost.
// Returns true if the request may proceed; writes 429 and returns false if capped.
func (h *Handler) checkSpendCap(w http.ResponseWriter) bool {
	// Ollama is free — no spend cap applies
	if h.cfg.LLM.Provider == "ollama" {
		return true
	}

	cap := h.cfg.LLM.MaxSessionSpendUSD
	if cap <= 0 {
		// Cap disabled
		return true
	}

	currentSpend := h.sessionSpend.Total()
	if currentSpend >= cap {
		render.Error(w, http.StatusTooManyRequests, "SPEND_CAP_REACHED",
			fmt.Sprintf("Session spend cap reached ($%.2f / $%.2f). Reset via DELETE /api/nlquery/spend or restart the application.", currentSpend, cap),
			map[string]interface{}{
				"current_spend_usd": currentSpend,
				"cap_usd":           cap,
			},
		)
		return false
	}

	return true
}

// Summarize wraps the summarize.go core in an HTTP handler. The body comes
// straight from the result panel: scenario metadata + columns + the rows
// that were displayed, so the model summarizes exactly what the user is
// looking at. Pre-flight estimate + session-spend recording match the
// /execute path so the cost UX stays consistent.
func (h *Handler) Summarize(w http.ResponseWriter, r *http.Request) {
	// --- Rate-limit guards (concurrency + spend cap) ---
	if !h.acquireLLM(w) {
		return
	}
	defer h.releaseLLM()

	if !h.checkSpendCap(w) {
		return
	}

	var req SummarizeRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}
	if len(req.Columns) == 0 {
		render.Error(w, http.StatusBadRequest, "missing_columns", "columns are required")
		return
	}

	// Pre-compute estimate against the rendered prompt so spend records
	// the same number the UI showed.
	rowsToSend := req.Rows
	if len(rowsToSend) > MaxSummarizeRows {
		rowsToSend = rowsToSend[:MaxSummarizeRows]
	}
	userPrompt := buildSummarizeUserPrompt(req, rowsToSend, len(req.Rows) > MaxSummarizeRows)
	est := EstimateCost(h.cfg, summarizeSystemPrompt, userPrompt, 0)

	provider := NewProvider(h.cfg)
	resp, err := Summarize(r.Context(), provider, req)
	if err != nil {
		render.Error(w, http.StatusInternalServerError, "summarize_error", err.Error())
		return
	}

	// Record spend the same way Execute does.
	h.sessionSpend.Record(est.EstTotalCostUSD, est.EstTotalCostUSD)

	render.JSON(w, http.StatusOK, resp)
}

// EstimateRequest carries the prompt the UI is about to run, so the backend
// can return a cost estimate rendered in the pre-flight banner.
type EstimateRequest struct {
	Prompt string `json:"prompt"`
}

// Estimate returns a CostEstimate for the given user prompt, computed against
// the currently-configured LLM model and rate card. The system prompt is the
// same one the actual Execute path would use, so the estimate matches the
// real run within the heuristic's tolerance.
func (h *Handler) Estimate(w http.ResponseWriter, r *http.Request) {
	var req EstimateRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}
	systemPrompt := h.svc.buildSystemPrompt()
	est := EstimateCost(h.cfg, systemPrompt, req.Prompt, 0)

	// Enrich the estimate with spend-cap awareness so the UI can show a
	// warning before the user clicks Run.
	type enrichedEstimate struct {
		CostEstimate
		CurrentSpendUSD float64 `json:"current_spend_usd"`
		CapUSD          float64 `json:"cap_usd"`
		WouldExceedCap  bool    `json:"would_exceed_cap"`
	}

	cap := h.cfg.LLM.MaxSessionSpendUSD
	currentSpend := h.sessionSpend.Total()
	wouldExceed := cap > 0 && h.cfg.LLM.Provider != "ollama" &&
		(currentSpend+est.EstTotalCostUSD) > cap

	render.JSON(w, http.StatusOK, enrichedEstimate{
		CostEstimate:    est,
		CurrentSpendUSD: currentSpend,
		CapUSD:          cap,
		WouldExceedCap:  wouldExceed,
	})
}

// Spend returns the running session-spend snapshot.
func (h *Handler) Spend(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, http.StatusOK, h.sessionSpend.Snapshot())
}

// ResetSpend zeroes the session-spend counter.
func (h *Handler) ResetSpend(w http.ResponseWriter, r *http.Request) {
	h.sessionSpend.Reset()
	render.JSON(w, http.StatusOK, h.sessionSpend.Snapshot())
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
			// SSE stream — text/event-stream content type, parsed by the browser
			// as event data, not as HTML. The XSS-via-html/template suggestion
			// from semgrep does not apply here; suppressed inline with
			// justification per CSR rules.
			w.Write([]byte("event: progress\ndata: ")) //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
			w.Write(data)                              //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
			w.Write([]byte("\n\n"))                    //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
			flusher.Flush()

			if state.Status == "idle" || state.Status == "error" || state.Status == "paused" {
				w.Write([]byte("event: done\ndata: {}\n\n")) //nolint:errcheck // nosemgrep: no-direct-write-to-responsewriter
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
	SQL         string          `json:"sql"`
	Columns     []string        `json:"columns"`
	Rows        [][]interface{} `json:"rows"`
	Error       string          `json:"error,omitempty"`
	ErrorHint   string          `json:"error_hint,omitempty"`   // user-facing summary
	ErrorDetail string          `json:"error_detail,omitempty"` // raw engine output, collapsible
}

func (h *Handler) Execute(w http.ResponseWriter, r *http.Request) {
	// --- Rate-limit guards (concurrency + spend cap) ---
	if !h.acquireLLM(w) {
		return
	}
	defer h.releaseLLM()

	if !h.checkSpendCap(w) {
		return
	}

	var req ExecuteRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}

	if req.Prompt == "" {
		render.Error(w, http.StatusBadRequest, "missing_prompt", "prompt field is required")
		return
	}

	// Compute the estimate before invoking the LLM and record it into the
	// session counter once we have a result. Until provider responses surface
	// real token usage, treat actual = estimated total; the counter is then a
	// "session-to-date estimated spend" view, which is good enough for
	// situational awareness in this single-user POC.
	systemPrompt := h.svc.buildSystemPrompt()
	est := EstimateCost(h.cfg, systemPrompt, req.Prompt, 0)

	result, err := h.svc.Execute(r.Context(), req.Prompt)
	if err != nil {
		// Errors before the model was billed don't count toward spend.
		render.Error(w, http.StatusInternalServerError, "execution_error", err.Error())
		return
	}

	// Record the spend. Provider responses don't currently surface usage
	// counts, so actual ~= estimate. When provider.go starts forwarding token
	// usage from the response body, swap the second arg to the real cost.
	h.sessionSpend.Record(est.EstTotalCostUSD, est.EstTotalCostUSD)

	render.JSON(w, http.StatusOK, result)
}
