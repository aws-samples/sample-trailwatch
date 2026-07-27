package nlquery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
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

// InvalidateIndex removes derived query data before source files are deleted.
func (h *Handler) InvalidateIndex() error {
	return h.microBatch.InvalidateIndex()
}

func (h *Handler) BeginIndexInvalidation() (func(), error) {
	return h.microBatch.BeginInvalidation()
}

func (h *Handler) Shutdown(ctx context.Context) error {
	return h.indexer.Shutdown(ctx)
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

// MaxPromptChars bounds the size of a free-form NLQ prompt forwarded to the
// paid LLM. The request body as a whole is already capped at 1 MiB by
// render.DecodeStrictJSON, but that cap is far larger than any legitimate
// question and would let a caller push ~1 MiB of text through the per-token
// billing path on each Execute. This second, tighter bound is applied after
// the concurrency/spend gates and before the model call so an oversized prompt
// is rejected cheaply rather than being priced and sent. ~8000 chars ≈ 2000
// input tokens, which is generous for a natural-language security question.
const MaxPromptChars = 8000

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
	totalRows := req.TotalRows
	if totalRows < len(req.Rows) {
		totalRows = len(req.Rows)
	}
	req.TotalRows = totalRows
	userPrompt := buildSummarizeUserPrompt(req, rowsToSend, totalRows > len(rowsToSend))
	est := EstimateCost(h.cfg, summarizeSystemPrompt, userPrompt, 0)

	provider := NewProvider(h.cfg)
	resp, err := Summarize(r.Context(), provider, req)
	if err != nil {
		// The underlying error can be a raw AWS SDK / provider string carrying
		// the caller's principal ARN or endpoint. Log the raw value
		// server-side and return a redacted message to the browser.
		slog.Warn("summarize call failed",
			"component", "cloudtrail-analyzer",
			"error", err.Error(),
		)
		render.Error(w, http.StatusInternalServerError, "summarize_error", redactErrorString(err.Error(), h.cfg))
		return
	}

	// Provider responses do not yet expose billed token usage, so actual cost
	// is unknown. Keep the estimate for the session cap without presenting it
	// as measured spend.
	h.sessionSpend.Record(est.EstTotalCostUSD, 0)

	// Carry the estimate the backend actually computed (same rows + same
	// system prompt that were sent) so the UI can reflect the real cost
	// instead of the pre-flight banner's approximation. See P1-14.
	resp.EstCostUSD = est.EstTotalCostUSD

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

	if err := h.indexer.StartBuildAsync(context.Background(), dataPath, 30*time.Minute); err != nil {
		if errors.Is(err, ErrAlreadyRunning) {
			render.Error(w, http.StatusConflict, "already_running", "Indexing is already in progress")
			return
		}
		render.Error(w, http.StatusInternalServerError, "index_start_failed", "Unable to start indexing")
		return
	}

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

	// Bound the prompt before it reaches the paid LLM. The concurrency and
	// spend-cap gates above already ran; this rejects an oversized prompt
	// cheaply so a caller can't forward ~1 MiB (the body cap) of text into the
	// per-token billing path on each request.
	if len(req.Prompt) > MaxPromptChars {
		render.Error(w, http.StatusRequestEntityTooLarge, "prompt_too_large",
			fmt.Sprintf("Question is too long (%d characters; limit %d). Ask a shorter question.", len(req.Prompt), MaxPromptChars))
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
		if errors.Is(err, ErrIndexRequired) {
			render.Error(w, http.StatusConflict, "INDEX_REQUIRED",
				"Build the local CloudTrail index before running an AI query.")
			return
		}
		render.Error(w, http.StatusInternalServerError, "execution_error", redactErrorString(err.Error(), h.cfg))
		return
	}

	// Provider responses do not yet surface billed token usage. Record the
	// estimate for the session cap and leave actual cost unknown (zero) rather
	// than copying the estimate into both fields.
	h.sessionSpend.Record(est.EstTotalCostUSD, 0)

	// A DuckDB failure surfaces as a 200 with the error fields populated. The
	// raw engine output can echo the local data-dir absolute path and the AWS
	// account/org IDs (they appear in the read_json() path). Keep the raw
	// detail server-side only and hand the browser a redacted copy plus the
	// user-facing hint.
	if result.Error != "" || result.ErrorDetail != "" {
		slog.Warn("duckdb query failed",
			"component", "cloudtrail-analyzer",
			"error", result.Error,
			"detail", result.ErrorDetail,
		)
		result.Error = redactErrorString(result.Error, h.cfg)
		result.ErrorDetail = redactErrorString(result.ErrorDetail, h.cfg)
	}

	render.JSON(w, http.StatusOK, result)
}

// redactErrorString removes locally-identifying detail from an engine/SDK error
// string before it is returned to the browser. The raw string is still logged
// server-side for diagnosis; this only strips what the client does not need:
//   - the absolute local data directory path (filesystem layout disclosure)
//   - the AWS account ID and org ID interpolated into the read_json() path
//
// It is deliberately conservative — it generalizes known-sensitive substrings
// rather than attempting to parse the message — so a hint like "field not
// found" still reaches the user intact.
func redactErrorString(s string, cfg *config.Config) string {
	if s == "" || cfg == nil {
		return s
	}
	// Order matters: redact the longer/more-specific values first so a data
	// dir that contains the account ID is generalized as a path, not split.
	// These are exactly the config-derived values interpolated into the
	// read_json() path that DuckDB echoes back in its stderr on error.
	for _, secret := range []string{
		cfg.DataDir,
		cfg.S3.Bucket,
		cfg.S3.OrgID,
		cfg.S3.AccountID,
	} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	return s
}
