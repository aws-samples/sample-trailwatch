package nlquery

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

type DashboardHandler struct {
	cfg *config.Config
}

func NewDashboardHandler(cfg *config.Config) *DashboardHandler {
	return &DashboardHandler{cfg: cfg}
}

type DashboardData struct {
	Summary       *QueryPanel `json:"summary"`
	TopAPICalls   *QueryPanel `json:"top_api_calls"`
	IdentityTypes *QueryPanel `json:"identity_types"`
	HourlyVolume  *QueryPanel `json:"hourly_volume"`
	TopSourceIPs  *QueryPanel `json:"top_source_ips"`
	TopErrors     *QueryPanel `json:"top_errors"`
	TopServices   *QueryPanel `json:"top_services"`
}

type QueryPanel struct {
	Columns []string        `json:"columns"`
	Rows    [][]interface{} `json:"rows"`
	Error   string          `json:"error,omitempty"`
}

func (h *DashboardHandler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	dataPath := h.buildDataPath()
	if dataPath == "" {
		render.Error(w, http.StatusBadRequest, "no_data", "S3 config not set — no data path available")
		return
	}

	ctx := r.Context()
	dashboard := &DashboardData{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	// events is the single unnested table-expression every panel reads from. It
	// escapes the config-derived path before it lands inside read_json('...')
	// so an embedded quote cannot break out of the literal (H6), and applies the
	// selected member-account subset so the panels aggregate over the chosen
	// accounts rather than every synced account (N33).
	events := h.buildEventsExpr(dataPath)

	queries := map[string]string{
		"summary": fmt.Sprintf(`SELECT
			COUNT(*) as total_events,
			COUNT(DISTINCT r.userIdentity.arn) as unique_identities,
			COUNT(DISTINCT r.sourceIPAddress) as unique_ips,
			COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) as error_events,
			ROUND(COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) as error_rate_pct,
			COUNT(DISTINCT r.eventSource) as unique_services,
			MIN(r.eventTime) as earliest_event,
			MAX(r.eventTime) as latest_event
		FROM %s;`, events),

		"top_api_calls": fmt.Sprintf(`SELECT r.eventName as name, COUNT(*) as value
		FROM %s
		GROUP BY r.eventName
		ORDER BY value DESC
		LIMIT 10;`, events),

		"identity_types": fmt.Sprintf(`SELECT r.userIdentity."type" as name, COUNT(*) as value
		FROM %s
		WHERE r.userIdentity."type" IS NOT NULL
		GROUP BY r.userIdentity."type"
		ORDER BY value DESC;`, events),

		"hourly_volume": fmt.Sprintf(`SELECT
			EXTRACT(HOUR FROM CAST(r.eventTime AS TIMESTAMP)) as hour,
			COUNT(*) as total,
			COUNT(CASE WHEN r.errorCode IS NOT NULL THEN 1 END) as errors,
			COUNT(CASE WHEN r.readOnly = 'false' THEN 1 END) as write_ops
		FROM %s
		GROUP BY hour
		ORDER BY hour;`, events),

		"top_source_ips": fmt.Sprintf(`SELECT r.sourceIPAddress as name, COUNT(*) as value
		FROM %s
		WHERE r.sourceIPAddress IS NOT NULL
		GROUP BY r.sourceIPAddress
		ORDER BY value DESC
		LIMIT 10;`, events),

		"top_errors": fmt.Sprintf(`SELECT r.errorCode as error_code, r.eventName as event_name, r.userIdentity.arn as identity, COUNT(*) as count
		FROM %s
		WHERE r.errorCode IS NOT NULL
		GROUP BY r.errorCode, r.eventName, r.userIdentity.arn
		ORDER BY count DESC
		LIMIT 15;`, events),

		"top_services": fmt.Sprintf(`SELECT r.eventSource as name, COUNT(*) as value
		FROM %s
		GROUP BY r.eventSource
		ORDER BY value DESC
		LIMIT 8;`, events),
	}

	svc := NewService(h.cfg)

	for key, sql := range queries {
		wg.Add(1)
		go func(k, q string) {
			defer wg.Done()
			cols, rows, err := svc.executeDuckDB(ctx, q)
			panel := &QueryPanel{Columns: cols, Rows: rows}
			if err != nil {
				panel.Error = err.Error()
			}
			mu.Lock()
			switch k {
			case "summary":
				dashboard.Summary = panel
			case "top_api_calls":
				dashboard.TopAPICalls = panel
			case "identity_types":
				dashboard.IdentityTypes = panel
			case "hourly_volume":
				dashboard.HourlyVolume = panel
			case "top_source_ips":
				dashboard.TopSourceIPs = panel
			case "top_errors":
				dashboard.TopErrors = panel
			case "top_services":
				dashboard.TopServices = panel
			}
			mu.Unlock()
		}(key, sql)
	}

	wg.Wait()
	render.JSON(w, http.StatusOK, dashboard)
}

func (h *DashboardHandler) GetFindings(w http.ResponseWriter, r *http.Request) {
	dataPath := h.buildDataPath()
	if dataPath == "" {
		render.Error(w, http.StatusBadRequest, "no_data", "S3 config not set")
		return
	}

	queries := BuildFindingQueries(dataPath)
	svc := NewService(h.cfg)

	type FindingResult struct {
		ID      string          `json:"id"`
		Columns []string        `json:"columns"`
		Rows    [][]interface{} `json:"rows"`
		Error   string          `json:"error,omitempty"`
	}

	var results []FindingResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for id, fq := range queries {
		wg.Add(1)
		go func(findingID, sql string) {
			defer wg.Done()
			cols, rows, err := svc.executeDuckDB(r.Context(), sql)
			fr := FindingResult{ID: findingID, Columns: cols, Rows: rows}
			if err != nil {
				fr.Error = err.Error()
			}
			mu.Lock()
			results = append(results, fr)
			mu.Unlock()
		}(id, fq.SummarySQL)
	}

	wg.Wait()
	render.JSON(w, http.StatusOK, results)
}

func (h *DashboardHandler) GetFindingDetail(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	dataPath := h.buildDataPath()
	if dataPath == "" {
		render.Error(w, http.StatusBadRequest, "no_data", "S3 config not set")
		return
	}

	queries := BuildFindingQueries(dataPath)
	fq, exists := queries[findingID]
	if !exists {
		render.Error(w, http.StatusNotFound, "not_found", fmt.Sprintf("finding %q not found", findingID))
		return
	}

	svc := NewService(h.cfg)
	cols, rows, err := svc.executeDuckDB(r.Context(), fq.DetailSQL)
	resp := &QueryPanel{Columns: cols, Rows: rows}
	out := map[string]interface{}{
		"id":      findingID,
		"sql":     fq.DetailSQL,
		"columns": resp.Columns,
		"rows":    resp.Rows,
	}
	if err != nil {
		hint, detail := classifyDuckDBError(err)
		out["error"] = err.Error()
		if hint != "" {
			out["error_hint"] = hint
		}
		if detail != "" {
			out["error_detail"] = detail
		}
	}
	render.JSON(w, http.StatusOK, out)
}

// buildEventsExpr returns the unnested CloudTrail events table-expression that
// every dashboard panel query reads from. It escapes the config-derived path
// before interpolating it into read_json('...') so an embedded single quote
// cannot break out of the literal (H6), and — when a member-account subset is
// selected — wraps the unnest in a subquery that constrains recipientAccountId
// to that subset (N33), so the panels reflect the chosen accounts rather than
// every synced account under the bucket/org root.
func (h *DashboardHandler) buildEventsExpr(dataPath string) string {
	base := fmt.Sprintf(
		`(SELECT unnest(Records) as r FROM read_json('%s**/*.json', maximum_object_size=%d, auto_detect=true, union_by_name=true))`,
		escapeSQLLiteral(dataPath), maxObjectSize)
	if scope := memberAccountScope(h.cfg); scope != "" {
		// scope is prefixed with " AND r.recipientAccountId IN (...)"; drop the
		// leading " AND " to use it as the sole WHERE predicate here.
		return fmt.Sprintf("(SELECT r FROM %s WHERE%s)", base, strings.TrimPrefix(scope, " AND"))
	}
	return base
}

func (h *DashboardHandler) buildDataPath() string {
	if h.cfg.S3.Bucket == "" {
		return ""
	}

	// When multiple accounts are selected, query across all account data under the bucket
	// This enables cross-account correlation
	if len(h.cfg.S3.MemberAccounts) > 1 {
		if h.cfg.S3.Mode == "control_tower" && h.cfg.S3.OrgID != "" {
			return fmt.Sprintf("%s/s3/%s/%s/AWSLogs/%s/",
				h.cfg.DataDir, h.cfg.S3.Bucket, h.cfg.S3.OrgID, h.cfg.S3.OrgID)
		}
		return fmt.Sprintf("%s/s3/%s/AWSLogs/",
			h.cfg.DataDir, h.cfg.S3.Bucket)
	}

	region := h.cfg.S3.LogRegion
	if region == "" {
		region = h.cfg.S3.Region
	}

	if h.cfg.S3.Mode == "control_tower" && h.cfg.S3.OrgID != "" {
		return fmt.Sprintf("%s/s3/%s/%s/AWSLogs/%s/%s/CloudTrail/%s/",
			h.cfg.DataDir, h.cfg.S3.Bucket,
			h.cfg.S3.OrgID, h.cfg.S3.OrgID, h.cfg.S3.AccountID, region)
	}

	return fmt.Sprintf("%s/s3/%s/AWSLogs/%s/CloudTrail/%s/",
		h.cfg.DataDir, h.cfg.S3.Bucket, h.cfg.S3.AccountID, region)
}
