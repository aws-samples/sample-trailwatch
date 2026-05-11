package nlquery

import (
	"fmt"
	"net/http"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"
)

type LookupsHandler struct {
	cfg *config.Config
}

func NewLookupsHandler(cfg *config.Config) *LookupsHandler {
	return &LookupsHandler{cfg: cfg}
}

type LookupValues struct {
	AccessKeys []string `json:"access_keys"`
	SourceIPs  []string `json:"source_ips"`
	Identities []string `json:"identities"`
	Accounts   []string `json:"accounts"`
	Roles      []string `json:"roles"`
}

func (h *LookupsHandler) GetLookups(w http.ResponseWriter, r *http.Request) {
	dataPath := h.buildDataPath()
	if dataPath == "" {
		render.Error(w, http.StatusBadRequest, "no_data", "No data path configured. Sync CloudTrail logs first.")
		return
	}

	svc := NewService(h.cfg)
	read := fmt.Sprintf(`read_json('%s**/*.json', maximum_object_size=16777216, auto_detect=true, union_by_name=true)`, dataPath)

	result := &LookupValues{}

	// Access Keys
	cols, rows, err := svc.executeDuckDB(r.Context(), fmt.Sprintf(
		`SELECT DISTINCT r.userIdentity.accessKeyId as val FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.accessKeyId IS NOT NULL ORDER BY val LIMIT 100;`, read))
	if err == nil {
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				result.AccessKeys = append(result.AccessKeys, fmt.Sprint(row[0]))
			}
		}
	}
	_ = cols

	// Source IPs
	_, rows, err = svc.executeDuckDB(r.Context(), fmt.Sprintf(
		`SELECT r.sourceIPAddress as val, COUNT(*) as cnt FROM (SELECT unnest(Records) as r FROM %s) WHERE r.sourceIPAddress IS NOT NULL GROUP BY val ORDER BY cnt DESC LIMIT 50;`, read))
	if err == nil {
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				result.SourceIPs = append(result.SourceIPs, fmt.Sprint(row[0]))
			}
		}
	}

	// Identities (ARNs)
	_, rows, err = svc.executeDuckDB(r.Context(), fmt.Sprintf(
		`SELECT r.userIdentity.arn as val, COUNT(*) as cnt FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.arn IS NOT NULL GROUP BY val ORDER BY cnt DESC LIMIT 50;`, read))
	if err == nil {
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				result.Identities = append(result.Identities, fmt.Sprint(row[0]))
			}
		}
	}

	// Accounts
	_, rows, err = svc.executeDuckDB(r.Context(), fmt.Sprintf(
		`SELECT DISTINCT r.recipientAccountId as val FROM (SELECT unnest(Records) as r FROM %s) WHERE r.recipientAccountId IS NOT NULL ORDER BY val;`, read))
	if err == nil {
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				result.Accounts = append(result.Accounts, fmt.Sprint(row[0]))
			}
		}
	}

	// Roles
	_, rows, err = svc.executeDuckDB(r.Context(), fmt.Sprintf(
		`SELECT DISTINCT r.userIdentity.sessionContext.sessionIssuer.userName as val FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.sessionContext.sessionIssuer.userName IS NOT NULL ORDER BY val LIMIT 50;`, read))
	if err == nil {
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				result.Roles = append(result.Roles, fmt.Sprint(row[0]))
			}
		}
	}

	render.JSON(w, http.StatusOK, result)
}

func (h *LookupsHandler) buildDataPath() string {
	if h.cfg.S3.Bucket == "" {
		return ""
	}

	if len(h.cfg.S3.MemberAccounts) > 1 {
		if h.cfg.S3.Mode == "control_tower" && h.cfg.S3.OrgID != "" {
			return fmt.Sprintf("%s/s3/%s/%s/AWSLogs/%s/",
				h.cfg.DataDir, h.cfg.S3.Bucket, h.cfg.S3.OrgID, h.cfg.S3.OrgID)
		}
		return fmt.Sprintf("%s/s3/%s/AWSLogs/", h.cfg.DataDir, h.cfg.S3.Bucket)
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
