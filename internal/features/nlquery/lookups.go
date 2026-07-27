package nlquery

import (
	"fmt"
	"net/http"
	"strings"

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
	// dataPath is assembled from config-derived values (S3 bucket, org_id,
	// account_id, region) which settings accept with only an emptiness check.
	// Escape the assembled path before it lands inside the read_json('...')
	// literal so a single quote in any component cannot break out of the
	// literal and bypass the read-only allowlist (H6).
	read := fmt.Sprintf(`read_json('%s**/*.json', maximum_object_size=%d, auto_detect=true, union_by_name=true)`, escapeSQLLiteral(dataPath), maxObjectSize)

	// When a member-account subset is selected, scope the lookups to those
	// accounts (N33). buildDataPath points at the bucket/org root in that case,
	// so without this filter the lookups would aggregate over every synced
	// account. The subset is appended as an AND clause to each query's WHERE.
	scope := memberAccountScope(h.cfg)

	result := &LookupValues{}

	// Access Keys
	cols, rows, err := svc.executeDuckDB(r.Context(), fmt.Sprintf(
		`SELECT DISTINCT r.userIdentity.accessKeyId as val FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.accessKeyId IS NOT NULL%s ORDER BY val LIMIT 100;`, read, scope))
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
		`SELECT r.sourceIPAddress as val, COUNT(*) as cnt FROM (SELECT unnest(Records) as r FROM %s) WHERE r.sourceIPAddress IS NOT NULL%s GROUP BY val ORDER BY cnt DESC LIMIT 50;`, read, scope))
	if err == nil {
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				result.SourceIPs = append(result.SourceIPs, fmt.Sprint(row[0]))
			}
		}
	}

	// Identities (ARNs)
	_, rows, err = svc.executeDuckDB(r.Context(), fmt.Sprintf(
		`SELECT r.userIdentity.arn as val, COUNT(*) as cnt FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.arn IS NOT NULL%s GROUP BY val ORDER BY cnt DESC LIMIT 50;`, read, scope))
	if err == nil {
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				result.Identities = append(result.Identities, fmt.Sprint(row[0]))
			}
		}
	}

	// Accounts
	_, rows, err = svc.executeDuckDB(r.Context(), fmt.Sprintf(
		`SELECT DISTINCT r.recipientAccountId as val FROM (SELECT unnest(Records) as r FROM %s) WHERE r.recipientAccountId IS NOT NULL%s ORDER BY val;`, read, scope))
	if err == nil {
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				result.Accounts = append(result.Accounts, fmt.Sprint(row[0]))
			}
		}
	}

	// Roles
	_, rows, err = svc.executeDuckDB(r.Context(), fmt.Sprintf(
		`SELECT DISTINCT r.userIdentity.sessionContext.sessionIssuer.userName as val FROM (SELECT unnest(Records) as r FROM %s) WHERE r.userIdentity.sessionContext.sessionIssuer.userName IS NOT NULL%s ORDER BY val LIMIT 50;`, read, scope))
	if err == nil {
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				result.Roles = append(result.Roles, fmt.Sprint(row[0]))
			}
		}
	}

	render.JSON(w, http.StatusOK, result)
}

// memberAccountScope constrains an organization-root scan to the configured
// member selection. Organization paths always start at the bucket mirror so
// they work for both standard Organizations and Control Tower layouts; the
// predicate is therefore required even when exactly one member is selected.
// Single-account mode remains scoped by its narrow filesystem path.
func memberAccountScope(cfg *config.Config) string {
	if !usesOrganizationQueryRoot(cfg) {
		return ""
	}
	ids := scopeAccountIDs(cfg)
	quoted := make([]string, 0, len(ids))
	for _, id := range ids {
		quoted = append(quoted, quoteSQLLiteral(id))
	}
	if len(quoted) == 0 {
		return ""
	}
	return fmt.Sprintf(" AND r.recipientAccountId IN (%s)", strings.Join(quoted, ", "))
}

func (h *LookupsHandler) buildDataPath() string {
	return localQueryRoot(h.cfg)
}
