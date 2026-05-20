package nlquery

import (
	"fmt"
	"net/http"
	"strings"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"
)

type InvestigateHandler struct {
	cfg *config.Config
}

func NewInvestigateHandler(cfg *config.Config) *InvestigateHandler {
	return &InvestigateHandler{cfg: cfg}
}

type InvestigateRequest struct {
	ScenarioID string             `json:"scenario_id"`
	Param      string             `json:"param"`
	Filters    InvestigateFilters `json:"filters,omitempty"`
}

// InvestigateFilters carries the toolbar context (time window + account
// scope) so every scenario inherits the responder's chosen pivots without
// each scenario's SQL changing. Empty fields mean "no constraint" — e.g.,
// no time_start means "from the beginning of the indexed data".
type InvestigateFilters struct {
	// TimeStart and TimeEnd are RFC3339 timestamps or YYYY-MM-DD dates.
	// Inclusive on both sides. Empty string means unbounded.
	TimeStart string `json:"time_start,omitempty"`
	TimeEnd   string `json:"time_end,omitempty"`
	// AccountIDs restricts to events whose recipientAccountId or
	// userIdentity.accountId is in this set. Empty list means no account
	// restriction (matches whatever data is on disk).
	AccountIDs []string `json:"account_ids,omitempty"`
}

func (h *InvestigateHandler) RunScenario(w http.ResponseWriter, r *http.Request) {
	var req InvestigateRequest
	if !render.DecodeStrictJSON(w, r, &req) {
		return
	}
	if req.ScenarioID == "" {
		render.Error(w, http.StatusBadRequest, "missing_scenario", "scenario_id is required")
		return
	}

	dataPath := h.buildDataPath()
	if dataPath == "" {
		render.Error(w, http.StatusBadRequest, "no_data", "No CloudTrail data available. Sync logs first via S3 Sync.")
		return
	}

	sql := h.buildSQL(req.ScenarioID, req.Param, dataPath, req.Filters)
	if sql == "" {
		render.Error(w, http.StatusNotFound, "unknown_scenario", fmt.Sprintf("Scenario %q not found", req.ScenarioID))
		return
	}

	svc := NewService(h.cfg)
	cols, rows, err := svc.executeDuckDB(r.Context(), sql)
	resp := map[string]interface{}{
		"scenario_id": req.ScenarioID,
		"param":       req.Param,
		"sql":         sql,
		"columns":     cols,
		"rows":        rows,
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	render.JSON(w, http.StatusOK, resp)
}

func (h *InvestigateHandler) ListScenarios(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, http.StatusOK, scenarios)
}

type Scenario struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	ParamType   string `json:"param_type"` // "none", "access_key", "ip", "account", "identity", "role"
	ParamLabel  string `json:"param_label,omitempty"`
	Severity    string `json:"severity"`
}

var scenarios = []Scenario{
	// --- IAM Activity ---
	{ID: "iam-write-ops", Name: "IAM Write Operations", Category: "IAM Activity", Description: "All write operations to IAM (Create/Delete/Put/Attach policies, users, roles)", ParamType: "none", Severity: "HIGH"},
	{ID: "iam-read-by-key", Name: "IAM Activity by Access Key", Category: "IAM Activity", Description: "All IAM read/list operations performed using a specific access key", ParamType: "access_key", ParamLabel: "Access Key ID", Severity: "MEDIUM"},
	{ID: "iam-users-created", Name: "Created IAM Users", Category: "IAM Activity", Description: "All CreateUser events — who created which user, when, from where", ParamType: "none", Severity: "HIGH"},
	{ID: "iam-users-deleted", Name: "Deleted IAM Users", Category: "IAM Activity", Description: "All DeleteUser events — who deleted which user", ParamType: "none", Severity: "MEDIUM"},
	// --- Access Denied ---
	{ID: "access-denied-all", Name: "All Access Denied Events", Category: "Access Denied", Description: "Every AccessDenied/UnauthorizedOperation grouped by identity", ParamType: "none", Severity: "HIGH"},
	{ID: "access-denied-by-identity", Name: "Access Denied by Identity", Category: "Access Denied", Description: "All denied API calls for a specific identity", ParamType: "identity", ParamLabel: "Identity ARN", Severity: "HIGH"},
	// --- IP Investigation ---
	{ID: "activity-by-ip", Name: "All Activity from IP", Category: "IP Investigation", Description: "Every API call from a specific source IP address", ParamType: "ip", ParamLabel: "Source IP Address", Severity: "MEDIUM"},
	{ID: "ip-to-identity-map", Name: "IP to Identity Mapping", Category: "IP Investigation", Description: "Which identities used each source IP — detect credential sharing", ParamType: "none", Severity: "MEDIUM"},
	// --- Compute Activity ---
	{ID: "ec2-instances-created", Name: "EC2 Instances Created", Category: "Compute Activity", Description: "All RunInstances events — instance types, who launched, AMI used", ParamType: "none", Severity: "HIGH"},
	{ID: "describe-vpc-ec2-sg", Name: "VPC/EC2/SG Describe Calls", Category: "Compute Activity", Description: "Reconnaissance — Describe calls to VPC, EC2, EBS, Security Groups", ParamType: "none", Severity: "MEDIUM"},
	{ID: "large-instances", Name: "Large/Expensive Instances", Category: "Compute Activity", Description: "EC2 instances launched with large instance types (*.xlarge and above)", ParamType: "none", Severity: "HIGH"},
	// --- Cross-Account ---
	{ID: "cross-account-all", Name: "Cross-Account Activity", Category: "Cross-Account", Description: "All API calls where source account differs from target account", ParamType: "none", Severity: "HIGH"},
	{ID: "cross-account-by-account", Name: "Activity from Specific Account", Category: "Cross-Account", Description: "All actions performed by principals from a specific source account", ParamType: "account", ParamLabel: "Source Account ID", Severity: "HIGH"},
	{ID: "cross-account-role-assumptions", Name: "Cross-Account Role Assumptions", Category: "Cross-Account", Description: "AssumeRole calls where caller is from a different account", ParamType: "none", Severity: "MEDIUM"},
	// --- Data Access ---
	{ID: "s3-data-access", Name: "S3 Data Access", Category: "Data Access", Description: "GetObject, PutObject, DeleteObject — who accessed what buckets", ParamType: "none", Severity: "MEDIUM"},
	{ID: "secrets-accessed", Name: "Secrets & Keys Accessed", Category: "Data Access", Description: "GetSecretValue, Decrypt, GetParameter — sensitive data retrieval", ParamType: "none", Severity: "HIGH"},
	// --- Role Investigation ---
	{ID: "activity-by-role", Name: "Activity by Role", Category: "Role Investigation", Description: "All API calls made by a specific IAM role", ParamType: "role", ParamLabel: "Role Name", Severity: "MEDIUM"},
	{ID: "role-across-accounts", Name: "Role Used Across Accounts", Category: "Role Investigation", Description: "Roles assumed from multiple different accounts — lateral movement", ParamType: "none", Severity: "HIGH"},
	// --- Console Activity ---
	{ID: "console-logins", Name: "Console Login Activity", Category: "Console Activity", Description: "All console sign-in events (success and failure)", ParamType: "none", Severity: "MEDIUM"},
	{ID: "console-logins-failed", Name: "Failed Console Logins", Category: "Console Activity", Description: "Failed sign-in attempts — brute force indicators", ParamType: "none", Severity: "HIGH"},

	// ===== GuardDuty-Aligned Findings (CloudTrail-Detectable) =====

	// --- Credential Access (GuardDuty: CredentialAccess:IAMUser) ---
	{ID: "gd-credential-harvesting", Name: "Credential Harvesting APIs", Category: "Credential Access", Description: "GetPasswordData, GetSecretValue, GenerateDbAuthToken — credential theft indicators", ParamType: "none", Severity: "CRITICAL"},
	{ID: "gd-access-key-created-persistence", Name: "Access Keys Created (Persistence)", Category: "Credential Access", Description: "CreateAccessKey events — attackers create keys for persistent access", ParamType: "none", Severity: "HIGH"},

	// --- Defense Evasion (GuardDuty: DefenseEvasion:IAMUser) ---
	{ID: "gd-logging-disabled", Name: "Logging/Monitoring Disabled", Category: "Defense Evasion", Description: "StopLogging, DeleteTrail, DeleteFlowLogs, DisableAlarmActions — covering tracks", ParamType: "none", Severity: "CRITICAL"},
	{ID: "gd-password-policy-weakened", Name: "Password Policy Weakened", Category: "Defense Evasion", Description: "UpdateAccountPasswordPolicy or DeleteAccountPasswordPolicy — reducing security controls", ParamType: "none", Severity: "HIGH"},
	{ID: "gd-guardduty-disabled", Name: "GuardDuty/SecurityHub Disabled", Category: "Defense Evasion", Description: "DeleteDetector, DisableOrganizationAdminAccount, BatchDisableStandards — disabling detection", ParamType: "none", Severity: "CRITICAL"},

	// --- Discovery/Recon (GuardDuty: Discovery:IAMUser, Recon:IAMUser) ---
	{ID: "gd-recon-enumeration", Name: "Resource Enumeration (Recon)", Category: "Discovery", Description: "High volume of List/Describe/Get calls from single identity — reconnaissance activity", ParamType: "none", Severity: "MEDIUM"},
	{ID: "gd-recon-by-identity", Name: "Recon Activity by Identity", Category: "Discovery", Description: "All List/Describe/Get calls by a specific identity — what did they enumerate?", ParamType: "identity", ParamLabel: "Identity ARN", Severity: "MEDIUM"},

	// --- Exfiltration (GuardDuty: Exfiltration:IAMUser) ---
	{ID: "gd-snapshot-exfil", Name: "Snapshot/Backup Exfiltration", Category: "Exfiltration", Description: "CreateSnapshot, CopySnapshot, ModifySnapshotAttribute, ShareImage — data staging for exfil", ParamType: "none", Severity: "CRITICAL"},
	{ID: "gd-s3-replication", Name: "S3 Replication/Copy (Exfil)", Category: "Exfiltration", Description: "PutBucketReplication, CopyObject to external — data leaving the account", ParamType: "none", Severity: "HIGH"},

	// --- Impact (GuardDuty: Impact:IAMUser, Impact:S3) ---
	{ID: "gd-destructive-actions", Name: "Destructive Actions", Category: "Impact", Description: "Delete* operations on critical resources — EC2, RDS, S3, IAM, CloudFormation", ParamType: "none", Severity: "CRITICAL"},
	{ID: "gd-s3-public-access", Name: "S3 Bucket Made Public", Category: "Impact", Description: "PutBucketPolicy, PutBucketAcl, PutObjectAcl, DeletePublicAccessBlock — exposing data", ParamType: "none", Severity: "CRITICAL"},

	// --- Persistence (GuardDuty: Persistence:IAMUser) ---
	{ID: "gd-persistence-mechanisms", Name: "Persistence Mechanisms", Category: "Persistence", Description: "CreateAccessKey, ImportKeyPair, CreateLoginProfile, CreateUser — maintaining access", ParamType: "none", Severity: "HIGH"},
	{ID: "gd-network-persistence", Name: "Network Backdoors", Category: "Persistence", Description: "AuthorizeSecurityGroupIngress, CreateVpcPeeringConnection — network persistence", ParamType: "none", Severity: "HIGH"},

	// --- Privilege Escalation (GuardDuty: PrivilegeEscalation:IAMUser) ---
	{ID: "gd-privesc-iam", Name: "Privilege Escalation (IAM)", Category: "Privilege Escalation", Description: "PutUserPolicy, PutRolePolicy, AttachRolePolicy, AddUserToGroup, CreatePolicyVersion — escalating permissions", ParamType: "none", Severity: "CRITICAL"},
	{ID: "gd-privesc-assume-role", Name: "Suspicious Role Assumptions", Category: "Privilege Escalation", Description: "AssumeRole to admin/powerful roles from unexpected sources", ParamType: "none", Severity: "HIGH"},

	// --- Policy Violations (GuardDuty: Policy:IAMUser) ---
	{ID: "gd-root-usage", Name: "Root Account Usage", Category: "Policy Violation", Description: "Any API call made by the root user — critical security violation", ParamType: "none", Severity: "CRITICAL"},
	{ID: "gd-s3-block-public-disabled", Name: "S3 Block Public Access Disabled", Category: "Policy Violation", Description: "DeletePublicAccessBlock or PutPublicAccessBlock with permissive settings", ParamType: "none", Severity: "HIGH"},

	// --- Unauthorized Access (GuardDuty: UnauthorizedAccess:IAMUser) ---
	{ID: "gd-console-multi-geo", Name: "Console Login from Multiple Geos", Category: "Unauthorized Access", Description: "Same user logging in from multiple IPs — possible credential compromise", ParamType: "none", Severity: "HIGH"},
	{ID: "gd-instance-cred-exfil", Name: "Instance Credential Exfiltration", Category: "Unauthorized Access", Description: "EC2 instance role credentials used from external IPs — stolen IMDS credentials", ParamType: "none", Severity: "CRITICAL"},

	// --- PenTest Detection (GuardDuty: PenTest:IAMUser) ---
	{ID: "gd-pentest-tools", Name: "Penetration Testing Tools", Category: "PenTest Detection", Description: "API calls from Kali Linux, Parrot Linux, Pentoo, or known pentest user agents", ParamType: "none", Severity: "HIGH"},
}

// buildFilteredEventsExpr returns a DuckDB table-expression that scenarios
// embed via `FROM %s`. The expression unnests the CloudTrail Records array
// and applies the toolbar's time + account filters, so every scenario
// inherits those constraints without each scenario's SQL string having to
// know about them.
//
// When no filters are set, the expression is the unfiltered unnest, exactly
// matching the pre-toolbar behavior.
//
// Filter semantics:
//   - TimeStart / TimeEnd: r.eventTime BETWEEN start AND end. Stored as
//     ISO-8601 strings inside CloudTrail records, so a string comparison
//     against YYYY-MM-DD or RFC3339 inputs works correctly.
//   - AccountIDs: matches if EITHER recipientAccountId OR
//     userIdentity.accountId is in the list. We match both because the
//     "account that owns the event" depends on the event type (cross-account
//     calls for instance) and responders typically want both perspectives.
//
// Single-quote-escapes user-supplied strings via SQL doubling. The list of
// account IDs is also stripped to digit-only via isValidAccountID before
// reaching here in the handler — see RunScenario.
func buildFilteredEventsExpr(rawRead string, f InvestigateFilters) string {
	base := fmt.Sprintf(`(SELECT unnest(Records) as r FROM %s)`, rawRead)

	var conds []string
	if ts := strings.TrimSpace(f.TimeStart); ts != "" {
		conds = append(conds, fmt.Sprintf("r.eventTime >= '%s'", strings.ReplaceAll(ts, "'", "''")))
	}
	if te := strings.TrimSpace(f.TimeEnd); te != "" {
		conds = append(conds, fmt.Sprintf("r.eventTime <= '%s'", strings.ReplaceAll(te, "'", "''")))
	}
	if len(f.AccountIDs) > 0 {
		var quoted []string
		for _, id := range f.AccountIDs {
			id = strings.TrimSpace(id)
			if !isValidAccountID(id) {
				continue
			}
			quoted = append(quoted, "'"+id+"'")
		}
		if len(quoted) > 0 {
			list := strings.Join(quoted, ", ")
			conds = append(conds,
				fmt.Sprintf("(r.recipientAccountId IN (%s) OR r.userIdentity.accountId IN (%s))", list, list))
		}
	}

	if len(conds) == 0 {
		return base
	}
	return fmt.Sprintf("(SELECT * FROM %s WHERE %s)", base, strings.Join(conds, " AND "))
}

// isValidAccountID is the same shape check used in the accounts handler —
// 12 digits, nothing else. Defends the SQL string against injection via the
// AccountIDs list even though all callers should be passing pre-validated
// values.
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

func (h *InvestigateHandler) buildSQL(scenarioID, param, dataPath string, filters InvestigateFilters) string {
	// Build the filtered, unnested events table-expression once. Every
	// scenario consumes it via `FROM %s` so toolbar context (time window +
	// account scope) is applied uniformly without each scenario's SQL string
	// having to know about it.
	rawRead := fmt.Sprintf(`read_json('%s**/*.json', maximum_object_size=16777216, auto_detect=true, union_by_name=true)`, dataPath)
	events := buildFilteredEventsExpr(rawRead, filters)
	safeParam := strings.ReplaceAll(param, "'", "''")

	switch scenarioID {
	case "iam-write-ops":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.recipientAccountId as account, r.sourceIPAddress, r.eventTime, r.errorCode FROM %s WHERE r.eventSource = 'iam.amazonaws.com' AND r.readOnly = 'false' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "iam-read-by-key":
		return fmt.Sprintf(`SELECT r.eventName, r.eventSource, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime FROM %s WHERE r.userIdentity.accessKeyId = '%s' AND r.eventSource = 'iam.amazonaws.com' ORDER BY r.eventTime DESC LIMIT 100;`, events, safeParam)

	case "iam-users-created":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as creator, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName = 'CreateUser' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "iam-users-deleted":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName = 'DeleteUser' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "access-denied-all":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.eventName, r.eventSource, r.recipientAccountId as account, r.sourceIPAddress, COUNT(*) as count FROM %s WHERE r.errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation') GROUP BY r.userIdentity.arn, r.eventName, r.eventSource, r.recipientAccountId, r.sourceIPAddress ORDER BY count DESC LIMIT 100;`, events)

	case "access-denied-by-identity":
		return fmt.Sprintf(`SELECT r.eventName, r.eventSource, r.errorCode, r.errorMessage, r.recipientAccountId as account, r.sourceIPAddress, r.eventTime FROM %s WHERE r.errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation') AND r.userIdentity.arn = '%s' ORDER BY r.eventTime DESC LIMIT 100;`, events, safeParam)

	case "activity-by-ip":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.eventName, r.eventSource, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.sourceIPAddress = '%s' ORDER BY r.eventTime DESC LIMIT 100;`, events, safeParam)

	case "ip-to-identity-map":
		return fmt.Sprintf(`SELECT r.sourceIPAddress as ip, r.userIdentity.arn as identity, COUNT(*) as call_count, MIN(r.eventTime) as first_seen, MAX(r.eventTime) as last_seen FROM %s WHERE r.sourceIPAddress IS NOT NULL AND r.sourceIPAddress NOT LIKE '%%.amazonaws.com' GROUP BY r.sourceIPAddress, r.userIdentity.arn ORDER BY call_count DESC LIMIT 100;`, events)

	case "ec2-instances-created":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as launcher, r.sourceIPAddress, r.recipientAccountId as account, r.awsRegion, r.eventTime, r.errorCode FROM %s WHERE r.eventName = 'RunInstances' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "describe-vpc-ec2-sg":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as identity, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime FROM %s WHERE r.eventName IN ('DescribeInstances', 'DescribeSecurityGroups', 'DescribeVpcs', 'DescribeSubnets', 'DescribeVolumes', 'DescribeNetworkInterfaces', 'DescribeAddresses') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "large-instances":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as launcher, r.sourceIPAddress, r.recipientAccountId as account, r.awsRegion, r.eventTime, r.errorCode FROM %s WHERE r.eventName = 'RunInstances' AND r.errorCode IS NULL ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "cross-account-all":
		return fmt.Sprintf(`SELECT r.userIdentity.accountId as source_account, r.recipientAccountId as target_account, r.userIdentity.arn as identity, r.eventName, r.eventSource, r.sourceIPAddress, r.eventTime FROM %s WHERE r.userIdentity.accountId IS NOT NULL AND r.recipientAccountId IS NOT NULL AND r.userIdentity.accountId != r.recipientAccountId ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "cross-account-by-account":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.eventName, r.eventSource, r.recipientAccountId as target_account, r.sourceIPAddress, r.eventTime, r.errorCode FROM %s WHERE r.userIdentity.accountId = '%s' AND r.recipientAccountId IS NOT NULL AND r.recipientAccountId != '%s' ORDER BY r.eventTime DESC LIMIT 100;`, events, safeParam, safeParam)

	case "cross-account-role-assumptions":
		return fmt.Sprintf(`SELECT r.userIdentity.accountId as source_account, r.recipientAccountId as target_account, r.userIdentity.arn as caller, r.sourceIPAddress, r.eventTime, r.errorCode FROM %s WHERE r.eventName = 'AssumeRole' AND r.userIdentity.accountId IS NOT NULL AND r.recipientAccountId IS NOT NULL AND r.userIdentity.accountId != r.recipientAccountId ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "s3-data-access":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as identity, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventSource = 's3.amazonaws.com' AND r.eventName IN ('GetObject', 'PutObject', 'DeleteObject', 'CopyObject') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "secrets-accessed":
		return fmt.Sprintf(`SELECT r.eventName, r.eventSource, r.userIdentity.arn as identity, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('GetSecretValue', 'Decrypt', 'GetParameter', 'GetParameters', 'GetParametersByPath') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "activity-by-role":
		return fmt.Sprintf(`SELECT r.eventName, r.eventSource, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.userIdentity.sessionContext.sessionIssuer.userName = '%s' ORDER BY r.eventTime DESC LIMIT 100;`, events, safeParam)

	case "role-across-accounts":
		return fmt.Sprintf(`SELECT r.userIdentity.sessionContext.sessionIssuer.userName as role_name, r.userIdentity.accountId as source_account, r.recipientAccountId as target_account, COUNT(*) as call_count FROM %s WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.accountId IS NOT NULL AND r.recipientAccountId IS NOT NULL AND r.userIdentity.accountId != r.recipientAccountId GROUP BY role_name, source_account, target_account ORDER BY call_count DESC LIMIT 50;`, events)

	case "console-logins":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorMessage FROM %s WHERE r.eventName = 'ConsoleLogin' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "console-logins-failed":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorMessage FROM %s WHERE r.eventName = 'ConsoleLogin' AND r.errorMessage IS NOT NULL ORDER BY r.eventTime DESC LIMIT 100;`, events)

	// ===== GuardDuty-Aligned Findings =====

	case "gd-credential-harvesting":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as identity, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('GetPasswordData', 'GetSecretValue', 'BatchGetSecretValue', 'GenerateDbAuthToken', 'GetAuthorizationToken', 'RequestCertificate') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-access-key-created-persistence":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as creator, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName = 'CreateAccessKey' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-logging-disabled":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'DeleteFlowLogs', 'DisableAlarmActions', 'DeleteAlarms', 'PutEventSelectors', 'DeleteEventDataStore') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-password-policy-weakened":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('UpdateAccountPasswordPolicy', 'DeleteAccountPasswordPolicy') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-guardduty-disabled":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('DeleteDetector', 'DisableOrganizationAdminAccount', 'DeleteMembers', 'BatchDisableStandards', 'DisableSecurityHub', 'DeleteInsight') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-recon-enumeration":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as identity, COUNT(*) as api_calls, COUNT(DISTINCT r.eventName) as unique_apis, COUNT(DISTINCT r.eventSource) as services_probed, r.recipientAccountId as account FROM %s WHERE (r.eventName LIKE 'List%%' OR r.eventName LIKE 'Describe%%' OR r.eventName LIKE 'Get%%') AND r.userIdentity.invokedBy IS NULL GROUP BY r.userIdentity.arn, r.recipientAccountId HAVING COUNT(*) > 50 ORDER BY api_calls DESC LIMIT 50;`, events)

	case "gd-recon-by-identity":
		return fmt.Sprintf(`SELECT r.eventName, r.eventSource, r.recipientAccountId as account, r.sourceIPAddress, r.eventTime FROM %s WHERE r.userIdentity.arn = '%s' AND (r.eventName LIKE 'List%%' OR r.eventName LIKE 'Describe%%' OR r.eventName LIKE 'Get%%') ORDER BY r.eventTime DESC LIMIT 100;`, events, safeParam)

	case "gd-snapshot-exfil":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('CreateSnapshot', 'CopySnapshot', 'ModifySnapshotAttribute', 'CreateDBSnapshot', 'CopyDBSnapshot', 'ModifyDBSnapshotAttribute', 'ShareImage', 'ModifyImageAttribute') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-s3-replication":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('PutBucketReplication', 'PutReplicationConfiguration', 'CopyObject') AND r.eventSource = 's3.amazonaws.com' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-destructive-actions":
		return fmt.Sprintf(`SELECT r.eventName, r.eventSource, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('TerminateInstances', 'DeleteDBInstance', 'DeleteDBCluster', 'DeleteBucket', 'DeleteStack', 'DeleteUser', 'DeleteRole', 'DeletePolicy', 'DeleteSecurityGroup', 'DeleteSubnet', 'DeleteVpc', 'DeleteFunction20150331') AND r.errorCode IS NULL ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-s3-public-access":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('PutBucketPolicy', 'PutBucketAcl', 'PutObjectAcl', 'DeletePublicAccessBlock', 'PutPublicAccessBlock', 'PutBucketPublicAccessBlock') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-persistence-mechanisms":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('CreateAccessKey', 'ImportKeyPair', 'CreateLoginProfile', 'UpdateLoginProfile', 'CreateUser', 'CreateRole', 'CreateInstanceProfile') AND r.errorCode IS NULL ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-network-persistence":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('AuthorizeSecurityGroupIngress', 'CreateVpcPeeringConnection', 'AcceptVpcPeeringConnection', 'CreateNetworkAclEntry', 'ReplaceNetworkAclEntry', 'CreateRoute', 'AttachInternetGateway') AND r.errorCode IS NULL ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-privesc-iam":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy', 'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', 'AddUserToGroup', 'CreatePolicyVersion', 'SetDefaultPolicyVersion') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-privesc-assume-role":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as caller, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime, r.errorCode FROM %s WHERE r.eventName IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity') AND r.userIdentity.invokedBy IS NULL ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-root-usage":
		return fmt.Sprintf(`SELECT r.eventName, r.eventSource, r.sourceIPAddress, r.recipientAccountId as account, r.userAgent, r.eventTime, r.errorCode FROM %s WHERE r.userIdentity."type" = 'Root' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-s3-block-public-disabled":
		return fmt.Sprintf(`SELECT r.eventName, r.userIdentity.arn as actor, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime FROM %s WHERE r.eventName IN ('DeletePublicAccessBlock', 'PutPublicAccessBlock') ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-console-multi-geo":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as identity, COUNT(DISTINCT r.sourceIPAddress) as unique_ips, COUNT(*) as login_count FROM %s WHERE r.eventName = 'ConsoleLogin' GROUP BY r.userIdentity.arn HAVING COUNT(DISTINCT r.sourceIPAddress) > 1 ORDER BY unique_ips DESC LIMIT 50;`, events)

	case "gd-instance-cred-exfil":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as role_arn, r.userIdentity.sessionContext.sessionIssuer.userName as role_name, r.sourceIPAddress, r.eventName, r.recipientAccountId as account, r.eventTime FROM %s WHERE r.userIdentity."type" = 'AssumedRole' AND r.userIdentity.invokedBy IS NULL AND r.sourceIPAddress NOT LIKE '10.%%' AND r.sourceIPAddress NOT LIKE '172.%%' AND r.sourceIPAddress NOT LIKE '192.168.%%' AND r.sourceIPAddress NOT LIKE '%%.amazonaws.com' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	case "gd-pentest-tools":
		return fmt.Sprintf(`SELECT r.userIdentity.arn as identity, r.userAgent, r.eventName, r.sourceIPAddress, r.recipientAccountId as account, r.eventTime FROM %s WHERE r.userAgent LIKE '%%kali%%' OR r.userAgent LIKE '%%Kali%%' OR r.userAgent LIKE '%%parrot%%' OR r.userAgent LIKE '%%Parrot%%' OR r.userAgent LIKE '%%pentoo%%' OR r.userAgent LIKE '%%Pentoo%%' OR r.userAgent LIKE '%%pacu%%' OR r.userAgent LIKE '%%Pacu%%' OR r.userAgent LIKE '%%prowler%%' OR r.userAgent LIKE '%%ScoutSuite%%' ORDER BY r.eventTime DESC LIMIT 100;`, events)

	default:
		return ""
	}
}

func (h *InvestigateHandler) buildDataPath() string {
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
