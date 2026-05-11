package sessions

import "time"

// SessionState represents the lifecycle state of a sync session.
type SessionState string

const (
	StatePending           SessionState = "pending"
	StateDownloading       SessionState = "downloading"
	StateExtracting        SessionState = "extracting"
	StateVerifying         SessionState = "verifying"
	StateQueryReady        SessionState = "query-ready"
	StatePartiallyVerified SessionState = "partially-verified"
	StateFailed            SessionState = "failed"
	StateInterrupted       SessionState = "interrupted"
	StateDeleted           SessionState = "deleted"
)

// Session represents a CloudTrail log sync session scoped to a specific
// bucket, account, region, and date range.
type Session struct {
	ID             string       `json:"id"`
	Bucket         string       `json:"bucket"`
	AccountID      string       `json:"account_id"`
	OrgID          string       `json:"org_id,omitempty"`
	Region         string       `json:"region"`
	LogRegion      string       `json:"log_region"`
	Mode           string       `json:"mode"`
	StartDate      string       `json:"start_date"`
	EndDate        string       `json:"end_date"`
	State          SessionState `json:"state"`
	TotalFiles     int          `json:"total_files"`
	DiskUsageBytes int64        `json:"disk_usage_bytes"`
	FailedFiles    string       `json:"failed_files,omitempty"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// CreateSessionRequest is the request body for creating a new sync session.
// Bucket, Region, Mode, and OrgID come from the saved S3 config — not from this request.
type CreateSessionRequest struct {
	AccountID string `json:"account_id" validate:"required"`
	OrgID     string `json:"org_id,omitempty"`
	LogRegion string `json:"log_region" validate:"required"`
	StartDate string `json:"start_date" validate:"required"`
	EndDate   string `json:"end_date" validate:"required"`
}
