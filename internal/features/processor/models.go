package processor

// ProcessingProgress represents the current state of a processing pipeline.
type ProcessingProgress struct {
	SessionID        string  `json:"session_id"`
	Phase            string  `json:"phase"` // "listing" | "downloading" | "extracting" | "verifying"
	FilesCompleted   int     `json:"files_completed"`
	TotalFiles       int     `json:"total_files"`
	BytesTransferred int64   `json:"bytes_transferred"`
	TotalBytes       int64   `json:"total_bytes"`
	Percentage       float64 `json:"percentage"`
	EstimatedETA     int     `json:"estimated_eta_seconds"`
	Message          string  `json:"message"`
}

// DiskEstimate represents the disk space requirements for a session.
type DiskEstimate struct {
	S3SizeBytes    int64 `json:"s3_size_bytes"`
	RequiredBytes  int64 `json:"required_bytes"` // 2.5x S3 size (compressed + extracted)
	AvailableBytes int64 `json:"available_bytes"`
	Sufficient     bool  `json:"sufficient"`
}

// S3Object represents a single object in S3.
type S3Object struct {
	Key  string
	Size int64
}
