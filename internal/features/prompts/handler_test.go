package prompts

import (
	"testing"

	"cloudtrail-analyzer/internal/config"
)

func TestBuildDataPathOrganizationUsesBucketRoot(t *testing.T) {
	h := NewHandler(&config.Config{
		DataDir: "/data",
		S3: config.S3Config{
			Bucket:    "org-trail-bucket",
			Region:    "us-east-1",
			AccountID: "111111111111",
			Mode:      "control_tower",
			OrgID:     "o-example",
		},
	})

	if got, want := h.buildDataPath(), "/data/s3/org-trail-bucket/"; got != want {
		t.Fatalf("buildDataPath() = %q, want %q", got, want)
	}
}

func TestBuildDataPathSingleAccountStaysNarrow(t *testing.T) {
	h := NewHandler(&config.Config{
		DataDir: "/data",
		S3: config.S3Config{
			Bucket:    "account-trail-bucket",
			Region:    "bucket-region",
			LogRegion: "ap-south-1",
			AccountID: "111111111111",
			Mode:      "single",
		},
	})

	want := "/data/s3/account-trail-bucket/AWSLogs/111111111111/CloudTrail/ap-south-1/"
	if got := h.buildDataPath(); got != want {
		t.Fatalf("buildDataPath() = %q, want %q", got, want)
	}
}
