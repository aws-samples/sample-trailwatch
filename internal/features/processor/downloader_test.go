package processor

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"cloudtrail-analyzer/internal/features/sessions"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type listObjectsStub struct {
	calls   []string
	objects map[string][]types.Object
	errs    map[string]error
}

func (s *listObjectsStub) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := aws.ToString(input.Prefix)
	s.calls = append(s.calls, prefix)
	if err := s.errs[prefix]; err != nil {
		return nil, err
	}
	return &s3.ListObjectsV2Output{Contents: s.objects[prefix]}, nil
}

func TestConstructS3PrefixesSupportsCloudTrailLayouts(t *testing.T) {
	date := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)
	const (
		account = "123456789012"
		org     = "o-example1234"
		region  = "us-east-1"
	)

	tests := []struct {
		name    string
		session *sessions.Session
		want    []string
	}{
		{
			name: "single account",
			session: &sessions.Session{
				Mode: "single", AccountID: account, LogRegion: region,
			},
			want: []string{
				"AWSLogs/123456789012/CloudTrail/us-east-1/2026/07/26/",
			},
		},
		{
			name: "organization and control tower",
			session: &sessions.Session{
				Mode: "control_tower", OrgID: org, AccountID: account, LogRegion: region,
			},
			want: []string{
				"AWSLogs/o-example1234/123456789012/CloudTrail/us-east-1/2026/07/26/",
				"o-example1234/AWSLogs/o-example1234/123456789012/CloudTrail/us-east-1/2026/07/26/",
				"o-example1234/AWSLogs/123456789012/CloudTrail/us-east-1/2026/07/26/",
			},
		},
		{
			name: "multi account mode without organization falls back to single account",
			session: &sessions.Session{
				Mode: "control_tower", AccountID: account, LogRegion: region,
			},
			want: []string{
				"AWSLogs/123456789012/CloudTrail/us-east-1/2026/07/26/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := constructS3Prefixes(tt.session, date)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("prefixes = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestListObjectsUsesFirstPopulatedLayout(t *testing.T) {
	session := &sessions.Session{
		Bucket:    "trail-bucket",
		AccountID: "123456789012",
		OrgID:     "o-example1234",
		LogRegion: "us-east-1",
		Mode:      "control_tower",
		StartDate: "2026-07-26",
		EndDate:   "2026-07-26",
	}
	date := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)
	prefixes := constructS3Prefixes(session, date)

	stub := &listObjectsStub{objects: make(map[string][]types.Object)}
	for i, prefix := range prefixes {
		size := int64(i + 1)
		stub.objects[prefix] = []types.Object{
			{Key: aws.String(prefix + "unique.json.gz"), Size: aws.Int64(size)},
			{Key: aws.String(prefix + "digest.json"), Size: aws.Int64(100)},
		}
	}

	objects, totalSize, err := listObjects(context.Background(), stub, session)
	if err != nil {
		t.Fatalf("list objects: %v", err)
	}
	if !slices.Equal(stub.calls, prefixes[:1]) {
		t.Fatalf("listed prefixes = %v, want %v", stub.calls, prefixes[:1])
	}
	if len(objects) != 1 {
		t.Fatalf("object count = %d, want 1: %v", len(objects), objects)
	}
	if totalSize != 1 {
		t.Fatalf("total size = %d, want 1", totalSize)
	}
}

func TestListObjectsFallsBackAcrossEmptyAndInaccessibleLayouts(t *testing.T) {
	session := &sessions.Session{
		Bucket: "trail-bucket", AccountID: "123456789012", OrgID: "o-example1234",
		LogRegion: "us-east-1", Mode: "control_tower",
		StartDate: "2026-07-26", EndDate: "2026-07-26",
	}
	date := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)
	prefixes := constructS3Prefixes(session, date)
	stub := &listObjectsStub{
		objects: map[string][]types.Object{
			prefixes[2]: {
				{Key: aws.String(prefixes[2] + "event.json.gz"), Size: aws.Int64(9)},
			},
		},
		errs: map[string]error{prefixes[0]: errors.New("access denied")},
	}

	objects, totalSize, err := listObjects(context.Background(), stub, session)
	if err != nil {
		t.Fatalf("list objects: %v", err)
	}
	if !slices.Equal(stub.calls, prefixes) {
		t.Fatalf("listed prefixes = %v, want %v", stub.calls, prefixes)
	}
	if len(objects) != 1 || objects[0].Key != prefixes[2]+"event.json.gz" || totalSize != 9 {
		t.Fatalf("objects = %#v, total size = %d", objects, totalSize)
	}
}
