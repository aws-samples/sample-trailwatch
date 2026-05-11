package processor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cloudtrail-analyzer/internal/features/sessions"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// listObjects lists all .json.gz files in S3 for the session's path and date range.
// Returns the list of objects and total size in bytes.
func listObjects(ctx context.Context, client *s3.Client, session *sessions.Session) ([]S3Object, int64, error) {
	var objects []S3Object
	var totalSize int64

	// Parse date range
	startDate, err := time.Parse("2006-01-02", session.StartDate)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing start_date: %w", err)
	}
	endDate, err := time.Parse("2006-01-02", session.EndDate)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing end_date: %w", err)
	}

	// Iterate over each day in the range
	for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
		prefix := constructS3Prefix(session, d)

		input := &s3.ListObjectsV2Input{
			Bucket: aws.String(session.Bucket),
			Prefix: aws.String(prefix),
		}

		paginator := s3.NewListObjectsV2Paginator(client, input)
		for paginator.HasMorePages() {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}

			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, 0, fmt.Errorf("listing objects at %s: %w", prefix, err)
			}

			for _, obj := range page.Contents {
				if obj.Key == nil {
					continue
				}
				key := *obj.Key
				// Only include .json.gz files
				if strings.HasSuffix(key, ".json.gz") {
					size := obj.Size
					if size != nil {
						objects = append(objects, S3Object{Key: key, Size: *size})
						totalSize += *size
					} else {
						objects = append(objects, S3Object{Key: key, Size: 0})
					}
				}
			}
		}
	}

	return objects, totalSize, nil
}

// downloadFiles downloads S3 objects concurrently using a worker pool.
// It preserves the S3 path structure locally and supports resume by skipping
// files that already exist with matching size.
func downloadFiles(ctx context.Context, client *s3.Client, session *sessions.Session, objects []S3Object, dataDir string, concurrency int, progressCh chan<- ProcessingProgress) error {
	workCh := make(chan S3Object, len(objects))
	var wg sync.WaitGroup

	var filesCompleted atomic.Int64
	var bytesTransferred atomic.Int64
	totalFiles := len(objects)
	var totalBytes int64
	for _, obj := range objects {
		totalBytes += obj.Size
	}

	// Fill work channel
	for _, obj := range objects {
		workCh <- obj
	}
	close(workCh)

	var downloadErr error
	var errOnce sync.Once

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for obj := range workCh {
				if ctx.Err() != nil {
					return
				}

				localPath := constructLocalPath(dataDir, session.Bucket, obj.Key)

				// Resume support: skip if file exists with matching size
				if info, err := os.Stat(localPath); err == nil && info.Size() == obj.Size {
					completed := filesCompleted.Add(1)
					bytesTransferred.Add(obj.Size)
					sendDownloadProgress(progressCh, session.ID, int(completed), totalFiles, bytesTransferred.Load(), totalBytes)
					continue
				}

				// Download the file
				if err := downloadSingleFile(ctx, client, session.Bucket, obj.Key, localPath); err != nil {
					slog.Error("failed to download file",
						"component", "cloudtrail-analyzer",
						"session_id", session.ID,
						"key", obj.Key,
						"error", err.Error(),
					)
					errOnce.Do(func() {
						downloadErr = fmt.Errorf("downloading %s: %w", obj.Key, err)
					})
					return
				}

				completed := filesCompleted.Add(1)
				bytesTransferred.Add(obj.Size)
				sendDownloadProgress(progressCh, session.ID, int(completed), totalFiles, bytesTransferred.Load(), totalBytes)
			}
		}()
	}

	wg.Wait()

	if downloadErr != nil {
		return downloadErr
	}

	return nil
}

// downloadSingleFile downloads a single S3 object to the local filesystem.
func downloadSingleFile(ctx context.Context, client *s3.Client, bucket, key, localPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0700); err != nil { // nosemgrep: incorrect-default-permission
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	// Download from S3
	output, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("GetObject: %w", err)
	}
	defer output.Body.Close()

	// Write to temporary file first, then rename (atomic write)
	tmpPath := localPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	_, err = io.Copy(f, output.Body)
	if closeErr := f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("writing file: %w", err)
	}

	// Rename temp file to final path
	if err := os.Rename(tmpPath, localPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}

// constructS3Prefix builds the S3 prefix for a given session and date.
func constructS3Prefix(session *sessions.Session, date time.Time) string {
	dateStr := date.Format("2006/01/02")

	if session.Mode == "control_tower" && session.OrgID != "" {
		return fmt.Sprintf("%s/AWSLogs/%s/%s/CloudTrail/%s/%s/",
			session.OrgID, session.OrgID, session.AccountID, session.LogRegion, dateStr)
	}

	return fmt.Sprintf("AWSLogs/%s/CloudTrail/%s/%s/",
		session.AccountID, session.LogRegion, dateStr)
}

// constructLocalPath builds the local filesystem path for a downloaded S3 object.
// Pattern: {dataDir}/s3/{bucket}/{s3Key}
func constructLocalPath(dataDir, bucket, s3Key string) string {
	return filepath.Join(dataDir, "s3", bucket, s3Key)
}

// sendDownloadProgress sends a download progress event.
func sendDownloadProgress(ch chan<- ProcessingProgress, sessionID string, completed, total int, bytesTransferred, totalBytes int64) {
	var pct float64
	if totalBytes > 0 {
		pct = float64(bytesTransferred) / float64(totalBytes) * 100
	}

	select {
	case ch <- ProcessingProgress{
		SessionID:        sessionID,
		Phase:            "downloading",
		FilesCompleted:   completed,
		TotalFiles:       total,
		BytesTransferred: bytesTransferred,
		TotalBytes:       totalBytes,
		Percentage:       pct,
		Message:          fmt.Sprintf("Downloaded %d/%d files", completed, total),
	}:
	default:
	}
}
