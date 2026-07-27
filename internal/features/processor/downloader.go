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

	"cloudtrail-analyzer/internal/cloudtrailpath"
	"cloudtrail-analyzer/internal/features/sessions"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// listObjects lists all .json.gz files in S3 for the session's path and date range.
// Returns the list of objects and total size in bytes.
//
// IMPORTANT — delivery date vs event time: CloudTrail partitions log files by
// the UTC *delivery* date (the day CloudTrail wrote the file to S3), which is
// encoded in the S3 prefix as .../CloudTrail/{region}/{YYYY}/{MM}/{DD}/. The
// session's StartDate/EndDate select that delivery-date partition, NOT the
// eventTime of the records inside. Because CloudTrail can batch and deliver an
// event up to ~15 minutes (occasionally longer) after it occurs, an event that
// happened just before a UTC midnight boundary may be delivered into the next
// day's partition. As a result, a single-day sync can miss a few records near
// the day boundary, and event-time filtering applied later (in queries) should
// be paired with a slightly wider sync window when boundary completeness
// matters. This is a known limitation of partitioning by delivery date.
func listObjects(ctx context.Context, client s3.ListObjectsV2APIClient, session *sessions.Session) ([]S3Object, int64, error) {
	var objects []S3Object
	var totalSize int64
	seenObjects := make(map[string]struct{})

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
		var firstErr error
		listedCandidate := false
		for _, prefix := range constructS3Prefixes(session, d) {
			prefixObjects, err := listObjectsAtPrefix(ctx, client, session.Bucket, prefix)
			if err != nil {
				if ctx.Err() != nil {
					return nil, 0, ctx.Err()
				}
				if firstErr == nil {
					firstErr = fmt.Errorf("listing objects at %s: %w", prefix, err)
				}
				continue
			}
			listedCandidate = true
			if len(prefixObjects) == 0 {
				continue
			}
			for _, object := range prefixObjects {
				if _, exists := seenObjects[object.Key]; exists {
					continue
				}
				seenObjects[object.Key] = struct{}{}
				objects = append(objects, object)
				totalSize += object.Size
			}
			// A trail writes one layout at a time. Prefer the standard
			// Organizations layout and use legacy layouts only as fallbacks so
			// migrated copies are not indexed twice.
			break
		}
		if !listedCandidate && firstErr != nil {
			return nil, 0, firstErr
		}
	}

	return objects, totalSize, nil
}

func listObjectsAtPrefix(
	ctx context.Context,
	client s3.ListObjectsV2APIClient,
	bucket, prefix string,
) ([]S3Object, error) {
	var objects []S3Object
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if key == "" || !strings.HasSuffix(key, ".json.gz") {
				continue
			}
			objects = append(objects, S3Object{Key: key, Size: aws.ToInt64(obj.Size)})
		}
	}
	return objects, nil
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
//
// This is the single write chokepoint for both the download-only and the
// pipelined download+extract paths, so the zip-slip / path-traversal guard
// (N25) lives here: an S3 key containing a ".." segment or an absolute path
// could otherwise resolve to a localPath OUTSIDE the data dir. We reject such
// keys before creating any directory or file.
func downloadSingleFile(ctx context.Context, client *s3.Client, bucket, key, localPath string) error {
	if hasUnsafeKeySegment(key) {
		return fmt.Errorf("refusing to write S3 key with unsafe path segment: %q", key)
	}

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

	// Write to a unique temporary file first, then rename atomically. A fixed
	// ".tmp" path lets overlapping syncs truncate or rename each other's work.
	f, err := os.CreateTemp(dir, "."+filepath.Base(localPath)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	_, err = io.Copy(f, output.Body)
	if closeErr := f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	// Rename temp file to final path
	if err := os.Rename(tmpPath, localPath); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}

// constructS3Prefixes builds every supported S3 prefix for a session and date.
func constructS3Prefixes(session *sessions.Session, date time.Time) []string {
	return cloudtrailpath.DatePrefixes(
		session.Mode,
		session.OrgID,
		session.AccountID,
		session.LogRegion,
		date,
	)
}

// constructS3Prefix returns the primary prefix retained for callers that only
// need the original single-account or legacy Control Tower layout.
func constructS3Prefix(session *sessions.Session, date time.Time) string {
	return constructS3Prefixes(session, date)[0]
}

// constructLocalPath builds the local filesystem path for a downloaded S3 object.
// Pattern: {dataDir}/s3/{bucket}/{s3Key}
//
// The returned path is NOT yet validated for containment: the S3 object key is
// attacker-influenceable (a malicious or misconfigured bucket can return keys
// containing ".." segments), so callers MUST route the actual write through
// downloadSingleFile, which validates the key against path traversal before
// touching the filesystem (zip-slip guard, N25). filepath.Join cleans the
// joined path, so a key like "../../etc/x" would otherwise resolve OUTSIDE the
// data dir — hence the guard at the single write chokepoint.
func constructLocalPath(dataDir, bucket, s3Key string) string {
	return filepath.Join(dataDir, "s3", bucket, s3Key)
}

// hasUnsafeKeySegment reports whether the slash-separated S3 key is unsafe to
// join under the data dir: an absolute key, or one containing a ".." parent
// segment, would let the local write escape {dataDir}/s3/{bucket} (zip-slip /
// path traversal). S3 uses "/" as its key separator independent of the host
// OS, so we split on "/" regardless of platform.
func hasUnsafeKeySegment(key string) bool {
	if strings.HasPrefix(key, "/") {
		return true
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
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
