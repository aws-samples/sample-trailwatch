package sessions

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloudtrail-analyzer/internal/config"

	_ "modernc.org/sqlite"
)

func newSessionTestService(t *testing.T) (*Service, *sql.DB, *config.Config) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE sessions (
		id TEXT PRIMARY KEY, bucket TEXT NOT NULL, account_id TEXT NOT NULL,
		org_id TEXT NOT NULL DEFAULT '', region TEXT NOT NULL, log_region TEXT NOT NULL,
		mode TEXT NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL,
		state TEXT NOT NULL, total_files INTEGER, disk_usage_bytes INTEGER,
		failed_files TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		DataDir: t.TempDir(),
		S3: config.S3Config{
			Bucket:    "trail-bucket",
			Region:    "us-east-1",
			AccountID: "123456789012",
			Mode:      "single",
		},
	}
	return NewService(db, cfg), db, cfg
}

func testSession(id string) *Session {
	now := time.Now().UTC()
	return &Session{
		ID: id, Bucket: "trail-bucket", AccountID: "123456789012",
		Region: "us-east-1", LogRegion: "us-east-1", Mode: "single",
		StartDate: "2026-07-01", EndDate: "2026-07-02", State: StateQueryReady,
		FailedFiles: "[]", CreatedAt: now, UpdatedAt: now,
	}
}

func TestDuplicateProcessingClaimsCannotBothSucceed(t *testing.T) {
	_, db, _ := newSessionTestService(t)
	db.SetMaxOpenConns(1)

	session := testSession("session-1")
	session.State = StatePending
	if err := Create(db, session); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	claim := func() {
		<-start
		_, err := ClaimForProcessing(db, session.ID)
		results <- err
	}
	go claim()
	go claim()
	close(start)

	var succeeded int
	for range 2 {
		if err := <-results; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("processing claims succeeded = %d, want exactly 1", succeeded)
	}

	got, err := GetByID(db, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateDownloading {
		t.Fatalf("session state = %q, want %q", got.State, StateDownloading)
	}
}

func TestProcessingAndDeletionClaimsCannotBothSucceed(t *testing.T) {
	_, db, _ := newSessionTestService(t)
	db.SetMaxOpenConns(1)

	session := testSession("session-1")
	session.State = StatePending
	if err := Create(db, session); err != nil {
		t.Fatal(err)
	}

	type claimResult struct {
		claim string
		err   error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	go func() {
		<-start
		_, err := ClaimForProcessing(db, session.ID)
		results <- claimResult{claim: "processing", err: err}
	}()
	go func() {
		<-start
		_, _, err := ClaimForDeletion(db, session.ID)
		results <- claimResult{claim: "deletion", err: err}
	}()
	close(start)

	var winner string
	for range 2 {
		result := <-results
		if result.err == nil {
			if winner != "" {
				t.Fatalf("%s and %s claims both succeeded", winner, result.claim)
			}
			winner = result.claim
		}
	}
	if winner == "" {
		t.Fatal("expected one lifecycle claim to succeed")
	}

	got, err := GetByID(db, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantState := StateDownloading
	if winner == "deletion" {
		wantState = StateDeleted
	}
	if got.State != wantState {
		t.Fatalf("session state = %q, want %q after %s claim", got.State, wantState, winner)
	}
}

func TestCreateSessionRejectsUnsafeScope(t *testing.T) {
	svc, _, _ := newSessionTestService(t)
	req := &CreateSessionRequest{
		AccountID: "../../tmp", LogRegion: "us-east-1",
		StartDate: "2026-07-01", EndDate: "2026-07-01",
	}

	if _, err := svc.CreateSession(context.Background(), req); err == nil {
		t.Fatal("expected unsafe account_id to be rejected")
	}
}

func TestCreateSessionRejectsOrgOverride(t *testing.T) {
	svc, _, cfg := newSessionTestService(t)
	cfg.S3.Mode = "control_tower"
	cfg.S3.OrgID = "o-example1234"
	req := &CreateSessionRequest{
		AccountID: "123456789012", OrgID: "o-different123",
		LogRegion: "us-east-1", StartDate: "2026-07-01", EndDate: "2026-07-01",
	}

	if _, err := svc.CreateSession(context.Background(), req); err == nil {
		t.Fatal("expected request org_id override to be rejected")
	}
}

func TestCreateSessionRejectsOverlappingRange(t *testing.T) {
	svc, db, _ := newSessionTestService(t)
	existing := testSession("existing")
	if err := Create(db, existing); err != nil {
		t.Fatal(err)
	}
	req := &CreateSessionRequest{
		AccountID: "123456789012", LogRegion: "us-east-1",
		StartDate: "2026-07-02", EndDate: "2026-07-03",
	}

	_, err := svc.CreateSession(context.Background(), req)
	if !errors.Is(err, ErrSessionOverlap) {
		t.Fatalf("expected ErrSessionOverlap, got %v", err)
	}
}

func TestLocalSessionPathsAreDateScopedAndContained(t *testing.T) {
	svc, _, cfg := newSessionTestService(t)
	paths, err := svc.localSessionPaths(testSession("session-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("got %d paths, want 2", len(paths))
	}
	want := filepath.Join(cfg.DataDir, "s3", "trail-bucket", "AWSLogs",
		"123456789012", "CloudTrail", "us-east-1", "2026", "07", "01")
	if paths[0] != want {
		t.Fatalf("first path = %q, want %q", paths[0], want)
	}

	unsafe := testSession("session-2")
	unsafe.AccountID = "../../outside"
	if _, err := svc.localSessionPaths(unsafe); !errors.Is(err, ErrUnsafeSessionPath) {
		t.Fatalf("expected ErrUnsafeSessionPath, got %v", err)
	}
}

func TestLocalSessionPathsIncludeEveryOrganizationLayoutWithoutDuplicates(t *testing.T) {
	svc, _, cfg := newSessionTestService(t)
	session := testSession("session-1")
	session.Mode = "control_tower"
	session.OrgID = "o-example1234"
	session.EndDate = session.StartDate

	paths, err := svc.localSessionPaths(session)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(cfg.DataDir, "s3", session.Bucket, "AWSLogs", session.OrgID,
			session.AccountID, "CloudTrail", session.LogRegion, "2026", "07", "01"),
		filepath.Join(cfg.DataDir, "s3", session.Bucket, session.OrgID, "AWSLogs",
			session.OrgID, session.AccountID, "CloudTrail", session.LogRegion, "2026", "07", "01"),
		filepath.Join(cfg.DataDir, "s3", session.Bucket, session.OrgID, "AWSLogs",
			session.AccountID, "CloudTrail", session.LogRegion, "2026", "07", "01"),
	}
	if len(paths) != len(want) {
		t.Fatalf("got %d paths, want %d: %#v", len(paths), len(want), paths)
	}
	seen := make(map[string]struct{}, len(paths))
	for i, path := range paths {
		if path != want[i] {
			t.Errorf("path[%d] = %q, want %q", i, path, want[i])
		}
		if _, exists := seen[path]; exists {
			t.Errorf("duplicate path %q", path)
		}
		seen[path] = struct{}{}
	}
}

func TestDeleteSessionHoldsLeaseUntilFilesAndRowAreDeleted(t *testing.T) {
	svc, db, cfg := newSessionTestService(t)
	session := testSession("session-1")
	session.EndDate = session.StartDate
	if err := Create(db, session); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(cfg.DataDir, "s3", session.Bucket, "AWSLogs", session.AccountID,
		"CloudTrail", session.LogRegion, "2026", "07", "01")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}

	var leaseAcquired, leaseReleased bool
	var fileExistedAtAcquire, rowExistedAtAcquire bool
	var fileRemovedAtRelease, rowRemovedAtRelease bool
	svc.SetDataDeleteLease(func() (func(), error) {
		leaseAcquired = true
		_, fileErr := os.Stat(path)
		fileExistedAtAcquire = fileErr == nil
		_, rowErr := GetByID(db, session.ID)
		rowExistedAtAcquire = rowErr == nil

		return func() {
			leaseReleased = true
			_, fileErr := os.Stat(path)
			fileRemovedAtRelease = os.IsNotExist(fileErr)
			_, rowErr := GetByID(db, session.ID)
			rowRemovedAtRelease = errors.Is(rowErr, ErrNotFound)
		}, nil
	})

	if err := svc.DeleteSession(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	if !leaseAcquired || !leaseReleased {
		t.Fatalf("lease acquired = %t, released = %t; want both true", leaseAcquired, leaseReleased)
	}
	if !fileExistedAtAcquire || !rowExistedAtAcquire {
		t.Fatalf("lease began after cleanup started: file existed = %t, row existed = %t",
			fileExistedAtAcquire, rowExistedAtAcquire)
	}
	if !fileRemovedAtRelease || !rowRemovedAtRelease {
		t.Fatalf("lease released before cleanup completed: file removed = %t, row removed = %t",
			fileRemovedAtRelease, rowRemovedAtRelease)
	}
}

func TestDeleteSessionRemovesEveryOrganizationLayout(t *testing.T) {
	svc, db, cfg := newSessionTestService(t)
	session := testSession("session-1")
	session.Mode = "control_tower"
	session.OrgID = "o-example1234"
	session.EndDate = session.StartDate
	if err := Create(db, session); err != nil {
		t.Fatal(err)
	}

	paths, err := svc.localSessionPaths(session)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "event.json"), []byte(`{"Records":[]}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := filepath.Join(cfg.DataDir, "s3", session.Bucket, "AWSLogs", session.OrgID,
		session.AccountID, "CloudTrail", session.LogRegion, "2026", "07", "02", "event.json")
	if err := os.MkdirAll(filepath.Dir(unrelated), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unrelated, []byte(`{"Records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}

	svc.SetBeforeDataDelete(func() error { return nil })
	if err := svc.DeleteSession(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("organization date path was not removed: %q (stat error: %v)", path, err)
		}
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated date was removed: %v", err)
	}
}

func TestDeleteSessionRejectsOrganizationPathResolvedOutsideDataRoot(t *testing.T) {
	svc, db, cfg := newSessionTestService(t)
	session := testSession("session-1")
	session.Mode = "control_tower"
	session.OrgID = "o-example1234"
	session.EndDate = session.StartDate
	if err := Create(db, session); err != nil {
		t.Fatal(err)
	}

	bucketRoot := filepath.Join(cfg.DataDir, "s3", session.Bucket)
	if err := os.MkdirAll(bucketRoot, 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsideDate := filepath.Join(outside, session.OrgID, session.AccountID, "CloudTrail",
		session.LogRegion, "2026", "07", "01")
	if err := os.MkdirAll(outsideDate, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(outsideDate, "keep.json")
	if err := os.WriteFile(marker, []byte(`{"Records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(bucketRoot, "AWSLogs")); err != nil {
		t.Fatal(err)
	}

	err := svc.DeleteSession(context.Background(), session.ID)
	if !errors.Is(err, ErrUnsafeSessionPath) {
		t.Fatalf("expected ErrUnsafeSessionPath, got %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("file outside data root was removed: %v", err)
	}
	got, err := GetByID(db, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateQueryReady {
		t.Fatalf("session state = %q, want restored state %q", got.State, StateQueryReady)
	}
}

func TestDeleteSessionRestoresPriorStateAfterFailure(t *testing.T) {
	svc, db, _ := newSessionTestService(t)
	session := testSession("session-1")
	session.State = StateInterrupted
	if err := Create(db, session); err != nil {
		t.Fatal(err)
	}

	var stateWhileClaimed SessionState
	svc.SetDataDeleteLease(func() (func(), error) {
		claimed, err := GetByID(db, session.ID)
		if err == nil {
			stateWhileClaimed = claimed.State
		}
		return nil, errors.New("index invalidation failed")
	})

	if err := svc.DeleteSession(context.Background(), session.ID); err == nil {
		t.Fatal("expected deletion to fail")
	}
	if stateWhileClaimed != StateDeleted {
		t.Fatalf("state during deletion = %q, want %q", stateWhileClaimed, StateDeleted)
	}
	got, err := GetByID(db, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateInterrupted {
		t.Fatalf("state after failed deletion = %q, want %q", got.State, StateInterrupted)
	}
}

func TestDeleteSessionRemovesOnlyItsDatesAndInvalidatesIndex(t *testing.T) {
	svc, db, cfg := newSessionTestService(t)
	session := testSession("session-1")
	if err := Create(db, session); err != nil {
		t.Fatal(err)
	}

	base := filepath.Join(cfg.DataDir, "s3", session.Bucket, "AWSLogs", session.AccountID,
		"CloudTrail", session.LogRegion, "2026", "07")
	for _, day := range []string{"01", "02", "03"} {
		if err := os.MkdirAll(filepath.Join(base, day), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, day, "event.json"), []byte(`{"Records":[]}`), 0600); err != nil {
			t.Fatal(err)
		}
	}

	invalidated := false
	svc.SetBeforeDataDelete(func() error {
		invalidated = true
		return nil
	})
	if err := svc.DeleteSession(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	if !invalidated {
		t.Fatal("expected derived index invalidation hook")
	}
	for _, day := range []string{"01", "02"} {
		if _, err := os.Stat(filepath.Join(base, day)); !os.IsNotExist(err) {
			t.Fatalf("expected day %s to be removed, stat err = %v", day, err)
		}
	}
	if _, err := os.Stat(filepath.Join(base, "03", "event.json")); err != nil {
		t.Fatalf("unrelated date was removed: %v", err)
	}
	if _, err := GetByID(db, session.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected session row deletion, got %v", err)
	}
}

func TestDeleteSessionKeepsDataWhenIndexInvalidationFails(t *testing.T) {
	svc, db, cfg := newSessionTestService(t)
	session := testSession("session-1")
	if err := Create(db, session); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.DataDir, "s3", session.Bucket, "AWSLogs", session.AccountID,
		"CloudTrail", session.LogRegion, "2026", "07", "01")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	svc.SetBeforeDataDelete(func() error { return errors.New("index busy") })

	if err := svc.DeleteSession(context.Background(), session.ID); err == nil {
		t.Fatal("expected deletion to fail")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("data should remain after failed invalidation: %v", err)
	}
	if _, err := GetByID(db, session.ID); err != nil {
		t.Fatalf("session row should remain after failed invalidation: %v", err)
	}
}

func TestDeleteSessionPreservesDatesReferencedByHistoricalOverlap(t *testing.T) {
	svc, db, cfg := newSessionTestService(t)
	first := testSession("first")
	if err := Create(db, first); err != nil {
		t.Fatal(err)
	}
	second := testSession("second")
	second.StartDate = "2026-07-02"
	second.EndDate = "2026-07-03"
	if err := Create(db, second); err != nil {
		t.Fatal(err)
	}

	base := filepath.Join(cfg.DataDir, "s3", first.Bucket, "AWSLogs", first.AccountID,
		"CloudTrail", first.LogRegion, "2026", "07")
	for _, day := range []string{"01", "02", "03"} {
		if err := os.MkdirAll(filepath.Join(base, day), 0700); err != nil {
			t.Fatal(err)
		}
	}
	svc.SetBeforeDataDelete(func() error { return nil })

	if err := svc.DeleteSession(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "01")); !os.IsNotExist(err) {
		t.Fatalf("unreferenced day should be removed, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "02")); err != nil {
		t.Fatalf("overlapping day should be retained: %v", err)
	}
}

func TestDeleteSessionChecksOrganizationOverlapOncePerDate(t *testing.T) {
	svc, db, _ := newSessionTestService(t)
	first := testSession("first")
	first.Mode = "control_tower"
	first.OrgID = "o-example1234"
	if err := Create(db, first); err != nil {
		t.Fatal(err)
	}
	second := testSession("second")
	second.Mode = first.Mode
	second.OrgID = first.OrgID
	second.StartDate = "2026-07-02"
	second.EndDate = "2026-07-03"
	if err := Create(db, second); err != nil {
		t.Fatal(err)
	}

	partitions, err := svc.localSessionDatePaths(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(partitions) != 2 {
		t.Fatalf("got %d date partitions, want 2", len(partitions))
	}
	for _, partition := range partitions {
		if len(partition.paths) != 3 {
			t.Fatalf("date %s has %d paths, want 3", partition.date, len(partition.paths))
		}
		for _, path := range partition.paths {
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	svc.SetBeforeDataDelete(func() error { return nil })

	if err := svc.DeleteSession(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	for _, path := range partitions[0].paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("unreferenced date path should be removed: %q (stat error: %v)", path, err)
		}
	}
	for _, path := range partitions[1].paths {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("overlapping date path should be retained: %q (%v)", path, err)
		}
	}
}
