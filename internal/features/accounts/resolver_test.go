package accounts

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	_ "modernc.org/sqlite"
)

// newTestDB returns an in-memory SQLite with the migration applied.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`
		CREATE TABLE account_names (
			account_id TEXT NOT NULL,
			name       TEXT NOT NULL,
			source     TEXT NOT NULL CHECK (source IN ('organizations', 'manual')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (account_id, source)
		);
	`)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

// failingLoader is the AWSConfigLoader used in tests that should never call AWS.
func failingLoader(_ context.Context, _ string) (aws.Config, error) {
	return aws.Config{}, errors.New("loader should not have been called")
}

func TestResolveMany_ReturnsUnresolvedForUnknownIDs(t *testing.T) {
	db := newTestDB(t)
	r := NewResolver(db, failingLoader, "")

	out, err := r.ResolveMany(context.Background(), []string{"111111111111", "222222222222"})
	if err != nil {
		t.Fatalf("ResolveMany: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	for _, e := range out {
		if e.Source != "unresolved" {
			t.Errorf("expected unresolved, got %q", e.Source)
		}
		if e.Name != "" {
			t.Errorf("expected empty name, got %q", e.Name)
		}
	}
}

func TestResolveMany_PreservesInputOrder(t *testing.T) {
	db := newTestDB(t)
	r := NewResolver(db, failingLoader, "")

	ids := []string{"333", "111", "222"}
	out, _ := r.ResolveMany(context.Background(), ids)
	for i, e := range out {
		if e.AccountID != ids[i] {
			t.Errorf("position %d: want %s, got %s", i, ids[i], e.AccountID)
		}
	}
}

func TestSetManualAndResolve(t *testing.T) {
	db := newTestDB(t)
	r := NewResolver(db, failingLoader, "")

	if err := r.SetManual(context.Background(), "247083000413", "prod-payments"); err != nil {
		t.Fatalf("SetManual: %v", err)
	}
	e, err := r.ResolveOne(context.Background(), "247083000413")
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "prod-payments" || e.Source != SourceManual {
		t.Errorf("unexpected entry %+v", e)
	}
}

func TestSetManual_EmptyNameDeletes(t *testing.T) {
	db := newTestDB(t)
	r := NewResolver(db, failingLoader, "")

	_ = r.SetManual(context.Background(), "247083000413", "prod-payments")
	if err := r.SetManual(context.Background(), "247083000413", ""); err != nil {
		t.Fatalf("delete: %v", err)
	}
	e, _ := r.ResolveOne(context.Background(), "247083000413")
	if e.Source != "unresolved" {
		t.Errorf("expected unresolved after delete, got %q (%q)", e.Source, e.Name)
	}
}

func TestManualOverridesOrganizations(t *testing.T) {
	db := newTestDB(t)
	r := NewResolver(db, failingLoader, "")

	// Simulate an Org-sourced entry...
	_, err := db.Exec(`
		INSERT INTO account_names (account_id, name, source) VALUES (?, ?, ?)
	`, "247083000413", "Production Payments LLC", SourceOrganizations)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// ...then a manual override.
	if err := r.SetManual(context.Background(), "247083000413", "prod-payments"); err != nil {
		t.Fatalf("SetManual: %v", err)
	}
	e, _ := r.ResolveOne(context.Background(), "247083000413")
	if e.Name != "prod-payments" {
		t.Errorf("expected manual override 'prod-payments', got %q (source=%q)", e.Name, e.Source)
	}
	if e.Source != SourceManual {
		t.Errorf("expected source manual, got %q", e.Source)
	}
}

func TestClearingManualFallsBackToOrganizations(t *testing.T) {
	db := newTestDB(t)
	r := NewResolver(db, failingLoader, "")

	_, _ = db.Exec(`
		INSERT INTO account_names (account_id, name, source) VALUES (?, ?, ?)
	`, "247083000413", "Production Payments LLC", SourceOrganizations)
	_ = r.SetManual(context.Background(), "247083000413", "prod-payments")
	_ = r.SetManual(context.Background(), "247083000413", "")

	e, _ := r.ResolveOne(context.Background(), "247083000413")
	if e.Source != SourceOrganizations {
		t.Errorf("expected fallback to organizations, got %q (%q)", e.Source, e.Name)
	}
	if e.Name != "Production Payments LLC" {
		t.Errorf("expected original org name preserved, got %q", e.Name)
	}
}

func TestListManual_OnlyManualEntries(t *testing.T) {
	db := newTestDB(t)
	r := NewResolver(db, failingLoader, "")

	_, _ = db.Exec(`INSERT INTO account_names (account_id, name, source) VALUES (?, ?, ?)`,
		"111", "Org Name 1", SourceOrganizations)
	_ = r.SetManual(context.Background(), "222", "manual-2")
	_ = r.SetManual(context.Background(), "333", "manual-3")

	got, err := r.ListManual(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 manual entries, got %d", len(got))
	}
	for _, e := range got {
		if e.Source != SourceManual {
			t.Errorf("ListManual returned non-manual entry %+v", e)
		}
	}
}

func TestSetManual_RejectsEmptyAccountID(t *testing.T) {
	db := newTestDB(t)
	r := NewResolver(db, failingLoader, "")
	if err := r.SetManual(context.Background(), "", "x"); err == nil {
		t.Error("expected error for empty account_id")
	}
}

func TestOnCredentialsChanged_ClearsStickyFailure(t *testing.T) {
	db := newTestDB(t)
	calls := 0
	loader := func(_ context.Context, _ string) (aws.Config, error) {
		calls++
		return aws.Config{}, errors.New("simulated AccessDenied")
	}
	r := NewResolver(db, loader, "us-east-1")

	// First call fails, sticky failure latches.
	_, _ = r.RefreshOrganizations(context.Background(), false)
	// Second unforced call should be a no-op.
	_, _ = r.RefreshOrganizations(context.Background(), false)
	if calls != 1 {
		t.Fatalf("setup: expected 1 call, got %d", calls)
	}

	// Auth surface changes — caller signals the resolver.
	r.OnCredentialsChanged()

	// Next unforced refresh should attempt again, since the sticky flag was cleared.
	_, _ = r.RefreshOrganizations(context.Background(), false)
	if calls != 2 {
		t.Errorf("expected resolver to retry after OnCredentialsChanged, got %d calls", calls)
	}
}

func TestRefreshOrganizations_HonorsTTLAndStickyFailure(t *testing.T) {
	db := newTestDB(t)
	calls := 0
	loader := func(_ context.Context, _ string) (aws.Config, error) {
		calls++
		return aws.Config{}, errors.New("simulated AccessDenied")
	}
	r := NewResolver(db, loader, "us-east-1")

	// First call: hits the loader, returns error.
	_, err := r.RefreshOrganizations(context.Background(), false)
	if err == nil {
		t.Fatal("expected error from failing loader")
	}
	// Second call: should be a no-op because we remembered the failure.
	_, err = r.RefreshOrganizations(context.Background(), false)
	if err != nil {
		t.Errorf("expected no-op success on sticky failure, got %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 loader call, got %d", calls)
	}
	// Forced call: bypasses the gate and tries again.
	_, _ = r.RefreshOrganizations(context.Background(), true)
	if calls != 2 {
		t.Errorf("expected 2 loader calls after force, got %d", calls)
	}
}
