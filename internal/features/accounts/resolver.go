// Package accounts resolves AWS account IDs to human-friendly names.
//
// Names come from two sources:
//   - AWS Organizations ListAccounts (source = "organizations"). Accurate but
//     requires `organizations:ListAccounts` permission on the calling principal,
//     and only works inside an Organization.
//   - User-supplied manual mapping (source = "manual"). Edited via Settings.
//
// At read time, manual entries win: an Org refresh never silently overwrites a
// deliberate user override. Both rows are kept in the cache so the original Org
// name is recoverable if the manual override is later cleared.
package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

// Source values stored in account_names.source.
const (
	SourceOrganizations = "organizations"
	SourceManual        = "manual"
)

// orgRefreshTTL bounds how often the resolver hits AWS Organizations.
// Single-user POC; 24h is plenty.
const orgRefreshTTL = 24 * time.Hour

// AWSConfigLoader returns an AWS config bound to the given region using whichever
// auth method the caller has configured. Mirrors the closure-style indirection
// already used elsewhere in the app to avoid pulling settings.Service into this
// package.
type AWSConfigLoader func(ctx context.Context, region string) (aws.Config, error)

// Entry is one row in the resolver's response.
type Entry struct {
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
	Source    string `json:"source"` // "organizations" | "manual" | "unresolved"
}

// Resolver is the read/write face for account-name lookups.
//
// Concurrency: the underlying SQLite handle is goroutine-safe (modernc/sqlite
// uses per-connection mutexes), but ResolveMany takes a copy of the cache into
// a map per call and is safe to invoke from many goroutines.
type Resolver struct {
	db        *sql.DB
	loadAWS   AWSConfigLoader
	region    string // region for the Organizations endpoint
	mu        sync.Mutex
	lastOrg   time.Time
	orgFailed bool // sticky once we've seen AccessDenied; avoids repeated calls
}

// NewResolver creates a resolver bound to the given SQLite handle and AWS config
// loader. region is the AWS region to use for the Organizations API call;
// Organizations is a global service but the SDK still needs a region to sign.
// "us-east-1" is the safe default.
func NewResolver(db *sql.DB, loadAWS AWSConfigLoader, region string) *Resolver {
	if region == "" {
		region = "us-east-1"
	}
	return &Resolver{db: db, loadAWS: loadAWS, region: region}
}

// ResolveMany looks up names for the given account IDs. It does not call AWS;
// callers wanting fresh Org data should call RefreshOrganizations first
// (typically eagerly at startup, lazily on first miss).
//
// Order in the response matches the input order. Unknown IDs come back with
// Name == "" and Source == "unresolved".
func (r *Resolver) ResolveMany(ctx context.Context, ids []string) ([]Entry, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	cache, err := r.loadCache(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(ids))
	for _, id := range ids {
		out = append(out, mergeEntry(id, cache[id]))
	}
	return out, nil
}

// ResolveOne is a convenience wrapper around ResolveMany.
func (r *Resolver) ResolveOne(ctx context.Context, id string) (Entry, error) {
	out, err := r.ResolveMany(ctx, []string{id})
	if err != nil {
		return Entry{}, err
	}
	if len(out) == 0 {
		return Entry{AccountID: id, Source: "unresolved"}, nil
	}
	return out[0], nil
}

// SetManual upserts a user-supplied mapping. Empty name removes the manual entry.
func (r *Resolver) SetManual(ctx context.Context, accountID, name string) error {
	if accountID == "" {
		return errors.New("account_id is required")
	}
	if name == "" {
		_, err := r.db.ExecContext(ctx,
			`DELETE FROM account_names WHERE account_id = ? AND source = ?`,
			accountID, SourceManual,
		)
		return err
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO account_names (account_id, name, source, updated_at)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT(account_id, source) DO UPDATE SET
			name = excluded.name,
			updated_at = excluded.updated_at
	`, accountID, name, SourceManual)
	return err
}

// ListManual returns every manual override the user has configured. Used by the
// Settings UI.
func (r *Resolver) ListManual(ctx context.Context) ([]Entry, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT account_id, name FROM account_names WHERE source = ? ORDER BY account_id
	`, SourceManual)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.AccountID, &e.Name); err != nil {
			return nil, err
		}
		e.Source = SourceManual
		out = append(out, e)
	}
	return out, rows.Err()
}

// RefreshOrganizations calls AWS Organizations ListAccounts and upserts every
// returned account into the cache as source="organizations". Returns the count
// of accounts learned. force=true bypasses the in-memory TTL gate; otherwise
// the call is skipped if the last successful refresh was within orgRefreshTTL.
//
// Failures are logged and remembered so subsequent unforced calls become
// no-ops; the resolver still serves whatever cache and manual entries exist.
func (r *Resolver) RefreshOrganizations(ctx context.Context, force bool) (int, error) {
	r.mu.Lock()
	if !force && time.Since(r.lastOrg) < orgRefreshTTL {
		r.mu.Unlock()
		return 0, nil
	}
	if !force && r.orgFailed {
		r.mu.Unlock()
		return 0, nil
	}
	r.mu.Unlock()

	awsCfg, err := r.loadAWS(ctx, r.region)
	if err != nil {
		r.mu.Lock()
		r.orgFailed = true
		r.mu.Unlock()
		return 0, fmt.Errorf("loading aws config: %w", err)
	}
	client := organizations.NewFromConfig(awsCfg)

	count := 0
	var token *string
	for {
		out, err := client.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: token})
		if err != nil {
			r.mu.Lock()
			r.orgFailed = true
			r.mu.Unlock()
			slog.Warn("organizations list_accounts failed; account names will fall back to manual mappings",
				"component", "cloudtrail-analyzer",
				"error", err.Error(),
			)
			return count, err
		}
		for _, a := range out.Accounts {
			if a.Id == nil || a.Name == nil {
				continue
			}
			if _, err := r.db.ExecContext(ctx, `
				INSERT INTO account_names (account_id, name, source, updated_at)
				VALUES (?, ?, ?, datetime('now'))
				ON CONFLICT(account_id, source) DO UPDATE SET
					name = excluded.name,
					updated_at = excluded.updated_at
			`, *a.Id, *a.Name, SourceOrganizations); err != nil {
				return count, fmt.Errorf("upserting account %s: %w", *a.Id, err)
			}
			count++
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}

	r.mu.Lock()
	r.lastOrg = time.Now()
	r.orgFailed = false
	r.mu.Unlock()

	slog.Info("organizations cache refreshed",
		"component", "cloudtrail-analyzer",
		"accounts", count,
	)
	return count, nil
}

// loadCache reads every row from account_names into a per-id map keyed by
// account ID. Each value contains both the manual name (if any) and the org
// name (if any) so mergeEntry can apply the precedence rule.
type cacheRow struct {
	manual string
	org    string
}

func (r *Resolver) loadCache(ctx context.Context) (map[string]cacheRow, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT account_id, name, source FROM account_names`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cache := map[string]cacheRow{}
	for rows.Next() {
		var id, name, source string
		if err := rows.Scan(&id, &name, &source); err != nil {
			return nil, err
		}
		row := cache[id]
		switch source {
		case SourceManual:
			row.manual = name
		case SourceOrganizations:
			row.org = name
		}
		cache[id] = row
	}
	return cache, rows.Err()
}

// mergeEntry applies the read-time precedence rule.
func mergeEntry(id string, row cacheRow) Entry {
	switch {
	case row.manual != "":
		return Entry{AccountID: id, Name: row.manual, Source: SourceManual}
	case row.org != "":
		return Entry{AccountID: id, Name: row.org, Source: SourceOrganizations}
	default:
		return Entry{AccountID: id, Source: "unresolved"}
	}
}
