// Package migrations exposes the SQLite schema migrations embedded in the
// application binary.
package migrations

import "embed"

// FS contains every numbered SQL migration in this directory.
//
//go:embed *.sql
var FS embed.FS
