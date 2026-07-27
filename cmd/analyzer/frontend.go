package main

import (
	"embed"
	"io/fs"
)

//go:embed dist/*
var frontendFS embed.FS

// FrontendEmbedded reports whether a real frontend build was embedded into the
// binary. The embed directive always matches at least the committed .gitkeep,
// so the presence of dist/* alone does not mean the SPA was built. We treat the
// existence of dist/index.html as the signal that `npm run build` ran before
// `go build` and produced servable assets.
//
// In dev mode (make dev / go run) no Vite build runs, so this returns false and
// the server serves an API-only placeholder pointing at the Vite dev server.
// In a production build (make build / deploy.sh) the Makefile runs the frontend
// build first, so a false result there means the embed silently captured only
// .gitkeep — a broken binary that would otherwise serve a placeholder with no
// build error. main.go logs a prominent warning and surfaces this in /api/health.
func FrontendEmbedded() bool {
	sub, err := fs.Sub(frontendFS, "dist")
	if err != nil {
		return false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return false
	}
	return true
}
