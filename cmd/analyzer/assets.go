package main

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// embeddedDist holds the production frontend bundle. The directory is
// populated by the build pipeline (deploy.sh / Makefile) which runs
// `npm run build` and copies web/dist/ here before `go build`. When the
// directory is empty (e.g. during dev work where the frontend is served
// by Vite on :5173), the handler falls back to a small placeholder page.
//
// The `all:dist` pattern includes files starting with `_` and `.`, which
// Vite emits for source maps and asset hashes. Without `all:`, Go's embed
// silently skips them and the production page breaks.
//
//go:embed all:dist
var embeddedDist embed.FS

// distFS returns the rooted dist filesystem (with the leading "dist/"
// directory removed) plus a flag indicating whether real assets were found.
// The flag lets main.go pick between serving the SPA and rendering the
// dev-mode placeholder.
func distFS() (fs.FS, bool) {
	sub, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		return nil, false
	}
	// Probe for index.html — empty embed (dev builds) returns an FS but with
	// no real files, and we want to fall back to the placeholder in that case.
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}

// spaHandler serves the embedded React SPA. Paths that match a real file in
// the bundle (e.g. /assets/index-xxx.js) are served as that file. Anything
// else falls through to index.html so React Router can resolve the route on
// the client. /api/* paths are NOT routed here — main.go registers the chi
// /api routes first and only falls through to this handler for unmatched
// paths.
func spaHandler(distRoot fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(distRoot))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Defence-in-depth: never let an /api/* request reach the SPA. The
		// chi router prevents this in normal operation, but the explicit
		// check guards against router misconfiguration.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		clean := path.Clean(r.URL.Path)
		if clean == "/" || clean == "." {
			serveIndex(w, r, distRoot)
			return
		}

		// Try the requested asset first.
		trimmed := strings.TrimPrefix(clean, "/")
		if _, err := fs.Stat(distRoot, trimmed); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Unknown path — let React Router handle it on the client.
				serveIndex(w, r, distRoot)
				return
			}
			http.Error(w, "static asset error", http.StatusInternalServerError)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// serveIndex writes the SPA's index.html with no-cache headers so the user
// always gets the latest deployed bundle (the hashed asset filenames inside
// index.html are themselves cache-friendly).
func serveIndex(w http.ResponseWriter, r *http.Request, distRoot fs.FS) {
	data, err := fs.ReadFile(distRoot, "index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
