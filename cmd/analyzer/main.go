package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/database"
	"cloudtrail-analyzer/internal/features/accounts"
	"cloudtrail-analyzer/internal/features/nlquery"
	"cloudtrail-analyzer/internal/features/processor"
	"cloudtrail-analyzer/internal/features/prompts"
	"cloudtrail-analyzer/internal/features/sessions"
	"cloudtrail-analyzer/internal/features/settings"
	"cloudtrail-analyzer/internal/middleware"
	"cloudtrail-analyzer/internal/render"
	"cloudtrail-analyzer/internal/startup"

	"github.com/go-chi/chi/v5"
)

var version = "dev"

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Session-credential method: STS tokens are short-lived and MUST NOT be
	// persisted across restarts. If a previous (insecure) build wrote them to
	// config.json, scrub them now and rewrite the file. The user re-applies
	// credentials via Settings → Credentials, which sets env vars in-process.
	if cfg.Auth.Method == "session_credentials" && (cfg.Auth.SessionToken != "" || cfg.Auth.SecretAccessKey != "") {
		cfg.Auth.AccessKeyID = ""
		cfg.Auth.SecretAccessKey = ""
		cfg.Auth.SessionToken = ""
		if err := config.SaveConfig(cfg); err != nil {
			slog.Warn("failed to scrub stale session credentials from config",
				"component", "cloudtrail-analyzer",
				"error", err.Error(),
			)
		} else {
			slog.Info("scrubbed stale session credentials from config",
				"component", "cloudtrail-analyzer",
			)
		}
	}

	// Configure slog level based on config
	var logLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Run startup validation
	startupStatus, err := startup.Validate(cfg)
	if err != nil {
		slog.Error("startup validation failed", "error", err)
		os.Exit(1)
	}

	// Open SQLite database
	db, err := database.NewDB(cfg.DataDir)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Run migrations
	if err := db.RunMigrations(); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Record startup time for uptime calculation
	startedAt := time.Now()

	// Set up Chi router
	r := chi.NewRouter()

	// Apply middleware
	r.Use(middleware.StructuredLogger)
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.CORS)
	r.Use(middleware.Recoverer)

	// Register /api/health endpoint
	r.Get("/api/health", func(w http.ResponseWriter, req *http.Request) {
		uptime := time.Since(startedAt).Seconds()
		render.JSON(w, http.StatusOK, map[string]interface{}{
			"status":  "ok",
			"version": version,
			"uptime":  fmt.Sprintf("%.0fs", uptime),
			"startup": startupStatus,
		})
	})

	// Register /api/settings routes
	settingsHandler := settings.NewHandler(cfg, config.SaveConfig)
	r.Mount("/api/settings", settingsHandler.Routes())

	// Account-name resolver: maps 12-digit account IDs to friendly names from
	// AWS Organizations + user-supplied overrides. Bedrock region is reused as
	// the AWS region for the Organizations endpoint (Organizations is global
	// but the SDK still needs a region to sign).
	orgRegion := cfg.Bedrock.Region
	if orgRegion == "" {
		orgRegion = "us-east-1"
	}
	accountResolver := accounts.NewResolver(db.Conn, settingsHandler.Service().LoadAWSConfig, orgRegion)
	r.Mount("/api/accounts", accounts.NewHandler(accountResolver, cfg).Routes())

	// Best-effort eager refresh: try AWS Organizations on boot but do not block
	// startup or fail it if the principal lacks the permission. The most common
	// startup state for a session_credentials user is "no creds applied yet",
	// in which case this attempt fails and the resolver remembers the failure.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := accountResolver.RefreshOrganizations(ctx, true); err != nil {
			slog.Info("organizations refresh skipped at startup; will retry after credentials are applied",
				"component", "cloudtrail-analyzer",
				"reason", err.Error(),
			)
		}
	}()

	// When the user applies new credentials via the UI, clear the resolver's
	// sticky-failure flag and re-attempt an Organizations refresh in the
	// background. Without this, the resolver would keep skipping refreshes
	// after a startup-time failure even once valid credentials are available.
	settingsHandler.OnAuthChanged(func() {
		accountResolver.OnCredentialsChanged()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := accountResolver.RefreshOrganizations(ctx, true); err != nil {
			slog.Info("organizations refresh after credential update did not succeed; manual mappings only",
				"component", "cloudtrail-analyzer",
				"reason", err.Error(),
			)
		}
	})

	// Register /api/sessions routes
	sessionsHandler := sessions.NewHandler(db.Conn, cfg)
	r.Mount("/api/sessions", sessionsHandler.Routes())

	// One-time backfill: populate disk_usage_bytes for sessions created before the field was wired
	if err := processor.BackfillDiskUsage(db.Conn, cfg.DataDir); err != nil {
		slog.Warn("disk usage backfill failed", "error", err.Error())
	}

	// Register processor routes under /api/sessions/{id}
	processorHandler := processor.NewHandler(db.Conn, cfg)
	r.Post("/api/sessions/{id}/process", processorHandler.StartProcess)
	r.Post("/api/sessions/{id}/cancel", processorHandler.CancelProcess)
	r.Get("/api/sessions/{id}/progress", processorHandler.StreamProgress)
	r.Get("/api/sessions/{id}/progress/snapshot", processorHandler.GetProgress)

	// Register /api/prompts routes
	promptsHandler := prompts.NewHandler(cfg)
	r.Mount("/api/prompts", promptsHandler.Routes())

	// Register /api/nlquery routes (Bedrock-powered NL query execution)
	nlqueryHandler := nlquery.NewHandler(cfg, db.Conn)
	r.Mount("/api/nlquery", nlqueryHandler.Routes())

	// Wire streaming micro-batch indexing: index files as they are extracted
	processorHandler.Service().OnFileExtracted = func(path string, size int64) {
		nlqueryHandler.MicroBatch().AddFile(path, size)
	}

	// Wire sync completion: flush remaining buffer and create B-tree indexes
	processorHandler.Service().OnSyncComplete = func() {
		nlqueryHandler.MicroBatch().Flush()
		dbPath := nlqueryHandler.Indexer().IndexPath()
		if !nlqueryHandler.Indexer().IsIndexed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		indexSQL := `
			CREATE INDEX IF NOT EXISTS idx_event_name ON events ((r.eventName));
			CREATE INDEX IF NOT EXISTS idx_event_source ON events ((r.eventSource));
			CREATE INDEX IF NOT EXISTS idx_error_code ON events ((r.errorCode));
		`
		nlqueryHandler.Indexer().ExecDuckDB(ctx, dbPath, indexSQL)
	}

	// Register /api/dashboard routes (security analytics dashboard)
	dashboardHandler := nlquery.NewDashboardHandler(cfg)
	r.Get("/api/dashboard", dashboardHandler.GetDashboard)
	r.Get("/api/dashboard/findings", dashboardHandler.GetFindings)
	r.Get("/api/dashboard/findings/{id}", dashboardHandler.GetFindingDetail)

	// Register /api/lookups route (auto-populate dropdowns)
	lookupsHandler := nlquery.NewLookupsHandler(cfg)
	r.Get("/api/lookups", lookupsHandler.GetLookups)

	// Register /api/investigate routes (parametrized investigation scenarios)
	investigateHandler := nlquery.NewInvestigateHandler(cfg)
	r.Get("/api/investigate/scenarios", investigateHandler.ListScenarios)
	r.Post("/api/investigate/run", investigateHandler.RunScenario)

	// Serve embedded frontend assets in production, or fallback dev page.
	// The frontendFS embed.FS is rooted at "dist/" inside cmd/analyzer/.
	frontendRoot, embErr := fs.Sub(frontendFS, "dist")
	hasFrontend := embErr == nil
	if hasFrontend {
		// Check that index.html actually exists in the embed (build was run)
		if _, err := fs.Stat(frontendRoot, "index.html"); err != nil {
			hasFrontend = false
		}
	}

	if hasFrontend {
		fileServer := http.FileServer(http.FS(frontendRoot))

		r.NotFound(func(w http.ResponseWriter, req *http.Request) {
			// Unknown /api/* paths return JSON 404
			if strings.HasPrefix(req.URL.Path, "/api/") {
				render.JSON(w, http.StatusNotFound, map[string]string{
					"code":    "NOT_FOUND",
					"message": "endpoint not found",
					"path":    req.URL.Path,
				})
				return
			}

			// Try to serve the exact file (JS, CSS, images, etc.)
			path := strings.TrimPrefix(req.URL.Path, "/")
			if path != "" {
				if _, err := fs.Stat(frontendRoot, path); err == nil {
					fileServer.ServeHTTP(w, req)
					return
				}
			}

			// SPA fallback: serve index.html for all other paths
			indexData, _ := fs.ReadFile(frontendRoot, "index.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write(indexData)
		})
	} else {
		// No embedded frontend — dev mode fallback
		r.NotFound(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/api/") {
				render.JSON(w, http.StatusNotFound, map[string]string{
					"code":    "NOT_FOUND",
					"message": "endpoint not found",
					"path":    req.URL.Path,
				})
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><h1>CloudTrail Analyzer API</h1><p>Use Vite dev server at <a href="http://localhost:5173">http://localhost:5173</a> for the UI.</p></body></html>`))
		})
	}

	// Configure server. Bind to cfg.Host (defaults to 127.0.0.1) so a single-user
	// local tool isn't reachable from the LAN unless the user explicitly opts
	// in by setting host to "0.0.0.0" in config.json.
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: r,
		// Conservative timeouts. WriteTimeout is generous because Bedrock NLQ
		// and DuckDB queries can run for ~minute on large datasets, but capped
		// to bound stuck-client memory. SSE endpoints opt out by writing their
		// own deadlines per-request via http.ResponseController.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // disabled at server level — handlers manage via context
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("starting cloudtrail-analyzer",
			"component", "cloudtrail-analyzer",
			"address", addr,
			"version", version,
			"log_level", cfg.LogLevel,
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down", "component", "cloudtrail-analyzer")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}

	slog.Info("shutdown complete", "component", "cloudtrail-analyzer")
}
