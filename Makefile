# CloudTrail Analyzer — Build System
# Single binary with embedded React frontend

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BINARY := cloudtrail-analyzer
DIST := ./dist
WEB_DIST := web/dist

.PHONY: build build-all frontend embed-assets test test-race lint clean run dev install

## dev: Start both Go API server and Vite frontend with one command (Ctrl+C stops both)
dev:
	@echo "Starting CloudTrail Analyzer (dev mode)..."
	@echo "  → API server:  http://localhost:7070"
	@echo "  → Frontend:    http://localhost:5173"
	@echo ""
	@trap 'kill 0' EXIT; \
		(cd web && npx vite) & \
		go run -ldflags "-X main.version=$(VERSION)" ./cmd/analyzer & \
		wait

## build: Build frontend, copy to embed location, then compile Go binary with embedded assets
build: frontend embed-assets
	@echo "Building Go binary (version: $(VERSION))..."
	@mkdir -p $(DIST)
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(DIST)/$(BINARY) ./cmd/analyzer
	@echo ""
	@echo "Done → $(DIST)/$(BINARY)"
	@echo "Run with: ./$(DIST)/$(BINARY)"

## build-all: Build for both Linux AMD64 and ARM64 (Graviton)
build-all: frontend embed-assets
	@echo "Building multi-arch binaries (version: $(VERSION))..."
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(DIST)/$(BINARY)-linux-arm64 ./cmd/analyzer
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(DIST)/$(BINARY)-linux-amd64 ./cmd/analyzer
	@echo ""
	@echo "Done:"
	@echo "  ARM64 (Graviton) → $(DIST)/$(BINARY)-linux-arm64"
	@echo "  AMD64 (Intel)    → $(DIST)/$(BINARY)-linux-amd64"

## install: Install all dependencies (Go + Node)
install:
	@echo "Installing Go dependencies..."
	go mod download
	@echo "Installing frontend dependencies..."
	@# Use npm ci so the install honours package-lock.json exactly, matching
	@# deploy.sh and avoiding lockfile drift between dev and deploy.
	cd web && npm ci
	@echo "Done."

## embed-assets: Copy frontend build output to cmd/analyzer/dist/ for go:embed
embed-assets:
	@echo "Copying frontend assets for embedding..."
	@rm -rf cmd/analyzer/dist
	@cp -r $(WEB_DIST) cmd/analyzer/dist
	@# Recreate the empty .gitkeep so the working tree stays clean after a build.
	@# go:embed needs the dist/ directory to exist at compile time; .gitkeep
	@# is the marker that keeps the directory tracked when it is otherwise empty.
	@touch cmd/analyzer/dist/.gitkeep

## frontend: Build React app to web/dist/
frontend:
	@echo "Building frontend..."
	cd web && npm run build

## test: Run Go and frontend tests
test:
	@echo "Running Go tests (with race detector)..."
	go test -race ./...
	@echo "Running frontend tests..."
	cd web && npm test

## test-race: Run Go tests with the race detector only (no frontend)
test-race:
	@echo "Running Go tests with race detector..."
	go test -race ./...

## lint: Check formatting (gofmt) and run go vet
lint:
	@echo "Checking gofmt..."
	@unformatted="$$(gofmt -l . 2>/dev/null)"; \
		if [ -n "$$unformatted" ]; then \
			echo "These files are not gofmt-clean:"; \
			echo "$$unformatted"; \
			echo "Run: gofmt -w ."; \
			exit 1; \
		fi
	@echo "Running go vet..."
	go vet ./...
	@echo "Lint passed."

## clean: Remove build artifacts (keeps cmd/analyzer/dist/.gitkeep that go:embed needs)
clean:
	@echo "Cleaning..."
	rm -rf $(DIST)
	rm -rf $(WEB_DIST)
	@# go:embed requires cmd/analyzer/dist to exist at compile time, with
	@# .gitkeep as the tracked marker. Remove the built assets but recreate
	@# the directory and its .gitkeep so a subsequent `go build` still works.
	rm -rf cmd/analyzer/dist
	@mkdir -p cmd/analyzer/dist
	@touch cmd/analyzer/dist/.gitkeep

## run: Build production binary and execute
run: build
	$(DIST)/$(BINARY)
