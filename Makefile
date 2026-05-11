# CloudTrail Analyzer — Build System
# Single binary with embedded React frontend

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BINARY := cloudtrail-analyzer
DIST := ./dist
WEB_DIST := web/dist

.PHONY: build frontend embed-assets test clean run dev install

## dev: Start both Go API server and Vite frontend with one command (Ctrl+C stops both)
dev:
	@echo "Starting CloudTrail Analyzer (dev mode)..."
	@echo "  → API server:  http://localhost:7070"
	@echo "  → Frontend:    http://localhost:5173"
	@echo ""
	@trap 'kill 0' EXIT; \
		(cd web && npx vite --host 0.0.0.0) & \
		go run -ldflags "-X main.version=$(VERSION)" ./cmd/analyzer & \
		wait

## build: Build frontend, copy to embed location, then compile Go binary with embedded assets
build: frontend embed-assets
	@echo "Building Go binary (version: $(VERSION))..."
	@mkdir -p $(DIST)
	go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/$(BINARY) ./cmd/analyzer
	@echo ""
	@echo "Done → $(DIST)/$(BINARY)"
	@echo "Run with: ./$(DIST)/$(BINARY)"

## install: Install all dependencies (Go + Node)
install:
	@echo "Installing Go dependencies..."
	go mod download
	@echo "Installing frontend dependencies..."
	cd web && npm install
	@echo "Done."

## embed-assets: Copy frontend build output to cmd/analyzer/dist/ for go:embed
embed-assets:
	@echo "Copying frontend assets for embedding..."
	@rm -rf cmd/analyzer/dist
	@cp -r $(WEB_DIST) cmd/analyzer/dist

## frontend: Build React app to web/dist/
frontend:
	@echo "Building frontend..."
	cd web && npm run build

## test: Run Go and frontend tests
test:
	@echo "Running Go tests..."
	go test ./...
	@echo "Running frontend tests..."
	cd web && npx vitest --run

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(DIST)
	rm -rf $(WEB_DIST)
	rm -rf cmd/analyzer/dist

## run: Build production binary and execute
run: build
	$(DIST)/$(BINARY)
