# V2 Enhancements — LLM Rate Limiting & Spend Cap

Status: implemented
Date: 2026-05-21

## Problem

The CloudTrail Analyzer has no protection against accidental LLM cost spikes. A React `useEffect` loop, double-click, or stuck retry could fire dozens of Bedrock/Anthropic/OpenAI requests in seconds, each costing $0.01–$0.10+. For a single-user tool where the operator IS the bill-payer, the concern isn't malicious abuse — it's self-inflicted bill shock from UI bugs or user error.

## Affected Endpoints

| Endpoint | LLM Cost? | DuckDB Cost? |
|----------|-----------|-------------|
| `POST /api/nlquery/execute` | Yes — LLM generates SQL | Yes — DuckDB runs it |
| `POST /api/nlquery/summarize` | Yes — LLM summarizes results | No |
| `POST /api/investigate/run` | No — handcoded SQL | Yes — DuckDB runs it |
| `GET /api/dashboard` | No | Yes — 7 parallel DuckDB queries |
| `GET /api/lookups` | No | Yes |

Only `/api/nlquery/execute` and `/api/nlquery/summarize` incur LLM provider costs.

## Solution: Concurrency Gate + Session Spend Cap

Two complementary controls, applied at the handler level before any LLM call:

### Control 1: Concurrency Gate (all providers)

Only one LLM request can be in-flight at a time. A second concurrent request receives HTTP 429 immediately.

**Rationale:**
- **Paid providers (Bedrock, Anthropic, OpenAI):** prevents parallel cost accumulation from UI bugs
- **Local providers (Ollama):** prevents CPU/memory exhaustion (a 7B model uses 4–8 GB RAM; two in parallel could OOM a c7g.large)

**Implementation:** `sync/atomic.Bool` — zero allocation, no goroutine, no timer.

```go
if !h.llmInFlight.CompareAndSwap(false, true) {
    render.Error(w, 429, "LLM_BUSY",
        "An AI query is already in progress. Wait for it to complete.")
    return
}
defer h.llmInFlight.Store(false)
```

### Control 2: Session Spend Cap (paid providers only)

A configurable dollar cap per session (app restart resets the counter). Once cumulative estimated spend reaches the cap, all paid-provider LLM endpoints return 429 until the user explicitly resets.

**Rationale:** Absolute bill-shock protection. The user thinks in dollars, not requests-per-minute.

**Scope:** Only enforced when `provider` is `bedrock`, `anthropic`, or `openai`. Ollama is free and exempt.

**Configuration:**
```json
{
  "llm": {
    "provider": "bedrock",
    "max_session_spend_usd": 5.00
  }
}
```

Default: `$5.00`. Set to `0` to disable the cap entirely.

**Implementation:**
```go
isPaidProvider := cfg.LLM.Provider != "ollama"
if isPaidProvider {
    cap := cfg.LLM.MaxSessionSpendUSD
    if cap > 0 && h.sessionSpend.Total() >= cap {
        render.Error(w, 429, "SPEND_CAP_REACHED",
            fmt.Sprintf("Session spend cap reached ($%.2f). Reset via Settings or restart.", cap))
        return
    }
}
```

**Reset mechanisms:**
- `DELETE /api/nlquery/spend` — zeroes the counter (already exists)
- App restart — counter is in-memory only

## Provider Matrix

| Provider | Concurrency Gate | Spend Cap | Spend Tracking |
|----------|-----------------|-----------|----------------|
| Bedrock | ✅ Applied | ✅ Enforced | ✅ Recorded |
| Anthropic API | ✅ Applied | ✅ Enforced | ✅ Recorded |
| OpenAI / Compatible | ✅ Applied | ✅ Enforced | ✅ Recorded |
| Ollama (local) | ✅ Applied | ❌ Exempt | ❌ Not recorded |

## UX Behavior

### When concurrency gate triggers (429 LLM_BUSY):
- Frontend shows inline "Query in progress..." indicator
- No error toast — this is expected behavior, not a failure
- Request can be retried immediately after the in-flight request completes

### When spend cap triggers (429 SPEND_CAP_REACHED):
- Frontend shows a warning banner: "Session spend cap reached ($5.00)"
- Banner includes current spend total and a "Reset Counter" button
- The pre-flight estimate banner (already exists) naturally pairs with this:
  "This query costs ~$0.03. Session total: $4.80 / $5.00 cap"

### Pre-flight estimate interaction:
- If `estimate + current_spend > cap`, the estimate response includes a `would_exceed_cap: true` field
- Frontend can show an amber warning before the user clicks Run

## Error Response Format

```json
{
  "code": "LLM_BUSY",
  "message": "An AI query is already in progress. Wait for it to complete."
}
```

```json
{
  "code": "SPEND_CAP_REACHED",
  "message": "Session spend cap reached ($5.00). Reset via DELETE /api/nlquery/spend or restart the application.",
  "details": {
    "current_spend_usd": 5.02,
    "cap_usd": 5.00
  }
}
```

## Files Modified

| File | Change |
|------|--------|
| `internal/config/config.go` | Add `MaxSessionSpendUSD` field to `LLMConfig` |
| `internal/features/nlquery/handler.go` | Add concurrency gate + spend cap checks before LLM calls |
| `docs/v2-enhancements.md` | This document |

## Design Decisions

1. **Why not per-minute rate limiting?** Doesn't map to the actual concern (cost). A spend cap is more intuitive — users think in dollars, not requests/minute.

2. **Why not prompt-hash deduplication?** Subset of the concurrency gate. If only 1 request can be in-flight, duplicates are already rejected.

3. **Why exempt Ollama from spend cap?** Ollama runs locally with zero API cost. Blocking it based on a dollar counter makes no sense. The concurrency gate still protects against CPU/memory exhaustion.

4. **Why in-memory counter (not persisted)?** Single-user POC. Durable per-day attribution is YAGNI. A restart is a natural reset point — the user is actively choosing to restart.

5. **Why $5.00 default?** Covers ~100–500 typical NLQ queries depending on model. High enough to not annoy during active investigation, low enough to catch runaway loops before they become expensive.


---

## DuckDB Setup — macOS Development

The auto-install logic targets Amazon Linux 2023 (the production deployment). On macOS (Apple Silicon or Intel), you need to install DuckDB manually.

### Install via Homebrew (recommended)

```bash
brew install duckdb
```

Verify:
```bash
duckdb --version
# v1.3.0 or later
```

Homebrew places the binary at `/opt/homebrew/bin/duckdb` (Apple Silicon) or `/usr/local/bin/duckdb` (Intel). Both are in the default PATH.

### Install manually (without Homebrew)

```bash
# Apple Silicon (M1/M2/M3/M4)
curl -L -o duckdb.zip https://github.com/duckdb/duckdb/releases/latest/download/duckdb_cli-osx-universal.zip
unzip duckdb.zip -d /usr/local/bin
chmod +x /usr/local/bin/duckdb
rm duckdb.zip

# Verify
duckdb --version
```

### PATH Requirements

The app finds DuckDB via `exec.LookPath("duckdb")` — it must be on your shell's PATH. The startup validator checks these locations:

| Path | Source |
|------|--------|
| `/usr/local/bin/duckdb` | Homebrew (Intel) or manual install |
| `/usr/bin/duckdb` | System-wide |
| `~/.local/bin/duckdb` | User-local install |
| `~/bin/duckdb` | User-local install |
| `/opt/homebrew/bin/duckdb` | Homebrew (Apple Silicon) — on PATH via shell profile |

If DuckDB is installed but the app reports "DuckDB CLI not found", ensure your PATH includes the install directory:

```bash
# Add to ~/.zshrc if needed
export PATH="/opt/homebrew/bin:$PATH"
```

### What Happens Without DuckDB

The app starts normally — DuckDB is a **non-blocking** startup check. Everything works except:
- Dashboard (security findings) — returns "no data" errors
- Investigation scenarios — returns DuckDB execution errors
- NL Query — generates SQL but can't execute it
- Indexing — cannot build the DuckDB index

S3 sync, session management, settings, and credentials all work without DuckDB.

### Environment Variables

No DuckDB-specific environment variables are required. The app uses these for its own configuration:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `7070` | HTTP listen port |
| `HOST` | `127.0.0.1` | Bind address |
| `DATA_DIR` | `./data` | Where sessions.db and downloaded logs live |
| `LOG_LEVEL` | `info` | Logging verbosity (debug/info/warn/error) |
| `MAX_DOWNLOAD_CONCURRENCY` | `16` | Parallel S3 download workers |
| `QUERY_TIMEOUT_SECONDS` | `60` | DuckDB query timeout |

AWS credentials (for S3 sync and Bedrock) are configured via the UI (Settings → Credentials) or standard AWS environment variables:

```bash
# Option 1: Session credentials (paste from SSO portal)
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Option 2: Named profile
export AWS_PROFILE=my-sso-profile

# Option 3: IMDS (automatic on EC2 with IAM role)
# No env vars needed
```

### macOS Development Workflow

```bash
# 1. Install DuckDB
brew install duckdb

# 2. Install dependencies
make install

# 3. Run in dev mode (Go API + Vite hot-reload)
make dev
# → API: http://localhost:7070
# → UI:  http://localhost:5173

# 4. Configure credentials in the UI
#    Open http://localhost:5173 → Settings → Credentials
#    Paste session credentials from your SSO portal

# 5. Configure S3 bucket
#    Settings → S3 Config → enter bucket name → Test Connection
```
