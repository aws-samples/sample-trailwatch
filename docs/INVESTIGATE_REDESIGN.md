# Investigate redesign — design doc

Status: draft for review
Owner: this PR
Last updated: 2026-05-17

## Problem

Customer feedback: the existing **Investigate** tab feels like a dump of data, not a tool. A 40-item scenario picker forces the responder to scan names, guess which one matches their question, click, read rows, and decide manually what to ask next. There is no narrative, no continuity between questions, and no help getting started under pressure.

Two real responder modes are not served:

1. **Cold start, broad sweep.** Something just happened. The responder has no specific identity yet. They want a curated situation report across recent CloudTrail to find shape of suspicion fast.
2. **Hot lead, drill from one fact.** They have an IP, an IAM ARN, an access key, or a time window. They want one place that takes that seed and shows everything connected to it — actions, IPs, accounts, persistence indicators, related identities, errors — so they can read a story rather than re-querying for each angle.

Two cross-cutting QoL gaps were also called out:

- Time window must be a first-class, deliberate choice — not implied by which logs are synced.
- Account names should appear next to account IDs everywhere. `247083000413` means nothing under pressure; `prod-payments` means everything.

## Audience and scope

Single-tenant deployment. Security incident responders or infrastructure engineers running this on their own EC2 in their own AWS account. They own the data and the host. No multi-user concerns. No auth (documented in README). Bedrock cost is opt-in and must be transparent.

## Non-goals

- Multi-tenancy, RBAC, or shared deployments. Out of scope.
- Replacing the existing dashboard. The dashboard remains the at-a-glance overview; Investigate is the workbench you go to when you need to dig.
- Heavy ML / statistical anomaly detection. The first version uses heuristics + an opt-in LLM-backed "Why is this weird?" explainer.

## Solution shape

Replace the existing Investigate tab with one page that operates in two coordinated modes, sharing a single context bar:

- **Mode A — Situation Report.** Cold-start sweep over a chosen time window and account set, returning a curated set of severity-banded findings. Hand-coded SQL only. No LLM cost. Click any value (ARN / IP / access key) inside a finding to pivot into Mode B with the time window preserved.
- **Mode B — Identity Profile.** Hot-lead drill-down from a seed. Six panels run in parallel: timeline, source IPs, accounts touched, persistence indicators, related identities, services and errors. Inline anomaly tags on the timeline link into the relevant panel. A scoped "Ask a follow-up" Bedrock NLQ box at the bottom is the only paid-cost surface.

The 40 existing scenarios fold into a **side drawer** on the same page (see "Scenario drawer" below). They remain available, inherit the toolbar's time + account context, and stop competing for the front door.

## Page anatomy (wireframe summary)

Top, persistently visible:

- Time window picker — required, no default. Presets dropdown for common windows.
- Accounts picker — multi-select with chip display. Each chip shows `id (resolved-name)`.
- Seed input — single text box with smart-detect of type (ARN / IP / access key / user / role / 12-digit account). Type chip below shows what was detected with a dropdown override.
- Two action buttons: **Investigate** (enabled when seed filled → Mode B) and **Start sweep** (enabled regardless of seed → Mode A).
- Top-right: Bedrock session spend counter, link to detail.
- Top-right: **Run a specific hunt…** link → opens scenario drawer.

Body switches between Sweep cards (Mode A) and Profile panels (Mode B) based on which action was triggered.

## Backend additions

### New endpoints

- `GET /api/investigate/sweep` — returns the situation report for the given time window + account set. Body groups findings under `critical`, `high`, `anomalies`. Each finding is `{id, title, severity, category, count, sample_rows, sql}`.
- `POST /api/investigate/profile` — body `{seed_type, seed_value, time_window, accounts}`. Orchestrates the six panel queries in parallel via `errgroup` and returns one JSON document with all results. Panel results carry `{name, columns, rows, error?}` — partial success is OK; one failed panel does not fail the response.
- `POST /api/investigate/explain` — body `{finding_id, event_context}`. Calls Bedrock with a scoped prompt explaining one anomaly. Pre-flight token estimate is computed locally and returned in the response if the caller omitted `confirm:true`. With `confirm:true`, the call goes through and the response includes actual cost.
- `GET /api/accounts/resolve` — returns `{account_id → friendly_name, source}` for accounts the user has synced. Source is `organizations` or `manual` or `unresolved`. Cached in SQLite, refreshed lazily on a 24h TTL or explicit `?refresh=true`.

### Reused unchanged

- `GET /api/investigate/scenarios` and `POST /api/investigate/run` — backing the scenario drawer.
- `GET /api/lookups` — populating dropdowns inside the drawer for parameterized scenarios.
- `POST /api/nlquery/execute` — backing the "Ask a follow-up" box, plus `ValidateReadSQL` already in place.

### Account-name resolver

Backed by a new SQLite table `accounts (id TEXT PRIMARY KEY, name TEXT, source TEXT, updated_at TEXT)`. On startup, if the user has Organizations permission, the resolver calls `ListAccounts` and upserts the cache. On a per-account miss, it returns the manually-mapped name (set in Settings) or falls back to the bare ID. The resolver is exposed as a small Go helper used by both new endpoints and the existing dashboard/lookups responses (those add a `name` field alongside `account_id`).

Failure modes:
- `organizations:ListAccounts` denied → log once, fall back to manual mapping silently.
- Network error → use cached values; surface staleness via `source: "stale"` if older than the TTL.

### Sweep SQL building blocks

The Situation Report runs about 12 short SQL queries. All are read-only, all run against the indexed DuckDB, all use the existing `events` schema. Categories:

- **Critical:** root account usage; CloudTrail trail mutation events (StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors); GuardDuty/SecurityHub disablement events.
- **High:** access keys created; IAM mutations (PutRolePolicy, AttachRolePolicy, AddUserToGroup, CreatePolicyVersion); cross-account AssumeRole; first-time-seen console logins; access-denied bursts (>50 per identity).
- **Anomalies:** off-hours window (00:00–06:00 UTC); IPs first seen in the time window; pentest-tool user agents; rare sensitive verbs (sensitive verb list called ≤3 times in the window).

Each query returns up to 50 rows; the UI shows a count badge and lazily fetches more on expand.

### Profile SQL building blocks (six panels)

Each panel takes the same `(seed_type, seed_value, time_window, accounts)` and runs one SQL:

1. **Timeline** — `SELECT eventTime, eventName, sourceIPAddress, recipientAccountId, errorCode FROM events WHERE <seed predicate> AND <time window> AND <account set> ORDER BY eventTime LIMIT 1000`. Returned to UI with anomaly tagging done client-side from a small allowlist of "interesting" eventNames + a NEW-IP marker derived from panel 2.
2. **Source IPs** — group by `sourceIPAddress`, count, mark `NEW` if first seen in window vs prior 7 days.
3. **Accounts touched** — group by `recipientAccountId`, join to account-name resolver, count.
4. **Persistence indicators** — count of CreateAccessKey, CreateLoginProfile, ImportKeyPair, AttachRolePolicy, PutRolePolicy, PutBucketPolicy, PutPublicAccessBlock, AuthorizeSecurityGroupIngress within the seed/time/account scope.
5. **Related identities** — identities (other than the seed) seen on the same source IPs OR using the same access key prefix during the window. Limit 20.
6. **Services + errors** — group by `eventSource` for service histogram; separately, group by `errorCode` filtering to non-NULL.

Seed predicate is a `CASE`-style switch on seed type:

| Seed type | Predicate |
|---|---|
| `arn` | `r.userIdentity.arn = ?` |
| `access_key` | `r.userIdentity.accessKeyId = ?` |
| `ip` | `r.sourceIPAddress = ?` |
| `account` | `r.userIdentity.accountId = ?` |
| `user` | `r.userIdentity.userName = ?` |
| `role` | `r.userIdentity.sessionContext.sessionIssuer.userName = ?` |

All values are passed through `ValidateReadSQL` and quote-escaped via the existing `safeParam` pattern in `investigate.go`.

### Bedrock cost UX

Three knobs already approved (see chat):

1. **Pre-flight estimate.** `cost_estimator.go` computes `input_tokens ≈ (len(system) + len(user)) / 4`, multiplies by the configured model's input rate, adds a fixed assumption of 800 output tokens × output rate, returns `{input_tokens, est_output_tokens, est_cost_usd, model, max_output_tokens}`. UI renders `≈ $0.0X (input only — output billed after run, capped at 2048 tokens ≈ $Y max)`.
2. **Hard output cap.** All Bedrock calls set `max_tokens=2048`. Provides the bill-shock seatbelt; cap is per-request, not session-wide.
3. **Session counter.** New endpoint `GET /api/llm/usage/session` returns `{queries, est_cost_usd, actual_cost_usd_so_far}`. Top bar shows `Bedrock spend: $0.27 (12 queries)`. Counter resets on app restart (single-user POC; durable per-day attribution is YAGNI).

Warning thresholds:
- Estimate >$0.50 → amber Run button + warning copy.
- Post-run actual >2× estimate → small badge on the result `cost $0.08 (estimated $0.02)`.

Pricing constants live in `internal/features/nlquery/pricing.go` keyed by model id. Default rates are documented inline; users on different rate cards can override via a Settings entry.

### Anomaly engine

Heuristics live in `internal/features/nlquery/anomalies.go`:

- `OffHoursTagger` — flags events with `EXTRACT(hour FROM eventTime) BETWEEN 0 AND 6`.
- `NewIPTagger` — `sourceIPAddress NOT IN (SELECT DISTINCT sourceIPAddress FROM events WHERE eventTime BETWEEN ? AND ?)` over the prior 7 days.
- `RareVerbTagger` — sensitive verb list (CreateAccessKey, PutBucketPolicy, AttachRolePolicy, ...) intersected with `event_count_in_window <= 3`.
- `PentestUATagger` — substring match against a known list (Kali/Pacu/ScoutSuite/Prowler/Pentoo/Parrot).

Each tagger surfaces `{tag, severity, why_short, sql_used}`. The Profile timeline applies tags at render time using the panel's data. The "Why is this weird?" button on a tagged event sends a scoped prompt to Bedrock with: the event JSON, the tag reason, and the same time/account context. Cost-gated like other NLQ paths — pre-flight banner with cap.

## Frontend additions

### New components

- `<InvestigatePage>` — orchestrator; owns toolbar state, mode switch, scenario drawer.
- `<InvestigateToolbar>` — time + accounts + seed + actions + spend counter.
- `<SituationReport>` — three severity bands of finding cards.
- `<FindingCard>` — collapsed/expanded states; renders `{title, severity, count, sample_rows, [pivot links]}`.
- `<IdentityProfile>` — header + timeline + 6-panel grid + follow-up box.
- `<Timeline>` — full-width chronological list with inline tags. Uses virtualized list for >1000 rows.
- `<Panel>` — generic wrapper for each profile panel; takes `{title, icon, fetchKey, render}`.
- `<ScenariosDrawer>` — right-side slide-in containing the existing scenario list, refactored from `InvestigateView.tsx`. Inherits toolbar context. Parameterized scenarios show their input inline.
- `<CostBanner>` — pre-flight estimate + amber warning + Run button.
- `<NLQFollowUp>` — wraps `<CostBanner>` and the existing NLQ execution path, scoped to the current seed + window.

### State and routing

`activeView === 'investigate'` continues to be the route. Internal state:
- `toolbar`: `{timeWindow, accounts, seed, seedType}`
- `mode`: `'idle' | 'sweeping' | 'profiling'`
- `result`: `Sweep | Profile | null`
- `drawerOpen`: `boolean`
- `sessionSpend`: `{queries, estUSD, actualUSD}`

Toolbar state is debounced into a `?` URL query string so refresh + back-button work, and so a responder can paste a URL that opens the same investigation. No deep-linking of result rows in v1 (saved investigations is a future bookmark feature).

### Drawer-as-side-panel

The `<ScenariosDrawer>` is implemented as a CSS-driven side panel (no portal). When open, the main page narrows to leave room. Closing keeps results visible. The drawer reads `toolbar.timeWindow` and `toolbar.accounts` as defaults — no separate inputs.

## Migration plan

Three PRs, each independently shippable. Every PR adds something a real user can notice; we do not accumulate half-finished work.

### PR 1 — Foundation (current)

Everything later modes depend on. No new pages; existing pages inherit the new capabilities.

1. **Account-name resolver** — backend Organizations + manual + cache; new `GET /api/accounts/resolve` endpoint; existing dashboard / lookups / investigate responses gain a parallel `account_name` field next to `account_id`; Settings page gets a "Account names" section for manual mapping.
2. **Shared investigate toolbar** — time picker (required, no default), account multi-select (chips show id + resolved name), seed input with smart-detect + override, kept in URL state. Mounted at the top of today's `InvestigateView` so it's live and useful before Mode B exists.
3. **Bedrock cost UX** — input-token estimator, hard 2048-token output cap applied to outgoing Bedrock calls, session spend counter in the top app bar, pre-flight banner on the existing NLQ flow.

PR 1 ships nothing new visually except the toolbar + account names + cost banner — but a customer using the tool today will immediately feel the difference.

### PR 2 — Identity Profile

The real UX shift the customer asked for.

1. New `<IdentityProfile>` page wired to `POST /api/investigate/profile` (timeline + 6 parallel panels + scoped NLQ follow-up box).
2. Existing 40-scenario list refactored into a `<ScenariosDrawer>` on the same page; inherits toolbar context. Old `Investigate` sidebar entry replaced.
3. Empty-state and no-Bedrock paths handled.

### PR 3 — Situation Report + heuristic anomalies (only if PR 2 feedback validates the bet)

Cold-start sweep, severity-banded findings cards, inline anomaly tags. Hand-coded SQL only — no LLM-backed explainer in v1.

### Explicitly deferred (out of scope for all three PRs unless re-asked)

- "Why is this weird?" Bedrock-backed anomaly explainer.
- Saved investigations / `[Save]` button — URL state already gives bookmarkability.
- AWS Pricing API integration — local constants + Settings override are sufficient.

Existing scenario backend endpoints are unchanged. The CSR pipeline remains green throughout because all changes are additive in PR 1.

## No-Bedrock fallback (binding constraint)

Today's Dashboard works without any LLM configured. **Every page introduced by these PRs must too.** Mode B without NLQ box. Drawer scenarios run on hand-coded SQL. Cost banner absent rather than broken when no model is configured. No codepath assumes a model exists.

## Test strategy

- **Backend:** unit tests for SQL builders (`sweep_builder_test.go`, `profile_builder_test.go`) — use a fixed DuckDB fixture seeded with synthetic CloudTrail events. Each test asserts `{columns, row_count, contains_expected_event}`. Cost estimator tested with table-driven cases. Anomaly taggers tested with hand-crafted events that hit / miss each rule.
- **Frontend:** Vitest unit tests for `useToolbar` reducer (URL sync, account multi-select), `<CostBanner>` (renders correct copy at threshold boundaries), `<Timeline>` (renders, virtualizes, applies tags). Mock the new endpoints with `msw`. Smoke test of the full page via existing testing setup if present, else skip.
- **Live smoke:** after PR 2 merges, manual sweep + profile against the existing 86k-event index. Verify happy path + an empty-result path.
- **Scanner sweep:** before each push, run `gitleaks`, `semgrep --config=auto`, `grype` against a tracked-files export. Zero findings required (per CSR rule).

## Decisions taken (resolving the design's earlier open questions)

1. Drawer button copy: "Run a specific hunt…". Re-evaluate in PR 2 review.
2. Saved investigations: not shipped; URL state covers bookmarking.
3. Bedrock pricing: local constants + Settings override; no Pricing API dependency.
4. Empty-state for sweep: list categories checked with green checkmarks (builds confidence under stress).
5. Anomaly tag persistence: recompute on each load. Cache only if responders complain.
6. "Why is this weird?" LLM explainer: dropped from v1.

## Appendix: file layout

### PR 1 (foundation)

New:
```
docs/INVESTIGATE_REDESIGN.md                                this doc
internal/features/accounts/                                  new package
  resolver.go                                                Organizations + manual + cache
  resolver_test.go
  handler.go                                                 GET /api/accounts/resolve, PUT manual mapping
internal/features/nlquery/
  pricing.go                                                 model rate constants per Bedrock model
  cost_estimator.go                                          token + USD estimator
  cost_estimator_test.go
  session_spend.go                                           in-process counter, exported via /api/llm/usage/session
migrations/003_account_cache.sql                             accounts table
web/src/features/investigate/                                new feature dir
  InvestigateToolbar.tsx                                     time + accounts + seed
  CostBanner.tsx                                             pre-flight estimate + cap warning
  hooks.ts                                                   useToolbarState, useAccountNames, useSessionSpend
  types.ts
web/src/comm/accounts.ts                                     small helper to fetch + cache account names
```

Modified:
```
cmd/analyzer/main.go                                          mount /api/accounts/* and /api/llm/usage/*
internal/features/nlquery/handler.go                          plumb cost estimator + 2048-token cap into Execute
internal/features/nlquery/provider.go                         set max_tokens=2048 on outgoing Bedrock InvokeModel calls
internal/features/nlquery/dashboard.go                        include account_name alongside account_id in panels
internal/features/nlquery/lookups.go                          include account_name in accounts response
internal/features/nlquery/investigate.go                      include account_name in scenario row outputs
internal/features/settings/handler.go                         GET / PUT manual account-name mappings
web/src/features/query/InvestigateView.tsx                    mount <InvestigateToolbar> at top; existing scenario list stays below for now
web/src/features/dashboard/DashboardView.tsx                  show account names in finding rows
web/src/features/settings/                                    add 'Account Names' section
web/src/arc/Layout.tsx                                        host session-spend chip in top bar
web/src/i18n.ts                                               toolbar + cost + account-mapping keys
README.md                                                     mention the new toolbar + account names + cost transparency
```

### PR 2 (Identity Profile) — to be added when scoped

### PR 3 (Situation Report + anomalies) — to be added if PR 2 validates the bet
