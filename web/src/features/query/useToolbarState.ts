// useToolbarState: Investigate toolbar state with URL persistence.
//
// The toolbar holds time window + selected accounts + seed (if any). The
// NON-SENSITIVE context (time window + selected accounts) is mirrored into the
// URL query string so:
//   - browser refresh keeps the investigation context
//   - back/forward buttons move between recent contexts
//   - a responder can paste the URL to share what they were looking at
//
// The SEED is deliberately NOT serialized. A seed is an investigation pivot
// value — an access key ID, ARN, IP, or account ID — i.e. potentially
// sensitive. Putting it in the URL leaks it into browser history, the
// `Referer` header on any outbound request, server/proxy access logs, and
// shared/bookmarked links. So the seed lives in component state only and never
// touches the address bar or history. (N81)
//
// Reads the non-sensitive context from the URL on mount and pushes it back via
// history.replaceState as the state changes (debounced via setTimeout in a
// single useEffect tick to avoid hammering history during rapid edits).

import { useCallback, useEffect, useState } from 'react'
import { detectSeedType, type SeedType } from './seedDetection'

export interface ToolbarState {
  timeStart: string  // 'YYYY-MM-DD' or RFC3339; empty = unbounded
  timeEnd: string
  accountIds: string[]
  seed: string
  seedType: SeedType        // detected; user can override
  seedTypeOverride?: SeedType // user pick takes precedence over detection
}

// Only the non-sensitive context is keyed into the URL. The seed and its type
// are intentionally absent — see the file header (N81).
const QS_KEY = {
  start: 'ts',
  end: 'te',
  accounts: 'accts',
}

// Legacy seed keys we proactively strip from the URL on mount, in case a user
// is opening an older bookmarked/shared link that still carried a seed.
const LEGACY_SEED_KEYS = ['seed', 'stype']

function readFromURL(): ToolbarState {
  const p = new URLSearchParams(window.location.search)
  // The seed is never read from the URL; it starts empty and lives in state.
  return {
    timeStart: p.get(QS_KEY.start) ?? '',
    timeEnd: p.get(QS_KEY.end) ?? '',
    accountIds: (p.get(QS_KEY.accounts) ?? '').split(',').filter(Boolean),
    seed: '',
    seedType: detectSeedType(''),
    seedTypeOverride: undefined,
  }
}

function writeToURL(s: ToolbarState) {
  const p = new URLSearchParams(window.location.search)
  setOrDelete(p, QS_KEY.start, s.timeStart)
  setOrDelete(p, QS_KEY.end, s.timeEnd)
  setOrDelete(p, QS_KEY.accounts, s.accountIds.join(','))
  // Defensively drop any seed left over from a legacy link so it never lingers
  // in history. The seed is otherwise never written here.
  for (const k of LEGACY_SEED_KEYS) p.delete(k)
  const qs = p.toString()
  const next = qs ? `${window.location.pathname}?${qs}` : window.location.pathname
  if (next !== `${window.location.pathname}${window.location.search}`) {
    window.history.replaceState(null, '', next)
  }
}

function setOrDelete(p: URLSearchParams, key: string, value: string) {
  if (value) p.set(key, value)
  else p.delete(key)
}

export function useToolbarState() {
  const [state, setState] = useState<ToolbarState>(() => readFromURL())

  useEffect(() => {
    const handle = setTimeout(() => writeToURL(state), 200)
    return () => clearTimeout(handle)
  }, [state])

  const setTimeStart = useCallback((v: string) => setState(s => ({ ...s, timeStart: v })), [])
  const setTimeEnd = useCallback((v: string) => setState(s => ({ ...s, timeEnd: v })), [])
  const setAccountIds = useCallback((ids: string[]) => setState(s => ({ ...s, accountIds: ids })), [])
  const setSeed = useCallback((v: string) => setState(s => ({
    ...s,
    seed: v,
    // Re-detect when there is no explicit override, otherwise keep the user's pick.
    seedType: s.seedTypeOverride ?? detectSeedType(v),
  })), [])
  const setSeedTypeOverride = useCallback((t: SeedType | undefined) => setState(s => ({
    ...s,
    seedTypeOverride: t,
    seedType: t ?? detectSeedType(s.seed),
  })), [])

  /**
   * Apply a preset time window like "last 24h" as a true rolling window
   * ending at "now".
   *
   * The previous implementation subtracted N*24h from now and then truncated
   * BOTH the start and the end to a YYYY-MM-DD date (`toISOString().slice(0,10)`).
   * That widened every window by up to a full calendar day: "last 24h" at
   * 08:00 produced start=yesterday, end=today — a ~2-calendar-day span once the
   * backend's inclusive `eventTime <= <end>` string compare is applied. (N7)
   *
   * The backend filters with a plain string comparison on the RFC3339
   * `eventTime` field and accepts RFC3339 inputs (see investigate.go
   * buildFilteredEventsExpr), and RFC3339 in UTC sorts lexicographically the
   * same as chronologically. So we emit full RFC3339 instants for an exact
   * rolling window instead of date-only strings. The date pickers in
   * InvestigateToolbar display just the YYYY-MM-DD portion; a manual edit
   * there overwrites the instant with a plain date, keeping the custom path
   * working.
   *
   * Milliseconds are dropped (second precision) to match the RFC3339 form
   * CloudTrail emits for eventTime, so the lexicographic boundary comparison
   * lines up exactly rather than tripping over a `.sssZ` vs `Z` suffix.
   */
  const applyPreset = useCallback((preset: 'last_1h' | 'last_24h' | 'last_7d' | 'last_30d' | 'custom_clear') => {
    if (preset === 'custom_clear') {
      setState(s => ({ ...s, timeStart: '', timeEnd: '' }))
      return
    }
    const now = new Date()
    const hours =
      preset === 'last_1h' ? 1 : preset === 'last_24h' ? 24 : preset === 'last_7d' ? 24 * 7 : 24 * 30
    const start = new Date(now.getTime() - hours * 60 * 60 * 1000)
    const rfc3339 = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')
    setState(s => ({ ...s, timeStart: rfc3339(start), timeEnd: rfc3339(now) }))
  }, [])

  return {
    state,
    setTimeStart,
    setTimeEnd,
    setAccountIds,
    setSeed,
    setSeedTypeOverride,
    applyPreset,
  }
}
