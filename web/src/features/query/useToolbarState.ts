// useToolbarState: Investigate toolbar state with URL persistence.
//
// The toolbar holds time window + selected accounts + seed (if any). State is
// mirrored into the URL query string so:
//   - browser refresh keeps the investigation context
//   - back/forward buttons move between recent contexts
//   - a responder can paste the URL to share what they were looking at
//
// Reads from the URL on mount and pushes back via history.replaceState as the
// state changes (debounced via setTimeout in a single useEffect tick to avoid
// hammering history during rapid edits).

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

const QS_KEY = {
  start: 'ts',
  end: 'te',
  accounts: 'accts',
  seed: 'seed',
  seedType: 'stype',
}

function readFromURL(): ToolbarState {
  const p = new URLSearchParams(window.location.search)
  const seed = p.get(QS_KEY.seed) ?? ''
  const override = (p.get(QS_KEY.seedType) as SeedType | null) ?? undefined
  return {
    timeStart: p.get(QS_KEY.start) ?? '',
    timeEnd: p.get(QS_KEY.end) ?? '',
    accountIds: (p.get(QS_KEY.accounts) ?? '').split(',').filter(Boolean),
    seed,
    seedType: override ?? detectSeedType(seed),
    seedTypeOverride: override,
  }
}

function writeToURL(s: ToolbarState) {
  const p = new URLSearchParams(window.location.search)
  setOrDelete(p, QS_KEY.start, s.timeStart)
  setOrDelete(p, QS_KEY.end, s.timeEnd)
  setOrDelete(p, QS_KEY.accounts, s.accountIds.join(','))
  setOrDelete(p, QS_KEY.seed, s.seed)
  setOrDelete(p, QS_KEY.seedType, s.seedTypeOverride ?? '')
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

  /** Apply a preset time window like "last 24h" by computing a concrete date pair. */
  const applyPreset = useCallback((preset: 'last_24h' | 'last_7d' | 'last_30d' | 'custom_clear') => {
    const now = new Date()
    const fmt = (d: Date) => d.toISOString().slice(0, 10)
    if (preset === 'custom_clear') {
      setState(s => ({ ...s, timeStart: '', timeEnd: '' }))
      return
    }
    const days = preset === 'last_24h' ? 1 : preset === 'last_7d' ? 7 : 30
    const start = new Date(now.getTime() - days * 24 * 60 * 60 * 1000)
    setState(s => ({ ...s, timeStart: fmt(start), timeEnd: fmt(now) }))
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
