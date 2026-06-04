// Frontend-only account-name resolution. The backend already exposes
// /api/accounts/resolve and /api/accounts/manual; this module gives every
// existing page a tiny shared interface so it can render "id (name)" without
// each page doing its own fetch + cache + invalidation.
//
// Design choices:
//   - One in-memory cache shared across the whole tab (subscribers re-render
//     when the cache changes), so the Dashboard, Lookups, Investigate and S3
//     Sync views all show the same name without coordinating.
//   - Lazy: a page asks for the IDs it cares about; we batch them together
//     and call the API once per ~100ms tick.
//   - Manual cache invalidation on save: AccountNamesSection calls
//     `refreshAccountNames(idsThatChanged)` after a successful PUT/DELETE so
//     other open pages reflect the change without a hard refresh.
//
// Resolution outcomes:
//   - "manual" / "organizations" → returns the friendly name
//   - "unresolved" → returns null; the display component renders the bare ID

import { useEffect, useState } from 'react'
import { endpoints } from '../config/api'

interface Entry {
  account_id: string
  name: string
  source: 'manual' | 'organizations' | 'unresolved'
}

// Module-level cache + subscribers. Module scope is intentional — the cache
// persists across page navigations within a single SPA session, mirroring the
// backend's process-wide cache.
const cache = new Map<string, Entry>()
const subscribers = new Set<() => void>()

// IDs requested but not yet fetched, batched to amortize roundtrips.
let pending: Set<string> = new Set()
let scheduled: ReturnType<typeof setTimeout> | null = null

function notify() {
  for (const fn of subscribers) fn()
}

function flushPending() {
  scheduled = null
  if (pending.size === 0) return
  const ids = Array.from(pending).filter(id => !cache.has(id))
  pending = new Set()
  if (ids.length === 0) return

  const url = `${endpoints.accountsResolve}?ids=${encodeURIComponent(ids.join(','))}`
  fetch(url)
    .then(res => (res.ok ? res.json() : Promise.reject(res.status)))
    .then((data: { entries: Entry[] }) => {
      // A successful response is authoritative: the backend reports a real
      // outcome for each ID, including a definitive "unresolved" (no manual
      // mapping and no Organizations name). That IS cacheable — caching it
      // stops us re-asking for an ID the backend has already told us it can't
      // name. The UI falls back to the bare ID.
      for (const e of data.entries || []) cache.set(e.account_id, e)
      notify()
    })
    .catch(() => {
      // Transient failure (network error, 5xx, or a 403 UNTRUSTED_HOST from the
      // Host-validation middleware). This is NOT a backend "unresolved" verdict,
      // so do NOT poison the cache: caching these IDs as "unresolved" would pin
      // them permanently and the UI would never recover after the blip clears.
      // Leave them uncached so the next schedule() retries. The UI renders the
      // bare ID in the meantime (a cache miss already falls back to the ID).
      // notify() so any in-flight on-demand lookups settle to the bare ID.
      notify()
    })
}

function schedule(ids: string[]) {
  for (const id of ids) {
    if (id && !cache.has(id)) pending.add(id)
  }
  if (scheduled === null && pending.size > 0) {
    scheduled = setTimeout(flushPending, 100)
  }
}

/**
 * Returns a function that maps an account ID to its friendly name (or null
 * if the ID is unresolved or unknown). Re-renders the calling component
 * when the cache updates.
 *
 * Pages call this at the top with the list of IDs they expect to render;
 * the hook schedules a single batched fetch on mount.
 */
export function useAccountNames(ids: string[]): (id: string | null | undefined) => string | null {
  const [, setVersion] = useState(0)

  // Subscribe to cache updates so this component re-renders when names arrive.
  useEffect(() => {
    const fn = () => setVersion(v => v + 1)
    subscribers.add(fn)
    return () => { subscribers.delete(fn) }
  }, [])

  // Schedule unresolved IDs for fetch. Using join() is cheap and stable.
  useEffect(() => {
    schedule(ids.filter(Boolean) as string[])
  }, [ids.join(',')])

  return (id) => {
    if (!id) return null
    const e = cache.get(id)
    if (!e) {
      // Schedule on demand for IDs the caller didn't list up front.
      schedule([id])
      return null
    }
    return e.source === 'unresolved' || !e.name ? null : e.name
  }
}

/**
 * Force-refresh specific account IDs. Called by the Settings UI after the
 * user saves or deletes a manual mapping so other open pages reflect the
 * change without a hard refresh.
 */
export function refreshAccountNames(ids: string[]): void {
  for (const id of ids) cache.delete(id)
  schedule(ids)
}

/**
 * Drop every cached "unresolved" entry and re-fetch the affected IDs. Call this
 * when the auth surface changes (e.g., the user pastes new STS credentials or
 * forces an AWS Organizations refresh): an ID that resolved to "unresolved"
 * under the old credentials may now have an Organizations name. Entries that
 * already have a name (manual/organizations) are left untouched so a credential
 * change does not flicker known names. Mirrors the backend resolver's
 * OnCredentialsChanged, which clears its sticky-failure flag for the same reason.
 */
export function retryUnresolved(): void {
  const stale: string[] = []
  for (const [id, e] of cache) {
    if (e.source === 'unresolved' || !e.name) {
      stale.push(id)
    }
  }
  for (const id of stale) cache.delete(id)
  if (stale.length > 0) {
    notify()
    schedule(stale)
  }
}

/**
 * formatIdName renders "id (name)" if a name is known, else just the id.
 * Used in places where JSX is overkill (CSV exports, copy-to-clipboard,
 * tooltips).
 */
export function formatIdName(id: string, name: string | null): string {
  if (!name) return id
  return `${id} (${name})`
}
