import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, Check, Loader2, RefreshCw, Save } from 'lucide-react'
import { endpoints } from '../../config/api'
import { readApiError } from '../../comm/apiError'
import { refreshAccountNames } from '../../comm/accountNames'

// Entry mirrors internal/features/accounts.Entry.
interface Entry {
  account_id: string
  name: string
  source: 'organizations' | 'manual' | 'unresolved'
}

interface ResolverStatus {
  org_available: boolean
  last_attempt?: string
  last_error?: string
  org_entries: number
  manual_entries: number
}

interface Props {
  // Account IDs to manage names for. Caller supplies them — typically the
  // union of S3-Sync-discovered accounts plus any in-flight selection in the
  // S3 Config form. The component is purely a name editor; it does not
  // discover accounts itself.
  accountIds: string[]
}

// AccountNamesSection lets the user map 12-digit AWS account IDs to friendly
// names. Names persist via PUT /api/accounts/manual/{id}; AWS Organizations
// is consulted automatically when the principal has access (typically not
// from a Control Tower log archive account, in which case manual mapping is
// the entire path forward — the diagnostic banner explains this when needed).
export function AccountNamesSection({ accountIds }: Props) {
  const { t } = useTranslation()

  const [entries, setEntries] = useState<Record<string, Entry>>({})
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [status, setStatus] = useState<ResolverStatus | null>(null)
  const [savingId, setSavingId] = useState<string | null>(null)
  const [savedId, setSavedId] = useState<string | null>(null)
  const [retrying, setRetrying] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Sorted unique IDs make the rendered list stable as inputs shift.
  const uniqueIds = useMemo(
    () => Array.from(new Set(accountIds.filter(Boolean))).sort(),
    [accountIds]
  )

  // Resolve every known ID at once so the UI shows current name + source.
  async function loadEntries() {
    if (uniqueIds.length === 0) {
      setEntries({})
      return
    }
    setError(null)
    try {
      const url = `${endpoints.accountsResolve}?ids=${encodeURIComponent(uniqueIds.join(','))}`
      const res = await fetch(url)
      if (!res.ok) {
        setError(await readApiError(res, 'Failed to load account names'))
        return
      }
      const data = await res.json() as { entries: Entry[] }
      const map: Record<string, Entry> = {}
      for (const e of data.entries || []) map[e.account_id] = e
      setEntries(map)
      // Seed drafts from resolved names so the user edits the current value.
      setDrafts(prev => {
        const next = { ...prev }
        for (const id of uniqueIds) {
          if (next[id] === undefined) next[id] = map[id]?.name ?? ''
        }
        return next
      })
    } catch (e: any) {
      setError(e?.message || 'Failed to load account names')
    }
  }

  async function loadStatus() {
    try {
      const res = await fetch(endpoints.accountsStatus)
      if (res.ok) setStatus(await res.json())
    } catch {
      /* ignore — diagnostic banner is best-effort */
    }
  }

  useEffect(() => { loadEntries() }, [uniqueIds.join(',')])
  useEffect(() => { loadStatus() }, [])

  async function saveOne(id: string) {
    const name = (drafts[id] ?? '').trim()
    setSavingId(id)
    setError(null)
    try {
      const current = entries[id]
      // If draft is empty and there is a manual entry, clear it. If draft is
      // empty and there is no manual entry, this is a no-op.
      if (name === '') {
        if (current?.source === 'manual') {
          const res = await fetch(endpoints.accountManual(id), { method: 'DELETE' })
          if (!res.ok) {
            setError(await readApiError(res, 'Failed to clear name'))
            return
          }
          const updated = await res.json() as Entry
          setEntries(prev => ({ ...prev, [id]: updated }))
          setDrafts(prev => ({ ...prev, [id]: updated.name ?? '' }))
          refreshAccountNames([id])
        }
        flashSaved(id)
        return
      }
      const res = await fetch(endpoints.accountManual(id), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      })
      if (!res.ok) {
        setError(await readApiError(res, 'Failed to save name'))
        return
      }
      const updated = await res.json() as Entry
      setEntries(prev => ({ ...prev, [id]: updated }))
      setDrafts(prev => ({ ...prev, [id]: updated.name }))
      refreshAccountNames([id])
      flashSaved(id)
    } catch (e: any) {
      setError(e?.message || 'Failed to save name')
    } finally {
      setSavingId(null)
    }
  }

  function flashSaved(id: string) {
    setSavedId(id)
    setTimeout(() => setSavedId(s => (s === id ? null : s)), 1200)
  }

  async function retryOrgRefresh() {
    setRetrying(true)
    setError(null)
    try {
      const res = await fetch(endpoints.accountsRefresh, { method: 'POST' })
      if (!res.ok) setError(await readApiError(res, 'Refresh failed'))
      // Re-pull entries + status regardless of refresh outcome — even on
      // failure, status carries the latest error message for the banner.
      await Promise.all([loadEntries(), loadStatus()])
      // Invalidate the shared cache so other open pages pick up org names.
      refreshAccountNames(uniqueIds)
    } finally {
      setRetrying(false)
    }
  }

  // Decide which banner (if any) to show. Three states:
  //   1) Org access available + at least one org entry → no banner
  //   2) Org access never tried (no last_attempt) → no banner
  //   3) Last attempt failed → show "set names manually" hint with retry
  const showOrgUnavailableBanner =
    status !== null &&
    !status.org_available &&
    !!status.last_attempt

  if (uniqueIds.length === 0) {
    return null
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-gray-900 dark:text-white">{t('settings.accountNames.title')}</h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">{t('settings.accountNames.subtitle')}</p>
        </div>
        <button
          type="button"
          onClick={retryOrgRefresh}
          disabled={retrying}
          className="inline-flex items-center gap-1 px-2 py-1 text-[11px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50"
        >
          {retrying ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
          {t('settings.accountNames.retryOrg')}
        </button>
      </div>

      {showOrgUnavailableBanner && (
        <div className="flex items-start gap-2 p-2.5 rounded border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/10">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-600 mt-0.5 shrink-0" />
          <div className="text-[11px] text-amber-800 dark:text-amber-200 leading-snug">
            <div className="font-medium">{t('settings.accountNames.orgUnavailable')}</div>
            <div className="text-amber-700 dark:text-amber-300/80">{t('settings.accountNames.orgUnavailableHint')}</div>
            {status?.last_error && (
              <details className="mt-1">
                <summary className="cursor-pointer text-[10px] opacity-80 hover:opacity-100">{t('settings.accountNames.showError')}</summary>
                <div className="text-[10px] font-mono mt-1 break-all">{status.last_error}</div>
              </details>
            )}
          </div>
        </div>
      )}

      {error && (
        <div className="p-2 text-[11px] rounded border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/10 text-red-700 dark:text-red-300">
          {error}
        </div>
      )}

      <div className="rounded border border-gray-200 dark:border-gray-700 divide-y divide-gray-100 dark:divide-gray-800">
        {uniqueIds.map((id) => {
          const entry = entries[id]
          const draft = drafts[id] ?? ''
          const dirty = (entry?.name ?? '') !== draft
          const sourceBadge =
            entry?.source === 'manual' ? 'manual' :
            entry?.source === 'organizations' ? 'organizations' :
            'unresolved'
          return (
            <div key={id} className="flex items-center gap-2 px-3 py-2">
              <span className="font-mono text-xs text-gray-700 dark:text-gray-300 w-32 shrink-0">{id}</span>
              <input
                type="text"
                value={draft}
                onChange={(e) => setDrafts(prev => ({ ...prev, [id]: e.target.value }))}
                onKeyDown={(e) => { if (e.key === 'Enter') saveOne(id) }}
                placeholder={t('settings.accountNames.placeholder')}
                className="flex-1 px-2 py-1 text-xs rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
              <span
                className={`text-[9px] uppercase font-semibold px-1.5 py-0.5 rounded shrink-0 ${
                  sourceBadge === 'manual'
                    ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                    : sourceBadge === 'organizations'
                    ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                    : 'bg-gray-100 dark:bg-gray-800 text-gray-500'
                }`}
              >
                {sourceBadge}
              </span>
              <button
                type="button"
                onClick={() => saveOne(id)}
                disabled={!dirty || savingId === id}
                className="inline-flex items-center gap-1 px-2 py-1 text-[11px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
              >
                {savingId === id ? <Loader2 className="w-3 h-3 animate-spin" /> : savedId === id ? <Check className="w-3 h-3 text-green-600" /> : <Save className="w-3 h-3" />}
                {t('settings.accountNames.save')}
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}
