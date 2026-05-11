import { useState, useEffect, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { CloudDownload, Loader2, Play, AlertCircle, RefreshCw } from 'lucide-react'
import { useSettings } from '../settings/hooks'
import { endpoints } from '../../config/api'
import type { Session, ProcessingProgress } from '../../types/session'

export function S3SyncView() {
  const { t } = useTranslation()
  const { data: settings, loading: settingsLoading } = useSettings()

  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [sessions, setSessions] = useState<Session[]>([])
  const [sessionsLoading, setSessionsLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [syncError, setSyncError] = useState<string | null>(null)
  const [liveProgress, setLiveProgress] = useState<Record<string, ProcessingProgress>>({})
  const eventSourcesRef = useRef<Record<string, EventSource>>({})

  const bucket = settings?.s3?.bucket || ''
  const bucketRegion = settings?.s3?.region || ''
  const mode = settings?.s3?.mode || 'single'
  const orgId = settings?.s3?.org_id || ''
  const accountId = settings?.s3?.account_id || ''
  const memberAccounts = settings?.s3?.member_accounts || []
  const logRegion = settings?.s3?.log_region || settings?.s3?.region || 'us-east-1'

  // Determine which accounts to sync
  const accountsToSync = mode === 'control_tower' && memberAccounts.length > 0
    ? memberAccounts
    : [accountId]

  const fetchSessions = useCallback(async () => {
    try {
      const res = await fetch('/api/sessions')
      if (res.ok) {
        const data = await res.json()
        if (Array.isArray(data)) setSessions(data.slice(0, 20))
      }
    } catch { /* silent */ }
    finally { setSessionsLoading(false) }
  }, [])

  useEffect(() => { fetchSessions() }, [fetchSessions])

  // Poll for active sessions
  useEffect(() => {
    const hasActive = sessions.some(s =>
      s.state === 'downloading' || s.state === 'extracting' || s.state === 'verifying'
    )
    if (!hasActive) return
    const interval = setInterval(fetchSessions, 3000)
    return () => clearInterval(interval)
  }, [sessions, fetchSessions])

  // Connect SSE for active sessions
  useEffect(() => {
    const activeSessions = sessions.filter(s =>
      s.state === 'downloading' || s.state === 'extracting' || s.state === 'verifying'
    )

    activeSessions.forEach(session => {
      if (eventSourcesRef.current[session.id]) return
      const es = new EventSource(endpoints.sessionProgress(session.id))
      eventSourcesRef.current[session.id] = es

      es.addEventListener('progress', (e) => {
        try {
          const progress: ProcessingProgress = JSON.parse((e as MessageEvent).data)
          setLiveProgress(prev => ({ ...prev, [session.id]: progress }))
        } catch { /* ignore */ }
      })

      es.addEventListener('done', () => {
        es.close()
        delete eventSourcesRef.current[session.id]
        fetchSessions()
      })

      es.onerror = () => {
        es.close()
        delete eventSourcesRef.current[session.id]
      }
    })

    return () => {
      Object.values(eventSourcesRef.current).forEach(es => es.close())
      eventSourcesRef.current = {}
    }
  }, [sessions, fetchSessions])

  // Start sync for all selected accounts
  const handleStartSync = async () => {
    if (!bucket || !startDate || !endDate || accountsToSync.length === 0) return
    setSyncing(true)
    setSyncError(null)

    try {
      for (const acct of accountsToSync) {
        // Create session
        const createRes = await fetch(endpoints.sessions, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            bucket, account_id: acct, org_id: orgId || undefined,
            region: bucketRegion, log_region: logRegion, mode,
            start_date: startDate, end_date: endDate,
          }),
        })
        if (!createRes.ok) {
          const err = await createRes.json().catch(() => ({ message: `Failed to create session for ${acct}` }))
          throw new Error(err.message)
        }
        const session: Session = await createRes.json()

        // Start processing
        const startRes = await fetch(endpoints.sessionProcess(session.id), { method: 'POST' })
        if (!startRes.ok) {
          const err = await startRes.json().catch(() => ({ message: `Failed to start sync for ${acct}` }))
          throw new Error(err.message)
        }
      }
      fetchSessions()
    } catch (e) {
      setSyncError((e as Error).message)
    } finally {
      setSyncing(false)
    }
  }

  const canSubmit = bucket && accountsToSync.length > 0 && startDate && endDate && !syncing

  if (settingsLoading) {
    return <div className="flex items-center justify-center h-full"><Loader2 className="w-5 h-5 animate-spin text-gray-400" /></div>
  }

  if (!bucket) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center p-8 rounded-lg border border-dashed border-gray-300 dark:border-gray-600">
          <AlertCircle className="w-8 h-8 text-amber-500 mx-auto mb-3" />
          <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-2">{t('data.sync.configIncomplete')}</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">{t('data.sync.goToSettings')}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900">
        <div className="flex items-center gap-3">
          <CloudDownload className="w-5 h-5 text-[#0972d3]" />
          <div>
            <h2 className="text-base font-semibold text-gray-900 dark:text-white">{t('data.sync.title')}</h2>
            <p className="text-[11px] text-gray-500 dark:text-gray-400">
              {t('data.sync.accountsSelected', { count: accountsToSync.length })}
              &nbsp;• Region: {logRegion} • {mode === 'control_tower' ? 'Control Tower' : 'Single Account'}
            </p>
          </div>
        </div>
        <button type="button" onClick={fetchSessions} className="inline-flex items-center gap-1 px-3 py-1.5 text-xs rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800">
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-3xl space-y-6">

          {/* New Sync Form */}
          <div className="p-4 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 space-y-4">
            <h3 className="text-sm font-medium text-gray-900 dark:text-white">{t('data.sync.newSync')}</h3>

            {/* Accounts summary */}
            <div className="p-3 rounded bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700">
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1.5">{t('data.sync.accountsToDownload')}</p>
              <div className="flex flex-wrap gap-1.5">
                {accountsToSync.map(acct => (
                  <span key={acct} className="inline-block px-2 py-0.5 text-[11px] font-mono bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded">
                    {acct}
                  </span>
                ))}
              </div>
              {accountsToSync.length === 0 && (
                <p className="text-xs text-amber-600">{t('data.sync.noAccountsSelected')}</p>
              )}
            </div>

            {/* Date range */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="startDate" className="block text-xs text-gray-500 mb-1">{t('data.sync.startDate')}</label>
                <input id="startDate" type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} className="w-full px-3 py-2 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
              </div>
              <div>
                <label htmlFor="endDate" className="block text-xs text-gray-500 mb-1">{t('data.sync.endDate')}</label>
                <input id="endDate" type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} className="w-full px-3 py-2 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
              </div>
            </div>

            <button type="button" onClick={handleStartSync} disabled={!canSubmit}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-[#0972d3] text-white hover:bg-[#0860b0] disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
              {syncing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {syncing ? t('data.sync.syncing', { count: accountsToSync.length }) : t('data.sync.startSync', { count: accountsToSync.length })}
            </button>
            {syncError && <p className="text-sm text-red-600 dark:text-red-400">{syncError}</p>}
          </div>

          {/* Active Downloads */}
          {sessions.filter(s => s.state === 'downloading' || s.state === 'extracting' || s.state === 'verifying').length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">{t('data.sync.activeDownloads')}</h3>
              <div className="space-y-2">
                {sessions.filter(s => s.state === 'downloading' || s.state === 'extracting' || s.state === 'verifying').map(session => (
                  <ActiveSessionCard key={session.id} session={session} progress={liveProgress[session.id]} />
                ))}
              </div>
            </div>
          )}

          {/* Completed Syncs */}
          <div>
            <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">{t('data.sync.syncHistory')}</h3>
            {sessionsLoading && <div className="flex items-center gap-2 text-sm text-gray-500"><Loader2 className="w-3 h-3 animate-spin" /> Loading...</div>}

            {!sessionsLoading && sessions.filter(s => s.state !== 'downloading' && s.state !== 'extracting' && s.state !== 'verifying').length === 0 && (
              <p className="text-sm text-gray-500 dark:text-gray-400">{t('data.sync.noCompleted')}</p>
            )}

            {sessions.filter(s => s.state !== 'downloading' && s.state !== 'extracting' && s.state !== 'verifying').length > 0 && (
              <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-gray-50 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
                      <th className="text-left px-3 py-2 font-medium text-gray-500">{t('data.sync.account')}</th>
                      <th className="text-left px-3 py-2 font-medium text-gray-500">{t('data.sync.dateRange')}</th>
                      <th className="text-left px-3 py-2 font-medium text-gray-500">{t('data.sync.files')}</th>
                      <th className="text-left px-3 py-2 font-medium text-gray-500">{t('data.sync.status')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.filter(s => s.state !== 'downloading' && s.state !== 'extracting' && s.state !== 'verifying').map(session => (
                      <tr key={session.id} className="border-b border-gray-100 dark:border-gray-800 last:border-0">
                        <td className="px-3 py-2 font-mono text-gray-900 dark:text-white">{session.account_id}</td>
                        <td className="px-3 py-2 text-gray-600 dark:text-gray-400">{session.start_date} → {session.end_date}</td>
                        <td className="px-3 py-2 text-gray-600 dark:text-gray-400">{session.total_files}</td>
                        <td className="px-3 py-2">
                          <StatusChip state={session.state} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function ActiveSessionCard({ session, progress }: { session: Session, progress?: ProcessingProgress }) {
  const pct = progress?.percentage || 0
  const filesCompleted = progress?.files_completed || 0
  const totalFiles = progress?.total_files || session.total_files || 0
  const phase = progress?.phase || session.state
  const message = progress?.message || `${phase}...`

  return (
    <div className="p-4 rounded-lg border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/10">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Loader2 className="w-4 h-4 animate-spin text-blue-600" />
          <span className="text-sm font-mono font-medium text-gray-900 dark:text-white">{session.account_id}</span>
          <span className="text-[10px] text-gray-500 bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 rounded">{session.log_region}</span>
        </div>
        <span className="text-xs font-medium text-blue-600">{pct}%</span>
      </div>

      {/* Progress bar */}
      <div className="w-full h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden mb-2">
        <div
          className="h-full bg-blue-500 rounded-full transition-all duration-500"
          style={{ width: `${Math.max(pct, 2)}%` }}
        />
      </div>

      <div className="flex items-center justify-between">
        <span className="text-[11px] text-gray-600 dark:text-gray-400">{message}</span>
        <span className="text-[11px] text-gray-500">
          {filesCompleted}/{totalFiles} files • {session.start_date} → {session.end_date}
        </span>
      </div>
    </div>
  )
}

function StatusChip({ state }: { state: string }) {
  const styles: Record<string, string> = {
    'query-ready': 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'failed': 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'pending': 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
    'interrupted': 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    'partially-verified': 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
  }
  return (
    <span className={`inline-block px-2 py-0.5 text-[10px] font-medium rounded ${styles[state] || styles['pending']}`}>
      {state === 'query-ready' ? 'Ready' : state}
    </span>
  )
}
