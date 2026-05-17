import { useState, useEffect, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { CloudDownload, Loader2, Play, AlertCircle, RefreshCw, Database, Square, RotateCw, Zap, Clock, HardDrive } from 'lucide-react'
import { useSettings } from '../settings/hooks'
import { useIndexStatus, useIndexProgress } from './hooks'
import { endpoints } from '../../config/api'
import { readApiError } from '../../comm/apiError'
import type { Session, ProgressSnapshot } from '../../types/session'

export function S3SyncView() {
  const { t } = useTranslation()
  const { data: settings, loading: settingsLoading } = useSettings()

  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [sessions, setSessions] = useState<Session[]>([])
  const [sessionsLoading, setSessionsLoading] = useState(true)
  const [sessionsError, setSessionsError] = useState<string | null>(null)
  const [syncing, setSyncing] = useState(false)
  const [syncError, setSyncError] = useState<string | null>(null)
  const [liveProgress, setLiveProgress] = useState<Record<string, ProgressSnapshot>>({})
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

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
      setSessionsError(null)
      const res = await fetch('/api/sessions')
      if (!res.ok) {
        setSessionsError(await readApiError(res, 'Failed to load sessions'))
        return
      }
      const data = await res.json()
      if (Array.isArray(data)) setSessions(data.slice(0, 30))
    } catch (e: any) {
      setSessionsError(e?.message || 'Failed to load sessions')
    } finally {
      setSessionsLoading(false)
    }
  }, [])

  useEffect(() => { fetchSessions() }, [fetchSessions])

  // Poll progress snapshots for active sessions every 2 seconds
  useEffect(() => {
    const activeSessions = sessions.filter(s =>
      s.state === 'downloading' || s.state === 'extracting' || s.state === 'verifying'
    )
    if (activeSessions.length === 0) {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
      return
    }

    const pollProgress = async () => {
      const updates: Record<string, ProgressSnapshot> = {}
      await Promise.all(activeSessions.map(async (session) => {
        try {
          const res = await fetch(endpoints.sessionProgressSnapshot(session.id))
          if (res.ok) {
            const snap = await res.json()
            if (snap.phase && snap.phase !== 'idle') {
              updates[session.id] = snap
            }
          }
        } catch { /* silent */ }
      }))
      if (Object.keys(updates).length > 0) {
        setLiveProgress(prev => ({ ...prev, ...updates }))
      }
    }

    pollProgress()
    pollRef.current = setInterval(() => { pollProgress(); fetchSessions() }, 2000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
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
              <div className="space-y-3">
                {sessions.filter(s => s.state === 'downloading' || s.state === 'extracting' || s.state === 'verifying').map(session => (
                  <ActiveSessionCard key={session.id} session={session} snapshot={liveProgress[session.id]} />
                ))}
              </div>
            </div>
          )}

          {/* Index Progress */}
          <IndexProgressCard />

          {/* Completed Syncs */}
          <div>
            <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3">{t('data.sync.syncHistory')}</h3>
            {sessionsLoading && <div className="flex items-center gap-2 text-sm text-gray-500"><Loader2 className="w-3 h-3 animate-spin" /> Loading...</div>}

            {sessionsError && (
              <div className="p-3 rounded-md border border-red-200 dark:border-red-900/30 bg-red-50 dark:bg-red-900/10 mb-3">
                <p className="text-xs text-red-700 dark:text-red-300">{sessionsError}</p>
              </div>
            )}

            {!sessionsLoading && !sessionsError && sessions.filter(s => s.state !== 'downloading' && s.state !== 'extracting' && s.state !== 'verifying').length === 0 && (
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
                      <th className="text-left px-3 py-2 font-medium text-gray-500">{t('data.sync.sizeOnDisk')}</th>
                      <th className="text-left px-3 py-2 font-medium text-gray-500">{t('data.sync.lastUpdated')}</th>
                      <th className="text-left px-3 py-2 font-medium text-gray-500">{t('data.sync.status')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.filter(s => s.state !== 'downloading' && s.state !== 'extracting' && s.state !== 'verifying').map(session => (
                      <tr key={session.id} className="border-b border-gray-100 dark:border-gray-800 last:border-0">
                        <td className="px-3 py-2 font-mono text-gray-900 dark:text-white">{session.account_id}</td>
                        <td className="px-3 py-2 text-gray-600 dark:text-gray-400">{session.start_date} → {session.end_date}</td>
                        <td className="px-3 py-2 text-gray-600 dark:text-gray-400">{session.total_files}</td>
                        <td className="px-3 py-2 text-gray-600 dark:text-gray-400 tabular-nums">{session.disk_usage_bytes > 0 ? formatBytes(session.disk_usage_bytes) : '—'}</td>
                        <td className="px-3 py-2 text-gray-600 dark:text-gray-400">{formatRelativeTime(session.updated_at)}</td>
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

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function formatRelativeTime(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  const t = d.getTime()
  // Reject invalid dates and Go's zero time (0001-01-01T00:00:00Z)
  if (Number.isNaN(t) || d.getUTCFullYear() < 1971) return '—'
  const secs = Math.max(0, Math.floor((Date.now() - t) / 1000))
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  if (days < 30) return `${days}d ago`
  return d.toLocaleDateString()
}

function IndexProgressCard() {
  const { t } = useTranslation()
  const { status, refresh } = useIndexStatus()
  const { data: progress, done, active, connect } = useIndexProgress()

  const handleBuild = async () => {
    await fetch(endpoints.indexBuild, { method: 'POST' })
    connect()
    refresh()
  }

  const handleCancel = async () => {
    await fetch(endpoints.indexCancel, { method: 'POST' })
    refresh()
  }

  useEffect(() => {
    if (done) refresh()
  }, [done, refresh])

  useEffect(() => {
    if (status?.index_status === 'building' && !active) {
      connect()
    }
  }, [status, active, connect])

  const pct = progress?.percentage || 0
  const isBuilding = status?.index_status === 'building' || active
  const isPaused = status?.index_status === 'paused'
  const isError = status?.index_status === 'error'

  return (
    <div className="p-4 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Database className="w-4 h-4 text-[#0972d3]" />
          <h3 className="text-sm font-medium text-gray-900 dark:text-white">{t('data.sync.duckdbIndex')}</h3>
        </div>
        {status?.indexed && !isBuilding && !isPaused && (
          <span className="text-[10px] text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/30 px-2 py-0.5 rounded font-medium">
            {t('data.sync.indexed')}
          </span>
        )}
        {isPaused && (
          <span className="text-[10px] text-amber-600 dark:text-amber-400 bg-amber-100 dark:bg-amber-900/30 px-2 py-0.5 rounded font-medium">
            {t('data.sync.paused')}
          </span>
        )}
      </div>

      {isBuilding && progress && (
        <>
          <div className="w-full h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden mb-2">
            <div
              className="h-full bg-blue-500 rounded-full transition-all duration-500"
              style={{ width: `${Math.max(pct, 2)}%` }}
            />
          </div>
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] text-gray-600 dark:text-gray-400">
              {formatBytes(progress.processed_bytes)} / {formatBytes(progress.total_bytes)}
            </span>
            <span className="text-[11px] text-gray-500">
              {progress.processed_files}/{progress.total_files} files • {pct.toFixed(0)}%
            </span>
          </div>
          <button type="button" onClick={handleCancel}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors">
            <Square className="w-3 h-3" /> Cancel
          </button>
        </>
      )}

      {isBuilding && !progress && (
        <div className="flex items-center gap-2 text-sm text-gray-500">
          <Loader2 className="w-3 h-3 animate-spin" /> Starting index build...
        </div>
      )}

      {!isBuilding && !isPaused && !isError && (
        <div className="flex items-center justify-between">
          <span className="text-[11px] text-gray-500 dark:text-gray-400">
            {status?.indexed
              ? `${status.total_files_indexed} files (${formatBytes(status.total_bytes_indexed || 0)}) — ${status.age_seconds && status.age_seconds < 60 ? '<1 min ago' : `${Math.round((status.age_seconds || 0) / 60)} min ago`}`
              : 'Not indexed yet'}
          </span>
          <button type="button" onClick={handleBuild}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
            <RotateCw className="w-3 h-3" /> {status?.indexed ? 'Re-index' : 'Build Index'}
          </button>
        </div>
      )}

      {isPaused && (
        <div className="flex items-center justify-between">
          <span className="text-[11px] text-gray-500 dark:text-gray-400">
            {status?.total_files_indexed} of {progress?.total_files || '?'} files indexed
          </span>
          <button type="button" onClick={handleBuild}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-blue-300 dark:border-blue-700 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors">
            <Play className="w-3 h-3" /> Resume
          </button>
        </div>
      )}

      {isError && (
        <div className="flex items-center justify-between">
          <span className="text-[11px] text-red-600 dark:text-red-400">{t('data.sync.indexingFailed')}</span>
          <button type="button" onClick={handleBuild}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
            <RotateCw className="w-3 h-3" /> Retry
          </button>
        </div>
      )}
    </div>
  )
}

function ActiveSessionCard({ session, snapshot }: { session: Session, snapshot?: ProgressSnapshot }) {
  const { t } = useTranslation()
  const pct = snapshot?.percentage || 0
  const filesCompleted = snapshot?.files_completed || 0
  const totalFiles = snapshot?.total_files || session.total_files || 0
  const phase = snapshot?.phase || session.state
  const speed = snapshot?.speed_bytes_per_sec || 0
  const filesPerSec = snapshot?.files_per_sec || 0
  const eta = snapshot?.eta_seconds || 0
  const concurrency = snapshot?.concurrency || 0

  const formatETA = (secs: number) => {
    if (secs <= 0) return '--'
    if (secs < 60) return `${secs}s`
    if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`
    return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`
  }

  const hasData = totalFiles > 0

  return (
    <div className="p-4 rounded-lg border border-blue-200 dark:border-blue-800 bg-blue-50/50 dark:bg-blue-900/10">
      {/* Header row */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="relative">
            <Loader2 className="w-4 h-4 animate-spin text-blue-600" />
          </div>
          <span className="text-sm font-mono font-semibold text-gray-900 dark:text-white">{session.account_id}</span>
          <span className="text-[10px] text-gray-500 bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 rounded">{session.log_region}</span>
          <span className="text-[10px] font-medium text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/40 px-1.5 py-0.5 rounded capitalize">
            {phase}
          </span>
        </div>
        <span className="text-lg font-bold text-blue-600 dark:text-blue-400 tabular-nums">
          {pct.toFixed(1)}%
        </span>
      </div>

      {/* Progress bar */}
      <div className="w-full h-2.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden mb-3">
        <div
          className="h-full bg-gradient-to-r from-blue-500 to-blue-400 rounded-full transition-all duration-1000 ease-out"
          style={{ width: `${Math.max(pct, 1)}%` }}
        />
      </div>

      {/* Stats row */}
      {hasData ? (
        <div className="grid grid-cols-4 gap-3">
          <div className="flex items-center gap-1.5">
            <HardDrive className="w-3 h-3 text-gray-400 shrink-0" />
            <div>
              <div className="text-[10px] text-gray-500">{t('data.sync.statFiles')}</div>
              <div className="text-xs font-medium text-gray-900 dark:text-white tabular-nums">
                {filesCompleted.toLocaleString()}/{totalFiles.toLocaleString()}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <Zap className="w-3 h-3 text-gray-400 shrink-0" />
            <div>
              <div className="text-[10px] text-gray-500">{t('data.sync.statSpeed')}</div>
              <div className="text-xs font-medium text-gray-900 dark:text-white tabular-nums">
                {speed > 0 ? `${formatBytes(speed)}/s` : '--'}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <Clock className="w-3 h-3 text-gray-400 shrink-0" />
            <div>
              <div className="text-[10px] text-gray-500">{t('data.sync.statETA')}</div>
              <div className="text-xs font-medium text-gray-900 dark:text-white tabular-nums">
                {formatETA(eta)}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <RefreshCw className="w-3 h-3 text-gray-400 shrink-0" />
            <div>
              <div className="text-[10px] text-gray-500">{t('data.sync.statWorkers')}</div>
              <div className="text-xs font-medium text-gray-900 dark:text-white tabular-nums">
                {concurrency > 0 ? concurrency : '--'} • {filesPerSec > 0 ? `${filesPerSec.toFixed(1)} f/s` : '--'}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <Loader2 className="w-3 h-3 animate-spin text-gray-400" />
          <span className="text-[11px] text-gray-500">{t('data.sync.listingObjects', { startDate: session.start_date, endDate: session.end_date })}</span>
        </div>
      )}

      {/* Date range footer */}
      {hasData && (
        <div className="mt-2 pt-2 border-t border-blue-100 dark:border-blue-800/50 flex items-center justify-between">
          <span className="text-[10px] text-gray-500">{session.start_date} → {session.end_date}</span>
          <span className="text-[10px] text-gray-500">
            {formatBytes(snapshot?.bytes_transferred || 0)} / {formatBytes(snapshot?.total_bytes || 0)}
          </span>
        </div>
      )}
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
