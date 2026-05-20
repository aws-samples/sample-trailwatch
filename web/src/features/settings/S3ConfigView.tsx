import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Database, CheckCircle2, XCircle, Loader2, Save, ShieldCheck, RefreshCw } from 'lucide-react'
import { useSettings } from './hooks'
import { AccountNamesSection } from './AccountNamesSection'
import { StatusBadge } from '../../comm/StatusBadge'
import { endpoints } from '../../config/api'
import { stableStringify } from '../../utils/json'

const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-south-1',
  'ca-central-1', 'sa-east-1',
]

interface CallerIdentity {
  account_id: string
  arn: string
  user_id: string
}

export function S3ConfigView() {
  const { t } = useTranslation()
  const { data: settings, loading: settingsLoading, refetch } = useSettings()

  // Form state
  const [bucket, setBucket] = useState('')
  const [region, setRegion] = useState('ap-south-1')
  const [mode, setMode] = useState<'single' | 'control_tower'>('single')
  const [orgId, setOrgId] = useState('')
  const [accountId, setAccountId] = useState('')

  // Discovery state
  const [callerIdentity, setCallerIdentity] = useState<CallerIdentity | null>(null)
  const [callerLoading, setCallerLoading] = useState(false)
  const [callerError, setCallerError] = useState<string | null>(null)
  const [discoveredAccounts, setDiscoveredAccounts] = useState<string[]>([])
  const [selectedAccounts, setSelectedAccounts] = useState<string[]>([])
  const [discoveringAccounts, setDiscoveringAccounts] = useState(false)

  // UI state
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ valid: boolean; message: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // Fetch caller identity on mount
  useEffect(() => {
    setCallerLoading(true)
    fetch(endpoints.callerIdentity)
      .then(res => res.ok ? res.json() : null)
      .then(data => { if (data) setCallerIdentity(data) })
      .catch(e => setCallerError(e.message))
      .finally(() => setCallerLoading(false))
  }, [])

  // Load saved settings
  useEffect(() => {
    if (settings) {
      setBucket(settings.s3.bucket || '')
      setRegion(settings.s3.region || 'us-east-1')
      setMode(settings.s3.mode || 'single')
      setOrgId(settings.s3.org_id || '')
      setAccountId(settings.s3.account_id || '')
      if (settings.s3.member_accounts && settings.s3.member_accounts.length > 0) {
        setSelectedAccounts(settings.s3.member_accounts)
      }
    }
  }, [settings])

  // Auto-fill account from caller identity for single mode
  useEffect(() => {
    if (mode === 'single' && callerIdentity?.account_id) {
      setAccountId(callerIdentity.account_id)
    }
  }, [mode, callerIdentity])

  // Detect bucket structure (auto-detect single vs CT mode)
  const detectStructure = useCallback(async () => {
    if (!bucket || !region) return
    setDiscoveringAccounts(true)
    setDiscoveredAccounts([])
    try {
      const res = await fetch(endpoints.detectStructure, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: stableStringify({ bucket, region }),
      })
      if (res.ok) {
        const data = await res.json()
        if (data.mode === 'control_tower') {
          setMode('control_tower')
          setOrgId(data.org_id || '')
          if (data.accounts?.length > 0) setDiscoveredAccounts(data.accounts)
        } else {
          setMode('single')
          if (data.accounts?.length > 0) {
            setDiscoveredAccounts(data.accounts)
            setAccountId(data.accounts[0])
          }
        }
      }
    } catch { /* silent */ }
    finally { setDiscoveringAccounts(false) }
  }, [bucket, region])

  // Discover accounts (uses form values, not saved config)
  const discoverAccounts = useCallback(async () => {
    if (!bucket || !region) return
    setDiscoveringAccounts(true)
    setDiscoveredAccounts([])
    try {
      // Save current form values first so the API can use them
      await fetch(endpoints.settings, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: stableStringify({ bucket, region, mode, org_id: orgId }),
      })
      const res = await fetch(endpoints.accounts)
      if (res.ok) {
        const data = await res.json()
        if (data?.accounts && data.accounts.length > 0) {
          setDiscoveredAccounts(data.accounts)
        }
      }
    } catch { /* silent */ }
    finally { setDiscoveringAccounts(false) }
  }, [bucket, region, mode, orgId])

  // Auto-discover on mount if CT mode with bucket configured
  useEffect(() => {
    if (mode === 'control_tower' && bucket && orgId) {
      discoverAccounts()
    }
  }, [mode, bucket, orgId, discoverAccounts])

  // Test Connection
  const handleTestConnection = useCallback(async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await fetch(endpoints.validateBucket, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: stableStringify({ bucket, region }),
      })
      setTestResult(await res.json())
    } catch (e) {
      setTestResult({ valid: false, message: (e as Error).message })
    } finally { setTesting(false) }
  }, [bucket, region])

  // Save
  const handleSave = useCallback(async () => {
    setSaving(true)
    setFeedback(null)
    try {
      const saveBody: Record<string, any> = { bucket, region, mode, org_id: orgId }
      if (mode === 'control_tower' && selectedAccounts.length > 0) {
        saveBody.account_id = selectedAccounts[0]
        saveBody.member_accounts = selectedAccounts
      } else {
        saveBody.account_id = accountId
      }
      const res = await fetch(endpoints.settings, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: stableStringify(saveBody),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({ message: 'Save failed' }))
        setFeedback({ type: 'error', text: data.message })
      } else {
        setFeedback({ type: 'success', text: 'Configuration saved' })
        refetch()
      }
    } catch (e) {
      setFeedback({ type: 'error', text: (e as Error).message })
    } finally { setSaving(false) }
  }, [bucket, region, mode, orgId, accountId, selectedAccounts, refetch])

  if (settingsLoading) {
    return <div className="flex items-center justify-center h-full"><Loader2 className="w-5 h-5 animate-spin text-gray-400" /></div>
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3">
          <Database className="w-5 h-5 text-blue-600 dark:text-blue-400" />
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{t('settings.s3config.title')}</h2>
            <p className="text-xs text-gray-600 dark:text-gray-300">{t('settings.s3config.subtitle')}</p>
          </div>
        </div>
        {testResult?.valid && <StatusBadge status="ok" label="Connected" />}
      </div>

      {/* Form */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-lg space-y-5">

          {/* Caller Identity */}
          <div className="p-3 rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheck className="w-4 h-4 text-gray-600 dark:text-gray-300" />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{t('settings.s3config.callerIdentity')}</span>
            </div>
            {callerLoading && <span className="text-sm text-gray-600 dark:text-gray-300">{t('settings.s3config.fetching')}</span>}
            {callerError && <span className="text-sm text-amber-600 dark:text-amber-400">{callerError}</span>}
            {callerIdentity && (
              <span className="text-sm"><span className="font-mono font-medium text-gray-900 dark:text-white">{callerIdentity.account_id}</span> <span className="text-xs text-gray-600 dark:text-gray-400">{callerIdentity.arn.split('/').pop()}</span></span>
            )}
          </div>

          {/* Account Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">{t('settings.s3config.accountMode')}</label>
            <div className="grid grid-cols-2 gap-2">
              <label className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border cursor-pointer transition-all ${mode === 'single' ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 ring-1 ring-blue-500' : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800'}`}>
                <input type="radio" name="mode" checked={mode === 'single'} onChange={() => { setMode('single'); setOrgId(''); setDiscoveredAccounts([]) }} className="text-blue-600" />
                <div><span className={`text-sm font-medium block ${mode === 'single' ? 'text-blue-700 dark:text-blue-300' : 'text-gray-900 dark:text-white'}`}>{t('settings.s3config.singleAccount')}</span><span className="text-xs text-gray-600 dark:text-gray-300">{t('settings.s3config.oneAccount')}</span></div>
              </label>
              <label className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border cursor-pointer transition-all ${mode === 'control_tower' ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 ring-1 ring-blue-500' : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800'}`}>
                <input type="radio" name="mode" checked={mode === 'control_tower'} onChange={() => setMode('control_tower')} className="text-blue-600" />
                <div><span className={`text-sm font-medium block ${mode === 'control_tower' ? 'text-blue-700 dark:text-blue-300' : 'text-gray-900 dark:text-white'}`}>{t('settings.s3config.controlTower')}</span><span className="text-xs text-gray-600 dark:text-gray-300">{t('settings.s3config.multiAccount')}</span></div>
              </label>
            </div>
          </div>

          {/* Bucket */}
          <div>
            <label htmlFor="bucket" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('settings.s3config.bucketName')}</label>
            <input id="bucket" type="text" value={bucket} onChange={(e) => { setBucket(e.target.value); setTestResult(null) }} placeholder="aws-cloudtrail-logs-..." className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>

          {/* Bucket Region */}
          <div>
            <label htmlFor="region" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('settings.s3config.bucketRegion')}</label>
            <select id="region" value={region} onChange={(e) => { setRegion(e.target.value); setTestResult(null) }} className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
              {AWS_REGIONS.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>

          {/* Auto-detect structure */}
          <button
            type="button"
            onClick={detectStructure}
            disabled={!bucket || !region || discoveringAccounts}
            className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${discoveringAccounts ? 'animate-spin' : ''}`} />
            {discoveringAccounts ? t('settings.s3config.detecting') : t('settings.s3config.detectStructure')}
          </button>

          {/* Org ID — CT only */}
          {mode === 'control_tower' && (
            <div>
              <label htmlFor="orgId" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('settings.s3config.orgId')} <span className="text-xs text-gray-500 dark:text-gray-400 font-normal">{t('settings.s3config.orgIdExample')}</span></label>
              <input id="orgId" type="text" value={orgId} onChange={(e) => setOrgId(e.target.value)} placeholder="o-xxxxxxxxxx" className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
          )}

          {/* Account Selection */}
          <div className="p-4 rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
                {mode === 'control_tower' ? t('settings.s3config.targetAccounts') : t('data.sync.account')}
              </label>
              {mode === 'control_tower' && (
                <button type="button" onClick={discoverAccounts} disabled={discoveringAccounts || !bucket}
                  className="inline-flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-50">
                  <RefreshCw className={`w-3 h-3 ${discoveringAccounts ? 'animate-spin' : ''}`} />
                  {discoveringAccounts ? t('settings.s3config.discovering') : t('settings.s3config.discover')}
                </button>
              )}
            </div>

            {/* Single mode: show caller identity account */}
            {mode === 'single' && (
              <div className="text-sm">
                <span className="font-mono text-gray-900 dark:text-white">{accountId || callerIdentity?.account_id || '—'}</span>
                <span className="text-xs text-gray-500 ml-2">(from caller identity)</span>
              </div>
            )}

            {/* CT mode: checkboxes for discovered accounts (multi-select) */}
            {mode === 'control_tower' && discoveredAccounts.length > 0 && (
              <div className="space-y-1">
                {/* Select All */}
                <label className="flex items-center gap-2 px-3 py-2 rounded cursor-pointer bg-gray-100 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                  <input
                    type="checkbox"
                    checked={selectedAccounts.length === discoveredAccounts.length}
                    onChange={(e) => setSelectedAccounts(e.target.checked ? [...discoveredAccounts] : [])}
                    className="rounded text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-xs font-medium text-gray-700 dark:text-gray-300">{t('settings.s3config.selectAll', { count: discoveredAccounts.length })}</span>
                </label>
                <div className="max-h-48 overflow-y-auto space-y-1">
                  {discoveredAccounts.map((acct) => (
                    <label key={acct} className={`flex items-center gap-2 px-3 py-2 rounded cursor-pointer transition-colors ${selectedAccounts.includes(acct) ? 'bg-blue-50 dark:bg-blue-900/20' : 'hover:bg-gray-100 dark:hover:bg-gray-700/50'}`}>
                      <input
                        type="checkbox"
                        checked={selectedAccounts.includes(acct)}
                        onChange={(e) => {
                          if (e.target.checked) setSelectedAccounts([...selectedAccounts, acct])
                          else setSelectedAccounts(selectedAccounts.filter(a => a !== acct))
                        }}
                        className="rounded text-blue-600 focus:ring-blue-500"
                      />
                      <span className="text-sm font-mono text-gray-900 dark:text-white">{acct}</span>
                      {callerIdentity && acct === callerIdentity.account_id && <span className="text-xs text-blue-600 dark:text-blue-400">(caller)</span>}
                    </label>
                  ))}
                </div>
              </div>
            )}

            {/* CT mode: no accounts discovered yet */}
            {mode === 'control_tower' && !discoveringAccounts && discoveredAccounts.length === 0 && (
              <p className="text-xs text-gray-600 dark:text-gray-300">{t('settings.s3config.clickDiscover')}</p>
            )}

            {/* Selected accounts summary */}
            {mode === 'control_tower' && selectedAccounts.length > 0 && (
              <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
                <span className="text-xs text-gray-600 dark:text-gray-300">{t('settings.s3config.accountsSelected', { count: selectedAccounts.length })}</span>
              </div>
            )}
          </div>

          {/* Test + Save */}
          <div className="flex items-center gap-3 pt-3 border-t border-gray-200 dark:border-gray-700">
            <button type="button" onClick={handleSave} disabled={saving || !bucket || !region || !accountId}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              {t('settings.s3config.save')}
            </button>
            <button type="button" onClick={handleTestConnection} disabled={!bucket || !region || testing}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
              {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Database className="w-4 h-4" />}
              {t('settings.s3config.testConnection')}
            </button>
            {testResult && (
              <span className={`flex items-center gap-1 text-sm ${testResult.valid ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                {testResult.valid ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                {testResult.valid ? t('settings.s3config.accessible') : t('settings.s3config.failed')}
              </span>
            )}
          </div>

          {/* Feedback */}
          {feedback && (
            <div className={`flex items-center gap-2 p-3 rounded-lg border ${feedback.type === 'success' ? 'bg-green-50 dark:bg-green-900/10 border-green-200 dark:border-green-900/30' : 'bg-red-50 dark:bg-red-900/10 border-red-200 dark:border-red-900/30'}`}>
              {feedback.type === 'success' ? <CheckCircle2 className="w-4 h-4 text-green-600" /> : <XCircle className="w-4 h-4 text-red-600" />}
              <span className={`text-sm ${feedback.type === 'success' ? 'text-green-700 dark:text-green-300' : 'text-red-700 dark:text-red-300'}`}>{feedback.text}</span>
            </div>
          )}

          {/* Account names: union of all known account IDs (selected + caller) */}
          <AccountNamesSection
            accountIds={[
              ...(mode === 'control_tower' ? selectedAccounts : []),
              ...(accountId ? [accountId] : []),
              ...(callerIdentity?.account_id ? [callerIdentity.account_id] : []),
            ]}
          />

        </div>
      </div>
    </div>
  )
}
