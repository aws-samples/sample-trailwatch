import { useState, useEffect, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Database, CheckCircle2, XCircle, Loader2, Save, ShieldCheck, RefreshCw, Plus } from 'lucide-react'
import { useSettings } from './hooks'
import { AccountNamesSection } from './AccountNamesSection'
import { StatusBadge } from '../../comm/StatusBadge'
import { readApiError } from '../../comm/apiError'
import { endpoints } from '../../config/api'
import { stableStringify } from '../../utils/json'

const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-south-1',
  'ca-central-1', 'sa-east-1',
]

export const ORGANIZATION_TRAIL_MODE = {
  value: 'control_tower',
  label: 'Organization / Control Tower',
  description: 'Multi-account trail',
} as const

interface CallerIdentity {
  account_id: string
  arn: string
  user_id: string
}

interface BucketStructureResponse {
  mode: 'single' | 'control_tower'
  org_id?: string
  accounts?: unknown
}

type AccountIdSource = 'caller' | 'saved' | 'detected' | null

export function S3ConfigView() {
  const { t } = useTranslation()
  const { data: settings, loading: settingsLoading, error: settingsError, refetch } = useSettings()

  // Form state
  const [bucket, setBucket] = useState('')
  const [region, setRegion] = useState('ap-south-1')
  const [mode, setMode] = useState<'single' | 'control_tower'>('single')
  const [orgId, setOrgId] = useState('')
  const [accountId, setAccountId] = useState('')
  const [accountIdSource, setAccountIdSource] = useState<AccountIdSource>(null)

  // Discovery state
  const [callerIdentity, setCallerIdentity] = useState<CallerIdentity | null>(null)
  const [callerLoading, setCallerLoading] = useState(false)
  const [callerError, setCallerError] = useState<string | null>(null)
  const callerRequestRef = useRef(0)
  const callerAbortRef = useRef<AbortController | null>(null)
  const [discoveredAccounts, setDiscoveredAccounts] = useState<string[]>([])
  const [selectedAccounts, setSelectedAccounts] = useState<string[]>([])
  const [manualAccountId, setManualAccountId] = useState('')
  const [discoveringAccounts, setDiscoveringAccounts] = useState(false)
  const [discoveryError, setDiscoveryError] = useState<string | null>(null)
  const discoveryRequestRef = useRef(0)
  const discoveryAbortRef = useRef<AbortController | null>(null)

  // UI state
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ valid: boolean; message: string } | null>(null)
  const testRequestRef = useRef(0)
  const testAbortRef = useRef<AbortController | null>(null)
  const [saving, setSaving] = useState(false)
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const loadCallerIdentity = useCallback(async () => {
    callerAbortRef.current?.abort()
    const requestId = ++callerRequestRef.current
    const controller = new AbortController()
    callerAbortRef.current = controller
    setCallerLoading(true)
    setCallerError(null)
    setCallerIdentity(null)

    try {
      const res = await fetch(endpoints.callerIdentity, { signal: controller.signal })
      if (!res.ok) {
        throw new Error(await readApiError(res, 'Failed to load caller identity'))
      }

      const data = await res.json() as Partial<CallerIdentity>
      if (requestId !== callerRequestRef.current) return
      if (
        typeof data.account_id !== 'string' ||
        typeof data.arn !== 'string' ||
        typeof data.user_id !== 'string'
      ) {
        throw new Error('Caller identity returned an invalid response')
      }
      setCallerIdentity(data as CallerIdentity)
    } catch (e) {
      if (controller.signal.aborted || requestId !== callerRequestRef.current) return
      setCallerError(e instanceof Error ? e.message : 'Failed to load caller identity')
    } finally {
      if (requestId === callerRequestRef.current) {
        setCallerLoading(false)
        if (callerAbortRef.current === controller) {
          callerAbortRef.current = null
        }
      }
    }
  }, [])

  // Fetch caller identity on mount and cancel it if the view is closed.
  useEffect(() => {
    void loadCallerIdentity()
    return () => {
      callerRequestRef.current += 1
      callerAbortRef.current?.abort()
    }
  }, [loadCallerIdentity])

  const invalidateTest = useCallback(() => {
    testRequestRef.current += 1
    testAbortRef.current?.abort()
    testAbortRef.current = null
    setTesting(false)
    setTestResult(null)
  }, [])

  // Load saved settings
  useEffect(() => {
    if (settings) {
      invalidateTest()
      setBucket(settings.s3.bucket || '')
      setRegion(settings.s3.region || 'us-east-1')
      setMode(settings.s3.mode || 'single')
      setOrgId(settings.s3.org_id || '')
      setAccountId(settings.s3.account_id || '')
      setAccountIdSource(settings.s3.account_id ? 'saved' : null)
      const savedAccounts = settings.s3.member_accounts || []
      setSelectedAccounts(savedAccounts)
      setDiscoveredAccounts(savedAccounts)
      setManualAccountId('')
    }
  }, [settings, invalidateTest])

  // Auto-fill account from caller identity for single mode
  useEffect(() => {
    if (
      mode === 'single' &&
      callerIdentity?.account_id &&
      (!accountId || accountIdSource === 'detected')
    ) {
      setAccountId(callerIdentity.account_id)
      setAccountIdSource('caller')
    }
  }, [mode, callerIdentity, accountId, accountIdSource])

  const cancelDiscovery = useCallback(() => {
    discoveryRequestRef.current += 1
    discoveryAbortRef.current?.abort()
    discoveryAbortRef.current = null
    setDiscoveringAccounts(false)
    setDiscoveryError(null)
  }, [])

  const invalidateDiscovery = useCallback(() => {
    cancelDiscovery()
    setDiscoveredAccounts([])
    setSelectedAccounts([])
    setManualAccountId('')
  }, [cancelDiscovery])

  useEffect(() => {
    return () => {
      discoveryRequestRef.current += 1
      discoveryAbortRef.current?.abort()
    }
  }, [])

  // Explicitly detect bucket structure and accounts from the current form.
  const detectStructure = useCallback(async () => {
    if (!settings || !bucket || !region) return

    discoveryAbortRef.current?.abort()
    const requestId = ++discoveryRequestRef.current
    const controller = new AbortController()
    discoveryAbortRef.current = controller
    setDiscoveringAccounts(true)
    setDiscoveryError(null)

    try {
      const res = await fetch(endpoints.detectStructure, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: stableStringify({ bucket, region }),
        signal: controller.signal,
      })
      if (!res.ok) {
        throw new Error(await readApiError(res, 'Failed to discover bucket structure'))
      }

      const data = await res.json() as Partial<BucketStructureResponse>
      if (requestId !== discoveryRequestRef.current) return
      if (data.mode !== 'single' && data.mode !== 'control_tower') {
        throw new Error('Bucket discovery returned an invalid response')
      }

      const accounts = Array.isArray(data.accounts)
        ? data.accounts.filter((account): account is string => typeof account === 'string')
        : []

      setDiscoveredAccounts(accounts)
      setSelectedAccounts(current => current.filter(account => accounts.includes(account)))
      if (data.mode === 'control_tower') {
        setMode('control_tower')
        setOrgId(data.org_id || '')
      } else {
        setMode('single')
        setOrgId('')
        setSelectedAccounts([])
        const detectedAccount = callerIdentity?.account_id || accounts[0] || ''
        setAccountId(detectedAccount)
        setAccountIdSource(
          callerIdentity?.account_id ? 'caller' : detectedAccount ? 'detected' : null,
        )
      }
    } catch (e) {
      if (controller.signal.aborted || requestId !== discoveryRequestRef.current) return
      setDiscoveryError((e as Error).message || 'Failed to discover bucket structure')
    } finally {
      if (requestId === discoveryRequestRef.current) {
        setDiscoveringAccounts(false)
        if (discoveryAbortRef.current === controller) {
          discoveryAbortRef.current = null
        }
      }
    }
  }, [settings, bucket, region, callerIdentity])

  const addManualAccount = useCallback(() => {
    const account = manualAccountId.trim()
    if (!/^\d{12}$/.test(account)) return
    setDiscoveredAccounts(current => current.includes(account) ? current : [...current, account])
    setSelectedAccounts(current => current.includes(account) ? current : [...current, account])
    setDiscoveryError(null)
    setManualAccountId('')
  }, [manualAccountId])

  // Test Connection
  const handleTestConnection = useCallback(async () => {
    testAbortRef.current?.abort()
    const requestId = ++testRequestRef.current
    const controller = new AbortController()
    testAbortRef.current = controller
    setTesting(true)
    setTestResult(null)

    try {
      const res = await fetch(endpoints.validateBucket, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: stableStringify({ bucket, region }),
        signal: controller.signal,
      })
      if (!res.ok) {
        throw new Error(await readApiError(res, 'Bucket validation failed'))
      }

      const result = await res.json() as { valid: boolean; message: string }
      if (requestId !== testRequestRef.current) return
      setTestResult(result)
    } catch (e) {
      if (controller.signal.aborted || requestId !== testRequestRef.current) return
      setTestResult({
        valid: false,
        message: e instanceof Error ? e.message : 'Bucket validation failed',
      })
    } finally {
      if (requestId === testRequestRef.current) {
        setTesting(false)
        if (testAbortRef.current === controller) {
          testAbortRef.current = null
        }
      }
    }
  }, [bucket, region])

  useEffect(() => {
    return () => {
      testRequestRef.current += 1
      testAbortRef.current?.abort()
    }
  }, [])

  // Save
  const handleSave = useCallback(async () => {
    setSaving(true)
    setFeedback(null)
    try {
      const saveBody = mode === 'control_tower'
        ? {
            bucket,
            region,
            mode,
            org_id: orgId,
            account_id: selectedAccounts[0],
            member_accounts: selectedAccounts,
          }
        : {
            bucket,
            region,
            mode,
            org_id: '',
            account_id: accountId,
            member_accounts: [],
          }
      const res = await fetch(endpoints.settings, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: stableStringify(saveBody),
      })
      if (!res.ok) {
        setFeedback({ type: 'error', text: await readApiError(res, 'Save failed') })
      } else {
        setFeedback({ type: 'success', text: 'Configuration saved' })
        await refetch()
      }
    } catch (e) {
      setFeedback({ type: 'error', text: (e as Error).message })
    } finally { setSaving(false) }
  }, [bucket, region, mode, orgId, accountId, selectedAccounts, refetch])

  if (settingsLoading) {
    return <div className="flex items-center justify-center h-full"><Loader2 className="w-5 h-5 animate-spin text-gray-400" /></div>
  }

  if (settingsError || !settings) {
    return (
      <div className="flex items-center justify-center h-full p-6">
        <div role="alert" className="max-w-md w-full p-5 rounded-lg border border-red-200 dark:border-red-900/30 bg-red-50 dark:bg-red-900/10 text-center">
          <XCircle className="w-7 h-7 text-red-500 mx-auto mb-2" />
          <h2 className="text-sm font-semibold text-red-800 dark:text-red-200">Unable to load settings</h2>
          <p className="mt-1 text-xs text-red-700 dark:text-red-300">{settingsError || 'The settings response was empty.'}</p>
          <button type="button" onClick={() => void refetch()}
            className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 hover:bg-red-100 dark:hover:bg-red-900/20">
            <RefreshCw className="w-3.5 h-3.5" /> {t('common.retry')}
          </button>
        </div>
      </div>
    )
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
            {callerError && (
              <div role="alert" className="flex items-center justify-between gap-3">
                <span className="text-sm text-amber-700 dark:text-amber-400">{callerError}</span>
                <button
                  type="button"
                  onClick={() => void loadCallerIdentity()}
                  disabled={callerLoading}
                  className="shrink-0 inline-flex items-center gap-1.5 px-2 py-1 text-xs font-medium rounded-md border border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-300 hover:bg-amber-100 dark:hover:bg-amber-900/20 disabled:opacity-50"
                >
                  <RefreshCw className="w-3 h-3" />
                  {t('common.retry')}
                </button>
              </div>
            )}
            {callerIdentity && (
              <span className="text-sm"><span className="font-mono font-medium text-gray-900 dark:text-white">{callerIdentity.account_id}</span> <span className="text-xs text-gray-600 dark:text-gray-400">{callerIdentity.arn.split('/').pop()}</span></span>
            )}
          </div>

          {/* Account Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">{t('settings.s3config.accountMode')}</label>
            <div className="grid grid-cols-2 gap-2">
              <label className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border cursor-pointer transition-all ${mode === 'single' ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 ring-1 ring-blue-500' : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800'}`}>
                <input type="radio" name="mode" checked={mode === 'single'} onChange={() => {
                  cancelDiscovery()
                  setMode('single')
                  const callerAccount = callerIdentity?.account_id
                  if (callerAccount) {
                    setAccountId(callerAccount)
                    setAccountIdSource('caller')
                  } else if (!accountId && settings.s3.account_id) {
                    setAccountId(settings.s3.account_id)
                    setAccountIdSource('saved')
                  }
                }} className="text-blue-600" />
                <div><span className={`text-sm font-medium block ${mode === 'single' ? 'text-blue-700 dark:text-blue-300' : 'text-gray-900 dark:text-white'}`}>{t('settings.s3config.singleAccount')}</span><span className="text-xs text-gray-600 dark:text-gray-300">{t('settings.s3config.oneAccount')}</span></div>
              </label>
              <label className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border cursor-pointer transition-all ${mode === ORGANIZATION_TRAIL_MODE.value ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 ring-1 ring-blue-500' : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800'}`}>
                <input type="radio" name="mode" checked={mode === ORGANIZATION_TRAIL_MODE.value} onChange={() => { cancelDiscovery(); setMode(ORGANIZATION_TRAIL_MODE.value) }} className="text-blue-600" />
                <div><span className={`text-sm font-medium block ${mode === ORGANIZATION_TRAIL_MODE.value ? 'text-blue-700 dark:text-blue-300' : 'text-gray-900 dark:text-white'}`}>{ORGANIZATION_TRAIL_MODE.label}</span><span className="text-xs text-gray-600 dark:text-gray-300">{ORGANIZATION_TRAIL_MODE.description}</span></div>
              </label>
            </div>
          </div>

          {/* Bucket */}
          <div>
            <label htmlFor="bucket" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('settings.s3config.bucketName')}</label>
            <input id="bucket" type="text" value={bucket} onChange={(e) => { invalidateDiscovery(); invalidateTest(); setBucket(e.target.value) }} placeholder="aws-cloudtrail-logs-..." className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>

          {/* Bucket Region */}
          <div>
            <label htmlFor="region" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('settings.s3config.bucketRegion')}</label>
            <select id="region" value={region} onChange={(e) => { invalidateDiscovery(); invalidateTest(); setRegion(e.target.value) }} className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
              {AWS_REGIONS.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>

          {/* Explicit structure detection */}
          <button
            type="button"
            onClick={detectStructure}
            disabled={!bucket || !region || discoveringAccounts}
            className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${discoveringAccounts ? 'animate-spin' : ''}`} />
            {discoveringAccounts ? t('settings.s3config.detecting') : t('settings.s3config.detectStructure')}
          </button>
          {discoveryError && (
            <div role="alert" className="p-3 rounded-lg border border-red-200 dark:border-red-900/30 bg-red-50 dark:bg-red-900/10">
              <p className="text-xs text-red-700 dark:text-red-300">{discoveryError}</p>
            </div>
          )}

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
                <button type="button" onClick={detectStructure} disabled={discoveringAccounts || !bucket || !region}
                  className="inline-flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-50">
                  <RefreshCw className={`w-3 h-3 ${discoveringAccounts ? 'animate-spin' : ''}`} />
                  {discoveringAccounts ? t('settings.s3config.discovering') : t('settings.s3config.discover')}
                </button>
              )}
            </div>

            {mode === 'control_tower' && (
              <div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    inputMode="numeric"
                    value={manualAccountId}
                    onChange={event => setManualAccountId(event.target.value)}
                    onKeyDown={event => {
                      if (event.key === 'Enter' && /^\d{12}$/.test(manualAccountId.trim())) {
                        event.preventDefault()
                        addManualAccount()
                      }
                    }}
                    aria-label={t('settings.s3config.manualAccount', { defaultValue: 'Add account ID manually' })}
                    aria-invalid={manualAccountId.length > 0 && !/^\d{12}$/.test(manualAccountId.trim())}
                    placeholder={t('settings.s3config.manualAccountPlaceholder', { defaultValue: '12-digit account ID' })}
                    className="min-w-0 flex-1 px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <button
                    type="button"
                    onClick={addManualAccount}
                    disabled={!/^\d{12}$/.test(manualAccountId.trim())}
                    aria-label={t('settings.s3config.addAccount', { defaultValue: 'Add account' })}
                    title={t('settings.s3config.addAccount', { defaultValue: 'Add account' })}
                    className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <Plus className="h-4 w-4" />
                  </button>
                </div>
                {manualAccountId.length > 0 && !/^\d{12}$/.test(manualAccountId.trim()) && (
                  <p role="alert" className="mt-1 text-xs text-red-600 dark:text-red-400">
                    {t('settings.s3config.accountIdFormat', { defaultValue: 'Account ID must contain exactly 12 digits.' })}
                  </p>
                )}
              </div>
            )}

            {/* Single mode: show caller identity account */}
            {mode === 'single' && (
              <div className="text-sm">
                <span className="font-mono text-gray-900 dark:text-white">{accountId || callerIdentity?.account_id || '—'}</span>
                {accountIdSource === 'caller' && callerIdentity?.account_id === accountId && (
                  <span className="text-xs text-gray-500 ml-2">(from caller identity)</span>
                )}
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
                    disabled={discoveringAccounts}
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
                        disabled={discoveringAccounts}
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
            {mode === 'control_tower' && !discoveringAccounts && !discoveryError && discoveredAccounts.length === 0 && (
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
            <button type="button" onClick={handleSave} disabled={saving || discoveringAccounts || !bucket || !region || (mode === 'control_tower' ? !orgId || selectedAccounts.length === 0 : !accountId)}
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
