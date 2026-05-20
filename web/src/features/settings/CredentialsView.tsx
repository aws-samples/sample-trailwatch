import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Shield, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { useSettings } from './hooks'
import { endpoints } from '../../config/api'

type AuthMethod = 'imds' | 'session_credentials' | 'sso' | 'static'

interface CredentialAttempt {
  source: string
  success: boolean
  reason: string
}

interface CredentialResult {
  source: string
  valid: boolean
  message: string
  attempts: CredentialAttempt[]
}

const AUTH_METHODS: { value: AuthMethod; labelKey: string; descKey: string; icon: string }[] = [
  { value: 'imds', labelKey: 'settings.credentials.method.imdsLabel', descKey: 'settings.credentials.method.imdsDesc', icon: '☁️' },
  { value: 'session_credentials', labelKey: 'settings.credentials.method.sessionLabel', descKey: 'settings.credentials.method.sessionDesc', icon: '🔐' },
  { value: 'sso', labelKey: 'settings.credentials.method.ssoLabel', descKey: 'settings.credentials.method.ssoDesc', icon: '🔑' },
  { value: 'static', labelKey: 'settings.credentials.method.staticLabel', descKey: 'settings.credentials.method.staticDesc', icon: '📋' },
]

export function CredentialsView() {
  const { t } = useTranslation()
  const { data: settings, loading: settingsLoading, refetch } = useSettings()

  const [method, setMethod] = useState<AuthMethod>('imds')
  const [accessKeyId, setAccessKeyId] = useState('')
  const [secretAccessKey, setSecretAccessKey] = useState('')
  const [ssoProfile, setSsoProfile] = useState('')

  // Session credentials state
  const [sessionAccessKeyId, setSessionAccessKeyId] = useState('')
  const [sessionSecretAccessKey, setSessionSecretAccessKey] = useState('')
  const [sessionToken, setSessionToken] = useState('')

  // Right panel state
  const [validating, setValidating] = useState(false)
  const [result, setResult] = useState<CredentialResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (settings) {
      setMethod(settings.auth.method || 'imds')
      if (settings.auth.sso_profile) {
        setSsoProfile(settings.auth.sso_profile)
      }
      // Pre-fill session credential fields from saved config
      if (settings.auth.method === 'session_credentials') {
        if (settings.auth.access_key_id) {
          setSessionAccessKeyId(settings.auth.access_key_id)
        }
      }
    }
  }, [settings])

  // Select method: save it, clear results, do NOT auto-validate
  // Select method: just switch the UI view, do NOT save to config
  const selectMethod = useCallback((newMethod: AuthMethod) => {
    setMethod(newMethod)
    setResult(null)
    setError(null)
  }, [])

  // Activate: saves method to config AND validates. This makes it the ACTIVE method.
  const activate = useCallback(async () => {
    setValidating(true)
    setResult(null)
    setError(null)
    // Save the method to make it active
    try {
      const saveRes = await fetch(endpoints.settings, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auth_method: method }),
      })
      if (saveRes.ok) {
        refetch()
      }
    } catch {
      // Continue
    }
    // Then validate
    try {
      const res = await fetch(endpoints.validateCredentials, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.message || `HTTP ${res.status}`)
      } else {
        setResult(data as CredentialResult)
      }
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setValidating(false)
    }
  }, [method, refetch])

  const applySessionCredentials = useCallback(async () => {
    if (!sessionAccessKeyId || !sessionSecretAccessKey || !sessionToken) {
      setError(t('settings.credentials.errAllFieldsRequired'))
      return
    }
    setSaving(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch(endpoints.applySessionCredentials, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          access_key_id: sessionAccessKeyId,
          secret_access_key: sessionSecretAccessKey,
          session_token: sessionToken,
        }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.message || `HTTP ${res.status}`)
        setSaving(false)
        return
      }
      // Show validation result from the response
      if (data.validation) {
        setResult(data.validation as CredentialResult)
      }
      // Refetch settings so ACTIVE badge updates
      refetch()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setSaving(false)
    }
  }, [sessionAccessKeyId, sessionSecretAccessKey, sessionToken, refetch])

  const saveSSOAndValidate = useCallback(async () => {
    setSaving(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch(endpoints.settings, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          auth_method: 'sso',
          sso_profile: ssoProfile || 'default',
        }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({ message: 'Save failed' }))
        setError(data.message)
        setSaving(false)
        return
      }
    } catch (e) {
      setError((e as Error).message)
      setSaving(false)
      return
    }
    setSaving(false)
    activate()
  }, [ssoProfile, activate])

  const saveStaticAndValidate = useCallback(async () => {
    if (!accessKeyId || !secretAccessKey) {
      setError(t('settings.credentials.errBothKeysRequired'))
      return
    }
    setSaving(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch(endpoints.settings, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          auth_method: 'static',
          access_key_id: accessKeyId,
          secret_access_key: secretAccessKey,
        }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({ message: 'Save failed' }))
        setError(data.message)
        setSaving(false)
        return
      }
    } catch (e) {
      setError((e as Error).message)
      setSaving(false)
      return
    }
    setSaving(false)
    activate()
  }, [accessKeyId, secretAccessKey, activate])

  if (settingsLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
      </div>
    )
  }

  // Determine which method is the persisted/active one
  const activeMethod = settings?.auth.method || 'imds'

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <Shield className="w-5 h-5 text-blue-600 dark:text-blue-400" />
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{t('settings.credentials.title')}</h2>
        <span className="ml-auto text-xs text-gray-600 dark:text-gray-300">
          {t('settings.credentials.subtitle')}
        </span>
      </div>

      {/* Master-Detail Layout */}
      <div className="flex-1 flex min-h-0">
        {/* Left: Method Selection */}
        <div className="w-64 flex-shrink-0 border-r border-gray-200 dark:border-gray-700 overflow-y-auto p-4 space-y-2">
          <p className="text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400 px-2 mb-3">
            {t('settings.credentials.authMethod')}
          </p>
          {AUTH_METHODS.map((m) => (
            <label
              key={m.value}
              onClick={() => selectMethod(m.value)}
              className={`flex items-center gap-3 w-full px-3 py-3 rounded-lg cursor-pointer transition-all ${
                method === m.value
                  ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800'
                  : 'hover:bg-gray-50 dark:hover:bg-gray-800 border border-transparent'
              }`}
            >
              <input
                type="radio"
                name="authMethod"
                value={m.value}
                checked={method === m.value}
                onChange={() => selectMethod(m.value)}
                className="w-4 h-4 text-blue-600 focus:ring-blue-500 flex-shrink-0"
              />
              <span className="text-lg">{m.icon}</span>
              <div className="min-w-0 flex-1">
                <span className={`text-sm font-medium block ${
                  method === m.value
                    ? 'text-blue-700 dark:text-blue-300'
                    : 'text-gray-900 dark:text-white'
                }`}>
                  {t(m.labelKey)}
                </span>
                <span className="text-xs text-gray-600 dark:text-gray-300 block truncate">
                  {t(m.descKey)}
                </span>
              </div>
              {activeMethod === m.value && (
                <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 flex-shrink-0">
                  {t('settings.credentials.active')}
                </span>
              )}
            </label>
          ))}
        </div>

        {/* Right: Detail Panel */}
        <div className="flex-1 overflow-y-auto p-6">
          {/* Method-specific guidance (shown when no result/error/validating) */}
          {!result && !error && !validating && !saving && (
            <>
              {method === 'imds' && (
                <div className="space-y-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {t('settings.credentials.imdsNote')}
                  </p>
                  <button
                    onClick={activate}
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors"
                  >
                    <Shield className="w-4 h-4" />
                    {t('settings.credentials.activate')}
                  </button>
                </div>
              )}

              {method === 'session_credentials' && (
                <div className="space-y-4">
                  <h3 className="text-sm font-medium text-gray-900 dark:text-white">{t('settings.credentials.sessionCreds')}</h3>
                  {settings?.auth.method === 'session_credentials' && settings.auth.access_key_id && (
                    <div className="flex items-center gap-2 p-2 rounded-lg bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-900/30">
                      <CheckCircle2 className="w-4 h-4 text-green-600 dark:text-green-400" />
                      <span className="text-xs text-green-700 dark:text-green-300">
                        {t('settings.credentials.savedActive', { key: settings.auth.access_key_id.slice(0, 8) })}
                      </span>
                    </div>
                  )}
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {t('settings.credentials.pasteInstructions')}
                  </p>
                  <div className="space-y-3">
                    <div>
                      <label htmlFor="sessionAccessKeyId" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                        {t('settings.credentials.accessKeyId')}
                      </label>
                      <input
                        id="sessionAccessKeyId"
                        type="text"
                        value={sessionAccessKeyId}
                        onChange={(e) => setSessionAccessKeyId(e.target.value)}
                        placeholder={t('settings.credentials.phAccessKeyId')}
                        className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label htmlFor="sessionSecretAccessKey" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                        {t('settings.credentials.secretAccessKey')}
                      </label>
                      <input
                        id="sessionSecretAccessKey"
                        type="password"
                        value={sessionSecretAccessKey}
                        onChange={(e) => setSessionSecretAccessKey(e.target.value)}
                        placeholder="••••••••••••••••••••••••••••••••"
                        className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label htmlFor="sessionToken" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                        {t('settings.credentials.sessionToken')}
                      </label>
                      <textarea
                        id="sessionToken"
                        value={sessionToken}
                        onChange={(e) => setSessionToken(e.target.value)}
                        placeholder={t('settings.credentials.phSessionToken')}
                        rows={3}
                        className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                      />
                    </div>
                  </div>
                  <p className="text-xs text-green-600 dark:text-green-400 font-medium">
                    {t('settings.credentials.savedToConfig')}
                  </p>
                  <button
                    onClick={applySessionCredentials}
                    disabled={!sessionAccessKeyId || !sessionSecretAccessKey || !sessionToken}
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <Shield className="w-4 h-4" />
                    {t('settings.credentials.applyValidate')}
                  </button>
                </div>
              )}

              {method === 'sso' && (
                <div className="space-y-4">
                  <h3 className="text-sm font-medium text-gray-900 dark:text-white">{t('settings.credentials.ssoConfig')}</h3>
                  <div>
                    <label htmlFor="ssoProfile" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                      {t('settings.credentials.profileName')}
                    </label>
                    <input
                      id="ssoProfile"
                      type="text"
                      value={ssoProfile}
                      onChange={(e) => setSsoProfile(e.target.value)}
                      placeholder="default"
                      className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                      {t('settings.credentials.ssoLogin', { profile: ssoProfile || '<name>' })}
                    </p>
                  </div>
                  <button
                    onClick={saveSSOAndValidate}
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors"
                  >
                    <Shield className="w-4 h-4" />
                    {t('settings.credentials.saveValidate')}
                  </button>
                </div>
              )}

              {method === 'static' && (
                <div className="space-y-4">
                  <h3 className="text-sm font-medium text-gray-900 dark:text-white">{t('settings.credentials.enterCreds')}</h3>
                  <div className="space-y-3">
                    <div>
                      <label htmlFor="accessKeyId" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                        {t('settings.credentials.accessKeyId')}
                      </label>
                      <input
                        id="accessKeyId"
                        type="text"
                        value={accessKeyId}
                        onChange={(e) => setAccessKeyId(e.target.value)}
                        placeholder={t('settings.credentials.phAccessKeyId')}
                        className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label htmlFor="secretAccessKey" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                        {t('settings.credentials.secretAccessKey')}
                      </label>
                      <input
                        id="secretAccessKey"
                        type="password"
                        value={secretAccessKey}
                        onChange={(e) => setSecretAccessKey(e.target.value)}
                        placeholder="••••••••••••••••••••••••••••••••"
                        className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                  </div>
                  <button
                    onClick={saveStaticAndValidate}
                    disabled={!accessKeyId || !secretAccessKey}
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <Shield className="w-4 h-4" />
                    {t('settings.credentials.saveValidate')}
                  </button>
                </div>
              )}
            </>
          )}

          {/* Loading state */}
          {(validating || saving) && (
            <div className="flex items-center gap-3 p-4 rounded-lg bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
              <Loader2 className="w-5 h-5 animate-spin text-blue-500" />
              <span className="text-sm text-gray-600 dark:text-gray-400">
                {saving ? t('settings.credentials.applying') : t('settings.credentials.validating')}
              </span>
            </div>
          )}

          {/* Error */}
          {error && !validating && !saving && (
            <div className="space-y-4">
              <div className="flex items-start gap-3 p-4 rounded-lg bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-900/30">
                <XCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-red-700 dark:text-red-300">{t('settings.credentials.validationFailed')}</p>
                  <p className="text-xs text-red-600 dark:text-red-400 mt-1">{error}</p>
                </div>
              </div>
              <button
                onClick={() => { setError(null) }}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              >
                {t('settings.credentials.dismiss')}
              </button>
            </div>
          )}

          {/* Success result */}
          {result && !validating && !saving && (
            <div className="space-y-4">
              {/* Status card */}
              <div className={`flex items-start gap-3 p-4 rounded-lg border ${
                result.valid
                  ? 'bg-green-50 dark:bg-green-900/10 border-green-200 dark:border-green-900/30'
                  : 'bg-amber-50 dark:bg-amber-900/10 border-amber-200 dark:border-amber-900/30'
              }`}>
                {result.valid ? (
                  <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-5 h-5 text-amber-600 dark:text-amber-400 flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <p className={`text-sm font-medium ${
                    result.valid
                      ? 'text-green-700 dark:text-green-300'
                      : 'text-amber-700 dark:text-amber-300'
                  }`}>
                    {result.valid ? t('settings.credentials.credentialsActive') : t('settings.credentials.credentialsFailed')}
                  </p>
                  <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">{result.message}</p>
                  {result.valid && result.source && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      {t('settings.credentials.source')} <span className="font-mono font-medium">{result.source}</span>
                    </p>
                  )}
                </div>
              </div>

              {/* Resolution attempt */}
              {result.attempts && result.attempts.length > 0 && (
                <div>
                  <h4 className="text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-2">
                    {t('settings.credentials.result')}
                  </h4>
                  <div className="space-y-1">
                    {result.attempts.map((attempt) => (
                      <div
                        key={attempt.source}
                        className="flex items-center gap-3 px-3 py-2 rounded-md bg-gray-50 dark:bg-gray-800/50"
                      >
                        {attempt.success ? (
                          <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                        )}
                        <div className="min-w-0 flex-1">
                          <span className="text-sm font-medium text-gray-900 dark:text-white capitalize">
                            {attempt.source}
                          </span>
                          <span className="text-xs text-gray-500 dark:text-gray-400 ml-2">
                            — {attempt.reason}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Re-validate button */}
              <button
                onClick={() => { setResult(null) }}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              >
                {t('settings.credentials.back')}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
