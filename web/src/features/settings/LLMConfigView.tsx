import { useState, useEffect, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Brain, CheckCircle2, Loader2, AlertTriangle, RefreshCw, Shield, Play } from 'lucide-react'
import { useSettings } from './hooks'
import { endpoints } from '../../config/api'
import { CostBanner } from '../../comm/CostBanner'
import { ExpandableCell } from '../../comm/ExpandableCell'
import { readApiError } from '../../comm/apiError'

export type Provider = 'bedrock' | 'anthropic' | 'openai' | 'ollama'

export interface BedrockModel {
  model_id: string
  model_name: string
  provider: string
  input_modes: string[]
  output_modes: string[]
  is_cris: boolean
  cris_note?: string
}

const PROVIDERS: { value: Provider; label: string; description: string }[] = [
  { value: 'bedrock', label: 'AWS Bedrock', description: 'Uses your configured AWS credentials. No additional API key needed.' },
  { value: 'anthropic', label: 'Anthropic API', description: 'Direct API access via api.anthropic.com. Requires an API key.' },
  { value: 'openai', label: 'OpenAI / Compatible', description: 'OpenAI, Azure OpenAI, or any OpenAI-compatible endpoint. Requires API key.' },
  { value: 'ollama', label: 'Ollama (Local)', description: 'Runs locally on your machine. Install Ollama and the selected model before use. No API key needed.' },
]

export const DEFAULT_BEDROCK_MODEL_ID = 'us.anthropic.claude-sonnet-4-6'

export const BEDROCK_REGIONS = [
  { value: 'ap-south-1', label: 'Asia Pacific (Mumbai)' },
  { value: 'ap-southeast-1', label: 'Asia Pacific (Singapore)' },
  { value: 'ap-southeast-2', label: 'Asia Pacific (Sydney)' },
  { value: 'ap-northeast-1', label: 'Asia Pacific (Tokyo)' },
  { value: 'ap-northeast-2', label: 'Asia Pacific (Seoul)' },
  { value: 'us-east-1', label: 'US East (N. Virginia)' },
  { value: 'us-east-2', label: 'US East (Ohio)' },
  { value: 'us-west-2', label: 'US West (Oregon)' },
  { value: 'eu-west-1', label: 'Europe (Ireland)' },
  { value: 'eu-west-2', label: 'Europe (London)' },
  { value: 'eu-central-1', label: 'Europe (Frankfurt)' },
  { value: 'ca-central-1', label: 'Canada (Central)' },
  { value: 'sa-east-1', label: 'South America (Sao Paulo)' },
]

export function isAnthropicBedrockModel(model: BedrockModel): boolean {
  return model.provider.trim().toLowerCase() === 'anthropic'
}

export function defaultModel(provider: Provider): string {
  switch (provider) {
    case 'bedrock': return DEFAULT_BEDROCK_MODEL_ID
    case 'anthropic': return 'claude-sonnet-4-20250514'
    case 'openai': return 'gpt-4o'
    case 'ollama': return 'codellama:7b'
  }
}

export function LLMConfigView() {
  const { t } = useTranslation()
  const { data: settings, loading: settingsLoading, error: settingsError, refetch } = useSettings()

  const [provider, setProvider] = useState<Provider>('bedrock')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [bedrockRegion, setBedrockRegion] = useState('ap-south-1')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  // Bedrock model discovery
  const [bedrockModels, setBedrockModels] = useState<BedrockModel[]>([])
  const [modelsLoading, setModelsLoading] = useState(false)
  const [modelsError, setModelsError] = useState('')
  const [crisAcknowledged, setCrisAcknowledged] = useState(false)
  const [selectedModelId, setSelectedModelId] = useState('')
  const modelRequestEpochRef = useRef(0)
  const modelAbortRef = useRef<AbortController | null>(null)

  // Test-this-model state. Lives in this view because Settings → AI Provider
  // is where users naturally validate their LLM is reachable.
  const [testPrompt, setTestPrompt] = useState('')
  const [testRunning, setTestRunning] = useState(false)
  const [testError, setTestError] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ sql: string; columns: string[] | null; rows: unknown[][] | null } | null>(null)
  const testRequestEpochRef = useRef(0)
  const testAbortRef = useRef<AbortController | null>(null)

  // Search filter for the Bedrock model lists. Matches against model_id +
  // model_name + provider so users can type "opus", "claude-3-5", "us.",
  // etc. and narrow quickly. Case-insensitive substring.
  const [modelSearch, setModelSearch] = useState('')

  useEffect(() => {
    if (settings) {
      setProvider((settings.llm?.provider as Provider) || 'bedrock')
      setModel(settings.llm?.model || '')
      setEndpoint(settings.llm?.endpoint || '')
      setBedrockRegion(settings.bedrock?.region || 'ap-south-1')
      setSelectedModelId(settings.bedrock?.model_id || '')
    }
  }, [settings])

  const fetchModels = useCallback(async (region: string) => {
    const requestEpoch = ++modelRequestEpochRef.current
    modelAbortRef.current?.abort()
    const controller = new AbortController()
    modelAbortRef.current = controller
    const isCurrentRequest = () =>
      modelRequestEpochRef.current === requestEpoch &&
      modelAbortRef.current === controller &&
      !controller.signal.aborted

    setModelsLoading(true)
    setModelsError('')
    try {
      const res = await fetch(endpoints.bedrockModels, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ region }),
        signal: controller.signal,
      })
      if (!res.ok) {
        throw new Error(await readApiError(res, 'Failed to fetch models'))
      }
      const data: unknown = await res.json()
      if (!data || typeof data !== 'object' || !Array.isArray((data as Record<string, unknown>).models)) {
        throw new Error('Model discovery returned a malformed response.')
      }
      if (isCurrentRequest()) {
        setBedrockModels((data as { models: BedrockModel[] }).models.filter(isAnthropicBedrockModel))
      }
    } catch (err: unknown) {
      if (isCurrentRequest()) {
        setModelsError(err instanceof Error ? err.message : 'Failed to fetch models')
        setBedrockModels([])
      }
    } finally {
      if (isCurrentRequest()) {
        modelAbortRef.current = null
        setModelsLoading(false)
      }
    }
  }, [])

  // Fetch models when Bedrock is selected and region changes
  useEffect(() => {
    if (settings && provider === 'bedrock' && bedrockRegion) {
      void fetchModels(bedrockRegion)
    }
    return () => {
      modelRequestEpochRef.current += 1
      modelAbortRef.current?.abort()
      modelAbortRef.current = null
    }
  }, [settings, provider, bedrockRegion, fetchModels])

  useEffect(() => {
    testRequestEpochRef.current += 1
    testAbortRef.current?.abort()
    testAbortRef.current = null
    setTestRunning(false)
    setTestError(null)
    setTestResult(null)
  }, [testPrompt, provider, apiKey, model, endpoint, bedrockRegion, selectedModelId])

  useEffect(() => {
    return () => {
      testRequestEpochRef.current += 1
      testAbortRef.current?.abort()
      testAbortRef.current = null
    }
  }, [])

  async function runTest() {
    const prompt = testPrompt.trim()
    if (!prompt) return

    testAbortRef.current?.abort()
    const requestEpoch = ++testRequestEpochRef.current
    const controller = new AbortController()
    testAbortRef.current = controller
    const isCurrentRequest = () =>
      testRequestEpochRef.current === requestEpoch &&
      testAbortRef.current === controller &&
      !controller.signal.aborted

    setTestRunning(true)
    setTestError(null)
    setTestResult(null)
    try {
      const res = await fetch(endpoints.nlqueryExecute, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
        signal: controller.signal,
      })
      if (!res.ok) {
        throw new Error(await readApiError(res, 'Test query failed'))
      }
      const result: unknown = await res.json()
      if (!result || typeof result !== 'object') {
        throw new Error('Test query returned an invalid response')
      }
      if (isCurrentRequest()) {
        setTestResult(result as { sql: string; columns: string[] | null; rows: unknown[][] | null })
      }
    } catch (e: unknown) {
      if (!isCurrentRequest()) return
      setTestError(e instanceof Error && e.message ? e.message : 'Test query failed')
    } finally {
      if (testRequestEpochRef.current === requestEpoch && testAbortRef.current === controller) {
        testAbortRef.current = null
        setTestRunning(false)
      }
    }
  }

  const save = useCallback(async (): Promise<boolean> => {
    setSaving(true)
    setSaved(false)
    setSaveError(null)
    try {
      const body: Record<string, string> = { llm_provider: provider }
      if (apiKey) body.llm_api_key = apiKey
      if (provider === 'bedrock') {
        body.llm_model = selectedModelId || defaultModel('bedrock')
        body.bedrock_region = bedrockRegion
      } else {
        if (model) body.llm_model = model
        else body.llm_model = defaultModel(provider)
      }
      // Empty is meaningful: it clears a previously configured custom endpoint.
      body.llm_endpoint = endpoint

      const res = await fetch(endpoints.settings, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!res.ok) {
        setSaveError(await readApiError(res, t('settings.llm.saveFailed', { defaultValue: 'Failed to save settings' })))
        return false
      }
      setApiKey('')
      setSaved(true)
      void refetch()
      setTimeout(() => setSaved(false), 3000)
      return true
    } catch (e) {
      setSaveError((e as Error)?.message || t('settings.llm.saveFailed', { defaultValue: 'Failed to save settings' }))
      return false
    } finally {
      setSaving(false)
    }
  }, [provider, apiKey, model, endpoint, bedrockRegion, selectedModelId, refetch, t])

  if (settingsLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
      </div>
    )
  }

  if (settingsError || !settings) {
    return (
      <div className="flex items-center justify-center h-full p-6">
        <div role="alert" className="max-w-md w-full p-5 rounded-lg border border-red-200 dark:border-red-900/30 bg-red-50 dark:bg-red-900/10 text-center">
          <AlertTriangle className="w-7 h-7 text-red-500 mx-auto mb-2" />
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

  const activeProvider = settings.llm?.provider ?? 'bedrock'
  const desiredModel = provider === 'bedrock'
    ? selectedModelId || defaultModel('bedrock')
    : model || defaultModel(provider)
  const activeModel = activeProvider === 'bedrock'
    ? settings.bedrock?.model_id || settings.llm?.model || defaultModel('bedrock')
    : settings.llm?.model || defaultModel(activeProvider)
  const activeConfigMatchesForm =
    activeProvider === provider &&
    activeModel === desiredModel &&
    (settings.llm?.endpoint || '').trim() === endpoint.trim() &&
    apiKey === '' &&
    (provider !== 'bedrock' || (settings.bedrock?.region || 'ap-south-1') === bedrockRegion)

  const matchesSearch = (m: BedrockModel) => {
    if (!modelSearch.trim()) return true
    const q = modelSearch.trim().toLowerCase()
    return (
      m.model_id.toLowerCase().includes(q) ||
      (m.model_name || '').toLowerCase().includes(q) ||
      (m.provider || '').toLowerCase().includes(q)
    )
  }
  const inRegionModels = bedrockModels.filter(m => !m.is_cris && matchesSearch(m))
  const crisModels = bedrockModels.filter(m => m.is_cris && matchesSearch(m))

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-6 max-w-2xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Brain className="w-5 h-5 text-purple-600" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{t('settings.llm.title')}</h2>
        </div>
        <p className="text-xs text-gray-600 dark:text-gray-300">
          {t('settings.llm.subtitle')}
        </p>

        {/* Provider selection */}
        <div className="space-y-2">
          {PROVIDERS.map(p => (
            <label
              key={p.value}
              onClick={() => { setProvider(p.value); setApiKey(''); setModel(''); setEndpoint('') }}
              className={`flex items-start gap-3 px-4 py-3 rounded-lg border cursor-pointer transition-all ${
                provider === p.value
                  ? 'border-purple-300 dark:border-purple-700 bg-purple-50 dark:bg-purple-900/20'
                  : 'border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800'
              }`}
            >
              <input
                type="radio"
                name="llm-provider"
                value={p.value}
                checked={provider === p.value}
                onChange={() => { setProvider(p.value); setApiKey(''); setModel(''); setEndpoint('') }}
                className="mt-0.5 w-4 h-4 text-purple-600"
              />
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-gray-900 dark:text-white">{p.label}</span>
                  {activeProvider === p.value && (
                    <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400">{t('settings.llm.active')}</span>
                  )}
                </div>
                <p className="text-xs text-gray-600 dark:text-gray-300 mt-0.5">{p.description}</p>
              </div>
            </label>
          ))}
        </div>

        {/* Bedrock config — region + model picker */}
        {provider === 'bedrock' && (
          <div className="pl-7 space-y-4">
            {/* Region selector */}
            <div>
              <label htmlFor="bedrock-region" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                {t('settings.llm.bedrockRegion')}
              </label>
              <select
                id="bedrock-region"
                value={bedrockRegion}
                onChange={e => { setBedrockRegion(e.target.value); setSelectedModelId('') }}
                className="w-full px-3 py-2 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
              >
                {BEDROCK_REGIONS.map(r => (
                  <option key={r.value} value={r.value}>{r.label} ({r.value})</option>
                ))}
              </select>
            </div>

            {/* Model list */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-medium text-gray-600 dark:text-gray-400">
                  {t('settings.llm.model')}
                </label>
                <button
                  onClick={() => fetchModels(bedrockRegion)}
                  disabled={modelsLoading}
                  className="inline-flex items-center gap-1 text-[10px] text-purple-600 hover:text-purple-800 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3 h-3 ${modelsLoading ? 'animate-spin' : ''}`} />
                  {t('settings.llm.refresh')}
                </button>
              </div>

              {modelsLoading && (
                <div className="flex items-center gap-2 py-4 justify-center">
                  <Loader2 className="w-4 h-4 animate-spin text-purple-500" />
                  <span className="text-xs text-gray-700 dark:text-gray-300">{t('settings.llm.loadingModels', { region: bedrockRegion })}</span>
                </div>
              )}

              {modelsError && (
                <div className="p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
                  <p className="text-xs text-red-700 dark:text-red-300">
                    {t('settings.llm.loadModelsFailed')} {modelsError}
                  </p>
                  <p className="text-[10px] text-red-500 mt-1">
                    {t('settings.llm.bedrockListPermissionPrefix')}{' '}
                    <code className="bg-red-100 dark:bg-red-900 px-1 rounded">bedrock:ListFoundationModels</code>{' '}
                    {t('settings.llm.bedrockListPermissionSuffix')}
                  </p>
                </div>
              )}

              {!modelsLoading && !modelsError && bedrockModels.length > 0 && (
                <div className="space-y-3">
                  {/* Search box: filters both in-region and CRIS lists by
                      id, name, or provider. Quick narrowing for users who
                      know the model family (e.g., type "opus") without
                      having to scroll. */}
                  <div className="relative">
                    <input
                      id="bedrock-model-search"
                      type="text"
                      value={modelSearch}
                      onChange={e => setModelSearch(e.target.value)}
                      aria-label={t('settings.llm.searchPlaceholder')}
                      placeholder={t('settings.llm.searchPlaceholder')}
                      className="w-full px-3 py-2 pr-8 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
                    />
                    {modelSearch && (
                      <button
                        type="button"
                        onClick={() => setModelSearch('')}
                        aria-label={t('settings.llm.searchClear')}
                        className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
                      >
                        ×
                      </button>
                    )}
                  </div>
                  {modelSearch && inRegionModels.length === 0 && crisModels.length === 0 && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 py-2">
                      {t('settings.llm.searchNoMatches', { query: modelSearch })}
                    </p>
                  )}
                  {/* In-region models */}
                  {inRegionModels.length > 0 && (
                    <div>
                      <div className="flex items-center gap-1.5 mb-1.5">
                        <Shield className="w-3 h-3 text-green-600" />
                        <span className="text-[10px] font-semibold uppercase text-green-700 dark:text-green-400">
                          {t('settings.llm.availableInRegion', { region: bedrockRegion })}
                        </span>
                      </div>
                      <div className="max-h-48 overflow-y-auto rounded border border-gray-200 dark:border-gray-700 divide-y divide-gray-100 dark:divide-gray-800">
                        {inRegionModels.map(m => (
                          <label
                            key={m.model_id}
                            className={`flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 ${
                              selectedModelId === m.model_id ? 'bg-purple-50 dark:bg-purple-900/20' : ''
                            }`}
                          >
                            <input
                              type="radio"
                              name="bedrock-model"
                              value={m.model_id}
                              checked={selectedModelId === m.model_id}
                              onChange={() => setSelectedModelId(m.model_id)}
                              className="w-3.5 h-3.5 text-purple-600"
                            />
                            <div className="flex-1 min-w-0">
                              <div className="text-xs font-medium text-gray-900 dark:text-white truncate">
                                {m.model_name}
                              </div>
                              <div className="text-[10px] text-gray-600 dark:text-gray-400 font-mono truncate">
                                {m.model_id}
                              </div>
                            </div>
                            <span className="text-[10px] text-gray-600 dark:text-gray-400 shrink-0">{m.provider}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* CRIS models */}
                  {crisModels.length > 0 && (
                    <div>
                      <div className="flex items-center gap-1.5 mb-1.5">
                        <AlertTriangle className="w-3 h-3 text-amber-500" />
                        <span className="text-[10px] font-semibold uppercase text-amber-700 dark:text-amber-400">
                          {t('settings.llm.crisLabel')}
                        </span>
                      </div>

                      {/* CRIS warning banner */}
                      <div className="p-2.5 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 mb-2">
                        <p className="text-[11px] text-amber-800 dark:text-amber-200 leading-relaxed">
                          {t('settings.llm.crisExplainPrefix')}{' '}
                          <strong>{bedrockRegion}</strong>{' '}
                          {t('settings.llm.crisExplainSuffix')}
                        </p>
                        <label className="flex items-center gap-2 mt-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={crisAcknowledged}
                            onChange={e => { setCrisAcknowledged(e.target.checked); if (!e.target.checked) setSelectedModelId(prev => crisModels.some(m => m.model_id === prev) ? '' : prev) }}
                            className="w-3.5 h-3.5 rounded border-amber-400 text-amber-600 focus:ring-amber-500"
                          />
                          <span className="text-[11px] font-medium text-amber-800 dark:text-amber-200">
                            {t('settings.llm.crisAck')}
                          </span>
                        </label>
                      </div>

                      {/* CRIS model list — grayed out unless acknowledged */}
                      <div className={`max-h-48 overflow-y-auto rounded border border-gray-200 dark:border-gray-700 divide-y divide-gray-100 dark:divide-gray-800 ${!crisAcknowledged ? 'opacity-40 pointer-events-none' : ''}`}>
                        {crisModels.map(m => (
                          <label
                            key={m.model_id}
                            className={`flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 ${
                              selectedModelId === m.model_id ? 'bg-purple-50 dark:bg-purple-900/20' : ''
                            }`}
                          >
                            <input
                              type="radio"
                              name="bedrock-model"
                              value={m.model_id}
                              checked={selectedModelId === m.model_id}
                              onChange={() => setSelectedModelId(m.model_id)}
                              disabled={!crisAcknowledged}
                              className="w-3.5 h-3.5 text-purple-600"
                            />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-1.5">
                                <span className="text-xs font-medium text-gray-900 dark:text-white truncate">
                                  {m.model_name}
                                </span>
                                <span className="text-[9px] font-bold uppercase px-1 py-0.5 rounded bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-400 shrink-0">
                                  {t('settings.llm.crisBadge')}
                                </span>
                              </div>
                              <div className="text-[10px] text-gray-600 dark:text-gray-400 font-mono truncate">
                                {m.model_id}
                              </div>
                            </div>
                            <span className="text-[10px] text-gray-600 dark:text-gray-400 shrink-0">{m.provider}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Selected model display */}
                  {selectedModelId && (
                    <div className="p-2 rounded bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800">
                      <p className="text-[10px] text-purple-700 dark:text-purple-300">
                        {t('settings.llm.selectedLabel')}{' '}
                        <code className="font-mono bg-purple-100 dark:bg-purple-900 px-1 rounded">{selectedModelId}</code>
                        {crisModels.some(m => m.model_id === selectedModelId) && (
                          <span className="ml-1 text-amber-600 font-semibold">({t('settings.llm.crisBadge')})</span>
                        )}
                      </p>
                    </div>
                  )}
                </div>
              )}

              {!modelsLoading && !modelsError && bedrockModels.length === 0 && (
                <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {t('settings.llm.noModelsFound')}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Provider-specific config: Anthropic / OpenAI */}
        {(provider === 'anthropic' || provider === 'openai') && (
          <div className="space-y-3 pl-7">
            <div>
              <label htmlFor="llm-api-key" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{t('settings.llm.apiKey')}</label>
              <input
                id="llm-api-key"
                type="password"
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder={provider === 'anthropic' ? 'sk-ant-...' : 'sk-...'}
                className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
              />
              {settings?.llm?.has_key && !apiKey && (
                <p className="text-[10px] text-green-600 mt-1">{t('settings.llm.apiKeyConfigured')}</p>
              )}
            </div>
            <div>
              <label htmlFor="llm-model" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{t('settings.llm.model')}</label>
              <input
                id="llm-model"
                type="text"
                value={model}
                onChange={e => setModel(e.target.value)}
                placeholder={defaultModel(provider)}
                className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
              />
            </div>
            {provider === 'openai' && (
              <div>
                <label htmlFor="llm-custom-endpoint" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                  {t('settings.llm.customEndpoint')} <span className="text-gray-500 dark:text-gray-400">{t('settings.llm.optional')}</span>
                </label>
                <input
                  id="llm-custom-endpoint"
                  type="text"
                  value={endpoint}
                  onChange={e => setEndpoint(e.target.value)}
                  placeholder="https://api.openai.com/v1"
                  className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
                />
                <p className="text-[10px] text-gray-600 dark:text-gray-400 mt-1">{t('settings.llm.azureNote')}</p>
              </div>
            )}
          </div>
        )}

        {provider === 'ollama' && (
          <div className="pl-7 space-y-3">
            <div className="p-3 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800">
              <p className="text-xs text-blue-700 dark:text-blue-300">
                {t('settings.llm.ollamaNote')}
              </p>
            </div>
            <div>
              <label htmlFor="ollama-model" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{t('settings.llm.model')}</label>
              <input
                id="ollama-model"
                type="text"
                value={model}
                onChange={e => setModel(e.target.value)}
                placeholder="codellama:7b"
                className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="ollama-endpoint" className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                {t('settings.llm.ollamaEndpoint')} <span className="text-gray-500 dark:text-gray-400">{t('settings.llm.optional')}</span>
              </label>
              <input
                id="ollama-endpoint"
                type="text"
                value={endpoint}
                onChange={e => setEndpoint(e.target.value)}
                placeholder="http://localhost:11434"
                className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
              />
            </div>
          </div>
        )}

        {/* Save button */}
        <div className="pt-2">
          <button
            onClick={() => { void save() }}
            disabled={saving || testRunning}
            className={`inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
              saved
                ? 'bg-green-600 text-white'
                : 'bg-purple-600 text-white hover:bg-purple-700'
            } disabled:opacity-50`}
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : saved ? <CheckCircle2 className="w-4 h-4" /> : <Brain className="w-4 h-4" />}
            {saving ? t('settings.llm.saving') : saved ? t('settings.llm.saved') : t('settings.llm.saveActivate')}
          </button>
          {saveError && (
            <div className="mt-2 p-2.5 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
              <p className="text-xs text-red-700 dark:text-red-300">{saveError}</p>
            </div>
          )}
        </div>

        {/* Test this model — sends one NLQ to validate the model is reachable
            and to give the user a feel for cost. Pre-flight banner updates
            live as the user types; Run actually invokes the LLM. */}
        <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-700 space-y-3">
          <div>
            <h3 className="text-sm font-medium text-gray-900 dark:text-white">{t('settings.llm.testTitle')}</h3>
            <p className="text-[11px] text-gray-500 dark:text-gray-400">{t('settings.llm.testSubtitle')}</p>
          </div>

          <textarea
            id="llm-test-prompt"
            value={testPrompt}
            onChange={(e) => setTestPrompt(e.target.value)}
            aria-label={t('settings.llm.testTitle')}
            placeholder={t('settings.llm.testPlaceholder')}
            rows={2}
            className="w-full px-3 py-2 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
          />

          {activeConfigMatchesForm && <CostBanner prompt={testPrompt} />}

          <div className="flex items-center gap-3">
            {!activeConfigMatchesForm && (
              <span id="llm-test-save-first" className="sr-only">
                {t('settings.llm.testSaveFirst', { defaultValue: 'Save and activate this configuration before testing.' })}
              </span>
            )}
            <button
              type="button"
              onClick={runTest}
              disabled={!testPrompt.trim() || testRunning || !activeConfigMatchesForm}
              aria-describedby={!activeConfigMatchesForm ? 'llm-test-save-first' : undefined}
              title={!activeConfigMatchesForm
                ? t('settings.llm.testSaveFirst', { defaultValue: 'Save and activate this configuration before testing.' })
                : undefined}
              className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded border border-purple-300 dark:border-purple-700 text-purple-700 dark:text-purple-300 hover:bg-purple-50 dark:hover:bg-purple-900/20 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {testRunning ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
              {testRunning ? t('settings.llm.testRunning') : t('settings.llm.testRun')}
            </button>
            {testError && (
              <span className="text-[11px] text-red-600 dark:text-red-400">{testError}</span>
            )}
          </div>

          {testResult && !testError && (
            <div className="space-y-2">
              {testResult.sql && (
                <details>
                  <summary className="text-[10px] cursor-pointer text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">{t('settings.llm.testShowSql')}</summary>
                  <pre className="mt-1 text-[10px] font-mono p-2 rounded bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 overflow-x-auto whitespace-pre-wrap">{testResult.sql}</pre>
                </details>
              )}
              {testResult.columns && testResult.rows && (
                <div className="border border-gray-200 dark:border-gray-700 rounded overflow-auto max-h-60">
                  <table className="w-full text-[11px]">
                    <thead className="sticky top-0 bg-gray-100 dark:bg-gray-800">
                      <tr>
                        {testResult.columns.map((col, i) => (
                          <th key={i} className="px-2 py-1.5 text-left font-medium text-gray-700 dark:text-gray-300 whitespace-nowrap">{col}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {testResult.rows.slice(0, 20).map((row, ri) => (
                        <tr key={ri} className="border-b border-gray-100 dark:border-gray-800">
                          {row.map((cell, ci) => (
                            <td key={ci} className="px-2 py-1 align-top text-gray-900 dark:text-gray-100 max-w-[260px]">
                              <ExpandableCell value={String(cell ?? '')} mono />
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {(!testResult.rows || testResult.rows.length === 0) && testResult.columns && (
                <p className="text-[11px] text-gray-500 dark:text-gray-400">{t('settings.llm.testNoRows')}</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
