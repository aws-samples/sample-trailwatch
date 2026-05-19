import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Brain, CheckCircle2, Loader2, AlertTriangle, RefreshCw, Shield, Play } from 'lucide-react'
import { useSettings } from './hooks'
import { endpoints } from '../../config/api'
import { CostBanner } from '../../comm/CostBanner'
import { readApiError } from '../../comm/apiError'

type Provider = 'bedrock' | 'anthropic' | 'openai' | 'ollama'

interface BedrockModel {
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
  { value: 'ollama', label: 'Ollama (Local)', description: 'Runs locally on your machine. Auto-installs and pulls codellama:7b. No API key needed.' },
]

const BEDROCK_REGIONS = [
  { value: 'ap-south-1', label: 'Asia Pacific (Mumbai)' },
  { value: 'ap-southeast-1', label: 'Asia Pacific (Singapore)' },
  { value: 'ap-southeast-2', label: 'Asia Pacific (Sydney)' },
  { value: 'ap-northeast-1', label: 'Asia Pacific (Tokyo)' },
  { value: 'ap-northeast-2', label: 'Asia Pacific (Seoul)' },
  { value: 'us-east-1', label: 'US East (N. Virginia)' },
  { value: 'us-west-2', label: 'US West (Oregon)' },
  { value: 'eu-west-1', label: 'Europe (Ireland)' },
  { value: 'eu-west-2', label: 'Europe (London)' },
  { value: 'eu-central-1', label: 'Europe (Frankfurt)' },
  { value: 'ca-central-1', label: 'Canada (Central)' },
  { value: 'sa-east-1', label: 'South America (Sao Paulo)' },
]

export function LLMConfigView() {
  const { t } = useTranslation()
  const { data: settings, loading: settingsLoading, refetch } = useSettings()

  const [provider, setProvider] = useState<Provider>('bedrock')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [bedrockRegion, setBedrockRegion] = useState('ap-south-1')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  // Bedrock model discovery
  const [bedrockModels, setBedrockModels] = useState<BedrockModel[]>([])
  const [modelsLoading, setModelsLoading] = useState(false)
  const [modelsError, setModelsError] = useState('')
  const [crisAcknowledged, setCrisAcknowledged] = useState(false)
  const [selectedModelId, setSelectedModelId] = useState('')

  // Test-this-model state. Lives in this view because Settings → AI Provider
  // is where users naturally validate their LLM is reachable.
  const [testPrompt, setTestPrompt] = useState('')
  const [testRunning, setTestRunning] = useState(false)
  const [testError, setTestError] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ sql: string; columns: string[] | null; rows: unknown[][] | null } | null>(null)

  useEffect(() => {
    if (settings) {
      setProvider((settings as any).llm?.provider || 'bedrock')
      setModel((settings as any).llm?.model || '')
      setEndpoint((settings as any).llm?.endpoint || '')
      setBedrockRegion((settings as any).bedrock?.region || 'ap-south-1')
      setSelectedModelId((settings as any).bedrock?.model_id || '')
    }
  }, [settings])

  const fetchModels = useCallback(async (region: string) => {
    setModelsLoading(true)
    setModelsError('')
    try {
      const res = await fetch(endpoints.bedrockModels, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ region }),
      })
      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.message || `HTTP ${res.status}`)
      }
      const data = await res.json()
      setBedrockModels(data.models || [])
    } catch (err: any) {
      setModelsError(err.message || 'Failed to fetch models')
      setBedrockModels([])
    } finally {
      setModelsLoading(false)
    }
  }, [])

  // Fetch models when Bedrock is selected and region changes
  useEffect(() => {
    if (provider === 'bedrock' && bedrockRegion) {
      fetchModels(bedrockRegion)
    }
  }, [provider, bedrockRegion, fetchModels])

  async function runTest() {
    const prompt = testPrompt.trim()
    if (!prompt) return
    setTestRunning(true)
    setTestError(null)
    setTestResult(null)
    try {
      const res = await fetch(endpoints.nlqueryExecute, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
      })
      if (!res.ok) {
        setTestError(await readApiError(res, 'Test query failed'))
        return
      }
      setTestResult(await res.json())
    } catch (e: any) {
      setTestError(e?.message || 'Test query failed')
    } finally {
      setTestRunning(false)
    }
  }

  const defaultModel = (p: Provider) => {
    switch (p) {
      case 'bedrock': return 'us.anthropic.claude-sonnet-4-20250514-v1:0'
      case 'anthropic': return 'claude-sonnet-4-20250514'
      case 'openai': return 'gpt-4o'
      case 'ollama': return 'codellama:7b'
    }
  }

  const save = useCallback(async () => {
    setSaving(true)
    setSaved(false)
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
      if (endpoint) body.llm_endpoint = endpoint

      const res = await fetch(endpoints.settings, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (res.ok) {
        setSaved(true)
        refetch()
        setTimeout(() => setSaved(false), 3000)
      }
    } finally {
      setSaving(false)
    }
  }, [provider, apiKey, model, endpoint, bedrockRegion, selectedModelId, refetch])

  if (settingsLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
      </div>
    )
  }

  const activeProvider = (settings as any)?.llm?.provider || 'bedrock'

  // Split models into in-region and CRIS
  const inRegionModels = bedrockModels.filter(m => !m.is_cris)
  const crisModels = bedrockModels.filter(m => m.is_cris)

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-6 max-w-2xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Brain className="w-5 h-5 text-purple-600" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{t('settings.llm.title')}</h2>
        </div>
        <p className="text-xs text-gray-500 dark:text-gray-400">
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
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{p.description}</p>
              </div>
            </label>
          ))}
        </div>

        {/* Bedrock config — region + model picker */}
        {provider === 'bedrock' && (
          <div className="pl-7 space-y-4">
            {/* Region selector */}
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                {t('settings.llm.bedrockRegion')}
              </label>
              <select
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
                  <span className="text-xs text-gray-500">{t('settings.llm.loadingModels', { region: bedrockRegion })}</span>
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
                              <div className="text-[10px] text-gray-400 font-mono truncate">
                                {m.model_id}
                              </div>
                            </div>
                            <span className="text-[10px] text-gray-400 shrink-0">{m.provider}</span>
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
                              <div className="text-[10px] text-gray-400 font-mono truncate">
                                {m.model_id}
                              </div>
                            </div>
                            <span className="text-[10px] text-gray-400 shrink-0">{m.provider}</span>
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
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{t('settings.llm.apiKey')}</label>
              <input
                type="password"
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder={provider === 'anthropic' ? 'sk-ant-...' : 'sk-...'}
                className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
              />
              {(settings as any)?.llm?.has_key && !apiKey && (
                <p className="text-[10px] text-green-600 mt-1">{t('settings.llm.apiKeyConfigured')}</p>
              )}
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{t('settings.llm.model')}</label>
              <input
                type="text"
                value={model}
                onChange={e => setModel(e.target.value)}
                placeholder={defaultModel(provider)}
                className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
              />
            </div>
            {provider === 'openai' && (
              <div>
                <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                  {t('settings.llm.customEndpoint')} <span className="text-gray-400">(optional)</span>
                </label>
                <input
                  type="text"
                  value={endpoint}
                  onChange={e => setEndpoint(e.target.value)}
                  placeholder="https://api.openai.com/v1"
                  className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
                />
                <p className="text-[10px] text-gray-400 mt-1">{t('settings.llm.azureNote')}</p>
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
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{t('settings.llm.model')}</label>
              <input
                type="text"
                value={model}
                onChange={e => setModel(e.target.value)}
                placeholder="codellama:7b"
                className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                {t('settings.llm.ollamaEndpoint')} <span className="text-gray-400">(optional)</span>
              </label>
              <input
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
            onClick={save}
            disabled={saving}
            className={`inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
              saved
                ? 'bg-green-600 text-white'
                : 'bg-purple-600 text-white hover:bg-purple-700'
            } disabled:opacity-50`}
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : saved ? <CheckCircle2 className="w-4 h-4" /> : <Brain className="w-4 h-4" />}
            {saving ? t('settings.llm.saving') : saved ? t('settings.llm.saved') : t('settings.llm.saveActivate')}
          </button>
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
            value={testPrompt}
            onChange={(e) => setTestPrompt(e.target.value)}
            placeholder={t('settings.llm.testPlaceholder')}
            rows={2}
            className="w-full px-3 py-2 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
          />

          <CostBanner prompt={testPrompt} />

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={runTest}
              disabled={!testPrompt.trim() || testRunning}
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
                          <th key={i} className="px-2 py-1.5 text-left font-medium text-gray-600 dark:text-gray-400 whitespace-nowrap">{col}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {(testResult.rows as unknown[][] || []).slice(0, 20).map((row, ri) => (
                        <tr key={ri} className="border-b border-gray-100 dark:border-gray-800">
                          {row.map((cell, ci) => (
                            <td key={ci} className="px-2 py-1 font-mono text-gray-900 dark:text-gray-100 whitespace-nowrap max-w-[260px] truncate" title={String(cell ?? '')}>
                              {cell === null ? <span className="text-gray-300">—</span> : String(cell)}
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
