import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Brain, CheckCircle2, Loader2 } from 'lucide-react'
import { useSettings } from './hooks'
import { endpoints } from '../../config/api'

type Provider = 'bedrock' | 'anthropic' | 'openai' | 'ollama'

const PROVIDERS: { value: Provider; label: string; description: string }[] = [
  { value: 'bedrock', label: 'AWS Bedrock', description: 'Uses your configured AWS credentials. No additional API key needed.' },
  { value: 'anthropic', label: 'Anthropic API', description: 'Direct API access via api.anthropic.com. Requires an API key.' },
  { value: 'openai', label: 'OpenAI / Compatible', description: 'OpenAI, Azure OpenAI, or any OpenAI-compatible endpoint. Requires API key.' },
  { value: 'ollama', label: 'Ollama (Local)', description: 'Runs locally on your machine. Auto-installs and pulls codellama:7b. No API key needed.' },
]

export function LLMConfigView() {
  const { t } = useTranslation()
  const { data: settings, loading: settingsLoading, refetch } = useSettings()

  const [provider, setProvider] = useState<Provider>('bedrock')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (settings) {
      setProvider((settings as any).llm?.provider || 'bedrock')
      setModel((settings as any).llm?.model || '')
      setEndpoint((settings as any).llm?.endpoint || '')
    }
  }, [settings])

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
      if (model) body.llm_model = model
      else body.llm_model = defaultModel(provider)
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
  }, [provider, apiKey, model, endpoint, refetch])

  if (settingsLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
      </div>
    )
  }

  const activeProvider = (settings as any)?.llm?.provider || 'bedrock'

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

        {/* Provider-specific config */}
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

        {provider === 'bedrock' && (
          <div className="pl-7">
            <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
              <p className="text-xs text-gray-600 dark:text-gray-400">
                {t('settings.llm.bedrockNote')} <code className="font-mono bg-gray-100 dark:bg-gray-700 px-1 rounded">{(settings as any)?.bedrock?.model_id || 'us.anthropic.claude-sonnet-4-20250514-v1:0'}</code>
              </p>
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
      </div>
    </div>
  )
}
