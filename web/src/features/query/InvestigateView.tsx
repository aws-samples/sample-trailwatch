import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Search, Play, Loader2, AlertTriangle, ChevronDown } from 'lucide-react'
import { endpoints } from '../../config/api'
import { readApiError } from '../../comm/apiError'
import { AccountLabel } from '../../comm/AccountLabel'
import { useAccountNames } from '../../comm/accountNames'
import type { NavigationContext } from '../../arc/Layout'

interface Scenario {
  id: string
  name: string
  category: string
  description: string
  param_type: string
  param_label?: string
  severity: string
}

interface LookupValues {
  access_keys: string[]
  source_ips: string[]
  identities: string[]
  accounts: string[]
  roles: string[]
}

interface RunResult {
  scenario_id: string
  param: string
  sql: string
  columns: string[] | null
  rows: any[][] | null
  error?: string
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'border-l-red-500 bg-red-50 dark:bg-red-950/20',
  HIGH: 'border-l-orange-500 bg-orange-50 dark:bg-orange-950/10',
  MEDIUM: 'border-l-yellow-500 bg-yellow-50 dark:bg-yellow-950/10',
  LOW: 'border-l-blue-500 bg-blue-50 dark:bg-blue-950/10',
}

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-white',
  LOW: 'bg-blue-500 text-white',
}

interface InvestigateViewProps {
  navContext?: NavigationContext
}

export function InvestigateView({ navContext }: InvestigateViewProps = {}) {
  const { t } = useTranslation()
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [lookups, setLookups] = useState<LookupValues | null>(null)
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [selectedScenario, setSelectedScenario] = useState<Scenario | null>(null)
  const [paramValue, setParamValue] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<RunResult | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      fetch(endpoints.investigateScenarios).then(r => r.json()),
      fetch(endpoints.lookups).then(r => r.ok ? r.json() : null),
    ]).then(([s, l]) => {
      setScenarios(s || [])
      setLookups(l)
    }).finally(() => setLoading(false))
  }, [])

  // Deep-link: when arriving from Dashboard with a scenarioId, auto-select that
  // scenario and switch its category filter so it's visible in the left list.
  // Auto-runs the scenario only when it requires no parameter input.
  useEffect(() => {
    const wanted = navContext?.scenarioId
    if (!wanted || scenarios.length === 0) return
    const match = scenarios.find(s => s.id === wanted)
    if (!match) return
    setSelectedScenario(match)
    setSelectedCategory(match.category)
    setParamValue('')
    setResult(null)
    if (match.param_type === 'none') {
      void runScenarioById(match)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navContext?.scenarioId, scenarios])

  async function runScenarioById(scenario: Scenario, param = '') {
    setRunning(true)
    setResult(null)
    try {
      const res = await fetch(endpoints.investigateRun, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: scenario.id, param }),
      })
      if (!res.ok) {
        const msg = await readApiError(res, 'Scenario run failed')
        setResult({ scenario_id: scenario.id, param, sql: '', columns: null, rows: null, error: msg })
        return
      }
      setResult(await res.json())
    } catch (e: any) {
      setResult({ scenario_id: scenario.id, param, sql: '', columns: null, rows: null, error: e?.message || 'Network error' })
    } finally {
      setRunning(false)
    }
  }

  const categories = ['all', ...Array.from(new Set(scenarios.map(s => s.category)))]
  const filtered = selectedCategory === 'all' ? scenarios : scenarios.filter(s => s.category === selectedCategory)

  async function runScenario() {
    if (!selectedScenario) return
    if (selectedScenario.param_type !== 'none' && !paramValue) return
    await runScenarioById(selectedScenario, paramValue)
  }

  function getDropdownOptions(): string[] {
    if (!lookups || !selectedScenario) return []
    switch (selectedScenario.param_type) {
      case 'access_key': return lookups.access_keys || []
      case 'ip': return lookups.source_ips || []
      case 'identity': return lookups.identities || []
      case 'account': return lookups.accounts || []
      case 'role': return lookups.roles || []
      default: return []
    }
  }

  // Pre-warm account-name cache for the account dropdown so labels render
  // without an extra round-trip when the user opens the picker.
  const accountIdsForLookup = (selectedScenario?.param_type === 'account')
    ? (lookups?.accounts || [])
    : []
  const lookupAccountName = useAccountNames(accountIdsForLookup)

  if (loading) {
    return <div className="flex items-center justify-center h-full"><Loader2 className="w-6 h-6 animate-spin text-gray-400" /></div>
  }

  return (
    <div className="h-full flex flex-col bg-white dark:bg-[#0f1b2d]">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900">
        <div className="flex items-center gap-3">
          <Search className="w-5 h-5 text-[#0972d3]" />
          <div>
            <h2 className="text-base font-semibold text-gray-900 dark:text-white">{t('security.investigate.title')}</h2>
            <p className="text-[11px] text-gray-500 dark:text-gray-400">{t('security.investigate.scenarios', { count: scenarios.length })} • {t('security.investigate.crossAccount')}</p>
          </div>
        </div>
      </div>

      <div className="flex flex-1 min-h-0">
        {/* Left: Scenario list */}
        <div className="w-80 flex-shrink-0 border-r border-gray-200 dark:border-gray-700 flex flex-col bg-gray-50 dark:bg-gray-900">
          {/* Category filter */}
          <div className="p-3 border-b border-gray-200 dark:border-gray-700">
            <select
              value={selectedCategory}
              onChange={e => setSelectedCategory(e.target.value)}
              className="w-full px-2 py-1.5 text-xs rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
            >
              {categories.map(c => (
                <option key={c} value={c}>{c === 'all' ? t('security.investigate.allCategories') : c}</option>
              ))}
            </select>
          </div>

          {/* Scenario list */}
          <div className="flex-1 overflow-y-auto">
            {filtered.map(s => (
              <button
                key={s.id}
                onClick={() => { setSelectedScenario(s); setParamValue(''); setResult(null) }}
                className={`w-full text-left px-4 py-3 border-b border-gray-100 dark:border-gray-800 border-l-3 transition-colors ${
                  selectedScenario?.id === s.id
                    ? 'bg-blue-50 dark:bg-blue-900/20 border-l-[3px] border-l-[#0972d3]'
                    : `hover:bg-white dark:hover:bg-gray-800 border-l-[3px] ${SEVERITY_COLORS[s.severity]?.split(' ')[0] || 'border-l-gray-300'}`
                }`}
              >
                <div className="flex items-center gap-1.5 mb-0.5">
                  <span className="text-[12px] font-medium text-gray-900 dark:text-white">{s.name}</span>
                  <span className={`px-1 py-0.5 text-[8px] font-bold uppercase rounded ${SEVERITY_BADGE[s.severity] || 'bg-gray-500 text-white'}`}>{s.severity}</span>
                </div>
                <p className="text-[10px] text-gray-500 dark:text-gray-400 leading-tight">{s.description}</p>
                {s.param_type !== 'none' && (
                  <span className="inline-block mt-1 text-[9px] text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 px-1.5 py-0.5 rounded">
                    {t('security.investigate.requires', { label: s.param_label })}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Right: Parameter input + Results */}
        <div className="flex-1 flex flex-col min-w-0">
          {!selectedScenario ? (
            <div className="flex items-center justify-center h-full text-center">
              <div>
                <Search className="w-10 h-10 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
                <p className="text-sm text-gray-500 dark:text-gray-400">{t('security.investigate.selectScenario')}</p>
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">{t('security.investigate.queriesRunAgainst')}</p>
              </div>
            </div>
          ) : (
            <>
              {/* Scenario header + param input */}
              <div className="px-5 py-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900">
                <div className="flex items-center gap-2 mb-2">
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{selectedScenario.name}</h3>
                  <span className={`px-1.5 py-0.5 text-[9px] font-bold uppercase rounded ${SEVERITY_BADGE[selectedScenario.severity]}`}>{selectedScenario.severity}</span>
                  <span className="text-[10px] text-gray-400 bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">{selectedScenario.category}</span>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">{selectedScenario.description}</p>

                {/* Parameter input */}
                {selectedScenario.param_type !== 'none' && (
                  <div className="mb-3">
                    <label className="block text-[11px] font-medium text-gray-600 dark:text-gray-400 mb-1">{selectedScenario.param_label}</label>
                    <div className="flex gap-2">
                      <div className="relative flex-1">
                        <select
                          value={paramValue}
                          onChange={e => setParamValue(e.target.value)}
                          className="w-full px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white appearance-none pr-8 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                        >
                          <option value="">{t('security.investigate.selectOrType')}</option>
                          {getDropdownOptions().map(v => {
                            const name = selectedScenario.param_type === 'account' ? lookupAccountName(v) : null
                            return <option key={v} value={v}>{name ? `${v} (${name})` : v}</option>
                          })}
                        </select>
                        <ChevronDown className="absolute right-2 top-2.5 w-4 h-4 text-gray-400 pointer-events-none" />
                      </div>
                    </div>
                    <input
                      type="text"
                      value={paramValue}
                      onChange={e => setParamValue(e.target.value)}
                      placeholder={`Or paste ${selectedScenario.param_label} here...`}
                      className="w-full mt-2 px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    />
                  </div>
                )}

                <button
                  onClick={runScenario}
                  disabled={running || (selectedScenario.param_type !== 'none' && !paramValue)}
                  className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded bg-[#0972d3] text-white hover:bg-[#0860b0] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                  {running ? t('security.investigate.running') : t('security.investigate.runInvestigation')}
                </button>
              </div>

              {/* Results */}
              <div className="flex-1 overflow-auto">
                {result?.error && (
                  <div className="m-4 p-3 rounded border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-red-500" />
                      <span className="text-xs font-medium text-red-700 dark:text-red-300">{t('security.investigate.queryError')}</span>
                    </div>
                    <pre className="text-[11px] text-red-600 dark:text-red-400 mt-1 whitespace-pre-wrap font-mono">{result.error}</pre>
                  </div>
                )}

                {result?.columns && result.columns.length > 0 && (
                  <div className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[11px] text-gray-500">{result.rows?.length || 0} results</span>
                    </div>
                    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-auto max-h-[60vh]">
                      <table className="w-full text-[11px]">
                        <thead className="sticky top-0">
                          <tr className="bg-gray-100 dark:bg-gray-800">
                            {result.columns.map((col, i) => (
                              <th key={i} className="px-3 py-2 text-left font-medium text-gray-600 dark:text-gray-400 whitespace-nowrap border-b border-gray-200 dark:border-gray-700">{col}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {(result.rows || []).map((row, ri) => (
                            <tr key={ri} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                              {row.map((cell: any, ci: number) => {
                                const colName = result.columns?.[ci] || ''
                                const isAccountCol = /\baccount(_?id)?\b|recipientaccountid|sourceaccount|targetaccount/i.test(colName)
                                const cellStr = cell === null ? '' : String(cell)
                                const isAccountValue = /^\d{12}$/.test(cellStr)
                                if (isAccountCol && isAccountValue) {
                                  return (
                                    <td key={ci} className="px-3 py-1.5 text-gray-900 dark:text-gray-100 whitespace-nowrap max-w-[300px] truncate" title={cellStr}>
                                      <AccountLabel accountId={cellStr} />
                                    </td>
                                  )
                                }
                                return (
                                  <td key={ci} className="px-3 py-1.5 font-mono text-gray-900 dark:text-gray-100 whitespace-nowrap max-w-[250px] truncate" title={cellStr}>
                                    {cell === null ? <span className="text-gray-300">—</span> : cellStr}
                                  </td>
                                )
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {result.sql && (
                      <details className="mt-3">
                        <summary className="text-[10px] text-gray-400 cursor-pointer hover:text-gray-600">{t('security.investigate.showSqlQuery')}</summary>
                        <pre className="text-[10px] font-mono text-gray-500 bg-gray-50 dark:bg-gray-900 p-3 rounded mt-1 overflow-x-auto border border-gray-200 dark:border-gray-700">{result.sql}</pre>
                      </details>
                    )}
                  </div>
                )}

                {result && !result.error && (!result.columns || result.columns.length === 0) && (
                  <div className="p-8 text-center">
                    <p className="text-sm text-gray-500">{t('security.investigate.noResults')}</p>
                    <p className="text-xs text-gray-400 mt-1">{t('security.investigate.noResultsHint')}</p>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
