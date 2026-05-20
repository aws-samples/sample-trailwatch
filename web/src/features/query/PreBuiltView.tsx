import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { endpoints } from '../../config/api'
import { ExpandableCell } from '../../comm/ExpandableCell'
import { exportRowsAsCSV, exportRowsAsJSON } from './tableExport'

interface PromptTemplate {
  id: string
  name: string
  category: string
  description: string
  prompt: string
  parameters: string[]
}

interface GetPromptResponse {
  template: PromptTemplate
  rendered_prompt: string
  substitutions: Record<string, string>
  data_path: string
}

interface QueryResult {
  sql: string
  columns: string[]
  rows: (string | number | null)[][]
  error?: string
}

interface PreBuiltViewProps {
  autoRunPromptId?: string
}

export function PreBuiltView({ autoRunPromptId }: PreBuiltViewProps) {
  const { t } = useTranslation()
  const [templates, setTemplates] = useState<PromptTemplate[]>([])
  const [categories, setCategories] = useState<string[]>([])
  const [selectedCategory, setSelectedCategory] = useState<string>('')
  const [selectedTemplate, setSelectedTemplate] = useState<GetPromptResponse | null>(null)
  const [editedPrompt, setEditedPrompt] = useState('')
  const [loading, setLoading] = useState(true)
  const [loadingPrompt, setLoadingPrompt] = useState(false)
  const [executing, setExecuting] = useState(false)
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')

  const [autoRunDone, setAutoRunDone] = useState(false)

  useEffect(() => {
    fetchTemplates()
  }, [])

  useEffect(() => {
    if (autoRunPromptId && templates.length > 0 && !autoRunDone) {
      setAutoRunDone(true)
      const tmpl = templates.find(t => t.id === autoRunPromptId)
      if (tmpl) {
        setSelectedCategory(tmpl.category)
        autoSelectAndRun(autoRunPromptId)
      }
    }
  }, [autoRunPromptId, templates, autoRunDone])

  async function autoSelectAndRun(id: string) {
    await selectTemplate(id)
    // Small delay to let state settle, then execute
    setTimeout(() => {
      executeQueryDirect(id)
    }, 200)
  }

  async function executeQueryDirect(id: string) {
    try {
      setExecuting(true)
      setQueryResult(null)
      const promptRes = await fetch(endpoints.prompt(id))
      if (!promptRes.ok) return
      const promptData: GetPromptResponse = await promptRes.json()
      const res = await fetch(endpoints.nlqueryExecute, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt_id: id, prompt: promptData.rendered_prompt }),
      })
      if (!res.ok) {
        const errData = await res.json().catch(() => null)
        throw new Error(errData?.message || `Request failed: ${res.status}`)
      }
      const data: QueryResult = await res.json()
      setQueryResult(data)
    } catch (err: any) {
      setQueryResult({ sql: '', columns: [], rows: [], error: err.message })
    } finally {
      setExecuting(false)
    }
  }

  async function fetchTemplates() {
    try {
      setLoading(true)
      const res = await fetch(endpoints.prompts)
      if (!res.ok) throw new Error(`Failed to load templates: ${res.status}`)
      const data = await res.json()
      setTemplates(data.templates)
      setCategories(data.categories)
      if (data.categories.length > 0) {
        setSelectedCategory(data.categories[0])
      }
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function selectTemplate(id: string) {
    try {
      setLoadingPrompt(true)
      setCopied(false)
      setQueryResult(null)
      const res = await fetch(endpoints.prompt(id))
      if (!res.ok) throw new Error(`Failed to load prompt: ${res.status}`)
      const data: GetPromptResponse = await res.json()
      setSelectedTemplate(data)
      setEditedPrompt(data.rendered_prompt)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoadingPrompt(false)
    }
  }

  async function executeQuery() {
    try {
      setExecuting(true)
      setQueryResult(null)
      const res = await fetch(endpoints.nlqueryExecute, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt_id: selectedTemplate?.template.id || '',
          prompt: editedPrompt,
        }),
      })
      if (!res.ok) {
        const errData = await res.json().catch(() => null)
        throw new Error(errData?.message || `Request failed: ${res.status}`)
      }
      const data: QueryResult = await res.json()
      setQueryResult(data)
    } catch (err: any) {
      setQueryResult({ sql: '', columns: [], rows: [], error: err.message })
    } finally {
      setExecuting(false)
    }
  }

  async function copyToClipboard() {
    try {
      await navigator.clipboard.writeText(editedPrompt)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      const textarea = document.createElement('textarea')
      textarea.value = editedPrompt
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const filteredTemplates = templates.filter(t => t.category === selectedCategory)

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-sm text-gray-500 dark:text-gray-400">{t('security.prebuilt.loading')}</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <p className="text-sm text-red-600 dark:text-red-400 mb-2">{error}</p>
          <button onClick={fetchTemplates} className="text-xs text-blue-600 hover:underline">{t('security.prebuilt.retry')}</button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-full">
      {/* Left panel: category tabs + template list */}
      <div className="w-80 border-r border-gray-200 dark:border-gray-700 flex flex-col">
        {/* Category tabs */}
        <div className="border-b border-gray-200 dark:border-gray-700 p-2">
          <div className="flex flex-wrap gap-1">
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => { setSelectedCategory(cat); setSelectedTemplate(null); setQueryResult(null) }}
                className={`px-2 py-1 text-xs rounded transition-colors ${
                  selectedCategory === cat
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Template list */}
        <div className="flex-1 overflow-y-auto">
          {filteredTemplates.map(tmpl => (
            <button
              key={tmpl.id}
              onClick={() => selectTemplate(tmpl.id)}
              className={`w-full text-left px-3 py-2.5 border-b border-gray-100 dark:border-gray-800 transition-colors ${
                selectedTemplate?.template.id === tmpl.id
                  ? 'bg-blue-50 dark:bg-blue-900/20 border-l-2 border-l-blue-600'
                  : 'hover:bg-gray-50 dark:hover:bg-gray-800/50'
              }`}
            >
              <div className="text-sm font-medium text-gray-900 dark:text-white">{tmpl.name}</div>
              <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{tmpl.description}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Right panel: rendered prompt + results */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {!selectedTemplate ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center text-gray-500 dark:text-gray-400">
              <p className="text-sm">{t('security.prebuilt.selectPrompt')}</p>
              <p className="text-xs mt-1">{t('security.prebuilt.placeholders')}</p>
            </div>
          </div>
        ) : loadingPrompt ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-sm text-gray-500">{t('security.prebuilt.loading2')}</div>
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                    {selectedTemplate.template.name}
                  </h3>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                    {selectedTemplate.template.description}
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={copyToClipboard}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
                      copied
                        ? 'bg-green-600 text-white'
                        : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
                    }`}
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                  <button
                    onClick={executeQuery}
                    disabled={executing}
                    className={`px-4 py-1.5 text-xs font-medium rounded transition-colors ${
                      executing
                        ? 'bg-orange-500 text-white cursor-wait'
                        : 'bg-blue-600 text-white hover:bg-blue-700'
                    }`}
                  >
                    {executing ? 'Running...' : 'Run Query'}
                  </button>
                </div>
              </div>
            </div>

            {/* Substitution context */}
            <div className="px-4 py-2 bg-gray-50 dark:bg-gray-800/50 border-b border-gray-200 dark:border-gray-700">
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
                <span className="text-gray-500 dark:text-gray-400">
                  {t('security.prebuilt.account')} <span className="text-gray-900 dark:text-white font-mono">{selectedTemplate.substitutions.account_id || '—'}</span>
                </span>
                <span className="text-gray-500 dark:text-gray-400">
                  {t('security.prebuilt.region')} <span className="text-gray-900 dark:text-white font-mono">{selectedTemplate.substitutions.region || '—'}</span>
                </span>
                <span className="text-gray-500 dark:text-gray-400">
                  {t('security.prebuilt.dates')} <span className="text-gray-900 dark:text-white font-mono">{selectedTemplate.substitutions.start_date || '—'} to {selectedTemplate.substitutions.end_date || '—'}</span>
                </span>
              </div>
              {(!selectedTemplate.substitutions.account_id || !selectedTemplate.substitutions.region) && (
                <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                  {t('security.prebuilt.emptyPlaceholders')}
                </p>
              )}
            </div>

            {/* Prompt editor (collapsible when results exist) */}
            <div className={`px-4 py-3 border-b border-gray-200 dark:border-gray-700 ${queryResult ? 'max-h-32' : 'flex-1'} overflow-hidden`}>
              <label className="text-xs text-gray-500 dark:text-gray-400 mb-1 block">
                {t('security.prebuilt.prompt')}
              </label>
              <textarea
                value={editedPrompt}
                onChange={(e) => setEditedPrompt(e.target.value)}
                className={`w-full p-2 text-xs font-mono bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded resize-none focus:outline-none focus:ring-1 focus:ring-blue-500 text-gray-900 dark:text-gray-100 ${queryResult ? 'h-20' : 'h-full min-h-[120px]'}`}
                spellCheck={false}
              />
            </div>

            {/* Query results */}
            {queryResult && (
              <div className="flex-1 flex flex-col overflow-hidden">
                {/* Generated SQL */}
                {queryResult.sql && (
                  <div className="px-4 py-2 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                    <label className="text-xs text-gray-500 dark:text-gray-400 mb-1 block font-medium">{t('security.prebuilt.generatedSql')}</label>
                    <pre className="text-xs font-mono text-gray-800 dark:text-gray-200 whitespace-pre-wrap overflow-x-auto max-h-24 overflow-y-auto bg-white dark:bg-gray-900 p-2 rounded border border-gray-200 dark:border-gray-700">
                      {queryResult.sql}
                    </pre>
                  </div>
                )}

                {/* Error */}
                {queryResult.error && (
                  <div className="px-4 py-3 bg-red-50 dark:bg-red-900/20 border-b border-red-200 dark:border-red-800">
                    <p className="text-xs font-medium text-red-700 dark:text-red-300">{t('security.prebuilt.error')}</p>
                    <pre className="text-xs text-red-600 dark:text-red-400 mt-1 whitespace-pre-wrap font-mono">{queryResult.error}</pre>
                  </div>
                )}

                {/* Results table */}
                {queryResult.columns && queryResult.columns.length > 0 && (
                  <div className="flex-1 overflow-auto px-4 py-2">
                    <div className="flex items-center justify-between mb-2">
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        {queryResult.rows?.length || 0} row{(queryResult.rows?.length || 0) !== 1 ? 's' : ''} returned
                      </div>
                      {(queryResult.rows?.length || 0) > 0 && (
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => exportRowsAsCSV(queryResult.columns, queryResult.rows || [], 'prebuilt-query')}
                            className="text-[11px] px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                          >
                            {t('table.exportCsv')}
                          </button>
                          <button
                            type="button"
                            onClick={() => exportRowsAsJSON(queryResult.columns, queryResult.rows || [], 'prebuilt-query')}
                            className="text-[11px] px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                          >
                            {t('table.exportJson')}
                          </button>
                        </div>
                      )}
                    </div>
                    <div className="overflow-auto border border-gray-200 dark:border-gray-700 rounded">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="bg-gray-100 dark:bg-gray-800">
                            {queryResult.columns.map((col, i) => (
                              <th key={i} className="px-3 py-2 text-left font-medium text-gray-700 dark:text-gray-300 border-b border-gray-200 dark:border-gray-700 whitespace-nowrap">
                                {col}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {(queryResult.rows || []).map((row, ri) => (
                            <tr key={ri} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                              {row.map((cell, ci) => (
                                <td key={ci} className="px-3 py-1.5 align-top text-gray-900 dark:text-gray-100 max-w-xs">
                                  <ExpandableCell value={String(cell ?? '')} mono />
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* No results */}
                {queryResult.columns && queryResult.columns.length === 0 && !queryResult.error && (
                  <div className="px-4 py-6 text-center text-sm text-gray-500 dark:text-gray-400">
                    {t('security.prebuilt.noResults')}
                  </div>
                )}
              </div>
            )}

            {/* Footer */}
            {!queryResult && (
              <div className="px-4 py-2 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {t('security.prebuilt.footer')}
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
