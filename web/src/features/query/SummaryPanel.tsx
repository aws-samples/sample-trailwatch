// SummaryPanel: right-side panel that requests a structured AI summary of
// the current scenario result and renders TL;DR + findings + entities, each
// with click-to-pivot affordances.
//
// The backend returns JSON ({tldr, findings[], entities[], suggested_pivots[]})
// produced under a strict prompt; a hallucination validator runs over the
// response and may attach a SuspiciousTokens list. When the model fails to
// emit valid JSON the backend falls back to a Summary string and we render
// it as plain text.
//
// onPivot is wired to the same seed setter that table cells use, so clicking
// "Pivot" on an entity behaves exactly like clicking "Use as seed" inside
// the result table — keeps the UX consistent.

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, ArrowRight, Check, Copy, Loader2, Sparkles, X } from 'lucide-react'
import { endpoints } from '../../config/api'
import { CostBanner } from '../../comm/CostBanner'
import type { SeedType } from './seedDetection'

// Click-to-expand value cell for the summary panel. Collapsed: single-line
// truncated. Expanded: full value wraps + Copy button. Sized for the 400px
// fixed panel where ARNs (~120 chars) overflow.
function ExpandValue({ value, mono = true }: { value: string; mono?: boolean }) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)
  async function copy(e: React.MouseEvent) {
    e.stopPropagation()
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard may be denied */ }
  }
  if (!expanded) {
    return (
      <button
        type="button"
        onClick={() => setExpanded(true)}
        title={t('cell.clickToExpand')}
        className={`flex-1 text-left truncate cursor-pointer hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded px-1 -mx-1 ${mono ? 'font-mono' : ''} text-[11px] text-gray-900 dark:text-gray-100`}
      >
        {value}
      </button>
    )
  }
  return (
    <span className="flex-1 min-w-0">
      <button
        type="button"
        onClick={() => setExpanded(false)}
        title={t('cell.clickToCollapse')}
        className={`block w-full text-left break-all cursor-pointer ${mono ? 'font-mono' : ''} text-[11px] text-gray-900 dark:text-gray-100`}
      >
        {value}
      </button>
      <button
        type="button"
        onClick={copy}
        className="mt-1 inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-white dark:hover:bg-gray-800"
      >
        {copied ? <Check className="w-3 h-3 text-green-600" /> : <Copy className="w-3 h-3" />}
        {copied ? t('cell.copied') : t('cell.copy')}
      </button>
    </span>
  )
}

interface Finding {
  severity: 'high' | 'medium' | 'low' | 'info' | string
  text: string
}
interface Entity {
  kind: string
  value: string
  count: number
}
interface Pivot {
  kind: string
  value: string
  reason: string
}

interface SummarizeResponse {
  // Structured (preferred)
  tldr?: string
  findings?: Finding[]
  entities?: Entity[]
  suggested_pivots?: Pivot[]
  // Legacy text fallback when the model didn't return JSON
  summary?: string
  // Validator output
  hallucination_warning?: string
  suspicious_tokens?: string[]
  rows_sent_to_model: number
  total_rows: number
}

interface Props {
  open: boolean
  onClose: () => void
  scenarioId: string
  scenarioName: string
  scenarioDescription?: string
  columns: string[] | null
  rows: unknown[][] | null
  recommended?: boolean
  // Click-to-pivot from an entity row. Same handler used by the table cells.
  onPivot?: (value: string, type: SeedType) => void
}

// kindToSeedType maps the backend's free-form "kind" to the SeedType the
// table-cell pivot handler expects. The handler tolerates 'unknown' for
// values we cannot confidently classify (rare for entities since the LLM
// is told to use a small enum).
function kindToSeedType(kind: string): SeedType {
  switch (kind) {
    case 'arn': return 'arn'
    case 'ip': return 'ip'
    case 'access_key': return 'access_key'
    case 'account': return 'account'
    case 'user': return 'user'
    case 'role': return 'role'
    default: return 'unknown'
  }
}

// Severity dot. Color picked to match the dashboard's severity rendering so
// the same finding looks the same in both places.
function SeverityDot({ severity }: { severity: string }) {
  const cls =
    severity === 'high'   ? 'bg-red-500' :
    severity === 'medium' ? 'bg-amber-500' :
    severity === 'low'    ? 'bg-blue-500' :
                            'bg-gray-400'
  return <span className={`inline-block w-2 h-2 rounded-full mt-1.5 shrink-0 ${cls}`} aria-hidden />
}

// isSuspect tells us whether to highlight this token because the validator
// flagged it as not-in-source. We compare on substring so a wrapping prefix
// (e.g., "arn:aws:..." in entities) still matches.
function isSuspect(value: string, suspects: string[] | undefined): boolean {
  if (!suspects || suspects.length === 0) return false
  return suspects.some(s => value.includes(s) || s.includes(value))
}

export function SummaryPanel({
  open,
  onClose,
  scenarioId,
  scenarioName,
  scenarioDescription,
  columns,
  rows,
  recommended,
  onPivot,
}: Props) {
  const { t } = useTranslation()
  const [summary, setSummary] = useState<SummarizeResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setSummary(null)
    setError(null)
  }, [scenarioId])

  // Esc closes the panel — keyboard shortcut keeps the keyboard-heavy
  // workflow flowing without needing to reach for the X button.
  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  const promptPreview = (() => {
    if (!columns || !rows) return ''
    const sliced = rows.slice(0, 50)
    return `${scenarioName}\n${(scenarioDescription ?? '')}\n${columns.join(',')}\n${JSON.stringify(sliced).slice(0, 8000)}`
  })()

  async function generate() {
    if (!columns || !rows) return
    setLoading(true)
    setError(null)
    setSummary(null)
    try {
      const res = await fetch(endpoints.nlquerySummarize, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_id: scenarioId,
          scenario_name: scenarioName,
          scenario_description: scenarioDescription,
          columns,
          rows,
          total_rows: rows.length,
        }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        setError(body?.message || `HTTP ${res.status}`)
        return
      }
      setSummary(await res.json())
    } catch (e: any) {
      setError(e?.message || 'Network error')
    } finally {
      setLoading(false)
    }
  }

  if (!open) return null

  const hasStructured = !!summary && (
    !!summary.tldr ||
    (summary.findings?.length ?? 0) > 0 ||
    (summary.entities?.length ?? 0) > 0
  )

  return (
    <div className="w-[400px] shrink-0 h-full bg-white dark:bg-gray-900 border-l border-gray-200 dark:border-gray-700 flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-purple-500" />
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{t('summaryPanel.title')}</h3>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label={t('summaryPanel.close')}
          className="p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-500 dark:text-gray-400"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div className="text-[11px] text-gray-600 dark:text-gray-300">
          {t('summaryPanel.scope', { scenario: scenarioName, rows: rows?.length || 0 })}
        </div>

        {!summary && !loading && (
          <>
            <CostBanner prompt={promptPreview} />
            <button
              type="button"
              onClick={generate}
              disabled={!columns || !rows || rows.length === 0}
              className={`w-full inline-flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium rounded ${
                recommended
                  ? 'bg-purple-600 text-white hover:bg-purple-700'
                  : 'border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800'
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              {recommended ? t('summaryPanel.generateRecommended') : t('summaryPanel.generate')}
            </button>
            <p className="text-[10px] text-gray-600 dark:text-gray-300">
              {t('summaryPanel.disclaimer')}
            </p>
          </>
        )}

        {loading && (
          <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400 py-4">
            <Loader2 className="w-4 h-4 animate-spin" />
            {t('summaryPanel.loading')}
          </div>
        )}

        {error && (
          <div className="p-3 rounded border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/10 text-xs text-red-700 dark:text-red-300">
            {error}
            <button type="button" onClick={generate} className="ml-2 underline">
              {t('summaryPanel.retry')}
            </button>
          </div>
        )}

        {summary && !loading && (
          <div className="space-y-4">
            {summary.hallucination_warning && (
              <div className="rounded border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 p-3">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-600 mt-0.5 shrink-0" />
                  <div className="text-[11px] text-amber-900 dark:text-amber-200">
                    <div className="font-semibold">{t('summaryPanel.warning.title')}</div>
                    <div className="mt-0.5">{summary.hallucination_warning}</div>
                  </div>
                </div>
              </div>
            )}

            <div className="text-[11px] text-gray-600 dark:text-gray-300">
              {summary.rows_sent_to_model < summary.total_rows
                ? t('summaryPanel.basedOn', { sent: summary.rows_sent_to_model, total: summary.total_rows })
                : t('summaryPanel.basedOnAll', { count: summary.total_rows })}
            </div>

            {/* TL;DR — bigger, leading text. Only renders when structured. */}
            {hasStructured && summary.tldr && (
              <section>
                <div className="text-[10px] uppercase tracking-wide text-gray-600 dark:text-gray-300 mb-1">
                  {t('summaryPanel.section.tldr')}
                </div>
                <p className="text-[13px] leading-snug text-gray-900 dark:text-gray-100">
                  {summary.tldr}
                </p>
              </section>
            )}

            {/* Findings — severity dot + one-line text. */}
            {hasStructured && (summary.findings?.length ?? 0) > 0 && (
              <section>
                <div className="text-[10px] uppercase tracking-wide text-gray-600 dark:text-gray-300 mb-1">
                  {t('summaryPanel.section.findings', { count: summary.findings!.length })}
                </div>
                <ul className="space-y-1.5">
                  {summary.findings!.map((f, i) => {
                    const suspect = isSuspect(f.text, summary.suspicious_tokens)
                    return (
                      <li key={i} className="flex items-start gap-2">
                        <SeverityDot severity={f.severity} />
                        <span className={`text-[12px] leading-snug ${suspect ? 'bg-amber-100 dark:bg-amber-900/30 rounded px-1' : 'text-gray-800 dark:text-gray-200'}`}>
                          {f.text}
                        </span>
                      </li>
                    )
                  })}
                </ul>
              </section>
            )}

            {/* Entities — small table with kind / value / count, each row a
                pivot button. This is the section users wanted: scannable,
                clickable, not buried inside prose. */}
            {hasStructured && (summary.entities?.length ?? 0) > 0 && (
              <section>
                <div className="text-[10px] uppercase tracking-wide text-gray-600 dark:text-gray-300 mb-1">
                  {t('summaryPanel.section.entities', { count: summary.entities!.length })}
                </div>
                <ul className="divide-y divide-gray-100 dark:divide-gray-800 rounded border border-gray-200 dark:border-gray-700">
                  {summary.entities!.map((e, i) => {
                    const suspect = isSuspect(e.value, summary.suspicious_tokens)
                    const seedType = kindToSeedType(e.kind)
                    const canPivot = !!onPivot && seedType !== 'unknown' && seedType !== 'user'
                    return (
                      <li key={i} className={`flex items-center gap-2 px-2 py-1.5 ${suspect ? 'bg-amber-50 dark:bg-amber-900/20' : ''}`}>
                        <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 shrink-0">
                          {e.kind}
                        </span>
                        <ExpandValue value={e.value} />
                        {e.count > 0 && (
                          <span className="text-[10px] text-gray-500 dark:text-gray-400 shrink-0 tabular-nums">
                            ×{e.count}
                          </span>
                        )}
                        {canPivot && (
                          <button
                            type="button"
                            onClick={() => onPivot!(e.value, seedType)}
                            title={t('summaryPanel.pivot')}
                            aria-label={t('summaryPanel.pivot')}
                            className="ml-1 inline-flex items-center justify-center p-1 rounded text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/30 shrink-0"
                          >
                            <ArrowRight className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </li>
                    )
                  })}
                </ul>
              </section>
            )}

            {/* Suggested pivots — separate section so the model's guidance
                doesn't compete with the entity catalog. Pivots reference one
                entity value with a reason. */}
            {hasStructured && (summary.suggested_pivots?.length ?? 0) > 0 && (
              <section>
                <div className="text-[10px] uppercase tracking-wide text-gray-600 dark:text-gray-300 mb-1">
                  {t('summaryPanel.section.suggestedPivots')}
                </div>
                <ul className="space-y-1.5">
                  {summary.suggested_pivots!.map((p, i) => {
                    const seedType = kindToSeedType(p.kind)
                    const canPivot = !!onPivot && seedType !== 'unknown' && seedType !== 'user'
                    return (
                      <li key={i} className="text-[12px] leading-snug">
                        <div className="text-gray-700 dark:text-gray-300">{p.reason}</div>
                        <div className="mt-0.5 flex items-center gap-2">
                          <ExpandValue value={p.value} />
                          {canPivot && (
                            <button
                              type="button"
                              onClick={() => onPivot!(p.value, seedType)}
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded border border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-300 hover:bg-blue-50 dark:hover:bg-blue-900/20"
                            >
                              <ArrowRight className="w-3 h-3" />
                              {t('summaryPanel.pivot')}
                            </button>
                          )}
                        </div>
                      </li>
                    )
                  })}
                </ul>
              </section>
            )}

            {/* Legacy fallback: model returned non-JSON. Render plain text. */}
            {!hasStructured && summary.summary && (
              <div className="text-[12px] text-gray-900 dark:text-gray-100 whitespace-pre-wrap leading-relaxed">
                {summary.summary}
              </div>
            )}

            <button
              type="button"
              onClick={() => { setSummary(null); generate() }}
              className="text-[11px] text-purple-600 dark:text-purple-400 hover:underline inline-flex items-center gap-1"
            >
              <Sparkles className="w-3 h-3" /> {t('summaryPanel.regenerate')}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
