import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Search, Play, Loader2, AlertTriangle, ChevronDown, X as XIcon } from 'lucide-react'
import { endpoints } from '../../config/api'
import { readApiError } from '../../comm/apiError'
import { AccountLabel } from '../../comm/AccountLabel'
import { useAccountNames } from '../../comm/accountNames'
import { InvestigateToolbar } from './InvestigateToolbar'
import { SummaryPanel } from './SummaryPanel'
import { seedTypeLabel, type SeedType } from './seedDetection'
import { ExpandableCell } from '../../comm/ExpandableCell'
import type { NavigationContext } from '../../arc/Layout'
import { Sparkles } from 'lucide-react'
import { exportRowsAsCSV, exportRowsAsJSON } from './tableExport'

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
  error_hint?: string
  error_detail?: string
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

// columnMinWidth picks a sensible CSS min-width for a result-table column
// based on its name. Rationale: ARNs are long (need ~360px); identities and
// error messages benefit from breathing room; counts and timestamps fit in
// less. The earlier blanket max-width: 220px squashed every column to the
// point of unreadability when the side panel was also open.
function columnMinWidth(col: string): string {
  const lc = col.toLowerCase()
  if (/arn|identity|actor|caller|creator|launcher|target_account|source_account|recipientaccountid/.test(lc)) return '280px'
  if (/error_?message|user_?agent|sql/.test(lc)) return '260px'
  if (/event_?name|event_?source|service|principal/.test(lc)) return '180px'
  if (/event_?time|first_?seen|last_?seen|created|updated/.test(lc)) return '160px'
  if (/source_?ip|ip_?address/.test(lc)) return '140px'
  if (/^count$|^value$|api_?calls|login_?count|call_?count|unique_/.test(lc)) return '90px'
  if (/account/.test(lc)) return '180px'
  return '140px'
}

interface ToolbarSnapshot {
  timeStart: string
  timeEnd: string
  accountIds: string[]
  seed: string
  seedType: SeedType
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
  // Toolbar context: time + accounts apply to scenario runs as filters; seed
  // is surfaced for the seed-driven scenario reorder (and PR 2's drill-down
  // workbench). Stored in a ref-style state updated by the toolbar's
  // onChange.
  const [toolbar, setToolbar] = useState<ToolbarSnapshot>({
    timeStart: '', timeEnd: '', accountIds: [], seed: '', seedType: 'unknown',
  })
  // clearSignal is a counter-and-kind handshake the active-filters strip
  // uses to ask the toolbar to clear a specific filter. The toolbar owns
  // its state via useToolbarState; rather than lift the whole thing up, we
  // expose this thin "you should clear <kind> now" channel.
  const [clearSignal, setClearSignal] = useState<{ seq: number; kind: 'time' | 'accounts' | 'seed' | null }>({ seq: 0, kind: null })
  const bumpClearSignal = useCallback((kind: 'time' | 'accounts' | 'seed') => {
    setClearSignal(s => ({ seq: s.seq + 1, kind }))
  }, [])

  // Click-to-pivot from result-table cells: an ExpandableCell asks the
  // toolbar to adopt this value as the seed. Bumping seq triggers the
  // toolbar's effect; the seed input updates and scenarios reorder.
  const [setSeedSignal, setSetSeedSignal] = useState<{ seq: number; value: string; type?: SeedType }>({ seq: 0, value: '' })
  // Toast and scroll target for the post-pivot guidance ("you set a seed,
  // here's what to do next"). The toast clears itself after a few seconds.
  const [pivotToast, setPivotToast] = useState<string | null>(null)
  // Esc dismisses the pivot toast — small affordance but matches the rest
  // of the keyboard-friendly workflow.
  useEffect(() => {
    if (!pivotToast) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setPivotToast(null)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [pivotToast])
  const recommendationsRef = useRef<HTMLDivElement | null>(null)
  const pivotToSeed = useCallback((value: string, type: SeedType) => {
    setSetSeedSignal(s => ({ seq: s.seq + 1, value, type }))
    setPivotToast(value)
    // Scroll the recommendations banner into view so the responder sees
    // the suggested next steps without hunting. Slight delay so the seed
    // state update has propagated and the banner has rendered.
    setTimeout(() => {
      recommendationsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, 50)
  }, [])

  // The pivot toast is dismissible (user-controlled) instead of timing out.
  // The earlier auto-clear flashed away before users could read it; if no
  // matching scenarios exist they were left wondering what just happened.
  // The "no recommendations" callout below picks up that case explicitly.
  // Clears automatically when the seed is cleared via the active-filters strip.
  useEffect(() => {
    if (!toolbar.seed) setPivotToast(null)
  }, [toolbar.seed])

  // Summary side panel: opt-in by default; auto-suggested on large results.
  const [summaryOpen, setSummaryOpen] = useState(false)
  const LARGE_RESULT_THRESHOLD = 500
  const isLargeResult = !!result?.rows && result.rows.length >= LARGE_RESULT_THRESHOLD

  // Per-row expansion in the result table. Tracks indices of rows the user
  // has clicked to wrap-mode (every cell shows full text on multiple lines).
  // Cleared on every new scenario run so a stale row index does not point
  // at unrelated data.
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set())
  const [wrapAllRows, setWrapAllRows] = useState(false)
  // Per-column width overrides set by dragging the column header's right
  // edge. Keys are the column name; values are pixel widths. Cleared on
  // every new scenario run so a column index from a stale result does not
  // persist into a new one.
  const [colWidths, setColWidths] = useState<Record<string, number>>({})
  useEffect(() => {
    setExpandedRows(new Set())
    setWrapAllRows(false)
    setColWidths({})
  }, [result?.scenario_id, result?.rows?.length])
  const toggleRow = useCallback((ri: number) => {
    setExpandedRows(prev => {
      const next = new Set(prev)
      if (next.has(ri)) next.delete(ri); else next.add(ri)
      return next
    })
  }, [])

  // Track which row has its "copied" check shown. Single-row scope is fine —
  // an analyst copies one row at a time during incident handoff.
  const [copiedRow, setCopiedRow] = useState<number | null>(null)
  const copyRowAsJSON = useCallback(async (ri: number) => {
    if (!result?.columns || !result.rows) return
    const row = result.rows[ri]
    if (!row) return
    const obj: Record<string, unknown> = {}
    result.columns.forEach((c, i) => { obj[c] = row[i] ?? null })
    try {
      await navigator.clipboard.writeText(JSON.stringify(obj, null, 2))
      setCopiedRow(ri)
      setTimeout(() => setCopiedRow(prev => (prev === ri ? null : prev)), 1500)
    } catch { /* clipboard may be denied */ }
  }, [result])

  // beginColumnResize wires up document-level mousemove + mouseup listeners
  // so the user can keep dragging even when the cursor leaves the small
  // resize handle. Tracks the starting width so subsequent dx is computed
  // from the original, not the previous frame.
  const beginColumnResize = useCallback((colName: string, startX: number, startWidthPx: number) => {
    const onMove = (e: MouseEvent) => {
      const dx = e.clientX - startX
      const next = Math.max(60, startWidthPx + dx)
      setColWidths(prev => ({ ...prev, [colName]: next }))
    }
    const onUp = () => {
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }, [])

  // When a result loads and it's large, auto-open the panel so the user
  // sees the Summarize call-to-action without hunting. We only open on the
  // transition (new result), not on every render.
  useEffect(() => {
    if (isLargeResult) {
      setSummaryOpen(true)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result?.scenario_id, result?.rows?.length])

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
      // Build the filters payload from the toolbar context. The backend
      // ignores empty fields, so omitting unset values is fine.
      const filters: Record<string, unknown> = {}
      if (toolbar.timeStart) filters.time_start = toolbar.timeStart
      if (toolbar.timeEnd) filters.time_end = toolbar.timeEnd
      if (toolbar.accountIds.length > 0) filters.account_ids = toolbar.accountIds
      const body: Record<string, unknown> = { scenario_id: scenario.id, param }
      if (Object.keys(filters).length > 0) body.filters = filters
      const res = await fetch(endpoints.investigateRun, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
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
  // Seed-driven reorder: when the user has pasted a seed (ARN/IP/access key/
  // account/user/role), scenarios whose param_type matches the detected
  // seed type bubble to the top of the list with a "matches your seed"
  // badge. The badge + reorder is purely visual; the param still has to be
  // confirmed by the user before running. This nudges the responder toward
  // relevant hunts without prescribing what to do.
  const seedMatchedScenarios = useMemo(() => {
    if (!toolbar.seed || toolbar.seedType === 'unknown') return new Set<string>()
    const matched = new Set<string>()
    for (const s of scenarios) {
      if (s.param_type === toolbar.seedType) matched.add(s.id)
    }
    return matched
  }, [scenarios, toolbar.seed, toolbar.seedType])

  const filtered = useMemo(() => {
    const inCategory = selectedCategory === 'all' ? scenarios : scenarios.filter(s => s.category === selectedCategory)
    if (seedMatchedScenarios.size === 0) return inCategory
    // Bubble matched scenarios to the top, preserving relative order within
    // each group.
    const matched: Scenario[] = []
    const rest: Scenario[] = []
    for (const s of inCategory) {
      if (seedMatchedScenarios.has(s.id)) matched.push(s)
      else rest.push(s)
    }
    return [...matched, ...rest]
  }, [scenarios, selectedCategory, seedMatchedScenarios])

  // Top recommendations to surface in the post-pivot banner. We pick from
  // scenarios whose param_type matches the detected seed type, sort by
  // severity (CRITICAL → HIGH → MEDIUM → LOW), and cap at 3 so the banner
  // stays scannable. Deterministic — no LLM, free.
  const recommendations = useMemo(() => {
    if (!toolbar.seed || toolbar.seedType === 'unknown') return []
    const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
    const matches = scenarios.filter(s => s.param_type === toolbar.seedType)
    matches.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9))
    return matches.slice(0, 3)
  }, [scenarios, toolbar.seed, toolbar.seedType])

  // When the seed is set but no scenarios match its type, suggest the seed
  // types that DO have scenarios. Users frequently paste an identity name
  // (which we detect as 'user') only to find no scenario takes a 'user'
  // param — guiding them to override to 'role' or 'arn' is the unblock.
  const suggestedSeedTypes = useMemo(() => {
    if (!toolbar.seed) return []
    if (recommendations.length > 0) return []
    // Build the set of param_types that scenarios actually accept (not 'none').
    const types = new Set<string>()
    for (const s of scenarios) {
      if (s.param_type && s.param_type !== 'none') types.add(s.param_type)
    }
    // Prefer the most likely useful types first.
    const preferred = ['arn', 'access_key', 'ip', 'account', 'role', 'identity']
    return preferred.filter(t => types.has(t) && t !== toolbar.seedType)
  }, [scenarios, toolbar.seed, toolbar.seedType, recommendations.length])

  // Show a guidance callout whenever a seed is set, regardless of whether
  // any scenarios matched. Drives the persistent banner below the toolbar.
  const showSeedCallout = !!toolbar.seed

  // Run a scenario directly with the toolbar seed as its parameter. Used by
  // the recommendations banner so the responder gets one-click drill-down
  // after a pivot. Selecting the scenario in the list AND triggering the
  // run keeps the regular detail panel in sync.
  const runRecommendation = useCallback((s: Scenario) => {
    setSelectedScenario(s)
    const param = s.param_type !== 'none' ? toolbar.seed : ''
    setParamValue(param)
    void runScenarioById(s, param)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toolbar.seed])

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
            <p className="text-[11px] text-gray-600 dark:text-gray-400">{t('security.investigate.scenarios', { count: scenarios.length })} • {t('security.investigate.crossAccount')}</p>
          </div>
        </div>
      </div>

      {/* Toolbar: time window + account scope + seed for drill-down (PR 2). */}
      <InvestigateToolbar onChange={setToolbar} clearSignal={clearSignal} setSeedSignal={setSeedSignal} />

      {/* Active filters strip — visible summary of what scenarios will run
          against. Each chip has an X to clear that one filter. Empty when
          no filters are set so the page is not visually noisy by default. */}
      <ActiveFiltersStrip
        timeStart={toolbar.timeStart}
        timeEnd={toolbar.timeEnd}
        accountIds={toolbar.accountIds}
        seed={toolbar.seed}
        seedType={toolbar.seedType}
        onClearTime={() => bumpClearSignal('time')}
        onClearAccounts={() => bumpClearSignal('accounts')}
        onClearSeed={() => bumpClearSignal('seed')}
      />

      {/* Pivot toast — confirmation that the seed was set. Persistent (does
          not auto-dismiss), since prior auto-clear flashed away before users
          could read it; user dismisses via X or by clearing the seed. */}
      {pivotToast && (
        <div role="status" aria-live="polite" className="px-6 py-2 bg-blue-600 dark:bg-blue-700 text-white text-[12px] flex items-center gap-2">
          <span className="font-medium">{t('security.investigate.pivotToast.title')}</span>
          <span className="opacity-90 truncate">{pivotToast}</span>
          <span className="ml-auto text-[11px] opacity-90">
            {recommendations.length > 0
              ? t('security.investigate.pivotToast.hint', { count: recommendations.length })
              : t('security.investigate.pivotToast.noMatchHint')}
          </span>
          <button
            type="button"
            onClick={() => setPivotToast(null)}
            aria-label={t('security.investigate.pivotToast.dismiss')}
            className="ml-2 p-0.5 rounded hover:bg-blue-700 dark:hover:bg-blue-800"
          >
            <XIcon className="w-3 h-3" />
          </button>
        </div>
      )}

      {/* Seed callout — single banner shown whenever a seed is set, with
          two variants:
          a) Recommendations: up to 3 matching scenarios, ranked by severity.
          b) No matches: explains why and suggests seed types that have
             scenarios available, plus a quick "Clear seed" affordance.
          Closes the "click Use as seed → nothing happens" dead end that the
          user reported. */}
      {showSeedCallout && (
        <div ref={recommendationsRef} className="px-6 py-3 border-b border-amber-200 dark:border-amber-900/40 bg-amber-50/60 dark:bg-amber-900/10">
          {recommendations.length > 0 ? (
            <>
              <div className="mb-2">
                <h3 className="text-xs font-semibold text-amber-900 dark:text-amber-200">
                  {t('security.investigate.recommended.title')}
                </h3>
                <p className="text-[11px] text-amber-800/80 dark:text-amber-300/70">
                  {t('security.investigate.recommended.subtitle', { type: seedTypeLabel(toolbar.seedType) })}
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                {recommendations.map(s => (
                  <button
                    key={s.id}
                    type="button"
                    onClick={() => runRecommendation(s)}
                    disabled={running}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] rounded border border-amber-300 dark:border-amber-700 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200 hover:bg-amber-100 dark:hover:bg-amber-900/30 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <span className={`px-1 py-0.5 text-[10px] font-bold uppercase rounded ${SEVERITY_BADGE[s.severity] || 'bg-gray-500 text-white'}`}>{s.severity}</span>
                    <span className="font-medium">{s.name}</span>
                    <Play className="w-3 h-3 text-blue-600 dark:text-blue-400" />
                  </button>
                ))}
              </div>
            </>
          ) : (
            // No-match variant: tell the user honestly that nothing matches,
            // and give them two ways out — change the seed type or clear it.
            <>
              <div className="mb-2">
                <h3 className="text-xs font-semibold text-amber-900 dark:text-amber-200">
                  {t('security.investigate.noMatch.title', { type: seedTypeLabel(toolbar.seedType) })}
                </h3>
                <p className="text-[11px] text-amber-800/80 dark:text-amber-300/70">
                  {t('security.investigate.noMatch.subtitle')}
                </p>
              </div>
              <div className="flex flex-wrap gap-2 items-center">
                {suggestedSeedTypes.length > 0 && (
                  <>
                    <span className="text-[11px] text-amber-900 dark:text-amber-200">
                      {t('security.investigate.noMatch.tryType')}
                    </span>
                    {suggestedSeedTypes.map(typeId => (
                      <button
                        key={typeId}
                        type="button"
                        onClick={() => setSetSeedSignal(s => ({ seq: s.seq + 1, value: toolbar.seed, type: typeId as SeedType }))}
                        className="inline-flex items-center gap-1 px-2 py-1 text-[11px] rounded border border-amber-300 dark:border-amber-700 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200 hover:bg-amber-100 dark:hover:bg-amber-900/30"
                      >
                        {seedTypeLabel(typeId as SeedType)}
                      </button>
                    ))}
                  </>
                )}
                <button
                  type="button"
                  onClick={() => bumpClearSignal('seed')}
                  className="ml-auto inline-flex items-center gap-1 px-2 py-1 text-[11px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                >
                  {t('security.investigate.noMatch.clearSeed')}
                </button>
              </div>
            </>
          )}
        </div>
      )}

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
            {filtered.map(s => {
              const matchesSeed = seedMatchedScenarios.has(s.id)
              return (
                <button
                  key={s.id}
                  onClick={() => {
                    setSelectedScenario(s)
                    // If the user had a seed and this scenario takes the matching
                    // type, auto-fill the param so they can run with one click.
                    if (matchesSeed && toolbar.seed) {
                      setParamValue(toolbar.seed)
                    } else {
                      setParamValue('')
                    }
                    setResult(null)
                  }}
                  className={`w-full text-left px-4 py-3 border-b border-gray-100 dark:border-gray-800 border-l-3 transition-colors ${
                    selectedScenario?.id === s.id
                      ? 'bg-blue-50 dark:bg-blue-900/20 border-l-[3px] border-l-[#0972d3]'
                      : matchesSeed
                      ? 'bg-amber-50/50 dark:bg-amber-900/10 hover:bg-amber-50 dark:hover:bg-amber-900/20 border-l-[3px] border-l-amber-400'
                      : `hover:bg-white dark:hover:bg-gray-800 border-l-[3px] ${SEVERITY_COLORS[s.severity]?.split(' ')[0] || 'border-l-gray-300'}`
                  }`}
                >
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <span className="text-[12px] font-medium text-gray-900 dark:text-white">{s.name}</span>
                    <span className={`px-1 py-0.5 text-[10px] font-bold uppercase rounded ${SEVERITY_BADGE[s.severity] || 'bg-gray-500 text-white'}`}>{s.severity}</span>
                    {matchesSeed && (
                      <span className="px-1 py-0.5 text-[10px] font-semibold uppercase rounded bg-amber-200 dark:bg-amber-900/50 text-amber-900 dark:text-amber-200">
                        {t('security.investigate.matchesSeed')}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-gray-600 dark:text-gray-300 leading-snug">{s.description}</p>
                  {s.param_type !== 'none' && (
                    <span className="inline-block mt-1 text-[10px] text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/30 px-1.5 py-0.5 rounded">
                      {t('security.investigate.requires', { label: s.param_label })}
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        </div>

        {/* Right: Parameter input + Results */}
        <div className="flex-1 flex flex-col min-w-0">
          {!selectedScenario ? (
            <div className="flex items-center justify-center h-full text-center">
              <div>
                <Search className="w-10 h-10 text-gray-400 dark:text-gray-500 mx-auto mb-3" />
                <p className="text-sm text-gray-700 dark:text-gray-300">{t('security.investigate.selectScenario')}</p>
                <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">{t('security.investigate.queriesRunAgainst')}</p>
              </div>
            </div>
          ) : (
            <>
              {/* Scenario header + param input */}
              <div className="px-5 py-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900">
                <div className="flex items-center gap-2 mb-2">
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{selectedScenario.name}</h3>
                  <span className={`px-1.5 py-0.5 text-[10px] font-bold uppercase rounded ${SEVERITY_BADGE[selectedScenario.severity]}`}>{selectedScenario.severity}</span>
                  <span className="text-[10px] text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">{selectedScenario.category}</span>
                </div>
                <p className="text-xs text-gray-600 dark:text-gray-300 mb-3">{selectedScenario.description}</p>

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
                      onKeyDown={e => {
                        if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && !running && paramValue) {
                          e.preventDefault()
                          runScenario()
                        }
                      }}
                      placeholder={`Or paste ${selectedScenario.param_label} here... (${navigator.platform.includes('Mac') ? '⌘' : 'Ctrl'}+Enter to run)`}
                      className="w-full mt-2 px-3 py-2 text-sm font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    />
                  </div>
                )}

                <button
                  onClick={runScenario}
                  disabled={running || (selectedScenario.param_type !== 'none' && !paramValue)}
                  title={navigator.platform.includes('Mac') ? '⌘+Enter' : 'Ctrl+Enter'}
                  className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded bg-[#0972d3] text-white hover:bg-[#0860b0] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                  {running ? t('security.investigate.running') : t('security.investigate.runInvestigation')}
                </button>
              </div>

              {/* Results */}
              <div className="flex-1 overflow-auto">
                {result?.error && (
                  <div role="alert" className="m-4 p-3 rounded border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-red-500" />
                      <span className="text-xs font-medium text-red-700 dark:text-red-300">{t('security.investigate.queryError')}</span>
                    </div>
                    {result.error_hint ? (
                      <p className="text-[12px] text-red-700 dark:text-red-300 mt-1">{result.error_hint}</p>
                    ) : null}
                    <details className="mt-2">
                      <summary className="text-[10px] cursor-pointer text-red-700 dark:text-red-300 hover:underline">{t('security.investigate.showTechnicalDetail')}</summary>
                      <pre className="text-[11px] text-red-600 dark:text-red-400 mt-1 whitespace-pre-wrap font-mono">{result.error_detail || result.error}</pre>
                    </details>
                  </div>
                )}

                {result?.columns && result.columns.length > 0 && (
                  <div className="p-4">
                    <div className="flex items-center justify-between mb-2 gap-2">
                      <span className="text-[11px] text-gray-500">
                        {t('security.investigate.resultCount', { count: result.rows?.length || 0 })}
                      </span>
                      <button
                        type="button"
                        onClick={() => setSummaryOpen(true)}
                        disabled={!result.rows || result.rows.length === 0}
                        className={`inline-flex items-center gap-1 px-2 py-1 text-[11px] rounded border ${
                          isLargeResult
                            ? 'border-purple-400 dark:border-purple-700 bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300'
                            : 'border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300'
                        } hover:bg-purple-50 dark:hover:bg-purple-900/30 disabled:opacity-40 disabled:cursor-not-allowed`}
                      >
                        <Sparkles className="w-3 h-3" />
                        {isLargeResult ? t('security.investigate.summarizeRecommended') : t('security.investigate.summarize')}
                      </button>
                    </div>
                    {isLargeResult && (
                      <div className="mb-2 p-2 rounded border border-amber-200 dark:border-amber-900/40 bg-amber-50/60 dark:bg-amber-900/10">
                        <div className="text-[11px] text-amber-900 dark:text-amber-200">
                          {t('security.investigate.largeResult', { count: result.rows?.length || 0 })}
                        </div>
                      </div>
                    )}
                    <div className="flex items-center gap-2 mb-2">
                      <button
                        type="button"
                        onClick={() => setWrapAllRows(v => !v)}
                        className="inline-flex items-center gap-1 px-2 py-1 text-[10px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                      >
                        {wrapAllRows
                          ? t('security.investigate.collapseAllRows')
                          : t('security.investigate.expandAllRows')}
                      </button>
                      {(result.rows?.length || 0) > 0 && (
                        <>
                          <button
                            type="button"
                            onClick={() => exportRowsAsCSV(result.columns!, (result.rows || []) as (string|number|null)[][], `investigate-${selectedScenario.id}`)}
                            className="inline-flex items-center gap-1 px-2 py-1 text-[10px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                          >
                            {t('table.exportCsv')}
                          </button>
                          <button
                            type="button"
                            onClick={() => exportRowsAsJSON(result.columns!, (result.rows || []) as (string|number|null)[][], `investigate-${selectedScenario.id}`)}
                            className="inline-flex items-center gap-1 px-2 py-1 text-[10px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                          >
                            {t('table.exportJson')}
                          </button>
                        </>
                      )}
                      <span className="text-[10px] text-gray-600 dark:text-gray-400">{t('security.investigate.tableHint')}</span>
                    </div>
                    <div className="relative">
                    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-auto max-h-[60vh]">
                      {/* table-fixed=false: cells get min-width but can grow to fit
                          content, and the surrounding div scrolls horizontally
                          when the row is wider than the panel. */}
                      <table className="text-[11px] border-collapse">
                        <thead className="sticky top-0 z-10">
                          <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="w-12 px-1 py-2 border-b border-gray-200 dark:border-gray-700"></th>
                            {result.columns.map((col, i) => {
                              const overrideWidth = colWidths[col]
                              const effectiveStyle: React.CSSProperties = overrideWidth
                                ? { width: overrideWidth, minWidth: overrideWidth, maxWidth: overrideWidth }
                                : { minWidth: columnMinWidth(col) }
                              return (
                                <th
                                  key={i}
                                  className="relative px-3 py-2 text-left font-medium text-gray-600 dark:text-gray-400 whitespace-nowrap border-b border-gray-200 dark:border-gray-700"
                                  style={effectiveStyle}
                                >
                                  {col}
                                  {/* Right-edge drag handle. The pointer-events
                                      area is wider than the visible bar so it's
                                      easy to grab without misclicks. */}
                                  <span
                                    onMouseDown={(e) => {
                                      e.preventDefault()
                                      const th = e.currentTarget.parentElement as HTMLElement | null
                                      const startWidth = th ? th.getBoundingClientRect().width : 140
                                      beginColumnResize(col, e.clientX, startWidth)
                                    }}
                                    onDoubleClick={() => {
                                      // Reset to the default min-width.
                                      setColWidths(prev => {
                                        const next = { ...prev }
                                        delete next[col]
                                        return next
                                      })
                                    }}
                                    title="Drag to resize · Double-click to reset"
                                    className="absolute top-0 -right-1 h-full w-3 cursor-col-resize select-none group"
                                  >
                                    <span className="absolute right-1 top-1 bottom-1 w-px bg-gray-300 dark:bg-gray-600 group-hover:w-0.5 group-hover:bg-blue-500" />
                                  </span>
                                </th>
                              )
                            })}
                          </tr>
                        </thead>
                        <tbody>
                          {(result.rows || []).map((row, ri) => {
                            const expanded = wrapAllRows || expandedRows.has(ri)
                            return (
                              <tr key={ri} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                <td className="w-12 px-1 py-1 align-top">
                                  <div className="flex items-center gap-0.5">
                                    <button
                                      type="button"
                                      onClick={() => toggleRow(ri)}
                                      aria-label={expanded ? 'Collapse row' : 'Expand row'}
                                      className="text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 p-0.5"
                                    >
                                      {expanded ? '▾' : '▸'}
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => copyRowAsJSON(ri)}
                                      title={t('security.investigate.copyRowAsJson')}
                                      aria-label={t('security.investigate.copyRowAsJson')}
                                      className="text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 p-0.5 text-[10px]"
                                    >
                                      {copiedRow === ri ? '✓' : '⎘'}
                                    </button>
                                  </div>
                                </td>
                                {row.map((cell: any, ci: number) => {
                                  const colName = result.columns?.[ci] || ''
                                  const isAccountCol = /\baccount(_?id)?\b|recipientaccountid|sourceaccount|targetaccount/i.test(colName)
                                  const cellStr = cell === null ? '' : String(cell)
                                  const isAccountValue = /^\d{12}$/.test(cellStr)
                                  const cellTdClass = expanded
                                    ? 'px-3 py-1.5 text-gray-900 dark:text-gray-100 align-top whitespace-normal break-words'
                                    : 'px-3 py-1.5 text-gray-900 dark:text-gray-100 align-top whitespace-nowrap overflow-hidden'
                                  const override = colWidths[colName]
                                  const tdStyle: React.CSSProperties = override
                                    ? { width: override, minWidth: override, maxWidth: override }
                                    : { minWidth: columnMinWidth(colName) }
                                  // Account-id columns keep AccountLabel for the inline "id (name)" treatment.
                                  if (isAccountCol && isAccountValue) {
                                    return (
                                      <td key={ci} className={cellTdClass} style={tdStyle}>
                                        <AccountLabel accountId={cellStr} />
                                      </td>
                                    )
                                  }
                                  return (
                                    <td key={ci} className={cellTdClass} style={tdStyle}>
                                      <ExpandableCell
                                        value={cellStr}
                                        onPivot={pivotToSeed}
                                        mono={/arn|ipaddress|accesskey|key|userAgent|errorMessage|sql/i.test(colName)}
                                        forceExpanded={expanded}
                                      />
                                    </td>
                                  )
                                })}
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                    {/* Right-edge gradient hint — signals additional columns off-screen.
                        pointer-events-none so it never blocks scroll/clicks. */}
                    <div aria-hidden className="pointer-events-none absolute top-0 right-0 h-full w-6 rounded-r-lg bg-gradient-to-l from-white/80 dark:from-gray-900/80 to-transparent" />
                    </div>

                    {result.sql && (
                      <details className="mt-3">
                        <summary className="text-[10px] text-gray-600 dark:text-gray-400 cursor-pointer hover:text-gray-800 dark:hover:text-gray-200">{t('security.investigate.showSqlQuery')}</summary>
                        <pre className="text-[10px] font-mono text-gray-500 bg-gray-50 dark:bg-gray-900 p-3 rounded mt-1 overflow-x-auto border border-gray-200 dark:border-gray-700">{result.sql}</pre>
                      </details>
                    )}
                  </div>
                )}

                {result && !result.error && (!result.columns || result.columns.length === 0) && (
                  <div className="p-8 text-center">
                    <p className="text-sm text-gray-500">{t('security.investigate.noResults')}</p>
                    {(toolbar.timeStart || toolbar.timeEnd || toolbar.accountIds.length > 0) ? (
                      <p className="text-xs text-gray-400 mt-1">
                        {t('security.investigate.noResultsFiltered', {
                          filters: [
                            (toolbar.timeStart || toolbar.timeEnd) && t('security.investigate.filterTime'),
                            toolbar.accountIds.length > 0 && t('security.investigate.filterAccounts', { count: toolbar.accountIds.length }),
                          ].filter(Boolean).join(' · '),
                        })}
                      </p>
                    ) : (
                      <p className="text-xs text-gray-400 mt-1">{t('security.investigate.noResultsHint')}</p>
                    )}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* AI summary side panel — sits in the same flex row as the scenario
            list and detail panel, so it pushes the table area when it opens
            instead of overlaying it. Width fixed in SummaryPanel. */}
        <SummaryPanel
          open={summaryOpen && !!result?.columns && (result.rows?.length || 0) > 0 && !!selectedScenario}
          onClose={() => setSummaryOpen(false)}
          scenarioId={selectedScenario?.id || ''}
          scenarioName={selectedScenario?.name || ''}
          scenarioDescription={selectedScenario?.description}
          columns={result?.columns ?? null}
          rows={(result?.rows ?? null) as unknown[][] | null}
          recommended={isLargeResult}
          onPivot={pivotToSeed}
        />
      </div>
    </div>
  )
}

// ActiveFiltersStrip renders a horizontal row of chips summarizing every
// filter currently in effect on the toolbar. Empty when nothing is set so
// the page is not visually noisy by default. Each chip has an X button that
// asks the toolbar to clear that filter via the parent's clearSignal handle.
//
// Why this is its own component (vs inline JSX): keeps InvestigateView
// readable and gives us one place to evolve chip rendering as more filter
// types appear in PR 2 (e.g., severity, identity-type filters).
function ActiveFiltersStrip({
  timeStart,
  timeEnd,
  accountIds,
  seed,
  seedType,
  onClearTime,
  onClearAccounts,
  onClearSeed,
}: {
  timeStart: string
  timeEnd: string
  accountIds: string[]
  seed: string
  seedType: SeedType
  onClearTime: () => void
  onClearAccounts: () => void
  onClearSeed: () => void
}) {
  const { t } = useTranslation()
  const hasTime = !!(timeStart || timeEnd)
  const hasAccounts = accountIds.length > 0
  const hasSeed = !!seed

  if (!hasTime && !hasAccounts && !hasSeed) return null

  const timeLabel = (() => {
    if (timeStart && timeEnd) return `${timeStart} → ${timeEnd}`
    if (timeStart) return `≥ ${timeStart}`
    if (timeEnd) return `≤ ${timeEnd}`
    return ''
  })()

  return (
    <div className="px-6 py-2 border-b border-gray-200 dark:border-gray-700 bg-blue-50/40 dark:bg-blue-900/10">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400">
          {t('investigateToolbar.active.label')}
        </span>
        {hasTime && (
          <ActiveChip label={t('investigateToolbar.active.time')} value={timeLabel} onClear={onClearTime} />
        )}
        {hasAccounts && (
          <ActiveChip
            label={t('investigateToolbar.active.accounts')}
            value={t('investigateToolbar.active.accountsValue', { count: accountIds.length })}
            onClear={onClearAccounts}
          />
        )}
        {hasSeed && (
          <ActiveChip
            label={t('investigateToolbar.active.seed', { type: seedTypeLabel(seedType) })}
            value={truncate(seed, 60)}
            fullValue={seed}
            onClear={onClearSeed}
          />
        )}
      </div>
    </div>
  )
}

function ActiveChip({ label, value, onClear, fullValue }: { label: string; value: string; onClear: () => void; fullValue?: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded-full border border-blue-200 dark:border-blue-800 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300" title={fullValue}>
      <span className="text-gray-500 dark:text-gray-400">{label}:</span>
      <span className="font-medium">{value}</span>
      <button
        type="button"
        onClick={onClear}
        aria-label={`Clear ${label}`}
        className="ml-1 p-0.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
      >
        <XIcon className="w-3 h-3" />
      </button>
    </span>
  )
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}
