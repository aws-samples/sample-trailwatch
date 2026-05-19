import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, Info } from 'lucide-react'
import { endpoints } from '../config/api'

// Mirrors internal/features/nlquery/cost_estimator.go::CostEstimate.
export interface CostEstimate {
  model_id: string
  rate_source: 'default' | 'override' | 'fallback'
  input_tokens: number
  est_output_tokens: number
  max_output_tokens: number
  input_cost_usd: number
  est_output_cost_usd: number
  est_total_cost_usd: number
  max_output_cost_usd: number
  max_total_cost_usd: number
  input_rate_per_million_usd: number
  output_rate_per_million_usd: number
  warn_threshold_usd: number
  exceeds_warn_threshold: boolean
}

interface Props {
  // The user prompt to estimate against. Empty string is fine — banner just
  // reflects the system-prompt-only minimum cost.
  prompt: string
  // Debounce for the live update as the user types. 350ms feels responsive
  // without hammering the backend.
  debounceMs?: number
}

// CostBanner shows a one-line pre-flight cost estimate for an outgoing LLM
// call. Reaches /api/nlquery/estimate as the prompt changes (debounced) so
// the user sees a refreshed estimate without clicking anything.
//
// Emerald (normal) when the estimate is below the configured warn threshold
// ($0.50 default). Amber when above. Both states are non-blocking — the
// banner is informational; clicking Run on the surrounding form is what
// actually spends money.
export function CostBanner({ prompt, debounceMs = 350 }: Props) {
  const { t } = useTranslation()
  const [estimate, setEstimate] = useState<CostEstimate | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    const handle = setTimeout(async () => {
      setLoading(true)
      setError(null)
      try {
        const res = await fetch(endpoints.nlqueryEstimate, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt }),
        })
        if (!res.ok) {
          if (!cancelled) setError(`HTTP ${res.status}`)
          return
        }
        const data = (await res.json()) as CostEstimate
        if (!cancelled) setEstimate(data)
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Estimate failed')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }, debounceMs)
    return () => {
      cancelled = true
      clearTimeout(handle)
    }
  }, [prompt, debounceMs])

  if (error) {
    return (
      <div className="text-[11px] text-gray-500 dark:text-gray-400">
        {t('cost.estimateUnavailable')} ({error})
      </div>
    )
  }
  if (!estimate) {
    return <div className="text-[11px] text-gray-400">{loading ? t('cost.estimating') : ''}</div>
  }

  const total = formatUSD(estimate.est_total_cost_usd)
  const max = formatUSD(estimate.max_total_cost_usd)
  const fallback = estimate.rate_source === 'fallback'
  const warn = estimate.exceeds_warn_threshold
  const colorCls = warn
    ? 'border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/10 text-amber-800 dark:text-amber-200'
    : 'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 text-gray-700 dark:text-gray-300'

  return (
    <div className={`flex items-start gap-2 p-2 rounded border text-[11px] ${colorCls}`}>
      {warn ? <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" /> : <Info className="w-3.5 h-3.5 shrink-0 mt-px text-gray-400" />}
      <div className="flex-1 min-w-0">
        <div>
          <span className="font-medium">{t('cost.estTotal')}: ≈ {total}</span>
          <span className="text-gray-500 dark:text-gray-400 ml-1">
            ({t('cost.inputOnly')}; {t('cost.outputBilledAfter')}, {t('cost.cappedAt', { tokens: estimate.max_output_tokens })} ≈ {max} {t('cost.maxTotal')})
          </span>
        </div>
        {warn && (
          <div className="font-medium mt-0.5">
            {t('cost.warn', { threshold: formatUSD(estimate.warn_threshold_usd) })}
          </div>
        )}
        {fallback && (
          <div className="text-gray-500 dark:text-gray-400 mt-0.5">
            {t('cost.rateFallback', { model: estimate.model_id })}
          </div>
        )}
      </div>
    </div>
  )
}

// formatUSD picks a precision that feels honest for small dollar amounts.
//   <$0.01 → 4 decimals ($0.0042)
//   <$1   → 3 decimals ($0.025)
//   ≥$1   → 2 decimals ($1.23)
function formatUSD(n: number): string {
  if (n < 0.01) return `$${n.toFixed(4)}`
  if (n < 1) return `$${n.toFixed(3)}`
  return `$${n.toFixed(2)}`
}
