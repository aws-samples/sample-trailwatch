import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { DollarSign } from 'lucide-react'
import { endpoints } from '../config/api'

// Mirrors internal/features/nlquery/session_spend.go::SessionSpendSnapshot.
interface Snapshot {
  queries: number
  estimated_usd: number
  actual_usd: number
  started_at: string
  last_query_at?: string
  last_query_usd: number
  exceeded_estimate_count: number
}

const POLL_MS = 5_000

// SessionSpendChip is a tiny header indicator showing estimated LLM cost in
// the current process. Polled every 5s — cheap (returns a small JSON struct)
// and keeps the value warm without the overhead of SSE.
//
// Hidden when zero queries have been recorded so the header stays uncluttered
// for users who do not use NLQ.
export function SessionSpendChip() {
  const { t } = useTranslation()
  const [snap, setSnap] = useState<Snapshot | null>(null)

  useEffect(() => {
    let cancelled = false
    async function poll() {
      try {
        const res = await fetch(endpoints.nlquerySpend)
        if (res.ok) {
          const data = (await res.json()) as Snapshot
          if (!cancelled) setSnap(data)
        }
      } catch {
        /* silent — chip is best-effort, not load-bearing */
      }
    }
    poll()
    const id = setInterval(poll, POLL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  if (!snap || snap.queries === 0) return null

  // Guard against a missing/NaN figure so the chip never renders "$NaN".
  const cost = Number.isFinite(snap.estimated_usd) ? snap.estimated_usd : 0
  return (
    <span
      className="inline-flex items-center gap-1 text-[11px] text-gray-300"
      title={t('cost.chipTitle', { queries: snap.queries, cost: cost.toFixed(4) })}
    >
      <DollarSign className="w-3 h-3 text-gray-400" />
      <span>{t('cost.chipLabel', { cost: cost < 0.01 ? cost.toFixed(4) : cost.toFixed(3), queries: snap.queries })}</span>
    </span>
  )
}
