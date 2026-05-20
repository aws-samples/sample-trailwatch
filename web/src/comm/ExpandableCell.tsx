// ExpandableCell renders a result-table cell that expands IN PLACE (not as
// a floating popover) when the user clicks it. Earlier popover-based design
// overlapped neighbouring columns when the cell was narrower than the
// popover panel; in-place expansion sidesteps that whole class of bugs.
//
// Collapsed state: single-line truncated text. Click anywhere on the cell.
// Expanded state: full value wraps, with Copy + (when value is pivotable)
//   "Use as seed" buttons stacked below. The cell row grows; a sibling cell
//   in the same <tr> wraps too because the table cell uses `align-top` and
//   the row's height is driven by the tallest cell.
//
// "Pivotable" = ARN, IP, access key, 12-digit account ID, IAM role. We do
// NOT offer pivot for the catch-all "user" detection because almost any
// plain string would pivot.

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Check, Copy, Search } from 'lucide-react'
import { detectSeedType, seedTypeLabel, type SeedType } from '../features/query/seedDetection'

interface Props {
  value: string
  onPivot?: (value: string, type: SeedType) => void
  // Reserved for future use; current implementation ignores it because
  // expansion is in-place and the cell width comes from the parent <td>.
  maxWidthPx?: number
  mono?: boolean
  // Optional: when true, the cell starts in expanded state. Used by the
  // row-level "Expand all rows" toggle in InvestigateView so individual
  // cells do not need their own state to follow the row.
  forceExpanded?: boolean
}

export function ExpandableCell({ value, onPivot, mono = false, forceExpanded = false }: Props) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)

  if (value === '' || value === null || value === undefined) {
    return <span className="text-gray-300 dark:text-gray-600">—</span>
  }

  const detectedType = detectSeedType(value)
  const canPivot = !!onPivot && detectedType !== 'unknown' && detectedType !== 'user'
  const isExpanded = forceExpanded || expanded

  async function copyValue(e: React.MouseEvent) {
    e.stopPropagation()
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard API may be denied; silent fail keeps the cell usable */
    }
  }

  function pivot(e: React.MouseEvent) {
    e.stopPropagation()
    onPivot?.(value, detectedType)
  }

  if (!isExpanded) {
    // Collapsed: single line, truncated by parent <td>'s overflow rules.
    // The parent's `whitespace-nowrap` + `min-width` style does the truncation.
    return (
      <button
        type="button"
        onClick={() => setExpanded(true)}
        title={t('cell.clickToExpand')}
        className={`block w-full text-left truncate cursor-pointer hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded px-1 -mx-1 ${mono ? 'font-mono' : ''}`}
      >
        {value}
      </button>
    )
  }

  // Expanded: full value wraps, with action buttons inline below.
  return (
    <div className="rounded bg-blue-50/40 dark:bg-blue-900/10 px-1 -mx-1 py-1">
      <button
        type="button"
        onClick={() => setExpanded(false)}
        title={t('cell.clickToCollapse')}
        className={`block w-full text-left cursor-pointer break-all leading-snug ${mono ? 'font-mono' : ''}`}
      >
        {value}
      </button>
      <div className="flex items-center gap-1 mt-1">
        <button
          type="button"
          onClick={copyValue}
          className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-white dark:hover:bg-gray-800"
        >
          {copied ? <Check className="w-3 h-3 text-green-600" /> : <Copy className="w-3 h-3" />}
          {copied ? t('cell.copied') : t('cell.copy')}
        </button>
        {canPivot && (
          <button
            type="button"
            onClick={pivot}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded border border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-300 hover:bg-blue-50 dark:hover:bg-blue-900/20"
          >
            <Search className="w-3 h-3" />
            {t('cell.useAsSeed')}
          </button>
        )}
        {canPivot && (
          <span className="ml-auto text-[9px] text-gray-500 dark:text-gray-400">
            {seedTypeLabel(detectedType)}
          </span>
        )}
      </div>
    </div>
  )
}
