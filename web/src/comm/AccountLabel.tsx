// AccountLabel renders an AWS account ID with its friendly name (when one is
// known) using the shared useAccountNames cache. Intended for use in tables
// and result rows where a 12-digit account ID alone is hard to read.
//
// Layout: ID is the primary text (font-mono, full color), name is appended
// in parentheses with a muted color so the eye locks onto whichever shape it
// recognizes. Falls back to the bare ID when no name is set.
import { useAccountNames } from './accountNames'

interface Props {
  accountId: string | null | undefined
  // When true, hide the ID and show only the name (falling back to ID if no
  // name is known). Useful in tight contexts where space is at a premium.
  compact?: boolean
  className?: string
}

export function AccountLabel({ accountId, compact = false, className = '' }: Props) {
  const lookup = useAccountNames(accountId ? [accountId] : [])
  if (!accountId) return <span className={className}>—</span>
  const name = lookup(accountId)
  if (compact && name) {
    return (
      <span className={className} title={accountId}>
        {name}
      </span>
    )
  }
  return (
    <span className={className}>
      <span className="font-mono">{accountId}</span>
      {name && <span className="text-gray-500 dark:text-gray-400 ml-1">({name})</span>}
    </span>
  )
}
