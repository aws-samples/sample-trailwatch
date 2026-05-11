type BadgeStatus =
  | 'ok'
  | 'error'
  | 'unconfigured'
  | 'pending'
  | 'downloading'
  | 'extracting'
  | 'verifying'
  | 'query-ready'
  | 'partially-verified'
  | 'failed'
  | 'interrupted'
  | 'deleted'

interface StatusBadgeProps {
  status: BadgeStatus
  label?: string
}

const statusColors: Record<BadgeStatus, string> = {
  ok: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  'query-ready': 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  'partially-verified': 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  error: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  deleted: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
  pending: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
  unconfigured: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
  downloading: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  extracting: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  verifying: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  interrupted: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
}

export function StatusBadge({ status, label }: StatusBadgeProps) {
  const colorClasses = statusColors[status]
  const displayLabel = label ?? status

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 text-xs font-medium rounded ${colorClasses}`}
    >
      {displayLabel}
    </span>
  )
}

export type { StatusBadgeProps, BadgeStatus }
