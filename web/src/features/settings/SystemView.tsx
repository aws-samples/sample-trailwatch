import { useTranslation } from 'react-i18next'
import { useHealth } from './hooks'
import { StatusBadge } from '../../comm/StatusBadge'

export function SystemView() {
  const { t } = useTranslation()
  const { data: health, loading, error, refetch } = useHealth()

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-sm text-gray-600 dark:text-gray-300">{t('settings.system.loading')}</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6 max-w-2xl mx-auto space-y-4">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">{t('settings.system.title')}</h2>
        <div className="p-3 rounded-md text-sm bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300">
          {t('settings.system.loadFailed')} {error}
        </div>
        <button
          onClick={refetch}
          className="px-4 py-2 text-sm font-medium rounded-md bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
        >
          {t('settings.system.retry')}
        </button>
      </div>
    )
  }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-6 overflow-y-auto h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">{t('settings.system.title')}</h2>
        <button
          onClick={refetch}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
        >
          {t('settings.system.refresh')}
        </button>
      </div>

      {health && (
        <>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="px-3 py-2 rounded bg-gray-50 dark:bg-gray-800">
              <span className="text-gray-600 dark:text-gray-300">{t('settings.system.version')}</span>
              <p className="font-medium text-gray-900 dark:text-white">{health.version || 'unknown'}</p>
            </div>
            <div className="px-3 py-2 rounded bg-gray-50 dark:bg-gray-800">
              <span className="text-gray-600 dark:text-gray-300">{t('settings.system.uptime')}</span>
              <p className="font-medium text-gray-900 dark:text-white">{health.uptime || 'unknown'}</p>
            </div>
          </div>

          <div className="space-y-3">
            <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300">{t('settings.system.startupValidation')}</h3>
            <ul className="space-y-2">
              {health.checks && health.checks.length > 0 ? (
                health.checks.map((check) => (
                  <li key={check.name} className="flex items-center justify-between px-3 py-2.5 rounded bg-gray-50 dark:bg-gray-800">
                    <div>
                      <span className="text-sm font-medium text-gray-900 dark:text-white">{check.name}</span>
                      <p className="text-xs text-gray-600 dark:text-gray-300 mt-0.5">{check.message}</p>
                    </div>
                    <StatusBadge status={check.status} />
                  </li>
                ))
              ) : (
                <li className="text-sm text-gray-600 dark:text-gray-300 px-3 py-2">
                  {t('settings.system.noChecks')}
                </li>
              )}
            </ul>
          </div>
        </>
      )}
    </div>
  )
}
