import { useTranslation } from 'react-i18next'

export function NLQueryView() {
  const { t } = useTranslation()
  return (
    <div className="flex items-center justify-center h-full">
      <div className="text-center p-8 rounded-lg border border-dashed border-gray-300 dark:border-gray-600">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">{t('security.query.nlQuery')}</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">{t('security.query.nlSubtitle')}</p>
        <span className="inline-block mt-3 px-2 py-1 text-xs bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300 rounded">{t('security.query.comingSoon')}</span>
      </div>
    </div>
  )
}
