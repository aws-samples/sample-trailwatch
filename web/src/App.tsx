import { useTranslation } from 'react-i18next'
import { Layout } from './arc/Layout'
import { LogViewerView } from './features/logviewer/LogViewerView'
import { S3SyncView } from './features/logviewer/S3SyncView'
import { DashboardView } from './features/dashboard/DashboardView'
import { InvestigateView } from './features/query/InvestigateView'
import { S3ConfigView } from './features/settings/S3ConfigView'
import { CredentialsView } from './features/settings/CredentialsView'
import { LLMConfigView } from './features/settings/LLMConfigView'
import { SystemView } from './features/settings/SystemView'

function App() {
  const { t } = useTranslation()
  return (
    <Layout>
      {(activeView, _navContext, navigate) => {
        switch (activeView) {
          case 'dashboard':
            return <DashboardView navigate={navigate} />
          case 'pre-built-queries':
            return <InvestigateView />
          case 'log-viewer':
            return <LogViewerView />
          case 's3-sync':
            return <S3SyncView />
          case 's3-config':
            return <S3ConfigView />
          case 'credentials':
            return <CredentialsView />
          case 'llm-config':
            return <LLMConfigView />
          case 'system':
            return <SystemView />
          default:
            return (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                    {t('app.general.title')}
                  </h1>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {t('app.general.selectView')}
                  </p>
                </div>
              </div>
            )
        }
      }}
    </Layout>
  )
}

export default App
