import { useState, useCallback, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Sidebar } from './Sidebar'

export interface NavigationContext {
  promptId?: string
}

interface LayoutProps {
  children: (activeView: string, navContext: NavigationContext, navigate: (viewId: string, ctx?: NavigationContext) => void) => React.ReactNode
}

const VIEW_TITLES: Record<string, string> = {
  'dashboard': 'Security Dashboard',
  'pre-built-queries': 'Investigate',
  'log-viewer': 'Log Viewer',
  's3-sync': 'S3 Sync',
  's3-config': 'S3 Configuration',
  'credentials': 'AWS Credentials',
  'llm-config': 'AI Provider',
  'system': 'System Status',
}

export function Layout({ children }: LayoutProps) {
  const { t } = useTranslation()
  const [activeView, setActiveView] = useState<string>(
    () => localStorage.getItem('cloudtrail-analyzer-active-view') || 'dashboard'
  )
  const [navContext, setNavContext] = useState<NavigationContext>({})
  const [account, setAccount] = useState<string>('')

  useEffect(() => {
    fetch('/api/settings')
      .then(r => r.json())
      .then(d => setAccount(d?.s3?.account_id || ''))
      .catch(() => {})
  }, [])

  const handleNavigate = useCallback((viewId: string, ctx?: NavigationContext) => {
    setActiveView(viewId)
    setNavContext(ctx || {})
    localStorage.setItem('cloudtrail-analyzer-active-view', viewId)
  }, [])

  return (
    <div className="h-screen flex flex-col bg-[#f2f3f3] dark:bg-[#0f1b2d]">
      {/* AWS-style top navigation bar */}
      <header className="h-10 flex items-center px-4 bg-[#232f3e] dark:bg-[#1a242f] border-b border-[#3b4a5a] flex-shrink-0 z-20">
        <div className="flex items-center gap-3 flex-1">
          <span className="text-[13px] font-medium text-white">{t('app.nav.cloudtrail')} {t('app.nav.securityInsights')}</span>
          <span className="text-[11px] text-gray-400">|</span>
          <span className="text-[11px] text-gray-400">{VIEW_TITLES[activeView] || activeView}</span>
        </div>
        <div className="flex items-center gap-4">
          {account && (
            <span className="text-[11px] text-gray-400">
              {t('app.nav.account')} <span className="text-gray-200 font-mono">{account}</span>
            </span>
          )}
          <span className="text-[11px] text-gray-400">{t('app.nav.region')} <span className="text-gray-200">us-east-1</span></span>
        </div>
      </header>

      <div className="flex flex-1 min-h-0">
        {/* Sidebar */}
        <div className="w-52 flex-shrink-0">
          <Sidebar activeView={activeView} onNavigate={(id) => handleNavigate(id)} />
        </div>
        {/* Main content */}
        <div className="flex-1 min-w-0 overflow-hidden">
          <div className="h-full overflow-auto">
            {children(activeView, navContext, handleNavigate)}
          </div>
        </div>
      </div>
    </div>
  )
}
