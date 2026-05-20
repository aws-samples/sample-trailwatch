import { useState, useCallback, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Menu } from 'lucide-react'
import { Sidebar } from './Sidebar'
import { SessionSpendChip } from '../comm/SessionSpendChip'

const SIDEBAR_COLLAPSED_KEY = 'cloudtrail-analyzer-sidebar-collapsed'

export interface NavigationContext {
  promptId?: string
  scenarioId?: string
}

interface LayoutProps {
  children: (activeView: string, navContext: NavigationContext, navigate: (viewId: string, ctx?: NavigationContext) => void) => React.ReactNode
}

const VIEW_TITLES: Record<string, string> = {
  'dashboard': 'Security Dashboard',
  'pre-built-queries': 'Investigate',
  's3-sync': 'S3 Sync',
  's3-config': 'S3 Configuration',
  'credentials': 'AWS Credentials',
  'llm-config': 'AI Provider',
  'system': 'System Status',
}

const ACTIVE_VIEW_KEY = 'cloudtrail-analyzer-active-view'
const DEFAULT_VIEW = 'dashboard'

// readInitialView returns a known view id, falling back to dashboard. Guards
// against stale localStorage values from removed views (e.g., the old Log
// Viewer) which would otherwise render an empty fallback page.
function readInitialView(): string {
  const stored = localStorage.getItem(ACTIVE_VIEW_KEY)
  if (stored && stored in VIEW_TITLES) return stored
  return DEFAULT_VIEW
}

export function Layout({ children }: LayoutProps) {
  const { t } = useTranslation()
  const [activeView, setActiveView] = useState<string>(readInitialView)
  const [navContext, setNavContext] = useState<NavigationContext>({})
  const [account, setAccount] = useState<string>('')
  const [region, setRegion] = useState<string>('')
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    return localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === '1'
  })
  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed(prev => {
      const next = !prev
      localStorage.setItem(SIDEBAR_COLLAPSED_KEY, next ? '1' : '0')
      return next
    })
  }, [])

  useEffect(() => {
    fetch('/api/settings')
      .then(r => r.json())
      .then(d => {
        setAccount(d?.s3?.account_id || '')
        setRegion(d?.s3?.log_region || d?.s3?.region || '')
      })
      .catch(() => {})
  }, [])

  const handleNavigate = useCallback((viewId: string, ctx?: NavigationContext) => {
    setActiveView(viewId)
    setNavContext(ctx || {})
    localStorage.setItem(ACTIVE_VIEW_KEY, viewId)
  }, [])

  return (
    <div className="h-screen flex flex-col bg-[#f2f3f3] dark:bg-[#0f1b2d]">
      {/* AWS-style top navigation bar */}
      <header className="h-10 flex items-center px-4 bg-[#232f3e] dark:bg-[#1a242f] border-b border-[#3b4a5a] flex-shrink-0 z-20">
        <button
          type="button"
          onClick={toggleSidebar}
          aria-label={sidebarCollapsed ? t('app.nav.expandSidebar') : t('app.nav.collapseSidebar')}
          title={sidebarCollapsed ? t('app.nav.expandSidebar') : t('app.nav.collapseSidebar')}
          className="mr-3 p-1 rounded text-gray-300 hover:text-white hover:bg-white/10"
        >
          <Menu className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-3 flex-1">
          <span className="text-[13px] font-medium text-white">{t('app.nav.cloudtrail')} {t('app.nav.securityInsights')}</span>
          <span className="text-[11px] text-gray-400">|</span>
          <span className="text-[11px] text-gray-400">{VIEW_TITLES[activeView] || activeView}</span>
        </div>
        <div className="flex items-center gap-4">
          <SessionSpendChip />
          {account && (
            <span className="text-[11px] text-gray-400">
              {t('app.nav.account')} <span className="text-gray-200 font-mono">{account}</span>
            </span>
          )}
          {region && (
            <span className="text-[11px] text-gray-400">{t('app.nav.region')} <span className="text-gray-200">{region}</span></span>
          )}
        </div>
      </header>

      <div className="flex flex-1 min-h-0">
        {/* Sidebar */}
        {!sidebarCollapsed && (
          <div className="w-52 flex-shrink-0">
            <Sidebar activeView={activeView} onNavigate={(id) => handleNavigate(id)} />
          </div>
        )}
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
