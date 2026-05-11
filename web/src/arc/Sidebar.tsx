import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import {
  FolderOpen,
  CloudDownload,
  BookOpen,
  Database,
  Key,
  Settings,
  LayoutDashboard,
  Brain,
  Shield,
  Sun,
  Moon,
} from 'lucide-react'

interface NavItem {
  id: string
  label: string
  icon: React.ReactNode
}

const insightsItems: NavItem[] = [
  { id: 'dashboard', label: 'Security Dashboard', icon: <LayoutDashboard className="w-4 h-4" /> },
  { id: 'pre-built-queries', label: 'Investigate', icon: <BookOpen className="w-4 h-4" /> },
]

const dataItems: NavItem[] = [
  { id: 'log-viewer', label: 'Log Viewer', icon: <FolderOpen className="w-4 h-4" /> },
  { id: 's3-sync', label: 'S3 Sync', icon: <CloudDownload className="w-4 h-4" /> },
]

const settingsItems: NavItem[] = [
  { id: 's3-config', label: 'S3 Config', icon: <Database className="w-4 h-4" /> },
  { id: 'credentials', label: 'Credentials', icon: <Key className="w-4 h-4" /> },
  { id: 'llm-config', label: 'AI Provider', icon: <Brain className="w-4 h-4" /> },
  { id: 'system', label: 'System', icon: <Settings className="w-4 h-4" /> },
]

interface SidebarProps {
  activeView: string
  onNavigate: (viewId: string) => void
}

export function Sidebar({ activeView, onNavigate }: SidebarProps) {
  const { t } = useTranslation()
  const [theme, setTheme] = useState<'light' | 'dark'>(
    () => (localStorage.getItem('theme') as 'light' | 'dark') || 'dark'
  )

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('theme', theme)
  }, [theme])

  return (
    <nav className="h-full flex flex-col bg-[#232f3e] text-gray-300">
      {/* Brand header */}
      <div className="px-4 py-4 border-b border-[#3b4a5a]">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-[#ff9900]" />
          <div>
            <h1 className="text-sm font-semibold text-white leading-tight">{t('app.nav.cloudtrail')}</h1>
            <p className="text-[10px] text-gray-400">{t('app.nav.securityInsights')}</p>
          </div>
        </div>
      </div>

      <div className="flex-1 py-2 overflow-y-auto">
        <NavGroup title="Security" items={insightsItems} activeId={activeView} onNavigate={onNavigate} />
        <NavGroup title="Data" items={dataItems} activeId={activeView} onNavigate={onNavigate} />
        <NavGroup title="Settings" items={settingsItems} activeId={activeView} onNavigate={onNavigate} />
      </div>

      {/* Theme toggle footer */}
      <div className="px-4 py-3 border-t border-[#3b4a5a]">
        <button
          onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
          className="flex items-center gap-2 text-[11px] text-gray-400 hover:text-white transition-colors"
        >
          {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
          <span>{theme === 'dark' ? t('app.nav.lightMode') : t('app.nav.darkMode')}</span>
        </button>
      </div>
    </nav>
  )
}

function NavGroup({ title, items, activeId, onNavigate }: { title: string, items: NavItem[], activeId: string, onNavigate: (id: string) => void }) {
  return (
    <div className="mb-1">
      <p className="px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">{title}</p>
      {items.map(item => {
        const isActive = activeId === item.id
        return (
          <button
            key={item.id}
            onClick={() => onNavigate(item.id)}
            className={`w-full flex items-center gap-2.5 px-4 py-2 text-[13px] transition-colors ${
              isActive
                ? 'bg-[#1a242f] text-white border-l-2 border-l-[#ff9900]'
                : 'text-gray-400 hover:text-white hover:bg-[#2a3a4a] border-l-2 border-l-transparent'
            }`}
          >
            {item.icon}
            <span>{item.label}</span>
          </button>
        )
      })}
    </div>
  )
}
