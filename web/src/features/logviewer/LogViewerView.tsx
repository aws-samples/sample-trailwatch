import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { FolderOpen, File, Loader2, RefreshCw, Copy, CheckCircle2 } from 'lucide-react'
import { endpoints } from '../../config/api'

interface FileNode {
  name: string
  path: string
  is_dir: boolean
  size: number
  children?: FileNode[]
}

export function LogViewerView() {
  const { t } = useTranslation()
  const [tree, setTree] = useState<FileNode[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const fetchTree = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${endpoints.logviewerSessions}`)
      if (!res.ok) {
        const data = await res.json().catch(() => ({ message: 'Failed to load' }))
        throw new Error(data.message || `HTTP ${res.status}`)
      }
      const data = await res.json()
      setTree(data)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchTree() }, [])

  const handleCopy = () => {
    if (selectedPath) {
      navigator.clipboard.writeText(selectedPath)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  if (loading) {
    return <div className="flex items-center justify-center h-full"><Loader2 className="w-5 h-5 animate-spin text-gray-400" /></div>
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3">
          <FolderOpen className="w-5 h-5 text-blue-600 dark:text-blue-400" />
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{t('data.logviewer.title')}</h2>
            <p className="text-xs text-gray-500 dark:text-gray-400">{t('data.logviewer.subtitle')}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {selectedPath && (
            <button type="button" onClick={handleCopy}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
              {copied ? <CheckCircle2 className="w-3 h-3 text-green-500" /> : <Copy className="w-3 h-3" />}
              {copied ? 'Copied' : 'Copy Path'}
            </button>
          )}
          <button type="button" onClick={fetchTree}
            className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* Selected path display */}
      {selectedPath && (
        <div className="px-6 py-2 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
          <code className="text-xs text-gray-700 dark:text-gray-300 break-all">{selectedPath}</code>
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {error && (
          <div className="p-3 rounded-lg border bg-red-50 dark:bg-red-900/10 border-red-200 dark:border-red-900/30">
            <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
          </div>
        )}

        {!error && (!tree || tree.length === 0) && (
          <div className="flex items-center justify-center h-full">
            <div className="text-center p-8">
              <FolderOpen className="w-10 h-10 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
              <h3 className="text-base font-medium text-gray-900 dark:text-white mb-1">{t('data.logviewer.noLogs')}</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">{t('data.logviewer.goToSync')}</p>
            </div>
          </div>
        )}

        {tree && tree.length > 0 && (
          <div className="font-mono text-sm">
            {tree.map((node) => (
              <TreeNode key={node.path} node={node} depth={0} selectedPath={selectedPath} onSelect={setSelectedPath} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function TreeNode({ node, depth, selectedPath, onSelect }: { node: FileNode; depth: number; selectedPath: string | null; onSelect: (path: string) => void }) {
  // eslint-disable-next-line react-props-in-state -- depth is intentionally used as initial value only; user toggles expanded state
  const [expanded, setExpanded] = useState(() => depth < 2) // nosemgrep: react-props-in-state
  const indent = depth * 16

  const isSelected = selectedPath === node.path

  if (node.is_dir) {
    return (
      <div>
        <div
          className={`flex items-center gap-1 py-0.5 px-2 rounded cursor-pointer transition-colors ${isSelected ? 'bg-blue-50 dark:bg-blue-900/20' : 'hover:bg-gray-100 dark:hover:bg-gray-800'}`}
          style={{ paddingLeft: `${indent + 8}px` }}
          onClick={() => { setExpanded(!expanded); onSelect(node.path) }}
        >
          <span className="text-gray-400 text-xs w-4">{expanded ? '▼' : '▶'}</span>
          <FolderOpen className="w-4 h-4 text-amber-500 flex-shrink-0" />
          <span className="text-gray-900 dark:text-white truncate">{node.name}/</span>
        </div>
        {expanded && node.children && node.children.map((child) => (
          <TreeNode key={child.path} node={child} depth={depth + 1} selectedPath={selectedPath} onSelect={onSelect} />
        ))}
      </div>
    )
  }

  return (
    <div
      className={`flex items-center gap-1 py-0.5 px-2 rounded cursor-pointer transition-colors ${isSelected ? 'bg-blue-50 dark:bg-blue-900/20' : 'hover:bg-gray-100 dark:hover:bg-gray-800'}`}
      style={{ paddingLeft: `${indent + 8}px` }}
      onClick={() => onSelect(node.path)}
    >
      <span className="w-4" />
      <File className="w-4 h-4 text-gray-400 flex-shrink-0" />
      <span className="text-gray-700 dark:text-gray-300 truncate">{node.name}</span>
      {node.size > 0 && <span className="text-xs text-gray-400 ml-auto">{formatSize(node.size)}</span>}
    </div>
  )
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)}K`
  return `${(bytes / (1024 * 1024)).toFixed(1)}M`
}
