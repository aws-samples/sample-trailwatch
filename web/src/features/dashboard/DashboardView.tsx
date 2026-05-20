import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import {
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area, Legend
} from 'recharts'
import { RefreshCw, ExternalLink, ShieldAlert, AlertTriangle, Info, Loader2 } from 'lucide-react'
import { endpoints } from '../../config/api'
import { readApiError } from '../../comm/apiError'
import { AccountLabel } from '../../comm/AccountLabel'
import { ExpandableCell } from '../../comm/ExpandableCell'
import { exportRowsAsCSV, exportRowsAsJSON } from '../query/tableExport'
import type { NavigationContext } from '../../arc/Layout'

interface QueryPanel {
  columns: string[] | null
  rows: (string | number | null)[][] | null
  error?: string
}

interface DashboardData {
  summary: QueryPanel
  top_api_calls: QueryPanel
  identity_types: QueryPanel
  hourly_volume: QueryPanel
  top_source_ips: QueryPanel
  top_errors: QueryPanel
  top_services: QueryPanel
}

interface FindingSummary {
  id: string
  columns: string[] | null
  rows: (string | number | null)[][] | null
  error?: string
}

interface FindingDetail {
  id: string
  sql: string
  columns: string[] | null
  rows: (string | number | null)[][] | null
  error?: string
}

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

interface FindingDef {
  id: string
  title: string
  description: string
  severity: Severity
  category: string
  promptId: string
  // scenarioId, if set, points at a real /api/investigate/scenarios id and
  // enables the "Open in Query view" link with deep-linking. Findings without
  // a clean Investigate counterpart leave this unset and hide the link.
  scenarioId?: string
}

const SEVERITY_STYLES: Record<Severity, { bg: string, border: string, text: string, badge: string, icon: any }> = {
  CRITICAL: { bg: 'bg-red-50 dark:bg-red-950/30', border: 'border-l-red-600', text: 'text-red-700 dark:text-red-300', badge: 'bg-red-600 text-white', icon: ShieldAlert },
  HIGH: { bg: 'bg-orange-50 dark:bg-orange-950/20', border: 'border-l-orange-500', text: 'text-orange-700 dark:text-orange-300', badge: 'bg-orange-500 text-white', icon: AlertTriangle },
  MEDIUM: { bg: 'bg-yellow-50 dark:bg-yellow-950/20', border: 'border-l-yellow-500', text: 'text-yellow-700 dark:text-yellow-300', badge: 'bg-yellow-500 text-white', icon: AlertTriangle },
  LOW: { bg: 'bg-blue-50 dark:bg-blue-950/20', border: 'border-l-blue-500', text: 'text-blue-700 dark:text-blue-300', badge: 'bg-blue-500 text-white', icon: Info },
}

const COLORS = ['#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#ec4899', '#6366f1']

const FINDINGS: FindingDef[] = [
  { id: 'root-account-usage', title: 'Root Account Usage', description: 'API calls by AWS root account', severity: 'CRITICAL', category: 'Malicious Activity', promptId: 'root-account-usage', scenarioId: 'gd-root-usage' },
  { id: 'cloudtrail-changes', title: 'CloudTrail Tampering', description: 'StopLogging, DeleteTrail, audit config changes', severity: 'CRITICAL', category: 'Operational Changes', promptId: 'cloudtrail-changes', scenarioId: 'gd-logging-disabled' },
  { id: 'unauthorized-api-calls', title: 'Unauthorized API Calls', description: 'AccessDenied / UnauthorizedOperation errors', severity: 'HIGH', category: 'Malicious Activity', promptId: 'unauthorized-api-calls', scenarioId: 'access-denied-all' },
  { id: 'failed-console-logins', title: 'Failed Console Logins', description: 'Failed sign-in attempts with source IPs', severity: 'HIGH', category: 'Access Key Discovery', promptId: 'failed-console-logins', scenarioId: 'console-logins-failed' },
  { id: 'iam-policy-changes', title: 'IAM Policy Changes', description: 'Policy attachments and permission modifications', severity: 'HIGH', category: 'Privilege Escalation', promptId: 'iam-policy-changes', scenarioId: 'iam-write-ops' },
  { id: 'suspicious-cross-account', title: 'Cross-Account Activity', description: 'API calls from foreign account principals', severity: 'HIGH', category: 'Malicious Activity', promptId: 'suspicious-cross-account', scenarioId: 'cross-account-all' },
  { id: 'container-serverless-data-exfil', title: 'Data Exfiltration Signals', description: 'GetObject, GetSecretValue, CopySnapshot from compute roles', severity: 'HIGH', category: 'Container & Serverless', promptId: 'container-serverless-data-exfil' },
  { id: 'permission-boundary-changes', title: 'Permission Boundary Changes', description: 'Boundary removal enables privilege escalation', severity: 'HIGH', category: 'Privilege Escalation', promptId: 'permission-boundary-changes' },
  { id: 'security-group-changes', title: 'Security Group Changes', description: 'Ingress/egress rule modifications', severity: 'MEDIUM', category: 'Network Security', promptId: 'security-group-changes' },
  { id: 'role-assumption-patterns', title: 'Role Assumptions', description: 'AssumeRole calls and role chaining', severity: 'MEDIUM', category: 'Privilege Escalation', promptId: 'role-assumption-patterns', scenarioId: 'cross-account-role-assumptions' },
  { id: 'access-key-creation', title: 'Access Key Lifecycle', description: 'Key creation and deletion events', severity: 'MEDIUM', category: 'Access Key Discovery', promptId: 'access-key-creation', scenarioId: 'gd-access-key-created-persistence' },
  { id: 'ec2-instance-sensitive-calls', title: 'EC2 Sensitive Calls', description: 'Instances calling IAM, STS, KMS, SecretsManager', severity: 'MEDIUM', category: 'EC2 Instance Activity', promptId: 'ec2-instance-sensitive-calls' },
  { id: 'uba-activity-by-hour', title: 'Off-Hours Activity', description: 'Human user activity 00:00–06:00 UTC', severity: 'MEDIUM', category: 'User Behavior Analytics', promptId: 'uba-activity-by-hour' },
  { id: 'uba-high-error-rate', title: 'High Error Rate Users', description: 'Identities with >20% failure rate', severity: 'MEDIUM', category: 'User Behavior Analytics', promptId: 'uba-high-error-rate' },
  { id: 'lambda-sensitive-operations', title: 'Lambda Sensitive Ops', description: 'Lambda calling IAM, KMS, SecretsManager', severity: 'MEDIUM', category: 'Container & Serverless', promptId: 'lambda-sensitive-operations' },
  { id: 'uba-human-user-write-ops', title: 'Human Write Operations', description: 'All mutating actions by human users', severity: 'LOW', category: 'User Behavior Analytics', promptId: 'uba-human-user-write-ops' },
  { id: 'vpc-changes', title: 'VPC Infrastructure Changes', description: 'VPC, subnet, IGW, peering changes', severity: 'LOW', category: 'Network Security', promptId: 'vpc-changes' },
  { id: 'resource-creation-deletion', title: 'Resource Lifecycle', description: 'EC2, RDS, Lambda, S3 creation/deletion', severity: 'LOW', category: 'Operational Changes', promptId: 'resource-creation-deletion', scenarioId: 'gd-destructive-actions' },
]

interface DashboardViewProps {
  navigate: (viewId: string, ctx?: NavigationContext) => void
}

export function DashboardView({ navigate }: DashboardViewProps) {
  const { t } = useTranslation()
  const [data, setData] = useState<DashboardData | null>(null)
  const [findingSummaries, setFindingSummaries] = useState<Record<string, FindingSummary>>({})
  const [loading, setLoading] = useState(true)
  const [findingsLoading, setFindingsLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'ALL'>('ALL')
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)
  const [findingDetail, setFindingDetail] = useState<FindingDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  async function fetchDashboard() {
    try {
      setLoading(true)
      setError('')
      // Check if index exists, trigger build if not
      const statusRes = await fetch(endpoints.indexStatus).catch(() => null)
      if (statusRes?.ok) {
        const status = await statusRes.json()
        if (!status.indexed) {
          fetch(endpoints.indexBuild, { method: 'POST' }).catch(() => {})
        }
      }
      const res = await fetch(endpoints.dashboard)
      if (!res.ok) {
        throw new Error(await readApiError(res, 'Failed to load dashboard'))
      }
      setData(await res.json())
    } catch (e: any) {
      setError(e?.message || 'Failed to load dashboard')
    } finally {
      setLoading(false)
    }
  }

  async function fetchFindings() {
    try {
      setFindingsLoading(true)
      const res = await fetch(endpoints.dashboardFindings)
      if (!res.ok) {
        console.warn('dashboard findings request failed', res.status, await readApiError(res, 'findings'))
        return
      }
      const results: FindingSummary[] = await res.json()
      const map: Record<string, FindingSummary> = {}
      results.forEach(r => { map[r.id] = r })
      setFindingSummaries(map)
    } catch (e) {
      console.warn('dashboard findings fetch error', e)
    } finally {
      setFindingsLoading(false)
    }
  }

  async function fetchDetail(id: string) {
    setDetailLoading(true)
    setFindingDetail(null)
    try {
      const res = await fetch(endpoints.dashboardFindingDetail(id))
      if (!res.ok) {
        const msg = await readApiError(res, 'Failed to load finding detail')
        setFindingDetail({ error: msg } as FindingDetail)
        return
      }
      setFindingDetail(await res.json())
    } catch (e: any) {
      setFindingDetail({ error: e?.message || 'Failed to load finding detail' } as FindingDetail)
    } finally {
      setDetailLoading(false)
    }
  }

  useEffect(() => { fetchDashboard(); fetchFindings() }, [])

  function handleFindingClick(finding: FindingDef) {
    if (expandedFinding === finding.id) {
      setExpandedFinding(null)
      setFindingDetail(null)
    } else {
      setExpandedFinding(finding.id)
      fetchDetail(finding.id)
    }
  }

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 animate-spin text-blue-500 mx-auto mb-3" />
          <p className="text-sm text-gray-600 dark:text-gray-400">{t('security.dashboard.analyzing')}</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-3" />
          <p className="text-sm text-red-600 mb-2">{error}</p>
          <button onClick={() => { fetchDashboard(); fetchFindings() }} className="text-xs text-blue-600 hover:underline">{t('security.dashboard.retry')}</button>
        </div>
      </div>
    )
  }

  if (!data) return <div />

  const summary = data.summary?.rows?.[0]
  const totalEvents = summary ? Number(summary[0]) : 0
  const uniqueIdentities = summary ? Number(summary[1]) : 0
  const uniqueIPs = summary ? Number(summary[2]) : 0
  const errorEvents = summary ? Number(summary[3]) : 0
  const errorRate = summary ? Number(summary[4]) : 0
  const uniqueServices = summary ? Number(summary[5]) : 0
  const earliestEvent = summary ? String(summary[6]).slice(0, 16) : ''
  const latestEvent = summary ? String(summary[7]).slice(0, 16) : ''

  const identityData = (data.identity_types?.rows || []).map(r => ({ name: String(r[0]), value: Number(r[1]) }))
  const hourlyData = (data.hourly_volume?.rows || []).map(r => ({ hour: `${String(r[0]).padStart(2, '0')}:00`, total: Number(r[1]), errors: Number(r[2]), writes: Number(r[3]) }))

  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  FINDINGS.forEach(f => severityCounts[f.severity]++)

  const filteredFindings = selectedSeverity === 'ALL' ? FINDINGS : FINDINGS.filter(f => f.severity === selectedSeverity)

  function getFindingCount(id: string): string {
    const s = findingSummaries[id]
    if (!s?.rows?.length) return findingsLoading ? '...' : '0'
    const row = (s.rows as any[])[0]
    if (!row || !row[0]) return '0'
    return String(row[0])
  }

  function getFindingExtra(id: string): string {
    try {
      const s = findingSummaries[id]
      if (!s) return ''
      const rows = s.rows as any[][] | null
      const cols = s.columns as string[] | null
      if (!rows || rows.length === 0 || !cols || cols.length < 2) return ''
      const val = rows[0]?.[1]
      if (!val) return ''
      return `${val} ${cols[1]!.replace(/_/g, ' ')}`
    } catch { return '' }
  }

  return (
    <div className="h-full overflow-y-auto bg-gray-50 dark:bg-gray-950">
      {/* Header */}
      <div className="sticky top-0 z-20 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 px-6 py-3 shadow-sm">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-base font-semibold text-gray-900 dark:text-white">{t('security.dashboard.title')}</h1>
            <p className="text-[11px] text-gray-500 dark:text-gray-400">
              {t('security.dashboard.accountInfo', { earliest: earliestEvent, latest: latestEvent, count: totalEvents.toLocaleString() })}
            </p>
          </div>
          <button onClick={() => { fetchDashboard(); fetchFindings() }} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800">
            <RefreshCw className="w-3.5 h-3.5" /> {t('security.dashboard.refresh')}
          </button>
        </div>
      </div>

      <div className="px-6 py-4 space-y-5">
        {/* Summary metrics */}
        <div className="grid grid-cols-3 lg:grid-cols-6 gap-2">
          <Metric label="Events" value={totalEvents.toLocaleString()} />
          <Metric label="Identities" value={String(uniqueIdentities)} />
          <Metric label="Source IPs" value={String(uniqueIPs)} />
          <Metric label="Errors" value={errorEvents.toLocaleString()} color={errorEvents > 0 ? 'text-red-600' : ''} />
          <Metric label="Error Rate" value={`${errorRate}%`} color={errorRate > 5 ? 'text-red-600' : ''} />
          <Metric label="Services" value={String(uniqueServices)} />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          <div className="lg:col-span-2 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
            <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">{t('security.dashboard.hourlyActivity')}</h3>
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={hourlyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" opacity={0.4} />
                <XAxis dataKey="hour" tick={{ fontSize: 9 }} stroke="#9ca3af" />
                <YAxis tick={{ fontSize: 9 }} stroke="#9ca3af" />
                <Tooltip contentStyle={{ fontSize: '10px', borderRadius: '6px' }} />
                <Legend wrapperStyle={{ fontSize: '9px' }} />
                <Area type="monotone" dataKey="total" name="Total" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.08} strokeWidth={1.5} />
                <Area type="monotone" dataKey="errors" name="Errors" stroke="#ef4444" fill="#ef4444" fillOpacity={0.05} strokeWidth={1.5} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
            <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">{t('security.dashboard.identityTypes')}</h3>
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie data={identityData} cx="50%" cy="50%" outerRadius={55} innerRadius={30} dataKey="value" label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`} labelLine={false}>
                  {identityData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ fontSize: '10px', borderRadius: '6px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity filter */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-medium text-gray-500 mr-1">{t('security.dashboard.filter')}</span>
          <FilterPill label="All" count={FINDINGS.length} active={selectedSeverity === 'ALL'} onClick={() => setSelectedSeverity('ALL')} />
          <FilterPill label="Critical" count={severityCounts.CRITICAL} active={selectedSeverity === 'CRITICAL'} onClick={() => setSelectedSeverity('CRITICAL')} color="text-red-700 bg-red-100 dark:bg-red-900/30 dark:text-red-300" />
          <FilterPill label="High" count={severityCounts.HIGH} active={selectedSeverity === 'HIGH'} onClick={() => setSelectedSeverity('HIGH')} color="text-orange-700 bg-orange-100 dark:bg-orange-900/30 dark:text-orange-300" />
          <FilterPill label="Medium" count={severityCounts.MEDIUM} active={selectedSeverity === 'MEDIUM'} onClick={() => setSelectedSeverity('MEDIUM')} color="text-yellow-700 bg-yellow-100 dark:bg-yellow-900/30 dark:text-yellow-300" />
          <FilterPill label="Low" count={severityCounts.LOW} active={selectedSeverity === 'LOW'} onClick={() => setSelectedSeverity('LOW')} color="text-blue-700 bg-blue-100 dark:bg-blue-900/30 dark:text-blue-300" />
        </div>

        {/* Findings list */}
        <div className="space-y-1">
          {filteredFindings.map(finding => {
            const style = SEVERITY_STYLES[finding.severity]
            const Icon = style.icon
            const count = getFindingCount(finding.id)
            const extra = getFindingExtra(finding.id)
            const isExpanded = expandedFinding === finding.id
            const hasEvents = count !== '0' && count !== '...'

            return (
              <div key={finding.id} className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden bg-white dark:bg-gray-900">
                <div
                  onClick={() => handleFindingClick(finding)}
                  className={`flex items-center gap-3 px-4 py-3 cursor-pointer transition-colors hover:bg-gray-50 dark:hover:bg-gray-800/50 border-l-4 ${style.border}`}
                >
                  <Icon className={`w-4 h-4 flex-shrink-0 ${style.text}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white">{finding.title}</h4>
                      <span className={`px-1.5 py-0.5 text-[9px] font-bold uppercase rounded ${style.badge}`}>{finding.severity}</span>
                      <span className="text-[10px] text-gray-400 bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">{finding.category}</span>
                    </div>
                    <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">{finding.description}</p>
                  </div>
                  {/* Live count */}
                  <div className="flex items-center gap-3 flex-shrink-0">
                    <div className="text-right">
                      <span className={`text-lg font-bold ${hasEvents ? 'text-gray-900 dark:text-white' : 'text-gray-300 dark:text-gray-600'}`}>
                        {count}
                      </span>
                      {extra && <p className="text-[10px] text-gray-500">{extra}</p>}
                    </div>
                    <ExternalLink className={`w-4 h-4 ${isExpanded ? 'text-blue-500' : 'text-gray-400'}`} />
                  </div>
                </div>

                {/* Expanded detail panel */}
                {isExpanded && (
                  <div className="border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 px-4 py-3">
                    {detailLoading ? (
                      <div className="flex items-center gap-2 py-4 justify-center">
                        <Loader2 className="w-4 h-4 animate-spin text-blue-500" />
                        <span className="text-xs text-gray-500">{t('security.dashboard.runningQuery')}</span>
                      </div>
                    ) : findingDetail?.error ? (
                      <div className="text-xs text-red-600 py-2">{findingDetail.error}</div>
                    ) : findingDetail?.columns && findingDetail.columns.length > 0 ? (
                      <>
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-[11px] text-gray-500">{t('security.dashboard.results', { count: findingDetail.rows?.length || 0 })}</span>
                          <div className="flex items-center gap-3">
                            {(findingDetail.rows?.length || 0) > 0 && (
                              <>
                                <button
                                  type="button"
                                  onClick={(e) => { e.stopPropagation(); exportRowsAsCSV(findingDetail.columns!, findingDetail.rows || [], `finding-${finding.id}`) }}
                                  className="text-[11px] text-gray-600 dark:text-gray-300 hover:underline"
                                >
                                  {t('table.exportCsv')}
                                </button>
                                <button
                                  type="button"
                                  onClick={(e) => { e.stopPropagation(); exportRowsAsJSON(findingDetail.columns!, findingDetail.rows || [], `finding-${finding.id}`) }}
                                  className="text-[11px] text-gray-600 dark:text-gray-300 hover:underline"
                                >
                                  {t('table.exportJson')}
                                </button>
                              </>
                            )}
                            {finding.scenarioId && (
                              <button
                                onClick={(e) => { e.stopPropagation(); navigate('pre-built-queries', { scenarioId: finding.scenarioId }) }}
                                className="text-[11px] text-blue-600 hover:underline font-medium"
                              >
                                {t('security.dashboard.openInQueryView')}
                              </button>
                            )}
                          </div>
                        </div>
                        <div className="overflow-auto max-h-60 border border-gray-200 dark:border-gray-700 rounded">
                          <table className="w-full text-[11px]">
                            <thead>
                              <tr className="bg-gray-100 dark:bg-gray-800">
                                {findingDetail.columns.map((col, i) => (
                                  <th key={i} className="px-2 py-1.5 text-left font-medium text-gray-600 dark:text-gray-400 whitespace-nowrap border-b border-gray-200 dark:border-gray-700">{col}</th>
                                ))}
                              </tr>
                            </thead>
                            <tbody>
                              {(findingDetail.rows || []).slice(0, 20).map((row, ri) => (
                                <tr key={ri} className="border-b border-gray-100 dark:border-gray-800 hover:bg-white dark:hover:bg-gray-800">
                                  {row.map((cell, ci) => {
                                    const colName = findingDetail.columns?.[ci] || ''
                                    const isAccountCol = /\baccount(_?id)?\b|recipientaccountid|sourceaccount|targetaccount/i.test(colName)
                                    const cellStr = cell === null ? '' : String(cell)
                                    const isAccountValue = /^\d{12}$/.test(cellStr)
                                    if (isAccountCol && isAccountValue) {
                                      return (
                                        <td key={ci} className="px-2 py-1 align-top text-gray-900 dark:text-gray-100 max-w-[260px]">
                                          <AccountLabel accountId={cellStr} />
                                        </td>
                                      )
                                    }
                                    return (
                                      <td key={ci} className="px-2 py-1 align-top text-gray-900 dark:text-gray-100 max-w-[280px]">
                                        <ExpandableCell value={cellStr} mono />
                                      </td>
                                    )
                                  })}
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        {findingDetail.sql && (
                          <details className="mt-2">
                            <summary className="text-[10px] text-gray-400 cursor-pointer hover:text-gray-600">{t('security.dashboard.showSql')}</summary>
                            <pre className="text-[10px] font-mono text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-900 p-2 rounded mt-1 overflow-x-auto">{findingDetail.sql}</pre>
                          </details>
                        )}
                      </>
                    ) : (
                      <p className="text-xs text-gray-500 py-2 text-center">{t('security.dashboard.noEvents')}</p>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function Metric({ label, value, color }: { label: string, value: string, color?: string }) {
  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded px-3 py-2">
      <p className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">{label}</p>
      <p className={`text-base font-bold ${color || 'text-gray-900 dark:text-white'}`}>{value}</p>
    </div>
  )
}

function FilterPill({ label, count, active, onClick, color }: { label: string, count: number, active: boolean, onClick: () => void, color?: string }) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium rounded-full transition-all ${color || 'text-gray-600 bg-gray-100 dark:bg-gray-800 dark:text-gray-300'} ${active ? 'ring-2 ring-blue-500 ring-offset-1' : 'opacity-75 hover:opacity-100'}`}
    >
      {label} <span className="font-bold">{count}</span>
    </button>
  )
}
