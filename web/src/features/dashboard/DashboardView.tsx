import { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import {
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area, Legend
} from 'recharts'
import { RefreshCw, ExternalLink, ShieldAlert, AlertTriangle, Info, Loader2, Database } from 'lucide-react'
import { endpoints } from '../../config/api'
import { readApiError, readApiErrorDetails } from '../../comm/apiError'
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
  error_hint?: string
  error_detail?: string
}

type FindingCountState =
  | { status: 'loading'; text: string; detail: string }
  | { status: 'failed'; text: string; detail: string }
  | { status: 'missing'; text: string; detail: string }
  | { status: 'error'; text: string; detail: string }
  | { status: 'ready'; text: string; value: number }

type PanelState<T> =
  | { ok: true; value: T }
  | { ok: false; error: string }

interface SummaryMetrics {
  totalEvents: number
  uniqueIdentities: number
  uniqueIPs: number
  errorEvents: number
  errorRate: number
  uniqueServices: number
  earliestEvent: string
  latestEvent: string
}

interface IdentityDatum {
  name: string
  value: number
}

interface HourlyDatum {
  hour: string
  total: number
  errors: number
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

// Recharts supplies tooltip values as unknown even though the chart data has
// already been validated. Keep that display boundary defensive.
function toNum(v: unknown): number {
  if (v === null || v === undefined || v === '') return 0
  const n = Number(v)
  return Number.isFinite(n) ? n : 0
}

// Compute a whole-number percentage, guarding against divide-by-zero so 0/0
// renders 0% instead of "NaN%" (N94).
function pct(part: number, whole: number): number {
  if (!whole || !Number.isFinite(whole) || !Number.isFinite(part)) return 0
  return Math.round((part / whole) * 100)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function readFiniteNumber(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  if (typeof value !== 'string' || value.trim() === '') return null
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

function readPanelRows(panel: unknown, label: string, minimumColumns: number): PanelState<unknown[] | null> {
  if (!isRecord(panel)) {
    return { ok: false, error: `${label} response was missing.` }
  }

  if (panel.error !== undefined && panel.error !== null) {
    if (typeof panel.error !== 'string') {
      return { ok: false, error: `${label} returned an invalid error response.` }
    }
    if (panel.error.trim() !== '') {
      return { ok: false, error: panel.error.trim() }
    }
  }

  if (
    !Array.isArray(panel.columns) ||
    panel.columns.length < minimumColumns ||
    !panel.columns.every(column => typeof column === 'string')
  ) {
    return { ok: false, error: `${label} returned an invalid column shape.` }
  }

  if (!Object.prototype.hasOwnProperty.call(panel, 'rows')) {
    return { ok: false, error: `${label} response did not include rows.` }
  }
  if (panel.rows !== null && !Array.isArray(panel.rows)) {
    return { ok: false, error: `${label} returned an invalid row shape.` }
  }

  return { ok: true, value: panel.rows as unknown[] | null }
}

export function parseSummaryPanel(panel: unknown): PanelState<SummaryMetrics> {
  const parsed = readPanelRows(panel, 'Summary', 8)
  if (!parsed.ok) return parsed
  if (parsed.value === null || parsed.value.length === 0) {
    return { ok: false, error: 'Summary response did not include a metrics row.' }
  }

  const row = parsed.value[0]
  if (!Array.isArray(row) || row.length < 8) {
    return { ok: false, error: 'Summary returned an invalid metrics row.' }
  }

  const values: number[] = []
  for (const index of [0, 1, 2, 3, 5]) {
    const value = readFiniteNumber(row[index])
    if (
      value === null ||
      value < 0 ||
      !Number.isInteger(value)
    ) {
      return { ok: false, error: 'Summary returned an invalid numeric metric.' }
    }
    values.push(value)
  }
  const errorRateValue = readFiniteNumber(row[4])
  const errorRate = errorRateValue === null && values[0] === 0 ? 0 : errorRateValue
  if (errorRate === null || errorRate < 0 || errorRate > 100) {
    return { ok: false, error: 'Summary returned an invalid numeric metric.' }
  }

  for (const index of [6, 7]) {
    const value = row[index]
    if (value !== null && value !== undefined && typeof value !== 'string' && typeof value !== 'number') {
      return { ok: false, error: 'Summary returned an invalid event timestamp.' }
    }
  }

  return {
    ok: true,
    value: {
      totalEvents: values[0]!,
      uniqueIdentities: values[1]!,
      uniqueIPs: values[2]!,
      errorEvents: values[3]!,
      errorRate,
      uniqueServices: values[4]!,
      earliestEvent: row[6] == null ? '' : String(row[6]).slice(0, 16),
      latestEvent: row[7] == null ? '' : String(row[7]).slice(0, 16),
    },
  }
}

export function parseIdentityPanel(panel: unknown): PanelState<IdentityDatum[]> {
  const parsed = readPanelRows(panel, 'Identity types', 2)
  if (!parsed.ok) return parsed
  if (parsed.value === null) return { ok: true, value: [] }

  const identities: IdentityDatum[] = []
  for (const row of parsed.value) {
    if (!Array.isArray(row) || row.length < 2) {
      return { ok: false, error: 'Identity types returned an invalid row.' }
    }

    const rawName = row[0]
    const value = readFiniteNumber(row[1])
    if (
      (typeof rawName !== 'string' && typeof rawName !== 'number') ||
      String(rawName).trim() === '' ||
      value === null ||
      value < 0 ||
      !Number.isInteger(value)
    ) {
      return { ok: false, error: 'Identity types returned invalid chart data.' }
    }
    identities.push({ name: String(rawName), value })
  }

  return { ok: true, value: identities }
}

export function parseHourlyPanel(panel: unknown): PanelState<HourlyDatum[]> {
  const parsed = readPanelRows(panel, 'Hourly activity', 4)
  if (!parsed.ok) return parsed

  const hourlyByHour = new Map<number, { total: number; errors: number }>()
  for (const row of parsed.value || []) {
    if (!Array.isArray(row) || row.length < 4) {
      return { ok: false, error: 'Hourly activity returned an invalid row.' }
    }

    const hour = readFiniteNumber(row[0])
    const total = readFiniteNumber(row[1])
    const errors = readFiniteNumber(row[2])
    const writeOps = readFiniteNumber(row[3])
    if (
      hour === null ||
      !Number.isInteger(hour) ||
      hour < 0 ||
      hour > 23 ||
      total === null ||
      !Number.isInteger(total) ||
      total < 0 ||
      errors === null ||
      !Number.isInteger(errors) ||
      errors < 0 ||
      errors > total ||
      writeOps === null ||
      !Number.isInteger(writeOps) ||
      writeOps < 0 ||
      writeOps > total ||
      hourlyByHour.has(hour)
    ) {
      return { ok: false, error: 'Hourly activity returned invalid chart data.' }
    }
    hourlyByHour.set(hour, { total, errors })
  }

  return {
    ok: true,
    value: Array.from({ length: 24 }, (_, hour) => {
      const counts = hourlyByHour.get(hour)
      return {
        hour: `${String(hour).padStart(2, '0')}:00`,
        total: counts?.total ?? 0,
        errors: counts?.errors ?? 0,
      }
    }),
  }
}

function isFindingSummary(value: unknown): value is FindingSummary {
  return isRecord(value) && typeof value.id === 'string' && value.id.trim() !== ''
}

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
  const [findingsError, setFindingsError] = useState('')
  const [error, setError] = useState('')
  const [configurationMissing, setConfigurationMissing] = useState(false)
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'ALL'>('ALL')
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)
  const [findingDetail, setFindingDetail] = useState<FindingDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const dashboardRequestEpochRef = useRef(0)
  const dashboardAbortRef = useRef<AbortController | null>(null)
  const findingsRequestEpochRef = useRef(0)
  const findingsAbortRef = useRef<AbortController | null>(null)
  const detailRequestEpochRef = useRef(0)
  const detailAbortRef = useRef<AbortController | null>(null)

  async function fetchDashboard() {
    const requestEpoch = ++dashboardRequestEpochRef.current
    dashboardAbortRef.current?.abort()
    const controller = new AbortController()
    dashboardAbortRef.current = controller
    const isCurrentRequest = () =>
      dashboardRequestEpochRef.current === requestEpoch &&
      dashboardAbortRef.current === controller &&
      !controller.signal.aborted

    try {
      setLoading(true)
      setError('')
      setConfigurationMissing(false)
      // Check if index exists, trigger build if not
      const statusRes = await fetch(endpoints.indexStatus, { signal: controller.signal }).catch(() => null)
      if (!isCurrentRequest()) return
      if (statusRes?.ok) {
        const status: unknown = await statusRes.json()
        if (!isCurrentRequest()) return
        if (isRecord(status) && status.indexed === false) {
          await fetch(endpoints.indexBuild, { method: 'POST', signal: controller.signal }).catch(() => null)
          if (!isCurrentRequest()) return
        }
      }
      const res = await fetch(endpoints.dashboard, { signal: controller.signal })
      if (!res.ok) {
        const apiError = await readApiErrorDetails(res, 'Failed to load dashboard')
        if (!isCurrentRequest()) return
        if (apiError.code === 'no_data') {
          setData(null)
          setConfigurationMissing(true)
          return
        }
        throw new Error(apiError.message)
      }
      const result: unknown = await res.json()
      if (!isRecord(result)) {
        throw new Error('Dashboard returned an invalid response')
      }
      if (isCurrentRequest()) {
        setData(result as unknown as DashboardData)
      }
    } catch (e: unknown) {
      if (!isCurrentRequest()) return
      setError(e instanceof Error && e.message ? e.message : 'Failed to load dashboard')
    } finally {
      if (dashboardRequestEpochRef.current === requestEpoch && dashboardAbortRef.current === controller) {
        dashboardAbortRef.current = null
        setLoading(false)
      }
    }
  }

  async function fetchFindings() {
    const requestEpoch = ++findingsRequestEpochRef.current
    findingsAbortRef.current?.abort()
    const controller = new AbortController()
    findingsAbortRef.current = controller
    const isCurrentRequest = () =>
      findingsRequestEpochRef.current === requestEpoch &&
      findingsAbortRef.current === controller &&
      !controller.signal.aborted

    try {
      setFindingsLoading(true)
      setFindingsError('')
      setFindingSummaries({})
      const res = await fetch(endpoints.dashboardFindings, { signal: controller.signal })
      if (!res.ok) {
        const apiError = await readApiErrorDetails(res, 'Failed to load finding summaries')
        if (!isCurrentRequest()) return
        if (apiError.code === 'no_data') {
          setFindingSummaries({})
          setFindingsError('')
          return
        }
        throw new Error(apiError.message)
      }
      const results: unknown = await res.json()
      if (!Array.isArray(results)) {
        throw new Error('Finding summaries returned an invalid response')
      }
      const map: Record<string, FindingSummary> = {}
      for (const result of results) {
        if (!isFindingSummary(result)) {
          throw new Error('Finding summaries returned an invalid item')
        }
        map[result.id] = result
      }
      if (isCurrentRequest()) {
        setFindingSummaries(map)
      }
    } catch (e: unknown) {
      if (!isCurrentRequest()) return
      console.warn('dashboard findings fetch error', e)
      setFindingsError(e instanceof Error && e.message ? e.message : 'Failed to load finding summaries')
    } finally {
      if (findingsRequestEpochRef.current === requestEpoch && findingsAbortRef.current === controller) {
        findingsAbortRef.current = null
        setFindingsLoading(false)
      }
    }
  }

  async function fetchDetail(id: string) {
    const requestEpoch = ++detailRequestEpochRef.current
    detailAbortRef.current?.abort()
    const controller = new AbortController()
    detailAbortRef.current = controller
    const isCurrentRequest = () =>
      detailRequestEpochRef.current === requestEpoch &&
      detailAbortRef.current === controller &&
      !controller.signal.aborted

    setDetailLoading(true)
    setFindingDetail(null)
    try {
      const res = await fetch(endpoints.dashboardFindingDetail(id), { signal: controller.signal })
      if (!res.ok) {
        const msg = await readApiError(res, 'Failed to load finding detail')
        if (isCurrentRequest()) {
          setFindingDetail({ error: msg } as FindingDetail)
        }
        return
      }
      const detail: FindingDetail = await res.json()
      if (isCurrentRequest()) {
        setFindingDetail(detail)
      }
    } catch (e: unknown) {
      if (!isCurrentRequest()) return
      setFindingDetail({ error: e instanceof Error && e.message ? e.message : 'Failed to load finding detail' } as FindingDetail)
    } finally {
      if (detailRequestEpochRef.current === requestEpoch && detailAbortRef.current === controller) {
        detailAbortRef.current = null
        setDetailLoading(false)
      }
    }
  }

  function discardFindingDetail() {
    detailRequestEpochRef.current += 1
    detailAbortRef.current?.abort()
    detailAbortRef.current = null
    setDetailLoading(false)
    setFindingDetail(null)
  }

  function refreshAll() {
    const detailID = expandedFinding
    discardFindingDetail()
    void fetchDashboard()
    void fetchFindings()
    if (detailID) {
      void fetchDetail(detailID)
    }
  }

  useEffect(() => {
    void fetchDashboard()
    void fetchFindings()
    return () => {
      dashboardRequestEpochRef.current += 1
      dashboardAbortRef.current?.abort()
      dashboardAbortRef.current = null
      findingsRequestEpochRef.current += 1
      findingsAbortRef.current?.abort()
      findingsAbortRef.current = null
      detailRequestEpochRef.current += 1
      detailAbortRef.current?.abort()
      detailAbortRef.current = null
    }
  }, [])

  function handleFindingClick(finding: FindingDef) {
    if (expandedFinding === finding.id) {
      setExpandedFinding(null)
      discardFindingDetail()
    } else {
      setExpandedFinding(finding.id)
      void fetchDetail(finding.id)
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

  if (configurationMissing) {
    return (
      <div className="flex items-center justify-center h-full px-6">
        <div className="max-w-sm text-center">
          <Database className="w-9 h-9 text-blue-500 mx-auto mb-3" />
          <h2 className="text-base font-semibold text-gray-900 dark:text-white">
            {t('data.sync.configIncomplete')}
          </h2>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
            {t('data.sync.goToSettings')}
          </p>
          <button
            type="button"
            onClick={() => navigate('s3-config')}
            className="mt-4 inline-flex items-center gap-2 px-3 py-2 text-sm font-medium rounded bg-[#0972d3] text-white hover:bg-[#0860b0]"
          >
            <Database className="w-4 h-4" />
            {t('security.dashboard.configureS3')}
          </button>
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
          <button onClick={refreshAll} className="text-xs text-blue-600 hover:underline">{t('security.dashboard.retry')}</button>
        </div>
      </div>
    )
  }

  if (!data) return <div />

  const summaryState = parseSummaryPanel(data.summary)
  const summaryMetrics = summaryState.ok ? summaryState.value : null
  const identityState = parseIdentityPanel(data.identity_types)
  const identityData = identityState.ok ? identityState.value : []
  // Successful empty hourly results still get a complete 0..23 series. Failed
  // or malformed results take the unavailable branch below instead.
  const hourlyState = parseHourlyPanel(data.hourly_volume)
  const hourlyData = hourlyState.ok ? hourlyState.value : []

  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  FINDINGS.forEach(f => severityCounts[f.severity]++)

  const filteredFindings = selectedSeverity === 'ALL' ? FINDINGS : FINDINGS.filter(f => f.severity === selectedSeverity)

  // Group findings by category so an analyst scanning the page sees IAM,
  // Network, Data Access etc. as distinct sections rather than one flat
  // list. Order categories by their first finding's appearance in FINDINGS
  // so severity-driven ordering is preserved within each section.
  const groupedFindings = filteredFindings.reduce<{ category: string; findings: typeof FINDINGS }[]>((acc, f) => {
    const existing = acc.find(g => g.category === f.category)
    if (existing) existing.findings.push(f)
    else acc.push({ category: f.category, findings: [f] })
    return acc
  }, [])

  function getFindingCount(id: string): FindingCountState {
    if (findingsLoading) {
      return { status: 'loading', text: '...', detail: 'Loading finding summary' }
    }
    if (findingsError) {
      return { status: 'failed', text: 'Failed', detail: findingsError }
    }

    const s = findingSummaries[id]
    if (!s) {
      return { status: 'missing', text: 'Missing', detail: 'Finding summary was missing from the response' }
    }
    if (s.error) {
      return { status: 'error', text: 'Error', detail: s.error }
    }

    const cell = s.rows?.[0]?.[0]
    if (cell === null || cell === undefined || (typeof cell === 'string' && cell.trim() === '')) {
      return { status: 'missing', text: 'Missing', detail: 'Finding summary did not include a count' }
    }

    const value = Number(cell)
    if (!Number.isFinite(value)) {
      return { status: 'error', text: 'Error', detail: 'Finding summary returned an invalid count' }
    }
    return { status: 'ready', text: String(value), value }
  }

  function getFindingExtra(id: string): string {
    const s = findingSummaries[id]
    const rows = s?.rows
    const cols = s?.columns
    if (!rows || rows.length === 0 || !cols || cols.length < 2) return ''
    const val = rows[0]?.[1]
    // Treat real null / empty as "no extra"; don't render the string "null".
    if (val === null || val === undefined || val === '') return ''
    return `${val} ${cols[1]!.replace(/_/g, ' ')}`
  }

  const hasIncompleteFindingSummaries =
    !findingsLoading &&
    !findingsError &&
    FINDINGS.some(finding => getFindingCount(finding.id).status !== 'ready')
  const findingSummaryNotice = findingsError ||
    (hasIncompleteFindingSummaries ? 'Some finding summaries are unavailable.' : '')

  return (
    <div className="h-full overflow-y-auto bg-gray-50 dark:bg-gray-950">
      {/* Header */}
      <div className="sticky top-0 z-20 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 px-6 py-3 shadow-sm">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-base font-semibold text-gray-900 dark:text-white">{t('security.dashboard.title')}</h1>
            <p className="text-[11px] text-gray-600 dark:text-gray-400">
              {summaryMetrics
                ? t('security.dashboard.accountInfo', {
                    earliest: summaryMetrics.earliestEvent,
                    latest: summaryMetrics.latestEvent,
                    count: summaryMetrics.totalEvents.toLocaleString(),
                  })
                : 'Summary metrics unavailable'}
            </p>
          </div>
          <button onClick={refreshAll} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800">
            <RefreshCw className={`w-3.5 h-3.5 ${loading || findingsLoading ? 'animate-spin' : ''}`} /> {t('security.dashboard.refresh')}
          </button>
        </div>
      </div>

      <div className="px-6 py-4 space-y-5">
        {/* Summary metrics */}
        {summaryMetrics ? (
          <div className="grid grid-cols-3 lg:grid-cols-6 gap-2">
            <Metric label={t('security.dashboard.metric.events')} value={summaryMetrics.totalEvents.toLocaleString()} />
            <Metric label={t('security.dashboard.metric.identities')} value={String(summaryMetrics.uniqueIdentities)} />
            <Metric label={t('security.dashboard.metric.sourceIPs')} value={String(summaryMetrics.uniqueIPs)} />
            <Metric label={t('security.dashboard.metric.errors')} value={summaryMetrics.errorEvents.toLocaleString()} color={summaryMetrics.errorEvents > 0 ? 'text-red-600' : ''} />
            <Metric label={t('security.dashboard.metric.errorRate')} value={`${summaryMetrics.errorRate}%`} color={summaryMetrics.errorRate > 5 ? 'text-red-600' : ''} />
            <Metric label={t('security.dashboard.metric.services')} value={String(summaryMetrics.uniqueServices)} />
          </div>
        ) : (
          <div className="rounded border border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30">
            <PanelUnavailable
              title="Summary unavailable"
              detail={summaryState.ok ? 'Summary metrics are unavailable.' : summaryState.error}
              retryLabel={t('security.dashboard.retry')}
              retrying={loading}
              onRetry={() => { void fetchDashboard() }}
            />
          </div>
        )}

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          <div className="lg:col-span-2 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
            <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">{t('security.dashboard.hourlyActivity')}</h3>
            {hourlyState.ok ? (
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
            ) : (
              <PanelUnavailable
                title="Hourly activity unavailable"
                detail={hourlyState.error}
                retryLabel={t('security.dashboard.retry')}
                retrying={loading}
                onRetry={() => { void fetchDashboard() }}
                className="min-h-[140px]"
              />
            )}
          </div>
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4 flex flex-col">
            <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">{t('security.dashboard.identityTypes')}</h3>
            {!identityState.ok ? (
              <PanelUnavailable
                title="Identity data unavailable"
                detail={identityState.error}
                retryLabel={t('security.dashboard.retry')}
                retrying={loading}
                onRetry={() => { void fetchDashboard() }}
                className="min-h-[140px]"
              />
            ) : identityData.length === 0 ? (
              <div className="flex-1 flex items-center justify-center text-[11px] text-gray-400">{t('common.noData', 'No data')}</div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={100}>
                  <PieChart>
                    <Pie data={identityData} cx="50%" cy="50%" outerRadius={45} innerRadius={25} dataKey="value">
                      {identityData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                    </Pie>
                    <Tooltip contentStyle={{ fontSize: '10px', borderRadius: '6px' }} formatter={(v: any, n: any) => {
                      const total = identityData.reduce((a, d) => a + d.value, 0)
                      const num = toNum(v)
                      return [`${num} (${pct(num, total)}%)`, String(n)]
                    }} />
                  </PieChart>
                </ResponsiveContainer>
                <ul className="mt-2 grid grid-cols-2 gap-x-2 gap-y-0.5 text-[10px] text-gray-700 dark:text-gray-300">
                  {(() => {
                    const total = identityData.reduce((a, d) => a + d.value, 0)
                    return identityData.map((d, i) => (
                      <li key={d.name} className="flex items-center gap-1.5 min-w-0">
                        <span className="inline-block w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: COLORS[i % COLORS.length] }} />
                        <span className="truncate" title={d.name}>{d.name}</span>
                        <span className="ml-auto tabular-nums text-gray-500 dark:text-gray-400">{pct(d.value, total)}%</span>
                      </li>
                    ))
                  })()}
                </ul>
              </>
            )}
          </div>
        </div>

        {/* Severity filter */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-medium text-gray-500 mr-1">{t('security.dashboard.filter')}</span>
          <FilterPill label={t('security.dashboard.severity.all')} count={FINDINGS.length} active={selectedSeverity === 'ALL'} onClick={() => setSelectedSeverity('ALL')} />
          <FilterPill label={t('security.dashboard.severity.critical')} count={severityCounts.CRITICAL} active={selectedSeverity === 'CRITICAL'} onClick={() => setSelectedSeverity('CRITICAL')} color="text-red-700 bg-red-100 dark:bg-red-900/30 dark:text-red-300" />
          <FilterPill label={t('security.dashboard.severity.high')} count={severityCounts.HIGH} active={selectedSeverity === 'HIGH'} onClick={() => setSelectedSeverity('HIGH')} color="text-orange-700 bg-orange-100 dark:bg-orange-900/30 dark:text-orange-300" />
          <FilterPill label={t('security.dashboard.severity.medium')} count={severityCounts.MEDIUM} active={selectedSeverity === 'MEDIUM'} onClick={() => setSelectedSeverity('MEDIUM')} color="text-yellow-700 bg-yellow-100 dark:bg-yellow-900/30 dark:text-yellow-300" />
          <FilterPill label={t('security.dashboard.severity.low')} count={severityCounts.LOW} active={selectedSeverity === 'LOW'} onClick={() => setSelectedSeverity('LOW')} color="text-blue-700 bg-blue-100 dark:bg-blue-900/30 dark:text-blue-300" />
        </div>

        {findingSummaryNotice && (
          <div role="alert" className="flex items-center justify-between gap-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 dark:border-amber-800 dark:bg-amber-950/30">
            <div className="flex min-w-0 items-center gap-2">
              <AlertTriangle className="h-4 w-4 flex-shrink-0 text-amber-600 dark:text-amber-400" />
              <span className="truncate text-xs text-amber-800 dark:text-amber-200" title={findingSummaryNotice}>
                {findingSummaryNotice}
              </span>
            </div>
            <button
              type="button"
              onClick={() => { void fetchFindings() }}
              className="flex flex-shrink-0 items-center gap-1 text-xs font-medium text-amber-800 hover:underline dark:text-amber-200"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              {t('security.dashboard.retry')}
            </button>
          </div>
        )}

        {/* Findings list — grouped by category */}
        <div className="space-y-4">
          {groupedFindings.map(group => (
          <div key={group.category}>
            <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-1.5 px-1">{group.category}</div>
            <div className="space-y-1">
          {group.findings.map(finding => {
            const style = SEVERITY_STYLES[finding.severity]
            const Icon = style.icon
            const countState = getFindingCount(finding.id)
            const extra = countState.status === 'ready' ? getFindingExtra(finding.id) : ''
            const isExpanded = expandedFinding === finding.id
            const hasEvents = countState.status === 'ready' && countState.value > 0
            const detailPanelId = `finding-detail-${finding.id}`
            const countColor = countState.status === 'ready'
              ? (hasEvents ? 'text-gray-900 dark:text-white' : 'text-gray-300 dark:text-gray-600')
              : (countState.status === 'loading' ? 'text-gray-300 dark:text-gray-600' : 'text-amber-700 dark:text-amber-300')

            return (
              <div key={finding.id} className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden bg-white dark:bg-gray-900">
                <button
                  type="button"
                  onClick={() => handleFindingClick(finding)}
                  aria-expanded={isExpanded}
                  aria-controls={detailPanelId}
                  className={`flex w-full items-center gap-3 border-l-4 px-4 py-3 text-left transition-colors hover:bg-gray-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500 dark:hover:bg-gray-800/50 ${style.border}`}
                >
                  <Icon className={`w-4 h-4 flex-shrink-0 ${style.text}`} />
                  <span className="flex-1 min-w-0">
                    <span className="flex items-center gap-2">
                      <span className="text-sm font-medium text-gray-900 dark:text-white">{finding.title}</span>
                      <span className={`px-1.5 py-0.5 text-[10px] font-bold uppercase rounded ${style.badge}`}>{finding.severity}</span>
                    </span>
                    <span className="mt-0.5 block text-[11px] text-gray-600 dark:text-gray-400">{finding.description}</span>
                  </span>
                  {/* Live count */}
                  <span className="flex items-center gap-3 flex-shrink-0">
                    <span className="min-w-[4.5rem] text-right">
                      <span
                        className={`${countState.status === 'ready' || countState.status === 'loading' ? 'text-lg font-bold' : 'text-[11px] font-semibold'} ${countColor}`}
                        title={'detail' in countState ? countState.detail : undefined}
                      >
                        {countState.text}
                      </span>
                      {extra && <span className="block text-[10px] text-gray-600 dark:text-gray-400">{extra}</span>}
                    </span>
                    <ExternalLink aria-hidden="true" className={`w-4 h-4 ${isExpanded ? 'text-blue-500' : 'text-gray-400'}`} />
                  </span>
                </button>

                {/* Expanded detail panel */}
                {isExpanded && (
                  <div id={detailPanelId} className="border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 px-4 py-3">
                    {detailLoading ? (
                      <div className="flex items-center gap-2 py-4 justify-center">
                        <Loader2 className="w-4 h-4 animate-spin text-blue-500" />
                        <span className="text-xs text-gray-700 dark:text-gray-300">{t('security.dashboard.runningQuery')}</span>
                      </div>
                    ) : findingDetail?.error ? (
                      <div role="alert" className="py-2">
                        {findingDetail.error_hint ? (
                          <p className="text-xs text-red-700 dark:text-red-300">{findingDetail.error_hint}</p>
                        ) : (
                          <p className="text-xs text-red-700 dark:text-red-300">{findingDetail.error}</p>
                        )}
                        {(findingDetail.error_detail || findingDetail.error_hint) && (
                          <details className="mt-1">
                            <summary className="text-[10px] cursor-pointer text-red-700 dark:text-red-300 hover:underline">{t('security.investigate.showTechnicalDetail')}</summary>
                            <pre className="text-[10px] text-red-600 dark:text-red-400 mt-1 whitespace-pre-wrap font-mono">{findingDetail.error_detail || findingDetail.error}</pre>
                          </details>
                        )}
                      </div>
                    ) : findingDetail?.columns && findingDetail.columns.length > 0 ? (
                      <>
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-[11px] text-gray-600 dark:text-gray-400">{t('security.dashboard.results', { count: findingDetail.rows?.length || 0 })}</span>
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
                                  <th key={i} className="px-2 py-1.5 text-left font-medium text-gray-700 dark:text-gray-300 whitespace-nowrap border-b border-gray-200 dark:border-gray-700">{col}</th>
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
                        {(findingDetail.rows?.length || 0) > 20 && (
                          <p className="text-[10px] text-gray-600 dark:text-gray-400 mt-1">
                            {t('security.dashboard.rowsTruncated', { shown: 20, total: findingDetail.rows!.length })}
                          </p>
                        )}
                        {findingDetail.sql && (
                          <details className="mt-2">
                            <summary className="text-[10px] text-gray-600 dark:text-gray-400 cursor-pointer hover:text-gray-800 dark:hover:text-gray-200">{t('security.dashboard.showSql')}</summary>
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
          ))}
        </div>
      </div>
    </div>
  )
}

function PanelUnavailable({
  title,
  detail,
  retryLabel,
  retrying,
  onRetry,
  className = '',
}: {
  title: string
  detail: string
  retryLabel: string
  retrying: boolean
  onRetry: () => void
  className?: string
}) {
  return (
    <div role="alert" className={`flex flex-col items-center justify-center px-4 py-3 text-center ${className}`}>
      <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400" />
      <p className="mt-1 text-xs font-medium text-amber-900 dark:text-amber-100">{title}</p>
      <p className="mt-0.5 max-w-full break-words text-[11px] text-amber-800 dark:text-amber-200">{detail}</p>
      <button
        type="button"
        disabled={retrying}
        onClick={onRetry}
        className="mt-2 flex items-center gap-1 text-xs font-medium text-amber-800 hover:underline disabled:cursor-wait disabled:opacity-60 dark:text-amber-200"
      >
        <RefreshCw className={`h-3.5 w-3.5 ${retrying ? 'animate-spin' : ''}`} />
        {retryLabel}
      </button>
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
