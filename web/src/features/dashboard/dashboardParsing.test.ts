import { describe, expect, it } from 'vitest'
import { parseHourlyPanel, parseIdentityPanel, parseSummaryPanel } from './DashboardView'

describe('dashboard panel parsing', () => {
  it('does not turn a summary query failure into zero metrics', () => {
    const result = parseSummaryPanel({ columns: null, rows: null, error: 'query failed' })
    expect(result.ok).toBe(false)
  })

  it('accepts a legitimate empty summary and normalizes its null rate to zero', () => {
    const result = parseSummaryPanel({
      columns: ['events', 'identities', 'ips', 'errors', 'rate', 'services', 'first', 'last'],
      rows: [[0, 0, 0, 0, null, 0, null, null]],
    })
    expect(result).toEqual({
      ok: true,
      value: {
        totalEvents: 0,
        uniqueIdentities: 0,
        uniqueIPs: 0,
        errorEvents: 0,
        errorRate: 0,
        uniqueServices: 0,
        earliestEvent: '',
        latestEvent: '',
      },
    })
  })

  it('rejects malformed chart rows instead of rendering empty charts', () => {
    expect(parseIdentityPanel({
      columns: ['name', 'value'],
      rows: [['IAMUser', 'not-a-count']],
    }).ok).toBe(false)

    expect(parseHourlyPanel({
      columns: ['hour', 'total', 'errors', 'writes'],
      rows: [[25, 1, 0, 0]],
    }).ok).toBe(false)
  })
})
