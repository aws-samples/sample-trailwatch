import { describe, expect, it } from 'vitest'
import {
  buildInvestigationSummaryPayload,
  MAX_SUMMARIZE_ROWS,
  resolveInvestigationCounts,
} from './investigationTruthfulness'

function rows(count: number): unknown[][] {
  return Array.from({ length: count }, (_, index) => [index])
}

describe('investigation result counts', () => {
  it('reports the displayed rows and authoritative pre-limit total', () => {
    expect(resolveInvestigationCounts({
      rows: rows(100),
      total_rows: 764,
      returned_rows: 100,
      truncated: true,
    })).toEqual({
      returnedRows: 100,
      totalRows: 764,
      truncated: true,
    })
  })

  it('remains backward-compatible with responses that have no metadata', () => {
    expect(resolveInvestigationCounts({ rows: rows(7) })).toEqual({
      returnedRows: 7,
      totalRows: 7,
      truncated: false,
    })
  })

  it('does not label a partial result complete when the explicit flag is stale', () => {
    expect(resolveInvestigationCounts({
      rows: rows(50),
      total_rows: 125,
      returned_rows: 50,
      truncated: false,
    }).truncated).toBe(true)
  })
})

describe('investigation summary payload', () => {
  it('preserves the true total after slicing rows for the model', () => {
    const payload = buildInvestigationSummaryPayload({
      scenarioId: 'activity-by-ip',
      scenarioName: 'All Activity from IP',
      columns: ['eventName'],
      rows: rows(100),
      totalRows: 764,
    })

    expect(payload.rows).toHaveLength(MAX_SUMMARIZE_ROWS)
    expect(payload.total_rows).toBe(764)
  })

  it('never reports fewer total rows than the rows being summarized', () => {
    const payload = buildInvestigationSummaryPayload({
      scenarioId: 'activity-by-ip',
      scenarioName: 'All Activity from IP',
      columns: ['eventName'],
      rows: rows(3),
      totalRows: 1,
    })

    expect(payload.total_rows).toBe(3)
  })
})
