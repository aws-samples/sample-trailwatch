export interface InvestigationCountSource {
  rows?: readonly (readonly unknown[])[] | null
  total_rows?: unknown
  returned_rows?: unknown
  truncated?: unknown
}

export interface InvestigationCounts {
  returnedRows: number
  totalRows: number
  truncated: boolean
}

function nonNegativeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value
    : null
}

export function resolveInvestigationCounts(source: InvestigationCountSource | null): InvestigationCounts {
  const returnedRows = source?.rows?.length ?? 0
  const reportedReturnedRows = nonNegativeInteger(source?.returned_rows) ?? 0
  const reportedTotalRows = nonNegativeInteger(source?.total_rows) ?? 0
  const totalRows = Math.max(returnedRows, reportedReturnedRows, reportedTotalRows)

  return {
    returnedRows,
    totalRows,
    truncated: source?.truncated === true || totalRows > returnedRows,
  }
}

export const MAX_SUMMARIZE_ROWS = 50

interface SummaryPayloadInput {
  scenarioId: string
  scenarioName: string
  scenarioDescription?: string
  columns: string[]
  rows: unknown[][]
  totalRows: number
}

export function buildInvestigationSummaryPayload(input: SummaryPayloadInput) {
  return {
    scenario_id: input.scenarioId,
    scenario_name: input.scenarioName,
    scenario_description: input.scenarioDescription,
    columns: input.columns,
    rows: input.rows.slice(0, MAX_SUMMARIZE_ROWS),
    total_rows: Math.max(input.rows.length, nonNegativeInteger(input.totalRows) ?? 0),
  }
}
