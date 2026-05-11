export interface QueryResult {
  columns: ColumnMeta[]
  rows: Record<string, unknown>[]
  total_rows: number
  execution_ms: number
}

export interface ColumnMeta {
  name: string
  type: string
}

export interface PreBuiltQuery {
  id: string
  name: string
  description: string
  category: string
  sql: string
  parameters: QueryParameter[]
}

export interface QueryParameter {
  name: string
  label: string
  type: 'string' | 'number' | 'date'
  required: boolean
  default_value?: string
}

export interface QueryHistoryEntry {
  id: string
  sql: string
  executed_at: string
  execution_ms: number
  row_count: number
  error?: string
}
