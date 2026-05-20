// Table export helpers for result grids. CSV uses RFC 4180 quoting (double
// any embedded quote, wrap fields containing commas/quotes/newlines).
// JSON exports an array of {column: value} objects so the file is usable
// directly in jq, spreadsheets, or SIEM ingest.

type Cell = string | number | boolean | null | undefined

function csvEscape(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v)
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`
  }
  return s
}

export function rowsToCSV(columns: string[], rows: Cell[][]): string {
  const header = columns.map(csvEscape).join(',')
  const body = rows.map(r => r.map(csvEscape).join(',')).join('\n')
  return body ? `${header}\n${body}\n` : `${header}\n`
}

export function rowsToJSON(columns: string[], rows: Cell[][]): string {
  const objs = rows.map(r => {
    const o: Record<string, Cell> = {}
    columns.forEach((c, i) => { o[c] = r[i] ?? null })
    return o
  })
  return JSON.stringify(objs, null, 2)
}

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
}

export function exportRowsAsCSV(columns: string[], rows: Cell[][], baseName = 'results') {
  download(`${baseName}-${timestamp()}.csv`, rowsToCSV(columns, rows), 'text/csv;charset=utf-8')
}

export function exportRowsAsJSON(columns: string[], rows: Cell[][], baseName = 'results') {
  download(`${baseName}-${timestamp()}.json`, rowsToJSON(columns, rows), 'application/json')
}
