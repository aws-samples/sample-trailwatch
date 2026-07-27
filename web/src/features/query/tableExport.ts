// Table export helpers for result grids. CSV uses RFC 4180 quoting (double
// any embedded quote, wrap fields containing commas/quotes/newlines) and
// neutralizes CSV/formula injection: attacker-influenced CloudTrail fields
// (userAgent, ARNs, errorMessage) can begin with = + - @ TAB or CR, which
// Excel/Sheets/LibreOffice interpret as formulas. Such string cells are
// prefixed with a single quote (') before RFC-4180 quoting. JSON exports an
// array of {column: value} objects so the file is usable directly in jq,
// spreadsheets, or SIEM ingest.

type Cell = string | number | boolean | null | undefined

// Leading characters that a spreadsheet treats as the start of a formula.
// TAB (0x09) and CR (0x0D) are included because some parsers strip leading
// whitespace before evaluating the first significant character.
const FORMULA_TRIGGERS = ['=', '+', '-', '@', '\t', '\r']

// neutralizeFormula prefixes a single quote (') to any string that begins
// with a formula trigger so spreadsheet apps render it as literal text
// instead of evaluating it. Non-dangerous strings are returned unchanged.
// Exported so a unit test can cover the neutralization in isolation.
export function neutralizeFormula(s: string): string {
  if (s.length > 0 && FORMULA_TRIGGERS.includes(s.charAt(0))) {
    return `'${s}`
  }
  return s
}

function csvEscape(v: unknown): string {
  if (v === null || v === undefined) return ''
  // Only string cells carry attacker-influenced content; numbers/booleans are
  // emitted verbatim and cannot start a formula. Neutralize before quoting so
  // the leading ' is part of the quoted field.
  if (typeof v === 'string') {
    const s = neutralizeFormula(v)
    if (/[",\r\n]/.test(s)) {
      return `"${s.replace(/"/g, '""')}"`
    }
    return s
  }
  const s = String(v)
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
