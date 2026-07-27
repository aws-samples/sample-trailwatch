import { describe, expect, it } from 'vitest'
import { neutralizeFormula, rowsToCSV, rowsToJSON } from './tableExport'

describe('table export', () => {
  it.each(['=1+1', '+cmd', '-2+3', '@SUM(A1)', '\tformula', '\rformula'])(
    'neutralizes spreadsheet formula input %j',
    (value) => {
      expect(neutralizeFormula(value)).toBe(`'${value}`)
    },
  )

  it('preserves safe text and applies RFC 4180 quoting', () => {
    expect(neutralizeFormula('arn:aws:iam::123456789012:role/Test')).toBe(
      'arn:aws:iam::123456789012:role/Test',
    )
    expect(rowsToCSV(
      ['event', 'detail'],
      [['CreateUser', 'value, with "quotes"'], ['Formula', '=1+1']],
    )).toBe(
      'event,detail\nCreateUser,"value, with ""quotes"""\nFormula,\'=1+1\n',
    )
  })

  it('maps missing cells to null in JSON', () => {
    expect(JSON.parse(rowsToJSON(['event', 'error'], [['ListBuckets']]))).toEqual([
      { event: 'ListBuckets', error: null },
    ])
  })
})
